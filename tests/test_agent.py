"""Tests for the panel's smart agent and stats parsing.

The panel is embedded in install.sh; this extracts it into a temp dir with the
path overrides pointed at a sandbox, then imports it.

Run:  python3 -m unittest discover -s tests -v
"""
import importlib.util
import os
import random
import re
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_TMP = tempfile.mkdtemp(prefix="shadow-agent-test-")
for sub in ("etc", "state", "run"):
    os.makedirs(os.path.join(_TMP, sub), exist_ok=True)
os.environ["SHADOW_ETC_DIR"] = os.path.join(_TMP, "etc")
os.environ["SHADOW_STATE_DIR"] = os.path.join(_TMP, "state")
os.environ["SHADOW_RUN_DIR"] = os.path.join(_TMP, "run")

with open(os.path.join(ROOT, "install.sh"), encoding="utf-8") as f:
    _src = re.search(r"<<'SHADOW_PANEL_PY_EOF'\n(.*?)\nSHADOW_PANEL_PY_EOF", f.read(), re.S).group(1)
_path = os.path.join(_TMP, "shadow_panel.py")
with open(_path, "w", encoding="utf-8") as f:
    f.write(_src)
_spec = importlib.util.spec_from_file_location("shadow_panel", _path)
P = importlib.util.module_from_spec(_spec)
sys.modules["shadow_panel"] = P
_spec.loader.exec_module(P)

BASE = {"rto_min_ms": 200, "max_retries": 8}
NOW = 1_000_000.0


def ctx(**kw):
    c = {"transport": "spoof", "live_ok": True, "active": "active", "restarts": 0,
         "uptime": 3600, "cpu": 20.0, "cpu_limit": 85}
    c.update(kw)
    return c


def win(sent=5000, retx=0, gave_up=0, srtt=80.0, var=10.0, rtt_samples=10, ts=NOW):
    return {"samples": 30, "sent": sent, "retx": retx, "gave_up": gave_up, "rtt_samples": rtt_samples,
            "retx_pct": round(100.0 * retx / sent, 2) if sent else None, "srtt_ms": srtt, "rttvar_ms": var,
            "latest_ts": ts, "core_rto_min_ms": 200, "core_max_retries": 8}


def decide_n(n, tuning, w, c=None, mem=None, strategy="balanced", base=None):
    mem = {} if mem is None else mem
    out = None
    for i in range(n):
        out = P.agent_decide(dict(tuning), dict(base or BASE), w, c or ctx(), mem, strategy, NOW + i)
    return out, mem


class StatsParsing(unittest.TestCase):
    def test_parses_core_line(self):
        d = P.parse_stats_line("[2026-10-12T12:00:00Z INFO  client] stats: tunnels=3 sent=1000 retx_timeout=30 "
                               "retx_nack=20 gave_up=1 rtt_samples=4 srtt_ms=82.5 rttvar_ms=9.0 rto_min_ms=200 "
                               "max_retries=8 interval_s=10")
        self.assertEqual(d["retx"], 50)
        self.assertEqual(d["retx_pct"], 5.0)
        self.assertEqual(d["srtt_ms"], 82.5)

    def test_missing_rtt_is_none(self):
        d = P.parse_stats_line("stats: tunnels=0 sent=0 retx_timeout=0 retx_nack=0 gave_up=0 rtt_samples=0 "
                               "srtt_ms=- rttvar_ms=- rto_min_ms=200 max_retries=8 interval_s=10")
        self.assertIsNone(d["srtt_ms"])
        self.assertIsNone(d["retx_pct"])

    def test_rejects_other_lines(self):
        self.assertIsNone(P.parse_stats_line("tunnel 4 established"))
        self.assertIsNone(P.parse_stats_line("stats: tunnels=x sent=1"))

    def test_window_aggregates_and_drops_old_samples(self):
        old = {"ts": NOW - 400, "sent": 999, "retx": 999, "gave_up": 0, "rtt_samples": 0}
        s = [old] + [{"ts": NOW - 10 * i, "sent": 100, "retx": 5, "gave_up": 0, "rtt_samples": 1,
                      "srtt_ms": 50.0, "rttvar_ms": 5.0, "rto_min_ms": 200, "max_retries": 8} for i in range(3)]
        w = P.agent_window(s, NOW)
        self.assertEqual(w["sent"], 300)
        self.assertEqual(w["retx_pct"], 5.0)


class AgentDecisions(unittest.TestCase):
    def test_tcp_transport_is_not_tuned(self):
        (cond, _, new), _ = decide_n(1, BASE, win(retx=900), ctx(transport="tcp"))
        self.assertEqual((cond, new), ("not_applicable", None))

    def test_old_core_is_observe_only(self):
        (cond, _, new), _ = decide_n(1, BASE, win(retx=900), ctx(live_ok=False))
        self.assertEqual((cond, new), ("observe_only", None))

    def test_low_traffic_is_not_judged(self):
        (cond, _, new), _ = decide_n(5, BASE, win(sent=50, retx=40))
        self.assertEqual((cond, new), ("idle", None))

    def test_hysteresis_band_holds(self):
        (cond, _, new), _ = decide_n(10, BASE, win(retx=150))  # 3% between exit 1.5 and enter 5
        self.assertEqual((cond, new), ("stable", None))

    def test_jitter_needs_a_sustained_streak_then_raises_rto(self):
        w = win(retx=500, srtt=100.0, var=80.0)  # 10% retx, var/srtt 0.8
        (cond, _, new), _ = decide_n(P.AGENT_BAD_STREAK - 1, BASE, w)
        self.assertEqual((cond, new), ("jitter", None))
        (cond, _, new), _ = decide_n(P.AGENT_BAD_STREAK, BASE, w)
        self.assertEqual(cond, "jitter")
        self.assertEqual(new["rto_min_ms"], 420)  # max(200*1.5, 100 + 4*80)
        self.assertEqual(new["max_retries"], 8)

    def test_real_loss_without_give_ups_is_reported_not_tuned(self):
        (cond, expl, new), _ = decide_n(5, BASE, win(retx=500, srtt=100.0, var=10.0))
        self.assertEqual((cond, new), ("packet_loss", None))
        self.assertIn("FEC", expl)

    def test_give_ups_raise_retries_within_cap(self):
        (cond, _, new), _ = decide_n(5, {"rto_min_ms": 200, "max_retries": 18}, win(retx=500, gave_up=3, var=5.0))
        self.assertEqual(new["max_retries"], 20)  # balanced cap

    def test_cooldown_blocks_changes(self):
        mem = {"cooldown_until": NOW + 300}
        (cond, expl, new), _ = decide_n(5, BASE, win(retx=500, srtt=100.0, var=80.0), mem=mem)
        self.assertIsNone(new)
        self.assertIn("cooldown", expl)

    def test_hourly_rate_limit(self):
        mem = {"changes": [NOW - 60 * i for i in range(P.AGENT_MAX_CHANGES_PER_HOUR)]}
        (_, expl, new), _ = decide_n(5, BASE, win(retx=500, srtt=100.0, var=80.0), mem=mem)
        self.assertIsNone(new)
        self.assertIn("limit", expl)

    def test_cpu_pressure_prevents_escalation(self):
        (cond, _, new), _ = decide_n(5, BASE, win(retx=500, srtt=100.0, var=80.0), ctx(cpu=95.0))
        self.assertEqual((cond, new), ("resource_pressure", None))

    def test_unresponsive_peer_is_not_tuned(self):
        (cond, _, new), _ = decide_n(5, BASE, win(retx=3500, rtt_samples=0))
        self.assertEqual((cond, new), ("peer_unresponsive", None))

    def test_relaxes_toward_baseline_but_never_below(self):
        high = {"rto_min_ms": 210, "max_retries": 9}
        (cond, _, new), _ = decide_n(P.AGENT_GOOD_STREAK, high, win(retx=10))
        self.assertEqual(cond, "healthy")
        self.assertEqual(new, BASE)

    def test_healthy_at_baseline_does_nothing(self):
        (cond, _, new), _ = decide_n(50, BASE, win(retx=10))
        self.assertEqual((cond, new), ("healthy", None))

    def test_restart_loop_reverts_and_pauses(self):
        mem = {}
        P.agent_decide(dict(BASE), BASE, win(), ctx(restarts=0), mem, "balanced", NOW)
        cond, _, new = P.agent_decide({"rto_min_ms": 600, "max_retries": 12}, BASE, win(), ctx(restarts=3), mem, "balanced", NOW + 60)
        self.assertEqual(cond, "restart_loop")
        self.assertEqual(new, BASE)
        cond, _, new = P.agent_decide(dict(BASE), BASE, win(retx=500, var=80.0, srtt=100.0), ctx(restarts=3), mem, "balanced", NOW + 90)
        self.assertEqual((cond, new), ("paused", None))

    def test_settling_after_restart(self):
        (cond, _, new), _ = decide_n(5, BASE, win(retx=500), ctx(uptime=30))
        self.assertEqual((cond, new), ("settling", None))

    def test_bounds_hold_under_random_inputs(self):
        rnd = random.Random(7)
        for _ in range(3000):
            strategy = rnd.choice(list(P.AGENT_STRATEGIES))
            cap = P.AGENT_STRATEGIES[strategy]
            base = {"rto_min_ms": rnd.choice([100, 200, 500]), "max_retries": rnd.choice([4, 8, 10])}
            tun = {"rto_min_ms": rnd.randint(base["rto_min_ms"], max(base["rto_min_ms"], cap["rto_cap"])),
                   "max_retries": rnd.randint(base["max_retries"], max(base["max_retries"], cap["retries_cap"]))}
            sent = rnd.randint(0, 20000)
            w = win(sent=sent, retx=rnd.randint(0, max(sent, 1)), gave_up=rnd.randint(0, 5),
                    srtt=rnd.choice([None, 20.0, 150.0, 900.0]), var=rnd.choice([None, 1.0, 50.0, 600.0]),
                    rtt_samples=rnd.randint(0, 5))
            mem = {"streak_bad": rnd.randint(0, 5), "streak_good": rnd.randint(0, 30)}
            _, _, new = P.agent_decide(tun, base, w, ctx(cpu=rnd.choice([10.0, 99.0])), mem, strategy, NOW)
            if new is None:
                continue
            self.assertTrue(10 <= new["rto_min_ms"] <= 60000 and 1 <= new["max_retries"] <= 100)
            self.assertGreaterEqual(new["rto_min_ms"], base["rto_min_ms"])
            self.assertGreaterEqual(new["max_retries"], base["max_retries"])
            self.assertLessEqual(new["rto_min_ms"], max(cap["rto_cap"], tun["rto_min_ms"]))
            self.assertLessEqual(new["max_retries"], max(cap["retries_cap"], tun["max_retries"]))
            self.assertNotEqual(new, tun)


class AgentSync(unittest.TestCase):
    def setUp(self):
        for f in (P.AGENT_JSON, P.AGENT_STATE):
            if os.path.exists(f):
                os.unlink(f)

    def test_newer_revision_wins(self):
        r = P.agent_receive("main", {"enabled": True, "strategy": "reliability", "cpu_limit": 80, "rev": 3})
        self.assertTrue(r["ok"])
        self.assertTrue(P.agent_settings("main")["enabled"])
        r = P.agent_receive("main", {"enabled": False, "strategy": "balanced", "cpu_limit": 80, "rev": 2})
        self.assertFalse(r["ok"])
        self.assertTrue(r["conflict"])
        self.assertTrue(P.agent_settings("main")["enabled"])

    def test_equal_revision_with_different_content_is_a_conflict(self):
        P.agent_receive("main", {"enabled": True, "strategy": "balanced", "cpu_limit": 85, "rev": 5})
        r = P.agent_receive("main", {"enabled": False, "strategy": "balanced", "cpu_limit": 85, "rev": 5})
        self.assertTrue(r.get("conflict"))
        r = P.agent_receive("main", {"enabled": True, "strategy": "balanced", "cpu_limit": 85, "rev": 5})
        self.assertTrue(r["ok"])

    def test_reconcile_clears_stale_failure_when_peer_already_matches(self):
        P.agent_receive("main", {"enabled": True, "strategy": "balanced", "cpu_limit": 85, "rev": 4})
        st = P.agent_state_all()
        st["main"]["sync"] = {"state": "failed", "error": "peer unreachable"}
        P._agent_save_state(st)
        orig = (P.load_panel, P._peer_request, P.instances)
        try:
            P.load_panel = lambda: {"peer_url": "http://peer", "sync_token": "x"}
            P._peer_request = lambda *a, **k: {"tunnels": {"main": dict(P.agent_settings("main"))}}
            P.instances = lambda: [P.Inst("main", "client", P.CONF_MAIN)]
            P.agent_reconcile()
            self.assertEqual(P.agent_state_all()["main"]["sync"]["state"], "synced")
            other = dict(P.agent_settings("main"), enabled=False)
            P._peer_request = lambda *a, **k: {"tunnels": {"main": other}}
            P.agent_reconcile()
            self.assertEqual(P.agent_state_all()["main"]["sync"]["state"], "conflict")
        finally:
            P.load_panel, P._peer_request, P.instances = orig

    def test_invalid_settings_are_rejected(self):
        with self.assertRaises(P.ApiError):
            P.agent_receive("main", {"strategy": "turbo", "rev": 9})
        with self.assertRaises(P.ApiError):
            P.agent_check_settings({"cpu_limit": 5})


if __name__ == "__main__":
    unittest.main()
