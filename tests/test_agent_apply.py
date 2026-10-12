"""Integration test for the agent's apply path: write config -> SIGHUP the
running core -> verify from the core's stats, or roll back.

A small child process stands in for the core: it records each SIGHUP.  A stub
`systemctl` reports that process as the unit's MainPID.

Run:  python3 -m unittest discover -s tests -v
"""
import os
import stat
import subprocess
import sys
import textwrap
import time
import unittest

from test_agent import P, _TMP  # noqa: F401  (imports the panel into a sandbox)

ETC = os.environ["SHADOW_ETC_DIR"]

CONFIG = textwrap.dedent("""\
    transport = "spoof"
    real_ip = "10.0.0.1"
    peer_real_ip = "203.0.113.1"
    spoofed_ip = "8.8.4.4"
    peer_spoofed_ip = "1.2.3.4"
    spoofed_ip_pool = []
    data_port = 51820
    icmp_id = 17185
    pre_shared_key = "%s"
    allowed_peers = []
    tunnel_count = 4
    mtu = 1380
    initial_cwnd = 10.0
    max_retries = 8
    rto_min_ms = 200
    auto_restart = "on-failure"
    restart_sec = 5
    interface = "eth0"
    socks5_port = 1080
    """) % ("a" * 64)


class AgentApply(unittest.TestCase):
    def setUp(self):
        self.hups = os.path.join(_TMP, "hups.txt")
        if os.path.exists(self.hups):
            os.unlink(self.hups)
        self.core = subprocess.Popen([sys.executable, "-c", textwrap.dedent("""\
            import signal, sys, time
            f = sys.argv[1]
            signal.signal(signal.SIGHUP, lambda *a: open(f, "a").write("hup\\n"))
            print("ready", flush=True)
            time.sleep(60)
            """), self.hups], stdout=subprocess.PIPE)
        self.core.stdout.readline()
        stub = os.path.join(_TMP, "systemctl")
        with open(stub, "w") as f:
            f.write("#!/bin/sh\nprintf 'Id=shadow-spoof-client.service\\nActiveState=active\\nSubState=running\\n"
                    "MainPID=%d\\nNRestarts=0\\nActiveEnterTimestampMonotonic=1\\nResult=success\\n'\n" % self.core.pid)
        os.chmod(stub, os.stat(stub).st_mode | stat.S_IEXEC)
        P.SYSTEMCTL = stub
        with open(os.path.join(ETC, "role"), "w") as f:
            f.write("client\n")
        with open(P.CONF_MAIN, "w") as f:
            f.write(CONFIG)
        P.agent_live_capable = lambda role: True
        self.inst = P.find_inst("main")

    def tearDown(self):
        self.core.kill()
        self.core.wait()
        self.core.stdout.close()

    def _hups(self):
        time.sleep(0.2)
        if not os.path.exists(self.hups):
            return 0
        with open(self.hups) as f:
            return f.read().count("hup")

    def _samples(self, now, n, retx, rto=200, retries=8, srtt=100.0, var=80.0):
        return [{"ts": now - 10 * i, "sent": 1000, "retx": retx, "gave_up": 0, "rtt_samples": 1,
                 "srtt_ms": srtt, "rttvar_ms": var, "rto_min_ms": rto, "max_retries": retries} for i in range(n)]

    def _drive_until_applied(self, mem, settings, now):
        ov = {"active": "active", "restarts": 0, "uptime": 3600}
        for i in range(P.AGENT_BAD_STREAK):
            P.agent_tick_one(self.inst, settings, mem, ov, self._samples(now + i, 10, retx=100), {"cpu": 10.0}, now + i)
        return ov

    def test_apply_signal_then_verify(self):
        mem, settings, now = {}, dict(P.AGENT_DEFAULTS, enabled=True), time.time()
        ov = self._drive_until_applied(mem, settings, now)
        self.assertIn("pending", mem)
        self.assertEqual(P.find_inst("main").cfg()["rto_min_ms"], 420)
        self.assertEqual(self._hups(), 1)
        later = now + 20
        P.agent_tick_one(self.inst, settings, mem, ov, self._samples(later, 1, retx=10, rto=420), {"cpu": 10.0}, later)
        self.assertNotIn("pending", mem)
        self.assertEqual(mem["log"][-1]["kind"], "verified")
        self.assertGreater(mem["cooldown_until"], later)

    def test_unconfirmed_change_is_rolled_back(self):
        mem, settings, now = {}, dict(P.AGENT_DEFAULTS, enabled=True), time.time()
        ov = self._drive_until_applied(mem, settings, now)
        self.assertEqual(P.find_inst("main").cfg()["rto_min_ms"], 420)
        late = now + P.AGENT_VERIFY_SEC + 5
        P.agent_tick_one(self.inst, settings, mem, ov, self._samples(late, 1, retx=100, rto=200), {"cpu": 10.0}, late)
        self.assertNotIn("pending", mem)
        self.assertEqual(mem["log"][-1]["kind"], "rollback")
        self.assertEqual(P.find_inst("main").cfg()["rto_min_ms"], 200)
        self.assertEqual(self._hups(), 2)

    def test_operator_reset_restores_baseline_and_pauses(self):
        mem, settings, now = {}, dict(P.AGENT_DEFAULTS, enabled=True), time.time()
        self._drive_until_applied(mem, settings, now)
        self.assertEqual(P.find_inst("main").cfg()["rto_min_ms"], 420)
        mem.pop("pending")
        P._agent_save_state({"main": mem})
        r = P.agent_reset("main")
        self.assertEqual(r["baseline"], {"rto_min_ms": 200, "max_retries": 8})
        self.assertEqual(P.find_inst("main").cfg()["rto_min_ms"], 200)
        st = P.agent_state_all()["main"]
        self.assertEqual(st["condition"], "paused")
        self.assertEqual(st["tuning"]["rto_min_ms"], 200)
        self.assertEqual(st["pending"]["tuning"]["rto_min_ms"], 200)
        self.assertEqual(self._hups(), 2)

    def test_manual_edit_becomes_new_baseline(self):
        mem, settings, now = {}, dict(P.AGENT_DEFAULTS, enabled=True), time.time()
        ov = {"active": "active", "restarts": 0, "uptime": 3600}
        P.agent_tick_one(self.inst, settings, mem, ov, self._samples(now, 10, retx=0), {"cpu": 10.0}, now)
        with open(P.CONF_MAIN, "w") as f:
            f.write(CONFIG.replace("rto_min_ms = 200", "rto_min_ms = 500"))
        P.agent_tick_one(self.inst, settings, mem, ov, self._samples(now + 30, 10, retx=0), {"cpu": 10.0}, now + 30)
        self.assertEqual(mem["baseline"]["rto_min_ms"], 500)
        self.assertTrue(any(e["kind"] == "manual" for e in mem["log"]))
        self.assertEqual(self._hups(), 0)


if __name__ == "__main__":
    unittest.main()
