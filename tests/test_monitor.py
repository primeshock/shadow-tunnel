"""Tests for the monitor's self-healing journal reader and non-colliding
tunnel-default suggestions."""
import os
import stat
import time
import unittest

from test_agent import P, _TMP

ETC = os.environ["SHADOW_ETC_DIR"]
STATE = os.environ["SHADOW_STATE_DIR"]


def _write(path, text, mode=0o755):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC if mode & 0o111 else os.stat(path).st_mode)


class JournalSelfHeal(unittest.TestCase):
    def setUp(self):
        os.makedirs(os.path.join(STATE, "monitor"), exist_ok=True)
        with open(os.path.join(ETC, "role"), "w") as f:
            f.write("client\n")
        # A journalctl stub that only emits a line when re-reading from scratch
        # (--since present); a plain cursor read returns nothing (stuck cursor).
        self.jc = os.path.join(_TMP, "journalctl_heal")
        with open(self.jc, "w") as f:
            f.write(
                "#!/bin/sh\n"
                "has_since=0\n"
                'for a in "$@"; do [ "$a" = "--since" ] && has_since=1; done\n'
                "cf=\n"
                'while [ $# -gt 0 ]; do if [ "$1" = "--cursor-file" ]; then shift; cf="$1"; fi; shift; done\n'
                '[ -n "$cf" ] && echo CURSOR > "$cf"\n'
                'if [ "$has_since" = "1" ]; then\n'
                "  now=$(python3 -c 'import time;print(int(time.time()*1e6))')\n"
                '  printf \'{"MESSAGE":"[x INFO client] stats: tunnels=4 sent=10 retx_timeout=0 retx_nack=0 '
                "gave_up=0 rtt_samples=2 srtt_ms=80.0 rttvar_ms=5.0 rto_min_ms=200 max_retries=8 interval_s=10 "
                'established=4 rx_pkts=20 bytes_tx=500 bytes_rx=800 transport=spoof","__REALTIME_TIMESTAMP":"%s",'
                '"PRIORITY":"6","_SYSTEMD_UNIT":"shadow-spoof-client.service"}\\n\' "$now"\n'
                "fi\nexit 0\n"
            )
        os.chmod(self.jc, 0o755)
        self._orig = P.JOURNALCTL
        P.JOURNALCTL = self.jc
        try:
            os.unlink(P.CURSOR_FILE)
        except OSError:
            pass
        self.addCleanup(lambda: setattr(P, "JOURNALCTL", self._orig))

    def test_recovers_from_a_stuck_cursor(self):
        m = P.Monitor()
        m.read_journal("client")                       # fresh (no cursor) -> gets a line
        self.assertEqual(m.jhealth["lines"], 1)
        self.assertTrue(m.last_est.get("main"))        # handshake refreshed from rx_pkts

        m.read_journal("client")                       # cursor now stuck -> 0 lines
        self.assertEqual(m.jhealth["lines"], 0)

        m.jhealth["lines_at"] = time.time() - 130       # 2+ min with no lines
        m.read_journal("client")                       # heal: re-read from scratch
        self.assertEqual(m.jhealth["lines"], 1)

    def test_a_single_empty_read_does_not_resync(self):
        m = P.Monitor()
        m.read_journal("client")
        before = os.path.getmtime(P.CURSOR_FILE)
        time.sleep(0.02)
        m.read_journal("client")                       # empty but <120s: keep the cursor
        self.assertEqual(m.jhealth["lines"], 0)


class TunnelDefaults(unittest.TestCase):
    def setUp(self):
        os.makedirs(os.path.join(ETC, "tunnels"), exist_ok=True)
        with open(os.path.join(ETC, "role"), "w") as f:
            f.write("client\n")
        key = "a" * 64
        with open(P.CONF_MAIN, "w") as f:
            f.write('transport="spoof"\nreal_ip="10.0.0.1"\npeer_real_ip="2.2.2.2"\n'
                    'spoofed_ip="8.8.8.8"\npeer_spoofed_ip="1.1.1.1"\ndata_port=40001\nicmp_id=111\n'
                    'pre_shared_key="%s"\ninterface="eth0"\nsocks5_port=1080\n' % key)
        ss = os.path.join(_TMP, "ss_none")
        with open(ss, "w") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(ss, 0o755)
        self._ss = P.SS
        P.SS = ss
        self.addCleanup(lambda: setattr(P, "SS", self._ss))

    def test_suggestions_never_collide_with_existing_tunnel(self):
        for _ in range(25):
            dp, icmp, sk = P.suggest_tunnel_defaults()
            self.assertTrue(20000 <= dp <= 65000 and 20000 <= sk <= 65000)
            self.assertTrue(1 <= icmp <= 65535)
            self.assertNotEqual(dp, 40001)
            self.assertNotEqual(icmp, 111)
            self.assertNotEqual(dp, sk)


if __name__ == "__main__":
    unittest.main()
