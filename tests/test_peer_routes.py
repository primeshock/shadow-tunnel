"""Unit tests for the panel-sync connection priority: direct -> local tunnel
SOCKS -> configured SOCKS proxy."""
import unittest

from test_agent import P  # imports the embedded panel into a sandbox


class Inst:
    def __init__(self, name, role, socks):
        self.name, self.role, self._socks = name, role, socks

    def cfg(self):
        return {"socks5_port": self._socks}


class PeerRoutes(unittest.TestCase):
    def setUp(self):
        self._inst, self._pl = P.instances, P.port_listening
        self.addCleanup(lambda: setattr(P, "instances", self._inst))
        self.addCleanup(lambda: setattr(P, "port_listening", self._pl))

    def routes(self, panel, insts=(), listening=()):
        P.instances = lambda: list(insts)
        P.port_listening = lambda port, local=False: port in listening
        return [label for label, _ in P._peer_routes(panel)]

    def test_direct_only_by_default(self):
        self.assertEqual(self.routes({}), ["direct"])

    def test_order_is_direct_then_tunnel_then_proxy(self):
        r = self.routes({"sync_proxy": "127.0.0.1:9050"},
                        insts=[Inst("main", "client", 1080)], listening={1080})
        self.assertEqual(r, ["direct", "tunnel:main", "proxy"])

    def test_tunnel_route_skipped_when_socks_not_listening(self):
        r = self.routes({}, insts=[Inst("main", "client", 1080)], listening=set())
        self.assertEqual(r, ["direct"])

    def test_server_tunnels_do_not_add_a_tunnel_route(self):
        r = self.routes({}, insts=[Inst("main", "server", 0)], listening={0})
        self.assertEqual(r, ["direct"])

    def test_multiple_client_tunnels_each_add_a_route(self):
        r = self.routes({}, insts=[Inst("main", "client", 1080), Inst("b", "client", 1081)],
                        listening={1080, 1081})
        self.assertEqual(r, ["direct", "tunnel:main", "tunnel:b"])

    def test_proxy_only_when_configured(self):
        self.assertEqual(self.routes({"sync_proxy": "1.2.3.4:1080"}), ["direct", "proxy"])
        self.assertEqual(self.routes({"sync_proxy": "   "}), ["direct"])


if __name__ == "__main__":
    unittest.main()
