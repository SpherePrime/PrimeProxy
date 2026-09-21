import unittest
import socket
from pathlib import Path
from unittest.mock import patch

from tools import run_diagnostics, _verdict, _suggest, _tls_key, RECOMMENDED_PROFILE
from tools.conn import _describe, _tcp_kind, default_gateway, lan_ip, tcp_probe, tls_probe
from tools.dnsinfo import _doh_resolve, _qname, _ips_overlap
from tools.windows_tools import (_admin_capable, _admin_capable_for, admin_status,
                                 defender_exclude, ensure_elevated,
                                 windivert_presence, windows_cleanup)


class TcpKindTest(unittest.TestCase):
    def test_kinds(self):
        self.assertEqual(_tcp_kind(ConnectionRefusedError()), "refused")
        self.assertEqual(_tcp_kind(ConnectionResetError()), "reset")
        self.assertEqual(_tcp_kind(ConnectionAbortedError()), "reset")
        ex = OSError(0, "timed out")
        self.assertEqual(_tcp_kind(ex), "timeout")

    def test_describe(self):
        self.assertIn("DPI", _describe("reset"))
        self.assertIn("блокировк", _describe("timeout"))


class TlsProbeTest(unittest.TestCase):
    def test_gaierror_dns(self):
        with patch("socket.create_connection", side_effect=socket.gaierror(-2, "Name or service not known")):
            res = tls_probe("no-such-host.invalid")
        self.assertFalse(res["ok"])
        self.assertEqual(res["kind"], "dns")

    def test_winsock_dns_errno(self):
        with patch("socket.create_connection", side_effect=OSError(11001, "host not found")):
            res = tls_probe("no-such-host.invalid")
        self.assertFalse(res["ok"])
        self.assertEqual(res["kind"], "dns")

    def test_timeout(self):
        exc = OSError(0, "timed out", 10060)

        def _fail(*a, **k):
            raise exc
        with patch("socket.create_connection", side_effect=_fail):
            res = tls_probe("example.com")
        self.assertFalse(res["ok"])
        self.assertEqual(res["kind"], "timeout")


class TcpProbeTest(unittest.TestCase):
    def test_ok(self):
        class FakeSock:
            def __enter__(self): return self
            def __exit__(self, *a): return False
        with patch("socket.create_connection", return_value=FakeSock()):
            res = tcp_probe("1.1.1.1", 443)
        self.assertTrue(res["ok"])
        self.assertEqual(res["kind"], "ok")


class NetInfoTest(unittest.TestCase):
    def test_gateway_parse(self):
        fake = ("IPv4 Route Table\n\n"
                "Active Routes:\n"
                "Network Destination        Netmask          Gateway       Interface  Metric\n"
                "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50    25\n")
        with patch("subprocess.run") as run:
            run.return_value.stdout = fake
            run.return_value.returncode = 0
            self.assertEqual(default_gateway(), "192.168.1.1")

    def test_gateway_none(self):
        with patch("subprocess.run", side_effect=Exception("x")):
            self.assertIsNone(default_gateway())

    def test_lan_ip(self):
        with patch("socket.socket") as sock:
            sock.return_value.getsockname.return_value = ("10.0.0.5", 0)
            self.assertEqual(lan_ip(), "10.0.0.5")


class DnsInfoTest(unittest.TestCase):
    def test_qname(self):
        self.assertEqual(_qname("core.telegram.org"),
                         b"\x04core\x08telegram\x03org\x00")

    def test_ips_overlap(self):
        self.assertTrue(_ips_overlap(["1.1.1.1", "2.2.2.2"], ["2.2.2.2"]))
        self.assertFalse(_ips_overlap(["1.1.1.1"], ["9.9.9.9"]))
        self.assertFalse(_ips_overlap([], ["1.1.1.1"]))

    def test_doh_resolve_invalid(self):
        with patch("urllib.request.urlopen", side_effect=OSError("no net")):
            self.assertEqual(_doh_resolve("example.com", "https://x/dns-query"), [])


class WindowsToolsTest(unittest.TestCase):
    def test_windivert_presence_shape(self):
        info = windivert_presence()
        self.assertIn("driver", info)
        self.assertIn("engine", info)
        self.assertIn("admin", info)
        self.assertIsInstance(info["engine"]["files"], dict)

    def test_windows_cleanup_all_ok(self):
        class CP:
            returncode = 0
        with patch("tools.windows_tools._run_hidden", return_value=CP()), \
             patch("dns.flush_dns_cache", return_value=""):
            res = windows_cleanup()
        self.assertEqual(res["level"], "success")
        self.assertIn("dynamic_ports", res["performed"])

    def test_windows_cleanup_failed(self):
        class CP:
            returncode = 1
        with patch("tools.windows_tools._run_hidden", return_value=CP()), \
             patch("dns.flush_dns_cache", side_effect=Exception("x")):
            res = windows_cleanup()
        self.assertEqual(res["level"], "error")
        self.assertFalse(res["ok"])

    def test_defender_requires_admin(self):
        with patch("tools.windows_tools.admin_status", return_value=False):
            res = defender_exclude()
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "admin_required")


class EnsureElevatedTest(unittest.TestCase):
    def test_non_windows_is_already(self):
        with patch("sys.platform", "linux"), patch("sys.argv", ["main.py"]):
            self.assertEqual(ensure_elevated(), "already")

    def test_admin_is_already(self):
        with patch("sys.platform", "win32"), \
             patch("tools.windows_tools.admin_status", return_value=True):
            self.assertEqual(ensure_elevated(), "already")

    def test_launches_uac(self):
        class FakeShell:
            def __init__(self, r): self._r = r
            def ShellExecuteW(self, *a): return self._r
        class FakeW:
            def __init__(self, r): self.shell32 = FakeShell(r)
        with patch("sys.platform", "win32"), \
             patch("tools.windows_tools.admin_status", return_value=False), \
             patch("tools.windows_tools.ctypes.windll", FakeW(42)), \
             patch("os.getcwd", return_value=r"C:\app"):
            self.assertEqual(ensure_elevated(["main.py", "--headless"]), "started")

    def test_uac_cancelled(self):
        class FakeShell:
            def __init__(self, r): self._r = r
            def ShellExecuteW(self, *a): return self._r
        class FakeW:
            def __init__(self, r): self.shell32 = FakeShell(r)
        with patch("sys.platform", "win32"), \
             patch("tools.windows_tools.admin_status", return_value=False), \
             patch("tools.windows_tools.ctypes.windll", FakeW(5)), \
             patch("os.getcwd", return_value=r"C:\app"):
            self.assertEqual(ensure_elevated(["main.py"]), "cancel")

    def test_uac_exception_is_cancel(self):
        class FakeW:
            def __getattr__(self, name):
                raise OSError("boom")
        with patch("sys.platform", "win32"), \
             patch("tools.windows_tools.admin_status", return_value=False), \
             patch("tools.windows_tools.ctypes.windll", FakeW()):
            self.assertEqual(ensure_elevated(["main.py"]), "cancel")

    def test_not_admin_capable(self):
        with patch("sys.platform", "win32"), \
             patch("tools.windows_tools.admin_status", return_value=False), \
             patch("tools.windows_tools._admin_capable", return_value=False):
            self.assertEqual(ensure_elevated(["main.py"]), "no")

    def test_admin_capable_converts_and_checks(self):
        class FakeAdv:
            def ConvertStringSidToSidW(self, s, out):
                out.contents.value = 12345
                return True
            def CheckTokenMembership(self, h, sid, out):
                out.contents.value = 1
                return True
        class FakeKernel:
            def LocalFree(self, sid):
                return True
        class FakeWindll:
            def __init__(self):
                self.advapi32 = FakeAdv()
                self.kernel32 = FakeKernel()
        with patch("tools.windows_tools.ctypes.windll", FakeWindll()):
            self.assertTrue(_admin_capable())

    def test_admin_capable_for_membership_only(self):
        self.assertTrue(_admin_capable_for(True, False))

    def test_admin_capable_for_deny_only_present(self):
        self.assertTrue(_admin_capable_for(False, True))

    def test_admin_capable_for_none(self):
        self.assertFalse(_admin_capable_for(False, False))

    def test_admin_capable_error_returns_true(self):
        class FakeKernel:
            def LocalFree(self, sid):
                return True
        class FakeAdv:
            def ConvertStringSidToSidW(self, s, out):
                return False
        class FakeWindll:
            def __init__(self):
                self.advapi32 = FakeAdv()
                self.kernel32 = FakeKernel()
        with patch("tools.windows_tools.ctypes.windll", FakeWindll()):
            self.assertTrue(_admin_capable())


class VerdictTest(unittest.TestCase):
    def test_ok(self):
        status, acts = _verdict({"tg_blocked": False, "gen_ok": True})
        self.assertEqual(status, "ok")
        self.assertEqual(acts[0]["action"], "none")

    def test_no_network(self):
        status, acts = _verdict({"no_network": True})
        self.assertEqual(status, "fail")
        self.assertEqual(acts[0]["action"], "internet_cleanup")

    def test_tg_blocked_with_engine(self):
        status, acts = _verdict({"tg_blocked": True, "engine_ok": True})
        self.assertEqual(status, "fail")
        self.assertEqual(acts[0]["action"], "start_dpi")
        self.assertEqual(acts[1]["action"], "open_profiles")

    def test_tg_blocked_without_engine(self):
        status, acts = _verdict({"tg_blocked": True, "engine_ok": False})
        self.assertEqual(acts[1]["action"], "open_profiles")
        self.assertEqual(acts[1]["key"], "dg.act_engine_missing")

    def test_dns_broken(self):
        status, acts = _verdict({"dns_broken": True})
        self.assertEqual(acts[0]["action"], "force_dns")

    def test_suggest(self):
        self.assertEqual(_suggest("x", "y.z"), {"action": "x", "key": "y.z"})
        self.assertEqual(RECOMMENDED_PROFILE, "Default (circular) v2.txt")


class RunDiagnosticsTest(unittest.TestCase):
    def test_runs_with_fakes(self):
        with patch("tools.default_gateway", return_value=None), \
             patch("tools.lan_ip", return_value=None), \
             patch("tools._public_ip", return_value=""), \
             patch("tools.read_dns_servers_status", return_value=[
                 {"server": "8.8.8.8", "reachable": True, "rtt_ms": 11}]), \
             patch("tools.read_dns_integrity", return_value=[
                 {"host": "core.telegram.org", "system_ips": ["149.154.175.50"],
                  "status": "ok"}]), \
             patch("tools.probe_many", return_value={
                 "core.telegram.org": {"ok": True, "ms": 20, "kind": "ok"}}), \
             patch("tools.tcp_probe", return_value={"ok": False, "ms": 100,
                                                     "kind": "timeout", "detail": ""}), \
             patch("tools._probe_engine", return_value={"ok": True, "dir": "C:\\app\\exe",
                                                        "found": {}}), \
             patch("tools._recent_crashes", return_value=[]):
            rep = run_diagnostics(proxy_running=False, proxy_port=1443)

        self.assertTrue(rep["ok"])
        keys = {g["key"] for g in rep["groups"]}
        self.assertTrue({"network", "dns", "telegram", "dpi", "proxy"} <= keys)
        self.assertEqual(rep["recommended_profile"], RECOMMENDED_PROFILE)
        tg = next(g for g in rep["groups"] if g["key"] == "telegram")
        self.assertTrue(any(it["msg_key"] == "tls_ok" for it in tg["items"]))
        self.assertTrue(any(it["msg_key"] == "tls_timeout" for it in tg["items"]))

    def test_tls_variant_keys(self):
        self.assertEqual(_tls_key({"ok": True, "kind": "ok"}), "tls_ok")
        self.assertEqual(_tls_key({"ok": False, "kind": "reset"}), "tls_reset")
        self.assertEqual(_tls_key({"ok": False, "kind": "no_tls"}), "tls_notls")
        self.assertEqual(_tls_key({"ok": False, "kind": "???"}), "tls_timeout")


if __name__ == "__main__":
    unittest.main()