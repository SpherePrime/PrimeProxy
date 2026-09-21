import unittest
from unittest.mock import patch

from dns.adapters import (
    _parse_dns_rows,
    _parse_interface_rows,
    _run_pwsh,
    get_network_adapters,
)
from dns.check import run_connectivity_test
from dns.poisoning import check_dns_poisoning
from dns.quick_check import run_quick_dns_check
from blockcheck.windows_icmp import WindowsPingResult


class ParsingTest(unittest.TestCase):
    def test_parses_interface_rows(self):
        rows = _parse_interface_rows("VLAN |5|Connected\nWi-Fi |12|Connected\ngarbage\n")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], {"name": "VLAN", "interface_index": 5, "status": "Connected"})
        self.assertEqual(rows[1]["name"], "Wi-Fi")

    def test_skips_bad_rows(self):
        self.assertEqual(_parse_interface_rows("nope\nEthernet|3\n|7|Connected\n|8|Connected"), [])
        self.assertEqual(_parse_interface_rows(""), [])

    def test_normalizes_nbsp_alias(self):
        rows = _parse_interface_rows("Ethernet\u00A03|9|Connected")
        self.assertEqual(rows[0]["name"], "Ethernet 3")

    def test_parses_dns_rows(self):
        out = _parse_dns_rows("VLAN |1.1.1.1, 8.8.8.8\nWi-Fi |2606:4700::1111\n")
        self.assertEqual(out["VLAN"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(out["Wi-Fi"], ["2606:4700::1111"])

    def test_run_pwsh_needs_windows(self):
        with patch("dns.adapters.sys.platform", "linux"):
            self.assertEqual(_run_pwsh("Get-NetIPInterface"), "")


class AdaptersTest(unittest.TestCase):
    def test_get_network_adapters(self):
        with patch("dns.adapters._run_pwsh", side_effect=[
            "VLAN |5|Connected\nWi-Fi |12|Disconnected\n",
            "VLAN |1.1.1.1, 8.8.8.8\n",
        ]):
            data = get_network_adapters()
        self.assertEqual(data["total"], 2)
        self.assertEqual(data["connected"], 1)
        vlan = next(a for a in data["adapters"] if a["name"] == "VLAN")
        self.assertTrue(vlan["is_connected"])
        self.assertEqual(vlan["dns_servers"], ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(vlan["interface_index"], 5)

    def test_fallback_when_pwsh_empty(self):
        with patch("dns.adapters._run_pwsh", return_value=""), \
             patch("dns.check._windows_connected_adapters", return_value=["Ethernet"]):
            data = get_network_adapters()
        self.assertEqual(data["total"], 1)
        self.assertEqual(data["adapters"][0]["name"], "Ethernet")
        self.assertEqual(data["adapters"][0]["dns_servers"], [])


class QuickCheckTest(unittest.TestCase):
    def test_all_resolved(self):
        with patch("dns.quick_check.resolve_ipv4", return_value="1.2.3.4"):
            res = run_quick_dns_check(timeout=1.0)
        self.assertTrue(res["overall"])
        self.assertEqual(res["checked"], 4)
        self.assertEqual(res["ok"], 4)
        self.assertTrue(all(r["ok"] for r in res["results"]))

    def test_partial_failure(self):
        def fake(host, **kw):
            return "1.2.3.4" if host in ("www.youtube.com", "discord.com") else None

        with patch("dns.quick_check.resolve_ipv4", side_effect=fake):
            res = run_quick_dns_check(timeout=1.0)
        self.assertFalse(res["overall"])
        self.assertEqual(res["ok"], 2)
        self.assertEqual(
            [r["status"] for r in res["results"]].count("fail"), 2
        )

    def test_all_failed(self):
        with patch("dns.quick_check.resolve_ipv4", return_value=None):
            res = run_quick_dns_check(timeout=1.0)
        self.assertFalse(res["overall"])
        self.assertEqual(res["ok"], 0)
        self.assertTrue(all(not r["ok"] for r in res["results"]))


class ConnectivityTest(unittest.TestCase):
    def test_all_reachable(self):
        with patch("dns.check.ping_ipv4_host_winapi",
                   return_value=WindowsPingResult(ok=True, average_ms=11.5)):
            res = run_connectivity_test([("A", "1.1.1.1"), ("B", "8.8.8.8")])
        rows = res["results"]
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(r["ok"] for r in rows))
        self.assertEqual(rows[0]["time_ms"], 11.5)

    def test_unreachable(self):
        with patch("dns.check.ping_ipv4_host_winapi",
                   return_value=WindowsPingResult(ok=False, error_code="TIMEOUT", detail="Timeout")):
            res = run_connectivity_test([("A", "1.1.1.1")])
        self.assertFalse(res["results"][0]["ok"])
        self.assertFalse(res["results"][0]["unsupported"])

    def test_unsupported(self):
        with patch("dns.check.ping_ipv4_host_winapi",
                   return_value=WindowsPingResult(
                       ok=False, error_code="UNSUPPORTED", detail="Windows ICMP API unavailable")):
            res = run_connectivity_test([("A", "8.8.8.8")])
        row = res["results"][0]
        self.assertIsNone(row["ok"])
        self.assertTrue(row["unsupported"])

    def test_no_hosts(self):
        res = run_connectivity_test([])
        self.assertEqual(res, {"results": []})


class PoisoningTest(unittest.TestCase):
    VALID_YT = "142.250.72.46"
    VALID_DC = "162.159.128.233"
    BLOCKED = "127.0.0.1"

    def _clean(self, *args, **kwargs):
        domain = args[0] if args else ""
        if "youtube" in domain or "googlevideo" in domain:
            return [self.VALID_YT]
        if "discord" in domain or domain.endswith(".gg"):
            return [self.VALID_DC]
        return ["8.8.4.4"]

    def _clean_ipv4(self, *args, **kwargs):
        ips = self._clean(*args, **kwargs)
        return ips[0] if ips else None

    def test_clean_dns(self):
        with patch("dns.poisoning.resolve_ipv4", side_effect=self._clean_ipv4), \
             patch("dns.poisoning.resolve_udp", side_effect=self._clean), \
             patch("dns.poisoning.resolve_doh", side_effect=self._clean):
            res = check_dns_poisoning()
        self.assertFalse(res["summary"]["dns_poisoning_detected"])
        self.assertFalse(res["summary"]["youtube_blocked"])
        self.assertFalse(res["summary"]["discord_blocked"])
        self.assertFalse(res["summary"]["external_dns_blocked"])
        self.assertTrue(all(
            d["verdict"] == "clean"
            for svc in res["services"].values() for d in svc["domains"].values()
        ))

    def test_poisoned_system_dns(self):
        def fake(host, **_kw):
            return "127.0.0.1" if "youtube" in host else self.VALID_DC

        with patch("dns.poisoning.resolve_ipv4", side_effect=fake), \
             patch("dns.poisoning.resolve_udp", side_effect=self._clean), \
             patch("dns.poisoning.resolve_doh", side_effect=self._clean):
            res = check_dns_poisoning()
        self.assertTrue(res["summary"]["dns_poisoning_detected"])
        self.assertTrue(res["summary"]["youtube_blocked"])
        self.assertTrue(res["summary"]["poisoned_domains"])
        self.assertEqual(
            res["services"]["youtube"]["domains"]["www.youtube.com"]["verdict"], "poisoned"
        )
        self.assertEqual(res["summary"]["recommended_dns"], "1.1.1.1")

    def test_all_resolvers_fail_inconclusive(self):
        with patch("dns.poisoning.resolve_ipv4", return_value=[]), \
             patch("dns.poisoning.resolve_udp", return_value=[]), \
             patch("dns.poisoning.resolve_doh", return_value=[]):
            res = check_dns_poisoning()
        self.assertFalse(res["summary"]["dns_poisoning_detected"])
        self.assertTrue(res["summary"]["external_dns_blocked"])
        self.assertTrue(all(
            d["verdict"] == "inconclusive"
            for svc in res["services"].values() for d in svc["domains"].values()
        ))

    def test_should_stop(self):
        with patch("dns.poisoning.resolve_ipv4", side_effect=self._clean_ipv4), \
             patch("dns.poisoning.resolve_udp", side_effect=self._clean), \
             patch("dns.poisoning.resolve_doh", side_effect=self._clean):
            res = check_dns_poisoning(should_stop=lambda: True)
        self.assertFalse(res["summary"]["dns_poisoning_detected"])

    def test_log_callback_called(self):
        seen = []
        with patch("dns.poisoning.resolve_ipv4", side_effect=self._clean_ipv4), \
             patch("dns.poisoning.resolve_udp", side_effect=self._clean), \
             patch("dns.poisoning.resolve_doh", side_effect=self._clean):
            check_dns_poisoning(log_callback=seen.append)
        self.assertTrue(any("YouTube" in line for line in seen))
        self.assertTrue(any("коррект" in line for line in seen))


class ApiSmokeTest(unittest.TestCase):
    def test_get_network_adapters(self):
        from ui.api import SwiftAPI
        with patch("dns.adapters.get_network_adapters", return_value={"adapters": [],
                                                                     "total": 0, "connected": 0}):
            res = SwiftAPI().get_network_adapters()
        self.assertEqual(res["total"], 0)

    def test_run_quick_dns_check(self):
        from ui.api import SwiftAPI
        with patch("dns.quick_check.run_quick_dns_check",
                   return_value={"results": [{"ok": True}], "ok": 1, "checked": 1, "overall": True}), \
             patch("dns.check.run_connectivity_test",
                   return_value={"results": [{"ok": True}]}):
            res = SwiftAPI().run_quick_dns_check()
        self.assertTrue(res["ok"])
        self.assertTrue(res["overall"])
        self.assertEqual(len(res["results"]), 2)

    def test_dns_poisoning_lifecycle(self):
        from ui.api import SwiftAPI

        def fake_check(log_callback=None, should_stop=None):
            log_callback("line-1")
            return {"services": {}, "summary": {"dns_poisoning_detected": False,
                                                "youtube_blocked": False,
                                                "discord_blocked": False,
                                                "external_dns_blocked": False,
                                                "recommended_dns": None,
                                                "poisoned_domains": []}}

        api = SwiftAPI()
        with patch("dns.poisoning.check_dns_poisoning", side_effect=fake_check):
            self.assertEqual(api.run_dns_poisoning_check(), {"ok": True})
        import time
        for _ in range(100):
            st = api.get_dns_check_status()
            if st["status"] != "running":
                break
            time.sleep(0.02)
        self.assertEqual(st["status"], "done")
        self.assertIn("line-1", st["lines"])

    def test_stop_dns_poisoning(self):
        from ui.api import SwiftAPI
        from ui import api as api_module
        res = SwiftAPI().stop_dns_poisoning_check()
        self.assertTrue(res["ok"])
        self.assertTrue(api_module._dns_check_cancel.is_set())
        api_module._dns_check_cancel.clear()


if __name__ == "__main__":
    unittest.main()