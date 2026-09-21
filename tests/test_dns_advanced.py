import unittest
from unittest.mock import patch

from dns.check import (
    _force_dns_windows,
    _restore_dns_windows,
    _windows_connected_adapters,
    force_dns,
    restore_dns,
)


class WindowsAdaptersTest(unittest.TestCase):
    def test_parses_aliases(self):
        fake = "-NoProfile -NonInteractive -Command Get-NetIPInterface -AddressFamily IPv4"
        with patch("dns.check.subprocess.run") as run:
            run.return_value.stdout = "WLAN 2\nEthernet\n"
            grab = _windows_connected_adapters()
        self.assertEqual(grab, ["WLAN 2", "Ethernet"])

    def test_no_output(self):
        with patch("dns.check.subprocess.run") as run:
            run.return_value.stdout = ""
            self.assertEqual(_windows_connected_adapters(), [])


class ForceRestoreWindowsTest(unittest.TestCase):
    def test_force_sets_primary_and_secondary(self):
        with patch("dns.check._windows_connected_adapters", return_value=["Ethernet"]), \
             patch("dns.check._command_success", return_value=True) as cmd:
            res = _force_dns_windows(["1.1.1.1", "8.8.8.8"])
        self.assertTrue(res["ok"])
        self.assertEqual(res["adapters"], ["Ethernet=1.1.1.1"])
        calls = [c[0][0][3:] for c in cmd.call_args_list]
        self.assertIn(["set", "dnsservers", "name=Ethernet", "static", "1.1.1.1", "primary"], calls)
        self.assertIn(["add", "dnsservers", "name=Ethernet", "8.8.8.8", "index=2"], calls)

    def test_force_no_adapters(self):
        with patch("dns.check._windows_connected_adapters", return_value=[]):
            res = _force_dns_windows(["1.1.1.1"])
        self.assertFalse(res["ok"])

    def test_restore_sets_dhcp(self):
        with patch("dns.check._windows_connected_adapters", return_value=["Ethernet"]), \
             patch("dns.check._command_success", return_value=True) as cmd:
            res = _restore_dns_windows()
        self.assertTrue(res["ok"])
        cmd.assert_called_with(
            ["netsh", "interface", "ipv4", "set", "dnsservers", "name=Ethernet", "source=dhcp"]
        )


class ForceRestoreDispatchTest(unittest.TestCase):
    def test_force_windows(self):
        with patch("dns.check.sys.platform", "win32"), \
             patch("dns.check._force_dns_windows", return_value={"ok": True}) as inner:
            res = force_dns(["1.1.1.1"])
        self.assertTrue(res["ok"])
        inner.assert_called_with(["1.1.1.1"])

    def test_restore_windows(self):
        with patch("dns.check.sys.platform", "win32"), \
             patch("dns.check._restore_dns_windows", return_value={"ok": True}) as inner:
            res = restore_dns()
        self.assertTrue(res["ok"])
        inner.assert_called_once()


if __name__ == "__main__":
    unittest.main()