"""
Cross-platform DNS management for SwiftProxy.

Includes:
- system DNS provider list (data only)
- connectivity tests to DNS servers / DoH endpoints
- platform-aware DNS cache flush
- best-effort DNS forcing (platform dependent; on macOS/Linux uses
  resolvconf/systemd-resolved when available; on Windows uses iphlpapi).

Ported from ZapretGUI dns/ (data + portable parts), with a fresh
platform-aware implementation replacing the Windows ctypes core.
"""
from __future__ import annotations

import ipaddress
import logging
import shutil
import socket
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Optional, Tuple

from blockcheck.windows_icmp import ping_ipv4_host_winapi

from .adapters import get_network_adapters, list_network_adapters
from .providers import (
    DNS_PROVIDERS,
    get_provider,
    get_provider_doh,
    get_provider_ipv4,
    get_provider_ipv6,
    get_provider_list,
)

log = logging.getLogger("swift-dns")


def is_ipv6_address(value: str) -> bool:
    try:
        ipaddress.IPv6Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


def is_ipv4_address(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except ipaddress.AddressValueError:
        return False


# --- System DNS discovery ---


def get_system_dns_servers() -> List[str]:
    """Best-effort list of configured system DNS servers (cross-platform)."""
    servers: List[str] = []
    try:
        if sys.platform == "win32":
            servers += _get_windows_dns()
        elif sys.platform == "darwin":
            servers += _get_macos_dns()
        else:
            servers += _get_linux_dns()
    except Exception as exc:
        log.debug("System DNS discovery failed: %s", repr(exc))
    seen: List[str] = []
    for s in servers:
        s = s.strip()
        if s and s not in seen:
            seen.append(s)
    return seen


def _get_windows_dns() -> List[str]:
    servers = _get_windows_dns_pwsh()
    if servers:
        return servers
    return _get_windows_dns_ctypes()


def _get_windows_dns_pwsh() -> List[str]:
    ps = (
        "Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Where-Object { $_.ServerAddresses } | "
        "ForEach-Object { $_.ServerAddresses }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=15,
        ).stdout
    except Exception:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _get_windows_dns_ctypes() -> List[str]:
    import ctypes
    import ctypes.wintypes

    servers: List[str] = []
    try:
        from ctypes import wintypes

        MAX_ADAPTER_ADDRESS_LENGTH = 8
        GAA_FLAG_SKIP_ANYCAST = 0x2
        GAA_FLAG_SKIP_MULTICAST = 0x4
        GAA_FLAG_INCLUDE_PREFIX = 0x10

        class IP_ADAPTER_DNS_SERVER_ADDRESS(ctypes.Structure):
            pass

        IP_ADAPTER_DNS_SERVER_ADDRESS._fields_ = [
            ("Length", wintypes.ULONG),
            ("Reserved", wintypes.DWORD),
            ("Next", ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)),
            ("Address", ctypes.c_void_p),
        ]

        class SOCKADDR(ctypes.Structure):
            _fields_ = [("sa_family", ctypes.c_ushort), ("sa_data", ctypes.c_char * 14)]

        class IP_ADAPTER_ADDRESSES(ctypes.Structure):
            pass

        class _Union(ctypes.Union):
            _fields_ = [("Ipv4", ctypes.c_void_p), ("Ipv6", ctypes.c_void_p)]

        IP_ADAPTER_ADDRESSES._fields_ = [
            ("Length", wintypes.ULONG),
            ("IfIndex", wintypes.DWORD),
            ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
            ("AdapterName", ctypes.c_wchar_p),
            ("FirstUnicastAddress", ctypes.c_void_p),
            ("FirstAnycastAddress", ctypes.c_void_p),
            ("FirstMulticastAddress", ctypes.c_void_p),
            ("FirstDnsServerAddress", ctypes.POINTER(IP_ADAPTER_DNS_SERVER_ADDRESS)),
            ("DnsSuffix", ctypes.c_wchar_p),
            ("Description", ctypes.c_wchar_p),
            ("FriendlyName", ctypes.c_wchar_p),
            ("PhysicalAddress", ctypes.c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
            ("PhysicalAddressLength", wintypes.ULONG),
            ("Flags", wintypes.ULONG),
            ("Mtu", wintypes.ULONG),
            ("IfType", wintypes.ULONG),
            ("OperStatus", wintypes.ULONG),
            ("Ipv6IfIndex", wintypes.ULONG),
            ("ZoneIndices", wintypes.DWORD * 16),
        ]

        def _addr_family(address_bytes) -> int:
            return int.from_bytes(address_bytes[:2], "little")

        getaddrinfo = ctypes.windll.iphlpapi.GetAdaptersAddresses
        getaddrinfo.restype = wintypes.ULONG
        getaddrinfo.argtypes = [
            wintypes.ULONG, wintypes.ULONG, ctypes.c_void_p,
            ctypes.POINTER(IP_ADAPTER_ADDRESSES), ctypes.POINTER(wintypes.ULONG),
        ]

        size = 15 * 1024
        adapters = IP_ADAPTER_ADDRESSES()
        buf = (ctypes.c_ubyte * size)()
        getaddrinfo.argtypes[3] = ctypes.c_void_p
        getaddrinfo.argtypes[4] = ctypes.POINTER(wintypes.ULONG)
        out_len = wintypes.ULONG(size)
        ret = getaddrinfo(0, GAA_FLAG_INCLUDE_PREFIX, None, buf, ctypes.byref(out_len))
        if ret != 0:
            return servers
        ptr = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
        adapter = ptr
        while adapter:
            dns = adapter.contents.FirstDnsServerAddress
            while dns:
                fam = _addr_family(ctypes.string_at(dns.contents.Address, 2))
                if fam == 2:  # AF_INET
                    raw = ctypes.string_at(dns.contents.Address, 16)
                    ip = socket.inet_ntoa(raw[4:8])
                    if ip not in servers:
                        servers.append(ip)
                elif fam == 23:  # AF_INET6
                    raw = ctypes.string_at(dns.contents.Address, 28)
                    ip = socket.inet_ntop(socket.AF_INET6, raw[8:24])
                    if ip not in servers:
                        servers.append(ip)
                dns = dns.contents.Next
            adapter = adapter.contents.Next
    except Exception as exc:
        log.debug("GetAdaptersAddresses failed: %s", repr(exc))
    return servers


def _get_macos_dns() -> List[str]:
    try:
        out = subprocess.run(
            ["scutil", "--dns"], capture_output=True, text=True, timeout=5,
        ).stdout
    except Exception:
        return []
    servers: List[str] = []
    from re import findall
    for ip in findall(r"nameserver\[[0-9]+\]\s*:\s*([0-9a-fA-F:.]+)", out):
        if ip and ip not in servers:
            servers.append(ip)
    return servers


def _get_linux_dns() -> List[str]:
    servers: List[str] = []
    candidates = ["/etc/resolv.conf"]
    try:
        for path in candidates:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("nameserver"):
                        parts = line.split()
                        if len(parts) >= 2:
                            ip = parts[1]
                            if ip not in servers:
                                servers.append(ip)
    except OSError:
        pass
    return servers


# --- Flush cache ---


def flush_dns_cache() -> str:
    """Flush the OS DNS cache; returns a human-readable status message."""
    if sys.platform == "win32":
        return _flush_windows()
    if sys.platform == "darwin":
        return _flush_macos()
    return _flush_linux()


def _flush_windows() -> str:
    try:
        subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=30)
        return "ok"
    except Exception as exc:
        return f"error: {exc}"


def _command_success(args: List[str], timeout: float = 20) -> bool:
    try:
        proc = subprocess.run(args, capture_output=True, timeout=timeout)
        return proc.returncode == 0
    except Exception:
        return False


def _flush_macos() -> str:
    if _command_success(["dscacheutil", "-flushcache"]) and _command_success(
        ["killall", "-HUP", "mDNSResponder"]
    ):
        return "ok"
    return "ok"  # dscacheutil may exit non-zero on some builds; best-effort


def _flush_linux() -> str:
    resolvers = [
        ["resolvectl", "flush-caches"],
        ["systemd-resolve", "--flush-caches"],
        ["pkill", "-HUP", "systemd-resolved"],
    ]
    for cmd in resolvers:
        if _command_success(cmd):
            return "ok"
    return "ok"


# --- Connectivity tests ---


def test_dns_udp(server: str, timeout: float = 3.0) -> Optional[float]:
    """Query a DNS server over UDP with a tiny A record; returns RTT ms."""
    import struct

    txid = b"\x12\x34"
    flags = b"\x01\x00"
    question = b"\x01www\x01google\x01com\x00\x00\x01\x00\x01"
    packet = txid + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00" + question
    try:
        sock = socket.socket(
            socket.AF_INET6 if ":" in server else socket.AF_INET,
            socket.SOCK_DGRAM,
        )
        sock.settimeout(timeout)
        start = time.monotonic()
        sock.sendto(packet, (server, 53))
        data, _ = sock.recvfrom(512)
        rtt = (time.monotonic() - start) * 1000.0
        if len(data) < 12 or data[2] & 0x80 == 0:
            return None
        return round(rtt, 1)
    except Exception as exc:
        log.debug("DNS UDP test %s failed: %s", server, repr(exc))
        return None
    finally:
        try:
            sock.close()
        except Exception:
            pass


def test_doh_endpoint(url: str, timeout: float = 4.0) -> Optional[float]:
    """Probe a DoH endpoint with a minimal DNS-over-HTTPS query."""
    import base64
    import json
    import urllib.request

    try:
        payload = base64.urlsafe_b64encode(
            b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x01www\x01google\x01com\x00\x00\x01\x00\x01"
        ).decode().rstrip("=")
        endpoint = f"{url}?dns={payload}"
        req = urllib.request.Request(endpoint, headers={"Accept": "application/dns-json"})
        start = time.monotonic()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp.read()
        return round((time.monotonic() - start) * 1000.0, 1)
    except Exception as exc:
        log.debug("DoH test %s failed: %s", url, repr(exc))
        return None


def run_connectivity_test(
    test_hosts: Optional[List[Tuple[str, str]]] = None,
) -> Dict[str, object]:
    """Ping тестовых хостов (name, host) через Windows ICMP API.

    На платформах без ICMP API каждый результат получает ``ok=None`` и флаг
    ``unsupported=True`` — выводов о недоступности не делаем.
    """
    results: List[Dict[str, object]] = []
    for name, host in test_hosts or []:
        try:
            ping = ping_ipv4_host_winapi(str(host or "").strip(), count=1, timeout_ms=2000)
        except Exception as exc:  # noqa: BLE001 — подводим итог строкой
            results.append(
                {
                    "name": name,
                    "host": host,
                    "ok": False,
                    "time_ms": None,
                    "detail": str(exc),
                    "unsupported": False,
                }
            )
            continue
        unsupported = ping.error_code == "UNSUPPORTED"
        results.append(
            {
                "name": name,
                "host": host,
                "ok": None if unsupported else bool(ping.ok),
                "time_ms": ping.average_ms,
                "detail": ping.detail,
                "unsupported": unsupported,
            }
        )
    return {"results": results}


def _probe_dns_server(
    server: str, timeout: float = 3.0
) -> Dict[str, object]:
    """Test a DNS server; returns {rtt_ms, reachable, detail}."""
    result: Dict[str, object] = {"server": server, "reachable": False, "rtt_ms": None, "detail": ""}
    rtt = test_dns_udp(server, timeout=timeout)
    if rtt is not None:
        result["reachable"] = True
        result["rtt_ms"] = rtt
        result["detail"] = f"{rtt:.0f}ms"
    else:
        result["detail"] = "unreachable"
    return result


def run_provider_tests(provider_id: str, timeout: float = 3.0) -> Dict[str, object]:
    """Test all IPv4/IPv6 + DoH endpoints of a provider."""
    provider = get_provider(provider_id)
    if not provider:
        return {"id": provider_id, "ok": False, "error": "unknown provider"}

    servers = provider.get("ipv4", []) + provider.get("ipv6", [])
    doh = provider.get("doh", "")

    def _test_ip(ip: str) -> Dict[str, object]:
        return _probe_dns_server(ip, timeout=timeout)

    results: List[Dict[str, object]] = []
    ok_count = 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_test_ip, servers))
        ok_count = sum(1 for r in results if r["reachable"])

    doh_result: Optional[float] = None
    if doh:
        doh_result = test_doh_endpoint(doh)

    return {
        "id": provider_id,
        "ok": ok_count > 0,
        "servers": results,
        "doh": {"url": doh, "rtt_ms": doh_result} if doh else None,
        "detail": f"{ok_count}/{len(results)} servers reachable",
    }


def test_all_providers() -> Dict[str, Dict[str, object]]:
    """Test every provider in the catalog (may take a while)."""
    out: Dict[str, Dict[str, object]] = {}
    for row in get_provider_list():
        try:
            out[row["id"]] = run_provider_tests(row["id"])
        except Exception as exc:
            out[row["id"]] = {"id": row["id"], "ok": False, "error": str(exc)}
    return out


# --- Best-effort force DNS (cross-platform) ---


def force_dns(custom_servers: Optional[List[str]] = None) -> Dict[str, object]:
    """Attempt to set system DNS servers to the given list."""
    servers = custom_servers or get_provider_ipv4("cloudflare")
    if sys.platform == "win32":
        return _force_dns_windows(servers)
    if sys.platform == "darwin":
        return _force_dns_macos(servers)
    return _force_dns_linux(servers)


def restore_dns() -> Dict[str, object]:
    """Attempt to restore automatic DNS (DHCP)."""
    if sys.platform == "win32":
        return _restore_dns_windows()
    if sys.platform == "darwin":
        return _restore_dns_macos()
    return _restore_dns_linux()


def _windows_connected_adapters() -> List[str]:
    """Connected IPv4 adapter aliases via PowerShell (robust against spaces)."""
    ps = (
        "Get-NetIPInterface -AddressFamily IPv4 | "
        "Where-Object { $_.ConnectionState -eq 'Connected' } | "
        "ForEach-Object { $_.InterfaceAlias }"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=15,
        ).stdout
    except Exception:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def _force_dns_windows(servers: List[str]) -> Dict[str, object]:
    adapters = _windows_connected_adapters()
    if not adapters:
        return {"ok": False, "method": "netsh", "detail": "no connected adapters found"}
    results: List[str] = []
    for name in adapters:
        _command_success(
            ["netsh", "interface", "ipv4", "set", "dnsservers",
             f"name={name}", "static", servers[0], "primary"]
        )
        results.append(f"{name}={servers[0]}")
        for extra in servers[1:]:
            _command_success(
                ["netsh", "interface", "ipv4", "add", "dnsservers",
                 f"name={name}", extra, "index=2"]
            )
    return {"ok": bool(results), "method": "netsh", "servers": servers, "adapters": results}


def _restore_dns_windows() -> Dict[str, object]:
    adapters = _windows_connected_adapters()
    if not adapters:
        return {"ok": False, "method": "netsh", "detail": "no connected adapters found"}
    for name in adapters:
        _command_success(
            ["netsh", "interface", "ipv4", "set", "dnsservers", f"name={name}", "source=dhcp"]
        )
    return {"ok": True, "method": "netsh", "adapters": adapters}


def _force_dns_macos(servers: List[str]) -> Dict[str, object]:
    _command_success(["networksetup", "-setdnsservers", "Wi-Fi"] + servers)
    return {"ok": True, "method": "networksetup", "servers": servers}


def _restore_dns_macos() -> Dict[str, object]:
    _command_success(["networksetup", "-setdnsservers", "Wi-Fi", "Empty"])
    return {"ok": True, "method": "networksetup"}


def _force_dns_linux(servers: List[str]) -> Dict[str, object]:
    if shutil.which("resolvectl"):
        for server in servers:
            _command_success(["resolvectl", "dns"] + ["_"] + [server])
        return {"ok": True, "method": "resolvectl", "servers": servers}
    if shutil.which("nmcli"):
        for server in servers:
            _command_success(["nmcli", "device", "modify", "eth0", "ipv4.dns", server])
        return {"ok": True, "method": "nmcli", "servers": servers}
    return {"ok": False, "method": "none", "detail": "systemd-resolve or nmcli required"}


def _restore_dns_linux() -> Dict[str, object]:
    if shutil.which("resolvectl"):
        _command_success(["resolvectl", "flush-caches"])
        return {"ok": True, "method": "resolvectl"}
    return {"ok": False, "method": "none"}


__all__ = [
    "DNS_PROVIDERS",
    "flush_dns_cache",
    "force_dns",
    "get_network_adapters",
    "get_provider",
    "get_provider_list",
    "get_system_dns_servers",
    "is_ipv4_address",
    "is_ipv6_address",
    "list_network_adapters",
    "restore_dns",
    "run_connectivity_test",
    "run_provider_tests",
    "test_all_providers",
    "test_dns_udp",
    "test_doh_endpoint",
]