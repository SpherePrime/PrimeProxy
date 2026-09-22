"""Network adapter enumeration for PrimeProxy (PowerShell, with fallbacks)."""

from __future__ import annotations

import subprocess
import sys
from typing import Dict, List

_PWSH = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]

_INTERFACE_SCRIPT = (
    "Get-NetIPInterface -AddressFamily IPv4 | "
    "Where-Object { $_.ConnectionState } | "
    "ForEach-Object { $_.InterfaceAlias + '|' + $_.InterfaceIndex + '|' + $_.ConnectionState }"
)

_DNS_SCRIPT = (
    "Get-DnsClientServerAddress -AddressFamily IPv4 | "
    "Where-Object { $_.ServerAddresses } | "
    "ForEach-Object { $_.InterfaceAlias + '|' + ($_.ServerAddresses -join ',') }"
)

FAMILIES_IPV4 = ["IPv4"]


def _normalize_alias(alias):
    if not isinstance(alias, str):
        return alias
    replacements = (
        ("\u00A0", " "),
        ("\u200E", ""),
        ("\u200F", ""),
        ("\t", " "),
    )
    for bad, good in replacements:
        alias = alias.replace(bad, good)
    return alias.strip()


def _run_pwsh(script: str, timeout: float = 15.0) -> str:
    if sys.platform != "win32":
        return ""
    try:
        out = subprocess.run(
            _PWSH + [script], capture_output=True, text=True, timeout=timeout
        ).stdout
    except Exception:
        return ""
    return out or ""


def _parse_interface_rows(stdout: str) -> List[Dict]:
    rows: List[Dict] = []
    for line in str(stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 3:
            continue
        name = _normalize_alias(parts[0])
        try:
            index = int(parts[1])
        except (TypeError, ValueError):
            continue
        state = parts[2].strip()
        if not name:
            continue
        rows.append({"name": name, "interface_index": index, "status": state})
    return rows


def _parse_dns_rows(stdout: str) -> Dict[str, List[str]]:
    rows: Dict[str, List[str]] = {}
    for line in str(stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("|", 1)
        if len(parts) != 2:
            continue
        name = _normalize_alias(parts[0])
        servers = [s.strip() for s in parts[1].split(",") if s.strip()]
        if name and servers:
            rows[name] = servers
    return rows


def _fallback_rows() -> List[Dict]:
    rows: List[Dict] = []
    try:
        from dns.check import _windows_connected_adapters

        for name in _windows_connected_adapters():
            rows.append(
                {
                    "name": _normalize_alias(name),
                    "interface_index": 0,
                    "status": "Connected",
                }
            )
    except Exception:
        return []
    return rows


def get_network_adapters() -> Dict:
    """Возвращает ``{adapters, total, connected}`` для веб-интерфейса."""
    interface_rows = _parse_interface_rows(_run_pwsh(_INTERFACE_SCRIPT))
    if not interface_rows:
        interface_rows = _fallback_rows()
    dns_map = _parse_dns_rows(_run_pwsh(_DNS_SCRIPT))

    adapters: List[Dict] = []
    for row in interface_rows:
        name = row["name"]
        state = row["status"]
        is_connected = bool(state and state.lower() in ("connected", "up"))
        adapters.append(
            {
                "name": name,
                "interface_index": int(row["interface_index"] or 0),
                "status": state or ("Connected" if is_connected else "Disconnected"),
                "dns_servers": dns_map.get(name, []),
                "families": list(FAMILIES_IPV4),
                "is_connected": is_connected,
            }
        )
    return {
        "adapters": adapters,
        "total": len(adapters),
        "connected": sum(1 for a in adapters if a["is_connected"]),
    }


def list_network_adapters() -> List[str]:
    """Имена подключённых адаптеров — без структуры, для программной логики."""
    data = get_network_adapters()
    return [a["name"] for a in data["adapters"] if a["is_connected"]]


__all__ = [
    "FAMILIES_IPV4",
    "get_network_adapters",
    "list_network_adapters",
    "_normalize_alias",
    "_parse_dns_rows",
    "_parse_interface_rows",
    "_run_pwsh",
]