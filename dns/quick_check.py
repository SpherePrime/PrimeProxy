"""Быстрая проверка системного DNS по контрольным доменам."""

from __future__ import annotations

import time
from typing import Dict

from utils.net_resolve import DEFAULT_DNS_TIMEOUT, resolve_ipv4

QUICK_DOMAINS = [
    {"name": "YouTube", "host": "www.youtube.com"},
    {"name": "Discord", "host": "discord.com"},
    {"name": "Google", "host": "google.com"},
    {"name": "Cloudflare", "host": "cloudflare.com"},
]


def run_quick_dns_check(timeout: float = DEFAULT_DNS_TIMEOUT) -> Dict:
    """Проверяет резолвинг контрольных доменов системным резолвером."""
    results = []
    for row in QUICK_DOMAINS:
        name, host = row["name"], row["host"]
        started = time.monotonic()
        ip = resolve_ipv4(host, timeout=timeout)
        time_ms = round((time.monotonic() - started) * 1000.0, 1)
        results.append(
            {
                "name": name,
                "host": host,
                "ok": bool(ip),
                "status": "ok" if ip else "fail",
                "ip": ip,
                "error": None if ip else "not resolved",
                "time_ms": time_ms,
            }
        )
    ok_count = sum(1 for r in results if r["ok"])
    return {
        "results": results,
        "checked": len(results),
        "ok": ok_count,
        "overall": ok_count == len(results),
    }


__all__ = ["QUICK_DOMAINS", "run_quick_dns_check"]