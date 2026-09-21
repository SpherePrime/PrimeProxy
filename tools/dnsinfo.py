# tools/dnsinfo.py
"""DNS-проверки: доступность системных резолверов и целостность ответов.

Сверка системного резолвинга с DoH позволяет отличать «просто нет сети»
от подмены / блокировки DNS для конкретных доменов.
"""
from __future__ import annotations

import socket
import urllib.request
import base64
from typing import Dict, List

from dns.check import get_system_dns_servers, test_dns_udp
from dns.providers import get_provider

_DOH_FALLBACK = "https://cloudflare-dns.com/dns-query"


def _doh_resolve(host: str, endpoint: str, timeout: float = 5.0) -> List[str]:
    """A-записи хоста через DoH (dns-json). Пустой список — DoH недоступен."""
    import json
    payload = base64.urlsafe_b64encode(
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        + _qname(host) + b"\x00\x01\x00\x01"
    ).decode().rstrip("=")
    req = urllib.request.Request(
        f"{endpoint}?dns={payload}",
        headers={"Accept": "application/dns-json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception:
        return []
    out: List[str] = []
    for answer in (data or {}).get("Answer", []):
        if answer.get("type") in (1, 28):
            out.append(answer.get("data", ""))
        elif answer.get("type") == 5 and answer.get("data"):
            out.append(answer["data"].rstrip("."))
    return [a for a in out if a]


def _qname(host: str) -> bytes:
    out = bytearray()
    for label in host.rstrip(".").split("."):
        out.append(len(label))
        out.extend(label.encode("idna"))
    out.append(0)
    return bytes(out)


def read_dns_integrity(hosts: List[str]) -> List[Dict]:
    """Сверка системного резолвинга с DoH.

    Returns: список отчётов {host, status, system_ips, doh_ips, detail}
        status: ok | poison | block | no_doh | error
    """
    doh_url = get_provider("cloudflare")["doh"] or _DOH_FALLBACK
    out: List[Dict] = []
    for host in hosts:
        sys_ips = _resolve_flatten(host)
        try:
            doh_ips = _doh_resolve(host, doh_url)
        except Exception:
            doh_ips = []
        entry = {
            "host": host,
            "system_ips": sys_ips,
            "doh_ips": doh_ips,
        }
        if not sys_ips and not doh_ips:
            entry.update({"status": "error", "detail": "не резолвится нигде"})
        elif not sys_ips:
            entry.update({"status": "block", "detail": "системный DNS не отдаёт адрес (DoH отвечает)"})
        elif not doh_ips:
            entry.update({"status": "no_doh", "detail": "DoH недоступен, сверка невозможна"})
        elif _ips_overlap(sys_ips, doh_ips):
            entry.update({"status": "ok", "detail": "ответы совпадают с DoH"})
        else:
            entry.update({"status": "poison", "detail": "системный DNS отдаёт иные адреса, чем DoH"})
        out.append(entry)
    return out


def read_dns_servers_status() -> List[Dict]:
    """Доступность каждого системного DNS-сервера (UDP 53)."""
    servers = get_system_dns_servers()
    out: List[Dict] = []
    for srv in servers:
        rtt = test_dns_udp(srv)
        out.append({
            "server": srv,
            "reachable": rtt is not None,
            "rtt_ms": rtt,
        })
    return out


def _resolve_flatten(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({info[4][0] for info in infos})


def _ips_overlap(ips_a: List[str], ips_b: List[str]) -> bool:
    norm_a = {a for a in ips_a if ":" not in a}
    norm_b = {b for b in ips_b if ":" not in b}
    return bool(norm_a & norm_b)