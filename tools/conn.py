# tools/conn.py
"""Сетевые проверки для диагностики: TCP/TLS-пробы, DNS, сетевая информация.

Только stdlib. Все пробы ограничены таймаутами, классификация результата
сводится к небольшому набору статусов, понятных в UI.
"""
from __future__ import annotations

import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Optional

PROBE_TIMEOUT = 4.0
_GATEWAY_PATTERN = ("0.0.0.0", "Default Gateway")


def tls_probe(host: str, port: int = 443, timeout: float = PROBE_TIMEOUT) -> Dict:
    """Настоящая TLS-проба подключения к хосту.

    Сначала TCP-коннект, затем полноценный TLS-handshake с SNI. Это отличает
    "просто закрытые TCP" от характерного для DPI поведения «accept + обрыв
    после ClientHello».

    Returns:
        {"ok": bool, "kind": str, "ms": float|None, "detail": str}
        kind: ok | refused | reset | timeout | no_tls | dns | unreachable
    """
    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            tcp_ms = (time.monotonic() - start) * 1000.0
            try:
                with ctx.wrap_socket(raw, server_hostname=host) as tls:
                    tls.settimeout(timeout)
                    tls.do_handshake()
            except ssl.SSLError as exc:
                return {"ok": False, "kind": "no_tls", "ms": round(tcp_ms, 1),
                        "detail": f"обрыв после ClientHello: {type(exc).__name__}"}
            except OSError as exc:
                kind = _tcp_kind(exc)
                return {"ok": False, "kind": kind, "ms": round(tcp_ms, 1),
                        "detail": _describe(kind)}
            total = (time.monotonic() - start) * 1000.0
            return {"ok": True, "kind": "ok", "ms": round(total, 1), "detail": f"{total:.0f} мс"}
    except socket.gaierror:
        return {"ok": False, "kind": "dns", "ms": None, "detail": "не резолвится"}
    except OSError as exc:
        kind = _tcp_kind(exc)
        return {"ok": False, "kind": kind, "ms": None, "detail": _describe(kind)}


def tcp_probe(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> Dict:
    """Простой TCP-коннект без TLS (для IP-адресов без SNI)."""
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ms = (time.monotonic() - start) * 1000.0
            return {"ok": True, "kind": "ok", "ms": round(ms, 1), "detail": f"{ms:.0f} мс"}
    except socket.gaierror:
        return {"ok": False, "kind": "dns", "ms": None, "detail": "не резолвится"}
    except OSError as exc:
        kind = _tcp_kind(exc)
        return {"ok": False, "kind": kind, "ms": None, "detail": _describe(kind)}


def resolve_host(host: str, timeout: float = 3.0) -> Dict:
    """Системный резолвинг хоста (getaddrinfo)."""
    start = time.monotonic()
    try:
        infos = socket.getaddrinfo(host, 443, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror:
        return {"ok": False, "ips": [], "ms": None, "detail": "не резолвится"}
    ips = sorted({info[4][0] for info in infos})
    ms = (time.monotonic() - start) * 1000.0
    return {"ok": bool(ips), "ips": ips, "ms": round(ms, 1), "detail": ", ".join(ips[:3])}


def _tcp_kind(exc: OSError) -> str:
    winerror = getattr(exc, "winerror", None)
    errno_ = getattr(exc, "errno", None)
    if winerror in (11001,) or errno_ in (11001, 11004):
        return "dns"
    if isinstance(exc, ConnectionRefusedError) or winerror in (10055, 10061) or errno_ in (111, 10061):
        return "refused"
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)) or winerror in (10053, 10054):
        return "reset"
    if winerror in (10050, 10051, 10065) or errno_ in (101, 11001):
        return "unreachable"
    return "timeout"


def _describe(kind: str) -> str:
    return {
        "refused": "соединение отклонено",
        "reset": "обрыв соединения (RST) — характерно для DPI",
        "timeout": "таймаут соединения — вероятно блокировка",
        "unreachable": "сеть/хост недоступен",
        "dns": "не резолвится",
        "no_tls": "TLS не установлен",
    }.get(kind, kind)


def default_gateway() -> Optional[str]:
    """IP шлюза по умолчанию (Windows: route print)."""
    try:
        out = subprocess.run(
            ["route", "print", "-4"], capture_output=True, text=True,
            timeout=8, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        ).stdout
    except Exception:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "0.0.0.0":
            for idx, p in enumerate(parts):
                if p == "0.0.0.0" and idx < len(parts) - 1 and parts[idx + 1] != "0.0.0.0":
                    return parts[idx + 1]
        if line.strip().startswith(_GATEWAY_PATTERN[1]):
            return parts[1] if len(parts) >= 2 else None
    return None


def lan_ip() -> Optional[str]:
    """Локальный IPv4-адрес (по умолчанию маршруту)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def probe_many(hosts, probe=tls_probe, workers: int = 6, timeout: float = PROBE_TIMEOUT) -> Dict[str, Dict]:
    """Параллельные пробы списка хостов: {host: result}."""
    out: Dict[str, Dict] = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(probe, host, 443, timeout): host for host in hosts}
        for fut in futs:
            host = futs[fut]
            try:
                out[host] = fut.result()
            except Exception:
                out[host] = {"ok": False, "kind": "timeout", "ms": None, "detail": "ошибка"}
    return out