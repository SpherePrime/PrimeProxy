# tools/__init__.py
"""Диагностика для мастера автонастройки («Диагностика» во вкладке Инструменты).

Объединяет сетевые, DNS, Telegram, DPI (winws) и прокси-проверки в один
отчёт ``run_diagnostics()`` с вердиктом и кнопками-действиями для UI.
Каждый элемент несёт ``msg_key`` — i18n-ключ переводимой строки, при этом
технические параметры (тайминги, IP) передаются отдельно.
"""
from __future__ import annotations

import time
import urllib.request
from typing import Any, Dict, List

from .conn import default_gateway, lan_ip, probe_many, tcp_probe
from .dnsinfo import read_dns_integrity, read_dns_servers_status

TELEGRAM_HOSTS = ("core.telegram.org", "t.me", "web.telegram.org")
TELEGRAM_IPS = ("149.154.175.50", "91.108.4.206")
GENERAL_HOSTS = ("google.com", "youtube.com", "github.com")
DNS_CHECK_HOSTS = ("core.telegram.org", "t.me", "api.telegram.org")
RECOMMENDED_PROFILE = "Default (circular) v2.txt"


def run_diagnostics(**context: Any) -> Dict[str, Any]:
    """Полная диагностика с короткими таймаутами (обычно < 15 с).

    ``context`` передаёт состояние, доступное только на уровне API:
        proxy_running, proxy_port, dpi_status
    """
    start = time.monotonic()
    groups: List[Dict[str, Any]] = []
    flags: Dict[str, bool] = {}

    # ── network ────────────────────────────────────────────────────
    network: List[Dict[str, Any]] = []
    gw = default_gateway()
    network.append(_item(gw and "gateway_ok" or "gateway_missing", "info", "",
                         {"value": gw or ""}))
    lan = lan_ip()
    network.append(_item(lan and "lan_ok" or "lan_missing", "info", "",
                         {"value": lan or ""}))
    pub = _public_ip()
    network.append(_item(pub and "pub_ok" or "pub_fail", "ok" if pub else "fail", "",
                         {"value": pub}))
    groups.append({"key": "network", "items": network})
    if not gw and not pub:
        flags["no_network"] = True

    # ── dns ────────────────────────────────────────────────────────
    dns_items: List[Dict[str, Any]] = []
    for srv in read_dns_servers_status():
        if srv["reachable"]:
            dns_items.append(_item("dns_srv_ok", "ok", srv["server"], {"ms": srv["rtt_ms"]}))
        else:
            dns_items.append(_item("dns_srv_fail", "warn", srv["server"], {}))
    for row in read_dns_integrity(DNS_CHECK_HOSTS):
        key = {"ok": "dns_int_ok", "poison": "dns_int_poison",
               "block": "dns_int_block", "no_doh": "dns_int_nodoh",
               "error": "dns_int_error"}.get(row["status"], "dns_int_error")
        status = {"ok": "ok", "no_doh": "info"}.get(row["status"], "fail")
        dns_items.append(_item(key, status, row["host"],
                               {"ips": _fmt_ips(row["system_ips"])}))
        if row["status"] in ("poison", "block"):
            flags["dns_broken"] = True
    groups.append({"key": "dns", "items": dns_items})

    # ── telegram / general TLS ─────────────────────────────────────
    tg: List[Dict[str, Any]] = []
    results = probe_many(list(TELEGRAM_HOSTS) + list(GENERAL_HOSTS))
    for host, res in results.items():
        tg.append(_item(_tls_key(res), "ok" if res["ok"] else "fail", host,
                        {"ms": res["ms"]}))
    for ip in TELEGRAM_IPS:
        r = tcp_probe(ip, 443)
        tg.append(_item(_tcp_key(r), "ok" if r["ok"] else "fail", ip,
                        {"ms": r["ms"]}))
    groups.append({"key": "telegram", "items": tg})

    tg_blocked = any(res and not res.get("ok") for res in results.values())
    gen_ok = any(res and res.get("ok") for host, res in results.items()
                 if host in GENERAL_HOSTS)

    # ── dpi (winws) ────────────────────────────────────────────────
    dpi: List[Dict[str, Any]] = []
    engine = _probe_engine()
    if engine["ok"]:
        dpi.append(_item("engine_ok", "info", "winws", {"dir": engine["dir"]}))
    else:
        dpi.append(_item("engine_missing", "warn", "winws", {}))
    dpi_status = context.get("dpi_status") or {}
    running = dpi_status.get("state") in ("running", "starting")
    if running:
        dpi.append(_item("dpi_running", "ok", "", {"pid": dpi_status.get("pid")}))
    else:
        dpi.append(_item("dpi_stopped", "info", "", {}))
    crashes = _recent_crashes()
    if crashes:
        dpi.append(_item("dpi_crashes", "warn", "", {"count": len(crashes)}))
    groups.append({"key": "dpi", "items": dpi})

    # ── proxy ──────────────────────────────────────────────────────
    prx_running = bool(context.get("proxy_running"))
    groups.append({"key": "proxy", "items": [
        _item(prx_running and "proxy_on" or "proxy_off",
              "ok" if prx_running else "info", "",
              {"port": context.get("proxy_port", 1443)}),
    ]})

    verdict, suggestions = _verdict({
        "no_network": flags.get("no_network"),
        "dns_broken": flags.get("dns_broken"),
        "tg_blocked": tg_blocked,
        "gen_ok": gen_ok,
        "engine_ok": engine["ok"],
    })

    return {
        "ok": True,
        "ts": int(time.time()),
        "duration_ms": round((time.monotonic() - start) * 1000, 1),
        "groups": groups,
        "verdict": verdict,
        "suggestions": suggestions,
        "recommended_profile": RECOMMENDED_PROFILE,
        "engine": engine,
    }


# ── helpers ─────────────────────────────────────────────────────────

def _item(msg_key: str, status: str, title: str, args: Dict[str, Any]) -> Dict[str, Any]:
    return {"msg_key": msg_key, "status": status, "title": title, **args}


def _fmt_ips(ips: List[str]) -> str:
    return ", ".join(ips[:3])


def _tls_key(res: Dict[str, Any]) -> str:
    if res["ok"]:
        return "tls_ok"
    return {"timeout": "tls_timeout", "reset": "tls_reset", "refused": "tls_refused",
            "no_tls": "tls_notls", "dns": "tls_dns",
            "unreachable": "tls_unreach"}.get(res.get("kind"), "tls_timeout")


def _tcp_key(res: Dict[str, Any]) -> str:
    if res["ok"]:
        return "tls_ok"
    return {"timeout": "tls_timeout", "reset": "tls_reset", "refused": "tls_refused",
            "dns": "tls_dns", "unreachable": "tls_unreach"}.get(res.get("kind"), "tls_timeout")


def _public_ip() -> str:
    try:
        req = urllib.request.Request("https://api.ipify.org",
                                     headers={"User-Agent": "PrimeProxy"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            text = resp.read(64).decode("utf-8", errors="replace").strip()
        return text if text and all(c.isdigit() or c == "." for c in text) else ""
    except Exception:
        return ""


def _probe_engine() -> Dict[str, Any]:
    try:
        from winws import paths
        probe = paths.find_engine()
        return {"ok": bool(probe.get("ok")), "dir": probe.get("dir", ""),
                "found": probe.get("found", {})}
    except Exception:
        return {"ok": False, "dir": "", "found": {}}


def _recent_crashes() -> List[str]:
    try:
        from winws.logs import recent_crashes
        return recent_crashes()
    except Exception:
        return []


def _verdict(ctx: Dict[str, Any]) -> tuple[str, List[Dict[str, Any]]]:
    """Итоговый вердикт + рекомендуемые действия."""
    if ctx.get("no_network"):
        return "fail", [
            _suggest("internet_cleanup", "dg.act_cleanup"),
            _suggest("flush_dns", "dg.act_flush"),
        ]
    if ctx.get("dns_broken"):
        return "fail", [
            _suggest("force_dns", "dg.act_force_dns"),
            _suggest("flush_dns", "dg.act_flush"),
        ]
    if ctx.get("tg_blocked"):
        acts: List[Dict[str, Any]] = [_suggest("start_dpi", "dg.act_start_dpi")]
        if ctx.get("engine_ok"):
            acts.append(_suggest("open_profiles", "dg.act_profiles"))
        else:
            acts.append(_suggest("open_profiles", "dg.act_engine_missing"))
        return "fail", acts
    if ctx.get("gen_ok") is False:
        return "warn", [_suggest("internet_cleanup", "dg.act_cleanup")]
    return "ok", [_suggest("none", "dg.act_none")]


def _suggest(action: str, key: str) -> Dict[str, Any]:
    return {"action": action, "key": key}