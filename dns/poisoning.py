"""Проверка DNS-подмены провайдером (порт из ZapretGUI dns_checker)."""

from __future__ import annotations

from typing import Callable, Dict, Optional

from blockcheck.config import KNOWN_BLOCK_IPS
from blockcheck.dns_integrity import resolve_doh, resolve_udp
from utils.net_resolve import DEFAULT_DNS_TIMEOUT, resolve_ipv4

SERVICES = {
    "youtube": {
        "label": "YouTube",
        "domains": ["www.youtube.com", "youtube.com", "googlevideo.com"],
        "valid_ranges": [
            "142.250.",
            "142.251.",
            "172.217.",
            "172.253.",
            "173.194.",
            "74.125.",
            "209.85.",
            "216.58.",
            "108.177.",
            "64.233.",
            "192.178.",
            "192.179.",
        ],
    },
    "discord": {
        "label": "Discord",
        "domains": ["discord.com", "discordapp.com", "discord.gg"],
        "valid_ranges": [
            "162.159.",
            "104.16.",
            "104.17.",
            "104.18.",
            "104.19.",
            "104.20.",
            "104.21.",
            "104.22.",
            "104.23.",
            "104.24.",
            "104.25.",
            "104.26.",
            "104.27.",
            "172.64.",
            "172.65.",
            "172.66.",
            "172.67.",
        ],
    },
}

PROBE_DOMAIN = "google.com"

DNS_SERVERS = [
    {"name": "System Default", "server": None},
    {"name": "Google DNS", "server": "8.8.8.8"},
    {"name": "Cloudflare", "server": "1.1.1.1"},
    {"name": "Google DoH", "doh": "https://dns.google/resolve"},
    {"name": "Cloudflare DoH", "doh": "https://cloudflare-dns.com/dns-query"},
]

KNOWN_BLOCK_IPS_SET = set(KNOWN_BLOCK_IPS)

LOCAL_PREFIXES = ("127.", "10.", "192.168.")

DEFAULT_RECOMMENDED_DNS = "1.1.1.1"


def _is_stop_requested(should_stop: Optional[Callable[[], bool]]) -> bool:
    if not callable(should_stop):
        return False
    try:
        return bool(should_stop())
    except Exception:
        return False


class DnsPoisoningChecker:
    """Проверяет резолвинг YouTube/Discord через системный и внешние DNS."""

    def __init__(self) -> None:
        self.known_ranges = SERVICES
        self.known_block_ips = list(KNOWN_BLOCK_IPS_SET)

    def check_dns_poisoning(
        self,
        log_callback: Optional[Callable[[str], None]] = None,
        should_stop: Optional[Callable[[], bool]] = None,
    ) -> Dict:
        results: Dict = {
            "services": {},
            "summary": {
                "youtube_blocked": False,
                "discord_blocked": False,
                "dns_poisoning_detected": False,
                "external_dns_blocked": False,
                "recommended_dns": None,
                "poisoned_domains": [],
            },
        }
        self._log("=" * 40, log_callback)
        self._log("ПРОВЕРКА DNS ПОДМЕНЫ", log_callback)
        self._log("=" * 40, log_callback)

        if _is_stop_requested(should_stop):
            return results

        external_ok = self._check_external_dns(log_callback, should_stop)
        results["summary"]["external_dns_blocked"] = not external_ok
        if _is_stop_requested(should_stop):
            return results

        for service_key in ("youtube", "discord"):
            if _is_stop_requested(should_stop):
                break
            service = self._check_service(service_key, log_callback, should_stop)
            results["services"][service_key] = service
            if service["poisoned"]:
                results["summary"][f"{service_key}_blocked"] = True
                results["summary"]["dns_poisoning_detected"] = True
                results["summary"]["poisoned_domains"].extend(
                    d for d, meta in service["domains"].items() if meta["verdict"] == "poisoned"
                )

        if _is_stop_requested(should_stop):
            return results

        for service_key in ("youtube", "discord"):
            label = SERVICES[service_key]["label"]
            blocked = results["summary"][f"{service_key}_blocked"]
            self._log(
                ("ОБНАРУЖЕНА DNS подмена: " if blocked else "DNS корректен: ") + label,
                log_callback,
            )

        if results["summary"]["dns_poisoning_detected"]:
            results["summary"]["recommended_dns"] = DEFAULT_RECOMMENDED_DNS
            self._log(
                "ТРЕБУЕТСЯ ДЕЙСТВИЕ: смените DNS на " + DEFAULT_RECOMMENDED_DNS,
                log_callback,
            )
        elif not external_ok:
            self._log("Внешние DNS недоступны — возможна блокировка резолверов.", log_callback)
        else:
            self._log("DNS работает корректно.", log_callback)

        return results

    def _check_external_dns(
        self,
        log_callback: Optional[Callable[[str], None]],
        should_stop: Optional[Callable[[], bool]],
    ) -> bool:
        self._log("Проверка доступности внешних DNS...", log_callback)
        for server in DNS_SERVERS:
            if _is_stop_requested(should_stop):
                return False
            if server.get("server") is None:
                continue
            resolved = self._resolve_domain(PROBE_DOMAIN, server)
            if resolved.get("ip"):
                self._log(
                    "Внешний DNS доступен: " + server["name"] + " (" + str(resolved["ip"]) + ")",
                    log_callback,
                )
                return True
        self._log("Все внешние DNS недоступны.", log_callback)
        return False

    def _check_service(
        self,
        service_key: str,
        log_callback: Optional[Callable[[str], None]],
        should_stop: Optional[Callable[[], bool]],
    ) -> Dict:
        info = self.known_ranges[service_key]
        service_results: Dict = {"blocked": False, "poisoned": False, "domains": {}}
        self._log("Проверка: " + info["label"], log_callback)

        for domain in info["domains"]:
            if _is_stop_requested(should_stop):
                break
            self._log("  Домен: " + domain, log_callback)
            domain_meta: Dict = {"resolvers": {}, "verdict": "inconclusive"}
            domain_poisoned = False
            domain_valid = False
            for server in DNS_SERVERS:
                if _is_stop_requested(should_stop):
                    break
                name = server["name"]
                resolved = self._resolve_domain(domain, server)
                ip = resolved.get("ip")
                validity = None
                if ip:
                    validity = self._check_ip_validity(ip, service_key)
                    if validity == "blocked":
                        service_results["blocked"] = True
                        service_results["poisoned"] = True
                        domain_poisoned = True
                    elif validity == "suspicious":
                        service_results["poisoned"] = True
                        domain_poisoned = True
                    else:
                        domain_valid = True
                domain_meta["resolvers"][name] = {
                    "ip": ip,
                    "validity": validity,
                    "error": resolved.get("error"),
                }
                self._log(
                    "    " + name + ": " + (str(ip) + " (" + str(validity) + ")" if ip else "не отвечает"),
                    log_callback,
                )
            if domain_poisoned:
                domain_meta["verdict"] = "poisoned"
            elif domain_valid:
                domain_meta["verdict"] = "clean"
            else:
                domain_meta["verdict"] = "inconclusive"
            service_results["domains"][domain] = domain_meta

        return service_results

    def _resolve_domain(self, domain: str, server: Dict) -> Dict:
        out: Dict = {"ip": None, "error": None}
        doh_url = server.get("doh")
        dns_server = server.get("server")
        try:
            if doh_url:
                ips = resolve_doh(domain, doh_url)
            elif dns_server:
                ips = resolve_udp(domain, dns_server)
            else:
                ips = resolve_ipv4(domain, timeout=DEFAULT_DNS_TIMEOUT)
                out["ip"] = ips or None
                if not out["ip"]:
                    out["error"] = "DNS resolution failed"
                return out
            out["ip"] = ips[0] if ips else None
            if not out["ip"]:
                out["error"] = "DNS resolution failed"
        except Exception as exc:  # noqa: BLE001 — ошибка резолва не валит проверку
            out["error"] = str(exc)
        return out

    def _check_ip_validity(self, ip: str, service_key: str) -> str:
        if ip in self.known_block_ips:
            return "blocked"
        if ip.startswith(LOCAL_PREFIXES):
            return "blocked"
        for prefix in self.known_ranges[service_key]["valid_ranges"]:
            if ip.startswith(prefix):
                return "valid"
        return "suspicious"

    @staticmethod
    def _log(
        message: str,
        callback: Optional[Callable[[str], None]],
    ) -> None:
        if callback:
            callback(message)
        else:
            print(message)


def check_dns_poisoning(
    log_callback: Optional[Callable[[str], None]] = None,
    should_stop: Optional[Callable[[], bool]] = None,
) -> Dict:
    """Публичная точка входа: результат в формате для веб-интерфейса."""
    checker = DnsPoisoningChecker()
    return checker.check_dns_poisoning(log_callback=log_callback, should_stop=should_stop)


__all__ = [
    "DNS_SERVERS",
    "DEFAULT_RECOMMENDED_DNS",
    "DnsPoisoningChecker",
    "SERVICES",
    "check_dns_poisoning",
]