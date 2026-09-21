from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RouteStatus(str, Enum):
    """Route confidence level for Telegram WSS routing."""

    STABLE = "stable"
    CANDIDATE = "candidate"
    FALLBACK_ONLY = "fallback_only"


@dataclass(frozen=True)
class WssRoute:
    dc: int
    hostname: str
    media_hostname: str
    relay_ip: str
    status: RouteStatus
    source: str
    note: str

    def domains_for(self, *, is_media: bool) -> tuple[str, str]:
        if is_media:
            return (self.media_hostname, self.hostname)
        return (self.hostname, self.media_hostname)


# Telegram's working WebSocket relay IP found in ZapretGUI, Flowseal
# tg-ws-proxy, and the decrypted GhostWire 1.0.13 config.
WSS_RELAY_IP = "149.154.167.220"
WSS_PATH = "/apiws"


# Keep this map conservative.  "candidate" means the WebSocket upgrade worked
# during manual checks, but the route is not yet allowed for automatic runtime
# routing until real Telegram traffic proves it safe for both SOCKS5 and MTProxy.
WSS_ROUTES: tuple[WssRoute, ...] = (
    WssRoute(
        dc=2,
        hostname="kws2.web.telegram.org",
        media_hostname="kws2-1.web.telegram.org",
        relay_ip=WSS_RELAY_IP,
        status=RouteStatus.STABLE,
        source="ZapretGUI + Flowseal tg-ws-proxy",
        note="Stable on 2026-06-14: repeated /apiws WebSocket Upgrade returned HTTP 101.",
    ),
    WssRoute(
        dc=4,
        hostname="kws4.web.telegram.org",
        media_hostname="kws4-1.web.telegram.org",
        relay_ip=WSS_RELAY_IP,
        status=RouteStatus.STABLE,
        source="ZapretGUI + Flowseal tg-ws-proxy",
        note="Stable on 2026-06-14: repeated /apiws WebSocket Upgrade returned HTTP 101.",
    ),
    WssRoute(
        dc=2,
        hostname="zws2.web.telegram.org",
        media_hostname="zws2-1.web.telegram.org",
        relay_ip=WSS_RELAY_IP,
        status=RouteStatus.CANDIDATE,
        source="GhostWire 1.0.13 decrypted config",
        note=(
            "Candidate only: HTTP 101 worked, but a 2026-06-14 live SOCKS5 "
            "probe made Telegram disable the proxy and produced recv=0/"
            "IncompleteReadError signs."
        ),
    ),
    WssRoute(
        dc=4,
        hostname="zws4.web.telegram.org",
        media_hostname="zws4-1.web.telegram.org",
        relay_ip=WSS_RELAY_IP,
        status=RouteStatus.CANDIDATE,
        source="GhostWire 1.0.13 decrypted config",
        note=(
            "Candidate only: HTTP 101 worked, but a 2026-06-14 live SOCKS5 "
            "probe made Telegram disable the proxy and produced recv=0/"
            "IncompleteReadError signs."
        ),
    ),
)


FALLBACK_ONLY_REASONS: dict[int, str] = {
    1: "kws1/zws1 did not prove a stable HTTP 101 route; use Cloudflare/Worker, TCP, or upstream SOCKS5.",
    3: "kws3/zws3 did not prove a stable HTTP 101 route; use Cloudflare/Worker, TCP, or upstream SOCKS5.",
    5: "kws5/zws5 did not prove a stable HTTP 101 route; use Cloudflare/Worker, TCP, or upstream SOCKS5.",
    203: "kws203 and direct DC203 IP did not prove stable HTTP 101; zws2 is only a candidate and must not be automatic yet.",
}


def _routes_for(dc: int, status: RouteStatus) -> tuple[WssRoute, ...]:
    return tuple(route for route in WSS_ROUTES if route.dc == int(dc) and route.status == status)


def wss_enabled_dcs() -> tuple[int, ...]:
    """Return DCs allowed for automatic WSS routing."""

    return tuple(sorted({route.dc for route in WSS_ROUTES if route.status == RouteStatus.STABLE}))


def stable_wss_domains_for_dc(dc: int, *, is_media: bool) -> tuple[str, ...]:
    """Return stable WSS domains for a DC in the order used by runtime routing."""

    domains: list[str] = []
    for route in _routes_for(dc, RouteStatus.STABLE):
        domains.extend(route.domains_for(is_media=is_media))
    return tuple(domains)


def candidate_wss_domains_for_dc(dc: int, *, is_media: bool) -> tuple[str, ...]:
    """Return visible-but-disabled WSS candidates for diagnostics and future testing."""

    domains: list[str] = []
    for route in _routes_for(dc, RouteStatus.CANDIDATE):
        domains.extend(route.domains_for(is_media=is_media))
    return tuple(domains)


def route_status_for_dc(dc: int) -> str:
    if stable_wss_domains_for_dc(dc, is_media=False):
        return RouteStatus.STABLE.value
    if candidate_wss_domains_for_dc(dc, is_media=False):
        return RouteStatus.CANDIDATE.value
    return RouteStatus.FALLBACK_ONLY.value


def fallback_only_reason(dc: int) -> str:
    return FALLBACK_ONLY_REASONS.get(
        int(dc),
        "No stable WSS route is recorded for this DC; use fallback routing.",
    )


def stable_wss_domain_map() -> dict[int, list[str]]:
    return {
        dc: list(stable_wss_domains_for_dc(dc, is_media=False))
        for dc in wss_enabled_dcs()
    }


__all__ = [
    "FALLBACK_ONLY_REASONS",
    "RouteStatus",
    "WSS_PATH",
    "WSS_RELAY_IP",
    "WSS_ROUTES",
    "WssRoute",
    "candidate_wss_domains_for_dc",
    "fallback_only_reason",
    "route_status_for_dc",
    "stable_wss_domain_map",
    "stable_wss_domains_for_dc",
    "wss_enabled_dcs",
]
