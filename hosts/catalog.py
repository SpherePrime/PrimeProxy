"""
Built-in service catalog for the hosts unblock page.

Data lives in the shipped SQLite catalog (resources/hosts/hosts_catalog.sqlite3,
72 services / 818 domains) read through :mod:`hosts.catalog_repository`. When
the database is not bundled (dev checkout, stripped package) we fall back to a
static inline catalog so the page never breaks.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Dict, List, Optional, Tuple

from . import catalog_repository as _repo

log = logging.getLogger("swift-hosts")

_BLOCK_IP = "127.0.0.1"

LEGACY_ID_MAP: Dict[str, str] = {
    "discord": "hosts.discord",
    "youtube": "hosts.youtube",
    "twitch": "dns.twitch",
    "instagram": "hosts.instagram",
    "x": "hosts.x_twitter",
    "notion": "dns.notion",
    "xgboost": "dns.microsoft_copilot_designer_xbox",
}

CUSTOM_SERVICE_IDS = ("adobe", "windows-telemetry")

# Static fallback catalog (used only when the SQLite resource is unavailable).
SERVICE_CATALOG: Dict[str, Dict[str, object]] = {
    "discord": {
        "name": "Discord",
        "mode": "block",
        "type": "hosts",
        "category": "direct",
        "icon": "discord",
        "domains": {
            "discord.gg": "127.0.0.1",
            "discord.com": "127.0.0.1",
            "discordapp.com": "127.0.0.1",
            "discord.media": "127.0.0.1",
            "discordapp.net": "127.0.0.1",
        },
    },
    "youtube": {
        "name": "YouTube",
        "mode": "block",
        "type": "hosts",
        "category": "direct",
        "icon": "youtube",
        "domains": {
            "youtube.com": "127.0.0.1",
            "www.youtube.com": "127.0.0.1",
            "youtube-nocookie.com": "127.0.0.1",
            "youtu.be": "127.0.0.1",
            "ytimg.com": "127.0.0.1",
        },
    },
    "twitch": {
        "name": "Twitch",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "twitch",
        "domains": {
            "twitch.tv": "127.0.0.1",
            "www.twitch.tv": "127.0.0.1",
            "jtvnw.net": "127.0.0.1",
            "ttvnw.net": "127.0.0.1",
        },
    },
    "steam": {
        "name": "Steam",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "steam",
        "domains": {
            "steampowered.com": "127.0.0.1",
            "steamcommunity.com": "127.0.0.1",
            "steamstatic.com": "127.0.0.1",
            "steamcdn-a.akamaihd.net": "127.0.0.1",
        },
    },
    "xgboost": {
        "name": "Xbox / MS Store",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "xbox",
        "domains": {
            "xbox.com": "127.0.0.1",
            "xboxlive.com": "127.0.0.1",
        },
    },
    "x": {
        "name": "X / Twitter",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "x",
        "domains": {
            "x.com": "127.0.0.1",
            "twitter.com": "127.0.0.1",
            "twimg.com": "127.0.0.1",
            "t.co": "127.0.0.1",
            "twittervideo.com": "127.0.0.1",
        },
    },
    "instagram": {
        "name": "Instagram",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "instagram",
        "domains": {
            "instagram.com": "127.0.0.1",
            "www.instagram.com": "127.0.0.1",
            "i.instagram.com": "127.0.0.1",
            "instagramstatic.com": "127.0.0.1",
            "cdninstagram.com": "127.0.0.1",
            "instaram.com": "127.0.0.1",
        },
    },
    "facebook": {
        "name": "Facebook",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "facebook",
        "domains": {
            "facebook.com": "127.0.0.1",
            "www.facebook.com": "127.0.0.1",
            "m.facebook.com": "127.0.0.1",
            "fbcdn.net": "127.0.0.1",
            "fbsbx.com": "127.0.0.1",
            "facebook.net": "127.0.0.1",
        },
    },
    "linkedin": {
        "name": "LinkedIn",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "linkedin",
        "domains": {
            "linkedin.com": "127.0.0.1",
            "www.linkedin.com": "127.0.0.1",
            "content.linkedin.com": "127.0.0.1",
            "licdn.com": "127.0.0.1",
            "media.licdn.com": "127.0.0.1",
        },
    },
    "reddit": {
        "name": "Reddit",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "reddit",
        "domains": {
            "reddit.com": "127.0.0.1",
            "www.reddit.com": "127.0.0.1",
            "new.reddit.com": "127.0.0.1",
            "redd.it": "127.0.0.1",
            "redditstatic.com": "127.0.0.1",
            "redditmedia.com": "127.0.0.1",
        },
    },
    "medium": {
        "name": "Medium",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "medium",
        "domains": {
            "medium.com": "127.0.0.1",
            "www.medium.com": "127.0.0.1",
            "m.medium.com": "127.0.0.1",
            "mediummedia.com": "127.0.0.1",
        },
    },
    "notion": {
        "name": "Notion",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "notion",
        "domains": {
            "notion.so": "127.0.0.1",
            "www.notion.so": "127.0.0.1",
            "notion.site": "127.0.0.1",
            "notion-static.com": "127.0.0.1",
        },
    },
    "adobe": {
        "name": "Adobe (активация)",
        "mode": "block",
        "type": "hosts",
        "category": "other",
        "icon": "adobe",
        "domains": {},
    },
    "windows-telemetry": {
        "name": "Windows телеметрия",
        "mode": "block",
        "type": "dns",
        "category": "other",
        "icon": "shield",
        "domains": {
            "v10.vortex-win.data.microsoft.com": "127.0.0.1",
            "v10.events.data.microsoft.com": "127.0.0.1",
            "v20.events.data.microsoft.com": "127.0.0.1",
            "settings-win.data.microsoft.com": "127.0.0.1",
            "settings-sandbox.data.microsoft.com": "127.0.0.1",
            "watson.telemetry.microsoft.com": "127.0.0.1",
            "oca.telemetry.microsoft.com": "127.0.0.1",
            "fcep.trafficmanager.net": "127.0.0.1",
            "df.telemetry.microsoft.com": "127.0.0.1",
            "browser.pipe.aria.microsoft.com": "127.0.0.1",
            "telemetry.measurementservice.net": "127.0.0.1",
            "windows.msn.com": "127.0.0.1",
            "cdn.gfx.ms": "127.0.0.1",
            "login.live.com": "127.0.0.1",
            "ntp.msn.com": "127.0.0.1",
            "msftconnecttest.com": "127.0.0.1",
            "dns.msftncsi.com": "127.0.0.1",
            "media-performance.microsoft.com": "127.0.0.1",
            "i.performance.microsoft.com": "127.0.0.1",
            "fe2.update.microsoft.com.akadns.net": "127.0.0.1",
            "storeedgefd.dsx.mp.microsoft.com": "127.0.0.1",
        },
    },
}

_CACHE: Dict[str, object] = {"sig": None, "entries": None, "version": ""}


def _adobe_domains() -> Dict[str, str]:
    from .adobe_domains import ADOBE_DOMAINS

    return dict(ADOBE_DOMAINS)


def _custom_entries() -> Dict[str, Dict[str, object]]:
    return {
        "adobe": {
            "name": "Adobe (активация)",
            "mode": "block",
            "type": "hosts",
            "category": "other",
            "icon": "adobe",
            "domains": _adobe_domains(),
        },
        "windows-telemetry": dict(SERVICE_CATALOG["windows-telemetry"]),
    }


def _fallback_entries() -> Dict[str, Dict[str, object]]:
    entries: Dict[str, Dict[str, object]] = {}
    for sid, entry in SERVICE_CATALOG.items():
        entry_copy = dict(entry)
        entry_copy["domains"] = dict(entry.get("domains") or {})
        entries[sid] = entry_copy
    entries["adobe"]["domains"] = _adobe_domains()
    return entries


def _sqlite_entries(catalog: _repo.HostsCatalog) -> Dict[str, Dict[str, object]]:
    entries: Dict[str, Dict[str, object]] = {}
    for sid in catalog.service_order:
        service = catalog.services[sid]
        if service.kind == "hosts":
            domains = {hostname: ip for hostname, ip in service.host_entries}
        else:
            domains = {hostname: _BLOCK_IP for hostname in service.domains}
        category = (
            service.category
            if service.category in ("other", "ai", "direct")
            else "other"
        )
        entries[sid] = {
            "name": service.name,
            "mode": "block",
            "type": service.kind,
            "category": category,
            "icon": service.icon_name,
            "domains": domains,
        }
    return entries


def _file_signature() -> Optional[Tuple[int, int]]:
    try:
        stat = _repo.catalog_path().stat()
        mtime_ns = getattr(stat, "st_mtime_ns", None)
        if mtime_ns is None:
            mtime_ns = int(stat.st_mtime * 1_000_000_000)
        return int(mtime_ns), int(stat.st_size)
    except OSError:
        return None


def _build_entries_and_version() -> Tuple[Dict[str, Dict[str, object]], str]:
    try:
        catalog = _repo.load_catalog(_repo.catalog_path())
    except Exception as exc:  # noqa: BLE001 — resource may be missing/corrupt
        log.warning("SQLite hosts catalog unavailable (%s); using static fallback", exc)
        entries = _fallback_entries()
        return entries, repr(entries)
    entries = _sqlite_entries(catalog)
    entries.update(_custom_entries())
    return entries, f"{catalog.catalog_version}|{catalog.content_sha256}"


def _get_entries() -> Tuple[Dict[str, Dict[str, object]], str]:
    signature = _file_signature()
    if _CACHE["sig"] == signature and _CACHE["entries"] is not None:
        return _CACHE["entries"], _CACHE["version"]  # type: ignore[return-value]
    entries, version = _build_entries_and_version()
    _CACHE["sig"] = signature
    _CACHE["entries"] = entries
    _CACHE["version"] = version
    return entries, version


def invalidate_catalog_cache() -> None:
    """Drop the cached catalog snapshot so the next call re-reads the file."""
    _CACHE["sig"] = None
    _CACHE["entries"] = None
    _CACHE["version"] = ""


def normalize_service_ids(service_ids: Optional[List[str]]) -> List[str]:
    """Map old PrimeProxy service ids onto current catalog ids, de-duplicating."""
    result: List[str] = []
    for sid in service_ids or []:
        if not isinstance(sid, str):
            continue
        value = sid.strip()
        if not value:
            continue
        value = LEGACY_ID_MAP.get(value, value)
        if value not in result:
            result.append(value)
    return result


def _lookup_entry_id(raw_id: str, entries: Dict[str, Dict[str, object]]) -> str:
    """Resolve a requested id against loaded entries, trying the legacy name."""
    value = raw_id.strip()
    if not value:
        return ""
    normalized = LEGACY_ID_MAP.get(value, value)
    if normalized in entries:
        return normalized
    if value in entries:
        return value
    return ""


def services_snapshot() -> List[Dict[str, object]]:
    entries, _version = _get_entries()
    rows: List[Dict[str, object]] = []
    for sid, entry in entries.items():
        domains = list(entry.get("domains") or {})
        rows.append({
            "id": sid,
            "name": entry["name"],
            "mode": entry.get("mode", "block"),
            "type": entry.get("type", "dns"),
            "category": entry.get("category", "other"),
            "icon": entry.get("icon", "fa5s.globe"),
            "domain_count": len(domains),
            "domains": domains,
        })
    return rows


def service_domains(service_id: str) -> Dict[str, str]:
    entries, _version = _get_entries()
    sid = _lookup_entry_id(service_id, entries)
    if not sid:
        return {}
    return {k: v for k, v in (entries[sid].get("domains") or {}).items()}


def merge_service_domains(
    service_ids: Optional[List[str]],
    adobe: bool = False,
) -> Dict[str, str]:
    """Build the full selected domain->ip map for the hosts block."""
    entries, _version = _get_entries()
    merged: Dict[str, str] = {}
    seen: set = set()
    for raw in service_ids or []:
        if not isinstance(raw, str):
            continue
        sid = _lookup_entry_id(raw, entries)
        if not sid or sid in seen:
            continue
        seen.add(sid)
        entry = entries[sid]
        merged.update(entry.get("domains") or {})
    if adobe:
        merged.update(_adobe_domains())
    return merged


def catalog_signature() -> Tuple[str, int]:
    entries, version = _get_entries()
    text = f"{version}\n{repr(entries)}"
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return digest, len(text)