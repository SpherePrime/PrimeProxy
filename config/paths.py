"""
Cross-platform application paths & directory resolution (single source of truth).

Replaces PrimeProxy utils/tray_common APP_DIR/CONFIG_FILE/LOG_FILE resolution
(portable + standard) and ZapretGUI config/runtime_layout ApplicationPaths.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

APP_NAME = "PrimeProxy"
PORTABLE_DIR_NAME = "PrimeProxy_data"
LEGACY_APP_NAMES = ("TgWsProxy", "ZapretUI")

IS_FROZEN = bool(getattr(sys, "frozen", False))


def _standard_app_dir() -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / APP_NAME


def exe_dir() -> Optional[Path]:
    try:
        base = getattr(sys, "frozen", False) and sys.executable or sys.argv[0]
    except Exception:
        return None
    if not base:
        return None
    try:
        p = Path(base).resolve(strict=False)
    except OSError:
        p = Path(os.path.realpath(base))
    return p.parent if p.is_file() else p


def _detect_portable() -> Optional[Path]:
    exe = exe_dir()
    if exe is None:
        return None
    portable_dir = exe / PORTABLE_DIR_NAME
    if "--portable" in sys.argv:
        try:
            portable_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            return None
    return portable_dir if portable_dir.is_dir() else None


def _legacy_app_dir(name: str) -> Path:
    if sys.platform == "win32":
        return Path(os.environ.get("APPDATA", Path.home())) / name
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / name
    return Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / name


def app_dir() -> Path:
    """The data directory (portable override preferred)."""
    from .store import ensure_dirs

    return ensure_dirs() or _standard_app_dir()


def config_file() -> Path:
    base = _detect_portable()
    if base is not None:
        base.mkdir(parents=True, exist_ok=True)
        return base / "config.json"
    return _standard_app_dir() / "config.json"


def log_file() -> Path:
    return config_file().parent / "proxy.log"


def resources_dir() -> Path:
    """Bundled read-only resources (hosts catalog, presets, UI assets)."""
    if IS_FROZEN:
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return Path(__file__).resolve().parents[1] / "resources"


def _migrate_legacy_configs(current: dict, target: Optional[Path] = None) -> dict:
    """Import settings from legacy PrimeProxy / Zapret UI config files.

    Legacy configs use flat keys (old PrimeProxy root-level keys, Zapret UI
    "telegram_proxy" section). This merges them into the unified schema.

    Migration is **fill-only**: a legacy value is applied only when the target
    section field is absent from the current config, so values the user has
    already saved (e.g. an MTProto port set in the new UI) are never
    overwritten on subsequent launches. Flat legacy keys that were successfully
    moved into sections are dropped from the current config to keep the file
    aligned with the documented schema.
    """
    from .store import load_saved_json

    legacy_section_map = {
        "port": ("proxy", "port"),
        "host": ("proxy", "host"),
        "dc_ip": ("proxy", "dc_ip"),
        "secret": ("proxy", "secret"),
        "verbose": ("proxy", "verbose"),
        "log_max_mb": ("proxy", "log_max_mb"),
        "buf_kb": ("proxy", "buf_kb"),
        "pool_size": ("proxy", "pool_size"),
        "cfproxy": ("proxy", "cfproxy"),
        "cfproxy_user_domain": ("proxy", "cfproxy_user_domain"),
        "cfproxy_worker_domain": ("proxy", "cfproxy_worker_domain"),
        "force_test_dc": ("proxy", "force_test_dc"),
        "language": ("app", "language"),
        "autostart": ("app", "autostart"),
        "check_updates": ("app", "check_updates"),
    }

    def _import_flat(flat: dict) -> bool:
        """Fill missing section fields from a flat legacy dict."""
        changed = False
        for key, (section, field) in legacy_section_map.items():
            if key not in flat:
                continue
            sec = current.setdefault(section, {})
            if field not in sec and flat[key] is not None:
                sec[field] = flat[key]
                changed = True
        tg = flat.get("telegram_proxy")
        if isinstance(tg, dict):
            tsec = current.setdefault("telegram", {})
            for key, value in tg.items():
                if key not in tsec and value is not None:
                    tsec[key] = value
                    changed = True
        return changed

    # 1) Current config's own flat legacy keys (files written by the pre-section
    #    PrimeProxy / migrated wholesale by tray_common) — move into sections
    #    and drop them so the document matches the unified schema.
    _import_flat(current)
    for key in list(current):
        if key in legacy_section_map:
            section, field = legacy_section_map[key]
            if field in current.get(section, {}):
                current.pop(key, None)

    # 2) Legacy app dirs fill anything still missing (fresh installs).
    for legacy_name in LEGACY_APP_NAMES:
        legacy_cfg = _legacy_app_dir(legacy_name) / "config.json"
        if not legacy_cfg.exists():
            continue
        try:
            data = load_saved_json(legacy_cfg)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        _import_flat(data)
        break
    return current