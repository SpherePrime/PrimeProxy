"""
Unified settings store for the merged PrimeProxy.

Backed by a single JSON document (config/PATH from config.paths). Sections:
- proxy:       MTProto->WS bridge engine settings (PrimeProxy)
- telegram:    Telegram WSS/SOCKS5 proxy settings (ZapretGUI)
- dns:         DNS providers & checks
- hosts:       hosts-file unblock catalog selections
- appearance:  UI theme (mode, card transparency, colors, background)
- blockcheck:  blockcheck diagnostics (user target domains)
- app:         language, autostart, update checks, logs
- updates:     manifest update source & state
- integrity:   engine fingerprint baseline
"""
from __future__ import annotations

import json
import logging
import os
import sys
import threading
from pathlib import Path
from typing import Any, Dict, Optional

from .paths import config_file, log_file, _migrate_legacy_configs

log = logging.getLogger("swift-config")

_SCHEMA = {
    "proxy": {
        "port": 1443,
        "host": "127.0.0.1",
        "dc_ip": ["2:149.154.167.220", "4:149.154.167.220"],
        "secret": "",
        "verbose": False,
        "log_max_mb": 5,
        "buf_kb": 256,
        "pool_size": 4,
        "cfproxy": True,
        "cfproxy_user_domain_enabled": False,
        "cfproxy_user_domain": [],
        "cfproxy_worker_enabled": False,
        "cfproxy_worker_domain": [],
        "force_test_dc": False,
    },
    "telegram": {
        "enabled": False,
        "mode": "socks5",             # socks5 | mtproxy
        "bind_host": "127.0.0.1",
        "port": 1353,
        "upstream": "1080",
        "upstream_host": "127.0.0.1",
        "use_relays": False,
        "relay": "",
        "auto_learn": True,
        "wss_domains": [],
    },
    "dns": {
        "force_dns": False,
        "provider_id": "cloudflare",
        "custom_servers": [],
        "check_on_startup": True,
        "restore_on_exit": True,
    },
    "hosts": {
        "managed": True,
        "selected": [],                # service ids (catalog)
        "adobe_block": True,
    },
    "appearance": {
        "mode": "auto",                # auto | light | dark
        "card_opacity": 0.85,          # card opacity 0.3..1.0
        "card_transparency": False,    # transparent cards toggle
        "glass_tabs": True,            # glass on sidebar tabs
        "accent": "#007AFF",
        "sidebar_bg": "",              # custom sidebar background (rgba hex or "")
        "nav_active_color": "",        # active nav item text color
        "nav_active_bg": "",           # active nav item background
        "text_color": "",              # main text color
        "surface_color": "",           # global panel surface color (hex or "")
        "wallpaper": "standard",       # standard | gradient | image | video
        "wallpaper_src": "",           # file path for image/video wallpaper
    },
    "zapret": {
        "enabled": False,              # DPI-движок сейчас включён (по желанию)
        "mode": "auto",                # auto | winws1 | winws2
        "profile_group": "winws2",     # winws1 | winws2 | user
        "profile": "",                 # файл/имя выбранного профиля
        "autostart": False,            # запускать winws при старте приложения
        "cleanup_on_exit": True,       # гасить winws-процессы при выходе
        "auto": {                      # автопилот «Обход Zapret»
            "enabled": False,
            "profile": "auto",         # пользовательский профиль автопилота
            "max_attempts": 4,         # перебор стратегий до отказа
            "catalog_limit": 250,      # доменов из hosts-каталога в скан (0 = все)
        },
    },
    "blockcheck": {
        "user_domains": [],            # домены пользователя для «Проверка сайтов»
    },
    "updates": {
        "source_url": "",              # URL манифеста обновлений (http/https/file)
        "last_check": None,            # ISO-строка последней проверки либо None
        "auto_check": False,           # автоматическая проверка обновлений
    },
    "integrity": {
        "engine_baseline": None,       # sha256-эталон файлов движка (dict либо None)
    },
    "app": {
        "language": "auto",
        "autostart": False,
        "check_updates": True,
        "close_to_tray": True,
        "minimize_to_tray": True,
        "start_minimized": False,
        "run_proxy_on_startup": True,
    },
}

_lock = threading.RLock()
_LANGUAGE_DETECTED = "auto"


def _resolve_defaults() -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for section, values in _SCHEMA.items():
        out[section] = {}
        for key, val in values.items():
            out[section][key] = val() if callable(val) else val
    out["app"]["language"] = _detect_language()
    return out


def detect_language() -> str:
    try:
        from ui.i18n import detect_system_language
        return detect_system_language().value
    except Exception:
        return _LANGUAGE_DETECTED


def _detect_language() -> str:
    try:
        import locale
        lang = (locale.getlocale()[0] or os.environ.get("LANG", "") or "").lower()
        if lang.startswith("uk") or lang.startswith("ua"):
            return "uk"
        if lang.startswith("ru"):
            return "ru"
        return "en"
    except Exception:
        return "en"


def load_saved_json(path: Path) -> Optional[dict]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError, TypeError):
        return None


def save_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


class SettingsStore:
    """Thread-safe settings wrapper over a JSON document."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or config_file()
        self._data: Dict[str, Any] = {}
        self._loaded = False

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> "SettingsStore":
        with _lock:
            if self._loaded:
                return self
            self._path.parent.mkdir(parents=True, exist_ok=True)
            data = load_saved_json(self._path) or {}
            data = _migrate_legacy_configs(data)
            defaults = _resolve_defaults()
            if not isinstance(data, dict):
                data = {}
            data = _deep_merge(defaults, data)
            self._data = data
            self._loaded = True
            self._apply_ui_language()
            return self

    def _apply_ui_language(self) -> None:
        if not self._loaded:
            return
        lang = self._data.get("app", {}).get("language", "auto")
        try:
            from ui.i18n import set_language
            set_language(lang if lang != "auto" else detect_language())
        except Exception:
            pass

    def save(self) -> None:
        with _lock:
            if not self._loaded:
                return
            save_json(self._path, self._data)

    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        with _lock:
            sec = self._data.get(section)
            if sec is None or not isinstance(sec, dict):
                return default
            if key is None:
                return sec
            return sec.get(key, default)

    def set(self, section: str, key: str, value: Any) -> None:
        with _lock:
            self._data.setdefault(section, {})[key] = value
            self.save()

    def set_section(self, section: str, values: Dict[str, Any]) -> None:
        with _lock:
            self._data.setdefault(section, {}).update(values)
            self.save()

    def snapshot(self) -> Dict[str, Any]:
        with _lock:
            return json.loads(json.dumps(self._data))

    def as_dict(self) -> Dict[str, Any]:
        return self.snapshot()

    def get_updates(self) -> Dict[str, Any]:
        return self.get("updates", None) or dict(_resolve_defaults()["updates"])

    def get_integrity(self) -> Dict[str, Any]:
        return self.get("integrity", None) or dict(_resolve_defaults()["integrity"])


def _deep_merge(base: dict, override: dict) -> dict:
    result = dict(base)
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


store: Optional[SettingsStore] = None


def get_store(force_reload: bool = False) -> SettingsStore:
    global store
    if store is None or force_reload:
        with _lock:
            if store is None or force_reload:
                new_store = SettingsStore()
                new_store.load()
                store = new_store
    return store


def ensure_dirs() -> None:
    base = config_file().parent
    base.mkdir(parents=True, exist_ok=True)


def reset_cache() -> None:
    global store

    store = None