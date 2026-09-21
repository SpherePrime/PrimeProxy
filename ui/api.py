"""
pywebview JavaScript ↔ Python API.

All public methods on :class:`SwiftAPI` are callable from JS:
``window.pywebview.api.get_proxy_status()``

The API is designed so the HTML layer never touches the filesystem or
proxy threads directly — only through this safe bridge.
"""
from __future__ import annotations

import asyncio
import datetime
import json
import logging
import socket
import threading
import time
from dataclasses import fields, is_dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from config import __version__, get_store
from proxy import __version__ as engine_version

log = logging.getLogger("swift-api")

_version = __version__
_engine_version = engine_version

# MTProto -> WS engine managed through utils.tray_common (proven lifecycle).
_mtproto_proxy_thread = None

# Telegram WSS/SOCKS5 engine (ZapretGUI engine) with its own event loop.
_tg_wss_proxy = None
_tg_loop = None

_proxy_lock = threading.Lock()

# Tracking maximized state for the frameless titlebar (pywebview has no getter).
_win_maximized = False

# BlockCheck («Проверка сайтов»): одиночный прогон в фоновом потоке.
_blockcheck_state: Dict[str, Any] = {"status": "idle", "message": "", "lines": [], "report": None}
_blockcheck_thread = None
_blockcheck_cancel = threading.Event()
_blockcheck_lock = threading.Lock()

# DNS poisoning check: фоновый поток + опрос состояния из JS.
_dns_check_state: Dict[str, Any] = {"status": "idle", "message": "", "lines": [], "result": None}
_dns_check_thread = None
_dns_check_cancel = threading.Event()
_dns_check_lock = threading.Lock()

# Manifest update check: фоновый поток + опрос состояния из JS.
_updates_check_state: Dict[str, Any] = {"status": "idle", "message": "", "result": None}
_updates_check_thread = None
_updates_check_lock = threading.Lock()

# Orchestra LEARNING (auto-lock стратегий через круговой профиль):
_orchestra_state: Dict[str, Any] = {
    "auto_learning": False,
    "started_at": None,
    "message": "",
}
_orchestra_lock = threading.Lock()


def _to_plain(obj: Any) -> Any:
    """Превращает dataclass/Enum дерево BlockCheck в JSON-совместимую структуру."""
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj):
        return {field_.name: _to_plain(getattr(obj, field_.name)) for field_ in fields(obj)}
    if isinstance(obj, dict):
        return {str(key): _to_plain(value) for key, value in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [_to_plain(value) for value in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def _get_config():
    return get_store().snapshot()


def _pick_media_file(kind: str) -> Optional[str]:
    patterns = (
        ("Images", "*.png;*.jpg;*.jpeg;*.webp;*.gif;*.bmp")
        if kind == "image"
        else ("Videos", "*.mp4;*.webm;*.mov;*.mkv")
    )
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        try:
            path = filedialog.askopenfilename(
                title="SwiftProxy — " + ("Wallpaper image" if kind == "image" else "Wallpaper video"),
                filetypes=[patterns, ("All files", "*.*")],
            )
            return path or None
        finally:
            root.destroy()
    except Exception:
        return _pick_media_file_ctypes(patterns)


def _pick_media_file_ctypes(pair) -> Optional[str]:
    try:
        import ctypes
        from ctypes import wintypes

        filt = "".join(
            f"{name}\0{ext};*.*\0" for name, ext in ([pair, ("All files", "*")])
        ) + "\0"

        class _OFNW(ctypes.Structure):
            _fields_ = [
                ("lStructSize", wintypes.DWORD),
                ("hwndOwner", wintypes.HWND),
                ("hInstance", wintypes.HINSTANCE),
                ("lpstrFilter", wintypes.LPCWSTR),
                ("lpstrCustomFilter", wintypes.LPWSTR),
                ("nMaxCustFilter", wintypes.DWORD),
                ("nFilterIndex", wintypes.DWORD),
                ("lpstrFile", wintypes.LPWSTR),
                ("nMaxFile", wintypes.DWORD),
                ("lpstrFileTitle", wintypes.LPWSTR),
                ("nMaxFileTitle", wintypes.DWORD),
                ("lpstrInitialDir", wintypes.LPCWSTR),
                ("lpstrTitle", wintypes.LPCWSTR),
                ("Flags", wintypes.DWORD),
                ("nFileOffset", wintypes.WORD),
                ("nFileExtension", wintypes.WORD),
                ("lpstrDefExt", wintypes.LPCWSTR),
                ("lCustData", wintypes.LPARAM),
                ("lpfnHook", wintypes.WNDPROC),
                ("lpTemplateName", wintypes.LPCWSTR),
                ("pvReserved", ctypes.c_void_p),
                ("dwReserved", wintypes.DWORD),
                ("FlagsEx", wintypes.DWORD),
            ]

        buf = ctypes.create_unicode_buffer(520)
        ofn = _OFNW()
        ofn.lStructSize = ctypes.sizeof(_OFNW)
        ofn.hwndOwner = None
        ofn.lpstrFilter = filt
        ofn.lpstrFile = buf
        ofn.nMaxFile = 520
        # OFN_FILEMUSTEXIST | OFN_HIDEREADONLY
        ofn.Flags = 0x00001000 | 0x00000004
        ok = ctypes.windll.comdlg32.GetOpenFileNameW(ctypes.byref(ofn))
        return buf.value if ok else None
    except Exception:
        return None


def _updates_dir():
    from config.paths import app_dir

    return app_dir() / "updates"


def _is_valid_source_url(url: str) -> bool:
    from urllib.parse import urlparse

    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme in ("http", "https"):
        return bool(parsed.netloc)
    if parsed.scheme == "file":
        return bool(parsed.path)
    return False


def _run_manifest_update(source_url: str) -> Dict[str, Any]:
    from utils.fast_download import download
    from utils.hardened_file_ops import safe_join
    from utils.versioning import is_newer

    updates_dir = _updates_dir()
    manifest_dest = updates_dir / ".manifest.json"
    fetched = download(source_url, manifest_dest)
    if not fetched["ok"]:
        return {"ok": False, "reason": "manifest_download", "error": fetched["error"]}
    try:
        manifest = json.loads(manifest_dest.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"ok": False, "reason": "bad_manifest"}
    finally:
        try:
            manifest_dest.unlink()
        except OSError:
            pass
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        return {"ok": False, "reason": "bad_manifest"}
    version = str(manifest.get("version") or "")
    if version and not is_newer(version, _version):
        return {"ok": True, "reason": "no_update", "found_version": version, "applied": False}
    errors: List[Dict[str, Any]] = []
    applied_paths: List[str] = []
    for entry in manifest["files"]:
        if not isinstance(entry, dict):
            errors.append({"path": None, "error": "invalid_entry"})
            continue
        rel = str(entry.get("path") or "").replace("\\", "/").strip("/")
        if not rel or rel in (".", "..") or not rel.split("/")[-1]:
            errors.append({"path": rel, "error": "invalid_path"})
            continue
        try:
            dest = safe_join(updates_dir, *rel.split("/"))
        except ValueError:
            errors.append({"path": rel, "error": "unsafe_path"})
            continue
        urls = entry.get("urls")
        if isinstance(urls, list) and urls:
            url_list = [u for u in urls if isinstance(u, str) and u]
        else:
            single = entry.get("url")
            url_list = [single] if isinstance(single, str) and single else []
        if not url_list:
            errors.append({"path": rel, "error": "no_url"})
            continue
        result = download(
            url_list[0],
            dest,
            sha256=entry.get("sha256"),
            max_bytes=entry.get("size"),
        )
        if not result["ok"]:
            errors.append({"path": rel, "error": result["error"]})
            continue
        applied_paths.append(rel)
    return {
        "ok": not errors,
        "reason": None,
        "found_version": version,
        "applied": bool(applied_paths),
        "files_applied": applied_paths,
        "errors": errors,
    }


def _diff_fingerprints(baseline, current: dict) -> dict:
    records: Dict[str, dict] = {}
    for ref in (baseline or {}).get("files") or []:
        if isinstance(ref, dict) and ref.get("exists"):
            records[ref.get("name")] = ref
    file_status: List[dict] = []
    changed_files: List[dict] = []
    for entry in current.get("files") or []:
        name = entry.get("name")
        ref = records.get(name)
        if not entry.get("exists"):
            status = "missing" if ref is not None else "ok"
        elif ref is None:
            status = "added"
        elif ref.get("sha256") and ref.get("sha256") == entry.get("sha256"):
            status = "ok"
        else:
            status = "tampered"
        file_status.append({"name": name, "status": status, "exists": entry.get("exists")})
        if status != "ok":
            changed_files.append({"name": name, "status": status})
    return {
        "ok": not changed_files,
        "files": file_status,
        "changed_files": changed_files,
        "added": [c for c in changed_files if c["status"] == "added"],
        "missing": [c for c in changed_files if c["status"] == "missing"],
        "tampered": [c for c in changed_files if c["status"] == "tampered"],
        "dir": current.get("dir", ""),
        "aggregate_hash": current.get("aggregate_hash", ""),
    }


class SwiftAPI:
    """Public API exposed to the webview frontend via window.pywebview.api.*."""

    # ─── App / meta ────────────────────────────────────────────────────

    def get_app_info(self) -> Dict[str, str]:
        import sys
        self._start_auto_check()
        return {
            "version": _version,
            "engine_version": _engine_version,
            "platform": sys.platform,
        }

    def get_settings(self) -> Dict[str, Any]:
        return get_store().snapshot()

    def set_setting(self, section: str, key: str, value: Any) -> bool:
        try:
            get_store().set(section, key, value)
            return True
        except Exception as exc:
            log.warning("set_setting failed: %s", repr(exc))
            return False

    # ─── MTProto proxy (SwiftProxy engine) ─────────────────────────────

    def get_proxy_status(self) -> Dict[str, Any]:
        global _mtproto_proxy_thread
        import threading as _t

        running = (
            _mtproto_proxy_thread is not None
            and _mtproto_proxy_thread.is_alive()
        )
        cfg = _get_config().get("proxy", {})
        return {
            "running": running,
            "host": cfg.get("host", "127.0.0.1"),
            "port": cfg.get("port", 1443),
            "secret": cfg.get("secret", ""),
        }

    def start_proxy(self) -> Dict[str, Any]:
        global _mtproto_proxy_thread
        from utils.tray_common import start_proxy as _start

        with _proxy_lock:
            if _mtproto_proxy_thread is not None and _mtproto_proxy_thread.is_alive():
                return {"ok": True, "detail": "already_running"}
            _start(_get_config().get("proxy", {}), _noop_error)
            _mtproto_proxy_thread = _running_thread()
            return {"ok": True, "detail": "started"}

    def stop_proxy(self) -> Dict[str, Any]:
        global _mtproto_proxy_thread
        from utils.tray_common import stop_proxy as _stop

        with _proxy_lock:
            _stop()
            _mtproto_proxy_thread = None
            return {"ok": True, "detail": "stopped"}

    # ─── Telegram WSS proxy (ZapretGUI engine) ────────────────────────

    def get_tg_proxy_status(self) -> Dict[str, Any]:
        cfg = _get_config().get("telegram", {})
        running = _tg_wss_proxy is not None and getattr(_tg_wss_proxy, "_running", False)
        return {
            "enabled": cfg.get("enabled", False),
            "mode": cfg.get("mode", "socks5"),
            "host": cfg.get("bind_host", "127.0.0.1"),
            "port": cfg.get("port", 1353),
            "running": running,
        }

    def start_tg_proxy(self) -> Dict[str, Any]:
        global _tg_wss_proxy, _tg_loop
        cfg = _get_config().get("telegram", {})
        if not cfg.get("enabled", False):
            return {"ok": False, "detail": "disabled"}
        if _tg_wss_proxy is not None and getattr(_tg_wss_proxy, "_running", False):
            return {"ok": True, "detail": "already_running"}
        try:
            from telegram import TelegramWSProxy

            proxy = TelegramWSProxy(
                port=int(cfg.get("port", 1353)),
                host=cfg.get("bind_host", "127.0.0.1"),
                mode=cfg.get("mode", "socks5"),
            )
            lo = asyncio.new_event_loop()

            def _run_loop():
                asyncio.set_event_loop(lo)
                try:
                    lo.run_until_complete(proxy.start())
                except Exception as exc:
                    log.exception("Telegram proxy start failed")
                lo.run_forever()

            t = threading.Thread(target=_run_loop, daemon=True, name="tg-wss-proxy")
            t.start()
            _tg_wss_proxy = proxy
            _tg_loop = lo
            return {"ok": True, "detail": "started"}
        except Exception as exc:
            log.exception("Failed to start Telegram WSS proxy")
            return {"ok": False, "detail": str(exc)}

    def stop_tg_proxy(self) -> Dict[str, Any]:
        global _tg_wss_proxy, _tg_loop
        if _tg_wss_proxy is None or _tg_loop is None:
            return {"ok": True, "detail": "not_running"}
        try:
            proxy = _tg_wss_proxy
            lo = _tg_loop

            def _shutdown():
                try:
                    asyncio.run_coroutine_threadsafe(proxy.stop(), lo).result(timeout=5)
                except Exception as exc:
                    log.warning("Telegram proxy stop error: %s", repr(exc))
                finally:
                    lo.call_soon_threadsafe(lo.stop)

            threading.Thread(target=_shutdown, daemon=True).start()
            time.sleep(0.5)
        except Exception as exc:
            log.warning("stop_tg_proxy: %s", repr(exc))
        _tg_wss_proxy = None
        _tg_loop = None
        return {"ok": True, "detail": "stopped"}

    # ─── DNS ───────────────────────────────────────────────────────────

    def get_dns_providers(self) -> List[Dict[str, Any]]:
        from dns import get_provider_list
        return get_provider_list()

    def get_dns_provider(self, provider_id: str) -> Optional[Dict[str, Any]]:
        from dns import get_provider
        return get_provider(provider_id)

    def run_dns_check(self, provider_id: str) -> Dict[str, Any]:
        from dns import run_provider_tests
        try:
            return run_provider_tests(provider_id)
        except Exception as exc:
            return {"id": provider_id, "ok": False, "error": str(exc)}

    def get_system_dns(self) -> List[str]:
        from dns import get_system_dns_servers
        return get_system_dns_servers()

    def flush_dns(self) -> str:
        from dns import flush_dns_cache
        return flush_dns_cache()

    def force_dns(self, servers: Optional[List[str]] = None) -> Dict[str, Any]:
        from dns import force_dns as _force
        return {"ok": True, **_force(servers)}

    def restore_dns(self) -> Dict[str, Any]:
        from dns import restore_dns as _restore
        return {"ok": True, **_restore()}

    def get_network_adapters(self) -> Dict[str, Any]:
        from dns.adapters import get_network_adapters
        try:
            return get_network_adapters()
        except Exception as exc:
            log.warning("get_network_adapters failed: %s", repr(exc))
            return {"ok": False, "adapters": [], "total": 0, "connected": 0, "error": str(exc)}

    def run_quick_dns_check(self) -> Dict[str, Any]:
        from dns.check import run_connectivity_test
        from dns.quick_check import run_quick_dns_check as _quick
        try:
            dns_part = _quick()
            conn = run_connectivity_test(
                [("Google DNS", "8.8.8.8"), ("Cloudflare", "1.1.1.1")]
            )
        except Exception as exc:
            log.warning("run_quick_dns_check failed: %s", repr(exc))
            return {"ok": False, "error": str(exc), "results": []}
        results = dns_part.get("results", []) + conn.get("results", [])
        return {
            "ok": True,
            "results": results,
            "overall": bool(results) and all(r.get("ok") is not False for r in results),
            "dns_ok": dns_part.get("ok", 0),
            "dns_checked": dns_part.get("checked", 0),
        }

    def run_dns_poisoning_check(self) -> Dict[str, Any]:
        global _dns_check_thread
        from dns.poisoning import check_dns_poisoning

        with _dns_check_lock:
            if _dns_check_state["status"] == "running":
                return {"ok": False, "error": "already running"}
            _dns_check_state.update(
                {"status": "running", "message": "", "lines": [], "result": None}
            )
            _dns_check_cancel.clear()

        def _worker() -> None:
            lines: List[str] = []

            def _log(message: str) -> None:
                lines.append(str(message))
                if len(lines) > 400:
                    del lines[:40]
                with _dns_check_lock:
                    _dns_check_state["lines"] = list(lines)

            def _is_cancelled() -> bool:
                return _dns_check_cancel.is_set()

            try:
                result = check_dns_poisoning(log_callback=_log, should_stop=_is_cancelled)
                cancelled = _is_cancelled()
                with _dns_check_lock:
                    _dns_check_state["status"] = "cancelled" if cancelled else "done"
                    _dns_check_state["message"] = "Отменено" if cancelled else "Готово"
                    _dns_check_state["result"] = result
                    _dns_check_state["lines"] = lines
            except Exception as exc:  # noqa: BLE001 — вернём ошибку наверх
                log.warning("dns poisoning check failed", exc_info=True)
                with _dns_check_lock:
                    _dns_check_state["status"] = "error"
                    _dns_check_state["message"] = str(exc)
                    _dns_check_state["lines"] = lines

        _dns_check_thread = threading.Thread(
            target=_worker, args=(), daemon=True, name="dns-poisoning"
        )
        _dns_check_thread.start()
        return {"ok": True}

    def get_dns_check_status(self) -> Dict[str, Any]:
        with _dns_check_lock:
            return json.loads(json.dumps(_dns_check_state))

    def stop_dns_poisoning_check(self) -> Dict[str, Any]:
        _dns_check_cancel.set()
        return {"ok": True}

    # ─── Hosts ─────────────────────────────────────────────────────────

    def get_hosts_services(self) -> List[Dict[str, Any]]:
        from hosts import services_snapshot
        return services_snapshot()

    def get_hosts_selection(self) -> List[str]:
        from hosts import normalize_service_ids
        try:
            selected = _get_config().get("hosts", {}).get("selected") or []
        except Exception:
            return []
        return normalize_service_ids(selected)

    def get_hosts_active(self) -> Dict[str, str]:
        from hosts import read_active_domains_map
        return read_active_domains_map()

    def apply_hosts_services(self, service_ids: List[str], adobe: bool = False) -> Dict[str, Any]:
        from hosts import apply_host_entries, merge_service_domains
        try:
            merged = merge_service_domains(service_ids, adobe)
            ok, count = apply_host_entries(merged)
            return {"ok": ok, "count": count}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def clear_hosts(self) -> Dict[str, Any]:
        from hosts import clear_host_entries
        try:
            ok, removed = clear_host_entries()
            return {"ok": ok, "removed": removed}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def get_tray_proxy_link(self) -> str:
        cfg = _get_config().get("proxy", {})
        host = cfg.get("host", "127.0.0.1")
        port = cfg.get("port", 1443)
        secret = cfg.get("secret", "")
        from proxy.utils import get_link_host
        link_host = get_link_host(host)
        return f"tg://proxy?server={link_host}&port={port}&secret=dd{secret}"

    def copy_proxy_link(self) -> bool:
        try:
            import pyperclip
            pyperclip.copy(self.get_tray_proxy_link())
            return True
        except Exception:
            return False

    def copy_text(self, text: str) -> bool:
        try:
            import pyperclip
            pyperclip.copy(text)
            return True
        except Exception:
            return False

    def open_proxy_link(self) -> bool:
        """Open the MTProto tg:// connect link in the default handler."""
        try:
            import webbrowser
            webbrowser.open(self.get_tray_proxy_link())
            return True
        except Exception:
            return False

    def open_link(self, url: str = "") -> bool:
        """Open a Telegram connect link (tg:// only) in the default handler."""
        try:
            u = (url or "").strip()
            if not u.lower().startswith("tg://"):
                return False
            import webbrowser
            webbrowser.open(u)
            return True
        except Exception:
            return False

    # ─── System proxy (route any app through SOCKS5) ────────────────────────

    def set_system_proxy(self, on: bool) -> Dict[str, Any]:
        """Enable/disable the Windows system proxy pointed at the SOCKS5 server."""
        import sys
        if sys.platform != "win32":
            return {"ok": False, "detail": "only supported on Windows"}
        port = _get_config().get("telegram", {}).get("port", 1353)
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_SET_VALUE)
            if on:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"socks=127.0.0.1:{port};http=127.0.0.1:{port};https=127.0.0.1:{port}")
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
            winreg.CloseKey(key)
            self._notify_wininet()
            return {"ok": True, "port": port}
        except Exception as exc:
            return {"ok": False, "detail": str(exc)}

    def get_system_proxy(self) -> Dict[str, Any]:
        """Read the current Windows system proxy state."""
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", 0, winreg.KEY_READ)
            try:
                enabled = int(winreg.QueryValueEx(key, "ProxyEnable")[0]) == 1
            except OSError:
                enabled = False
            try:
                server = winreg.QueryValueEx(key, "ProxyServer")[0] or ""
            except OSError:
                server = ""
            winreg.CloseKey(key)
            return {"ok": True, "enabled": enabled, "server": server}
        except Exception as exc:
            return {"ok": False, "detail": str(exc)}

    @staticmethod
    def _notify_wininet() -> None:
        """Tell WinINet about proxy changes (so apps notice immediately)."""
        try:
            import ctypes
            INTERNET_OPTION_SETTINGS_CHANGED = 39
            INTERNET_OPTION_REFRESH = 37
            i = ctypes.c_int(0)
            h = ctypes.windll.internetapi32.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
            if h:
                ctypes.windll.internetapi32.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)
        except Exception:
            try:
                import ctypes
                ctypes.windll.wininet.InternetSetOptionW(None, 39, None, 0)
                ctypes.windll.wininet.InternetSetOptionW(None, 37, None, 0)
            except Exception:
                pass

    # ─── Window controls (custom titlebar / frameless) ─────────────────────

    def _window(self):
        try:
            import webview
            if webview.windows:
                return webview.windows[0]
        except Exception:
            pass
        return None

    def window_state(self) -> Dict[str, Any]:
        w = self._window()
        if not w:
            return {"maximized": _win_maximized, "fullscreen": False}
        fl = False
        try:
            fl = bool(getattr(w, "fullscreen", False))
        except Exception:
            pass
        return {"maximized": _win_maximized, "fullscreen": fl}

    def window_minimize(self) -> bool:
        w = self._window()
        if not w:
            return False
        try:
            w.minimize()
            return True
        except Exception:
            return False

    def window_toggle_maximize(self) -> bool:
        global _win_maximized
        w = self._window()
        if not w:
            return False
        try:
            if _win_maximized:
                w.restore()
                _win_maximized = False
            else:
                w.maximize()
                _win_maximized = True
            return True
        except Exception:
            return False

    def window_toggle_fullscreen(self) -> bool:
        w = self._window()
        if not w:
            return False
        try:
            w.toggle_fullscreen()
            return True
        except Exception:
            return False

    def window_close(self) -> None:
        from config import get_store as _get_store

        try:
            zap = _get_store().get("zapret", {}) or {}
            if zap.get("cleanup_on_exit", True):
                from winws import runner
                runner.kill_all()
        except Exception:
            pass
        w = self._window()
        if not w:
            return
        try:
            w.destroy()
        except Exception:
            pass

    def apply_window_effect(self) -> Dict[str, Any]:
        try:
            from ui import window as _win
            return dict(_win.apply_window_effect())
        except Exception:
            return {"ok": False}

    def set_live_glass(self, enabled: bool, sharp: bool = False) -> Dict[str, Any]:
        # Live-glass capture engine is disabled.
        return {"ok": True, "enabled": False, "sharp": False}

    # ─── Wallpaper (background presets: photo / video from local disk) ─────

    def pick_wallpaper(self, kind: str) -> Dict[str, Any]:
        import os

        kind = kind if kind == "video" else "image"
        path = _pick_media_file(kind)
        if not path:
            return {"ok": False, "path": None, "name": None}
        return {"ok": True, "path": os.path.abspath(path), "name": os.path.basename(path)}

    def wallpaper_url(self, path: str) -> Dict[str, Any]:
        import base64
        import os

        if not path:
            return {"ok": False, "url": None}
        try:
            ext = os.path.splitext(path)[1].lower()
            if ext in (".png", ".jpg", ".jpeg", ".webp", ".gif", ".bmp"):
                if os.path.isfile(path) and os.path.getsize(path) <= 8 * 1024 * 1024:
                    mime = {
                        ".png": "image/png",
                        ".jpg": "image/jpeg",
                        ".jpeg": "image/jpeg",
                        ".webp": "image/webp",
                        ".gif": "image/gif",
                        ".bmp": "image/bmp",
                    }.get(ext, "image/jpeg")
                    with open(path, "rb") as fh:
                        payload = base64.b64encode(fh.read()).decode("ascii")
                    return {"ok": True, "url": f"data:{mime};base64,{payload}"}
            from ui import asset_server

            url = asset_server.url_for(path)
            return {"ok": bool(url), "url": url}
        except Exception as exc:
            log.warning("wallpaper_url failed: %s", repr(exc))
            return {"ok": False, "url": None}

    # ─── Updates (check / download / install / rollback) ──────────────────

    _auto_check_started = False

    def _start_auto_check(self) -> None:
        """Фоновую проверку обновлений запускаем один раз при старте UI."""
        if SwiftAPI._auto_check_started:
            return
        SwiftAPI._auto_check_started = True
        cfg = _get_config().get("app", {})
        if not cfg.get("check_updates", True):
            return

        def _run():
            time.sleep(4.0)
            try:
                from utils import update_check
                update_check.run_check(__version__)
            except Exception:
                log.exception("auto update check failed")

        threading.Thread(target=_run, daemon=True, name="swift-update-check").start()

    def get_update_status(self) -> Dict[str, Any]:
        from utils import update_check
        from winws import paths as wp

        updates = get_store().get("updates") or {}
        probe = wp.find_engine()
        st = update_check.get_status()
        st["current"] = _version
        st["app_path"] = __import__("sys").executable
        st["restart_pending"] = self._restart_pending()
        st["source_url"] = str(updates.get("source_url") or "")
        st["last_check"] = updates.get("last_check")
        st["auto_check"] = bool(updates.get("auto_check", False))
        st["engine_files_present"] = any(
            bool(found) for found in (probe.get("found") or {}).values()
        )
        return st

    # ─── Manifest updates (hardened source / integrity) ────────────────

    def set_update_source(self, url: str) -> Dict[str, Any]:
        value = str(url or "").strip()
        if value and not _is_valid_source_url(value):
            return {"ok": False, "error": "invalid_url"}
        get_store().set("updates", "source_url", value)
        return {"ok": True, "source_url": value}

    def set_auto_check(self, enabled: bool) -> Dict[str, Any]:
        get_store().set("updates", "auto_check", bool(enabled))
        return {"ok": True, "auto_check": bool(enabled)}

    def run_updates_check(self) -> Dict[str, Any]:
        global _updates_check_thread

        with _updates_check_lock:
            if _updates_check_state["status"] == "running":
                return {"ok": False, "error": "already_running"}
            _updates_check_state.update({"status": "running", "message": "", "result": None})

        def _worker() -> None:
            try:
                store = get_store()
                source_url = (store.get("updates") or {}).get("source_url", "")
                source_url = (source_url or "").strip()
                if not source_url:
                    with _updates_check_lock:
                        _updates_check_state.update({
                            "status": "done",
                            "message": "",
                            "result": {"source_url": "", "ok": False, "reason": "no_source"},
                        })
                    return
                result = _run_manifest_update(source_url)
                store.set("updates", "last_check", time.strftime("%Y-%m-%dT%H:%M:%S"))
                with _updates_check_lock:
                    _updates_check_state.update({
                        "status": "done",
                        "message": "",
                        "result": {**result, "source_url": source_url},
                    })
            except Exception as exc:
                log.warning("run_updates_check failed", exc_info=True)
                with _updates_check_lock:
                    _updates_check_state.update({"status": "error", "message": str(exc), "result": None})

        _updates_check_thread = threading.Thread(
            target=_worker, daemon=True, name="swift-manifest-update"
        )
        _updates_check_thread.start()
        return {"ok": True, "detail": "started"}

    def get_updates_check_status(self) -> Dict[str, Any]:
        with _updates_check_lock:
            return json.loads(json.dumps(_updates_check_state))

    def engine_fingerprint(self, compute: bool = True) -> Dict[str, Any]:
        from utils.file_integrity import fingerprint_engine

        baseline = self._read_engine_baseline()
        if baseline is None and not compute:
            return {"ok": None, "reason": "no_baseline", "files": [], "changed_files": []}
        current = fingerprint_engine()
        if baseline is None and compute:
            record = {"dir": current["dir"], "files": current["files"]}
            get_store().set("integrity", "engine_baseline", record)
            return {
                "ok": True,
                "created": True,
                "dir": current["dir"],
                "aggregate_hash": current["aggregate_hash"],
                "changed_files": [],
            }
        return _diff_fingerprints(baseline, current)

    def reset_engine_baseline(self) -> Dict[str, Any]:
        get_store().set("integrity", "engine_baseline", None)
        return {"ok": True}

    def _read_engine_baseline(self) -> Optional[dict]:
        integrity = get_store().get("integrity") or {}
        baseline = integrity.get("engine_baseline")
        return baseline if isinstance(baseline, dict) else None

    def check_updates(self, force: bool = False) -> Dict[str, Any]:
        from utils import update_check
        if force:
            try:
                update_check.run_check(_version)
            except Exception as exc:
                return {"ok": False, "error": str(exc), "current": _version}
        st = dict(update_check.get_status())
        st["current"] = _version
        return st

    def get_update_job(self) -> Dict[str, Any]:
        from utils import updater
        return updater.get_job()

    def download_update(self) -> Dict[str, Any]:
        """Скачивает и раскладывает последний релиз (фоновый поток)."""
        from utils import updater

        def _run():
            releases = updater.list_releases(limit=1)
            if not releases:
                updater._set_job(state="error", message="no_releases")
                return
            updater.stage_release_update(releases[0])

        threading.Thread(target=_run, daemon=True, name="swift-update-download").start()
        return {"ok": True, "detail": "started"}

    def rollback_to(self, tag: str) -> Dict[str, Any]:
        """Откат к указанной версии релиза (фоновый поток)."""
        from utils import updater

        def _run():
            release = updater.release_by_tag(tag)
            if release is None:
                updater._set_job(state="error", message=f"release not found: {tag}")
                return
            updater.stage_release_update(release)

        threading.Thread(target=_run, daemon=True, name="swift-update-rollback").start()
        return {"ok": True, "detail": "started"}

    def list_available_versions(self, limit: int = 10) -> list:
        from utils import updater
        return updater.list_releases(limit)

    def restart_pending(self) -> bool:
        return self._restart_pending()

    def _restart_pending(self) -> bool:
        try:
            from utils import updater
            return updater.restart_pending()
        except Exception:
            return False

    def open_downloads_dir(self) -> None:
        from utils import updater
        d = updater._downloads_dir()
        try:
            import os
            if __import__("platform").system() == "Windows":
                os.startfile(str(d))  # noqa: S606
            else:
                import subprocess
                opener = "open" if __import__("platform").system() == "Darwin" else "xdg-open"
                subprocess.Popen([opener, str(d)])
        except Exception as exc:
            log.warning("open_downloads_dir: %s", repr(exc))

    def restart_app(self) -> None:
        """Закрывает окно и перезапускает приложение (после отложенной установки)."""
        import subprocess
        import sys
        try:
            exe = sys.executable
            if getattr(sys, "frozen", False):
                args = [exe]
            else:
                args = [exe, sys.argv[0]] + [a for a in sys.argv[1:] if a != "--headless"]
            subprocess.Popen(args, close_fds=True)
        except Exception as exc:
            log.warning("restart_app: %s", repr(exc))
        self.window_close()

    # ─── Presets (обход) ───────────────────────────────────────────────────

    def _lang(self) -> str:
        try:
            lang = _get_config().get("app", {}).get("language", "auto")
            if lang and lang != "auto" and lang in ("ru", "uk", "en"):
                return lang
            from ui.i18n import detect_system_language
            return detect_system_language().value
        except Exception:
            return "en"

    def get_presets(self) -> List[Dict[str, Any]]:
        from utils.presets import list_presets
        return list_presets(self._lang())

    def get_active_preset(self) -> Optional[str]:
        from utils.presets import detect_active_preset
        return detect_active_preset(_get_config(), self._lang())

    def apply_preset(self, preset_id: str) -> Dict[str, Any]:
        from utils.presets import apply_preset
        return apply_preset(
            preset_id,
            get_store(),
            restart=True,
            on_error=_noop_error,
        )

    def save_user_preset(self, label: str, description: str, changes: List[Dict[str, Any]]) -> Dict[str, Any]:
        from utils.presets import save_user_preset
        return save_user_preset(label or "", description or "", changes or [])

    def delete_user_preset(self, preset_id: str) -> Dict[str, Any]:
        from utils.presets import delete_user_preset
        return delete_user_preset(preset_id or "")

    # ─── Zapret profiles (winws справочник) ───────────────────────────────

    def get_zapret_profiles(self, group: str = "winws2") -> List[Dict[str, Any]]:
        from utils.zapret_profiles import list_profiles
        return list_profiles(group, self._lang())

    def get_zapret_profile_text(self, group: str, file_name: str) -> Dict[str, Any]:
        from utils.zapret_profiles import get_profile_text
        return get_profile_text(group, file_name)

    def get_zapret_strategies(self) -> List[Dict[str, Any]]:
        from utils.zapret_profiles import list_strategies
        return list_strategies()

    # ─── Zapret engine (winws runtime) ────────────────────────────────────

    def get_zapret_engine(self) -> Dict[str, Any]:
        from winws import paths as wp
        from config import get_store as _store

        probe = wp.find_engine()
        cfg = _store().get("zapret") or {}
        return {
            **probe,
            "mode": cfg.get("mode", "auto"),
            "profile_group": cfg.get("profile_group", "winws2"),
            "profile": cfg.get("profile", ""),
            "autostart": bool(cfg.get("autostart", False)),
            "cleanup_on_exit": bool(cfg.get("cleanup_on_exit", True)),
        }

    def set_zapret_settings(self, values: Dict[str, Any]) -> Dict[str, Any]:
        from config import get_store as _store

        allowed = {"mode", "profile_group", "profile", "autostart", "cleanup_on_exit"}
        store = _store()
        clean = {}
        for key in allowed:
            if key in values:
                clean[key] = values[key]
        if clean:
            store.set_section("zapret", clean)
        return {"ok": True, "settings": store.get("zapret") or {}}

    def get_dpi_status(self) -> Dict[str, Any]:
        from winws import runner, paths as wp

        st = runner.status()
        probe = wp.find_engine()
        return {
            "state": st.get("state", "stopped"),
            "pid": st.get("pid"),
            "mode": st.get("mode", ""),
            "label": st.get("label", ""),
            "started_at": st.get("started_at", ""),
            "exit_code": st.get("exit_code"),
            "last_error": st.get("last_error", ""),
            "engine_ok": probe.get("ok", False),
            "engine_dir": probe.get("dir", ""),
            "engines": probe.get("found", {}),
        }

    def start_dpi(self, group: str = "", file_name: str = "") -> Dict[str, Any]:
        from config import get_store as _store
        from winws import paths as wp
        from winws import profiles as pfp
        from winws import runner

        cfg = _store().get("zapret") or {}
        group = (group or cfg.get("profile_group") or "winws2").strip()
        file_name = (file_name or cfg.get("profile")).strip()

        if not file_name:
            try:
                lst = pfp.profile_list() or {}
                rec = (lst.get("recommended") or "").strip()
                if rec:
                    pfp.ensure_recommended()
                    file_name = rec
            except Exception:
                pass

        if not file_name:
            return {"ok": False, "error": "no_profile"}

        res = pfp.resolve_profile(group, file_name)
        if not res.get("ok"):
            return res

        mode = pfp.engine_mode_for(group, cfg.get("mode", "auto"))
        mode = wp.preferred_mode(mode) or (mode if mode in ("winws1", "winws2") else None)
        exe_path = wp.resolve_mode_exe(mode or "auto")
        if not exe_path:
            return {"ok": False, "error": "engine_missing",
                    "detail": "Поместите winws.exe или winws2.exe в папку exe/ рядом с приложением"}

        work_dir = wp.engine_dir()
        result = runner.start(mode=mode or "winws2", exe_path=exe_path, work_dir=str(work_dir),
                              text=res.get("text", ""), label=res.get("file", file_name))

        if result.get("ok"):
            _store().set_section("zapret", {
                "enabled": True,
                "profile_group": group,
                "profile": file_name,
                "mode": mode or "auto",
            })
        return result

    def stop_dpi(self) -> Dict[str, Any]:
        from winws import runner
        result = runner.stop()
        from config import get_store as _store
        _store().set("zapret", "enabled", False)
        return result

    def restart_dpi(self) -> Dict[str, Any]:
        from config import get_store as _store
        cfg = _store().get("zapret") or {}
        return self.start_dpi(group=cfg.get("profile_group", "winws2"), file_name=cfg.get("profile", ""))

    def get_winws_log(self, limit: int = 8000) -> Dict[str, Any]:
        from winws import logs
        return {"ok": True, "log": logs.tail(int(limit))}

    def get_winws_log_status(self) -> Dict[str, Any]:
        from logs.winws_log_analyzer import summarize_log
        from winws.paths import log_path
        try:
            return summarize_log(log_path())
        except Exception as exc:
            log.warning("get_winws_log_status failed: %s", repr(exc))
            return {"ok": False, "error": str(exc), "has_log": False,
                    "sessions_count": 0, "errors": [], "warnings": [], "last_session": None,
                    "verdict": {"has_log": False, "status": "no_log", "reason": "no_log", "detail": "", "lines_total": 0}}

    def read_winws_log_last(self, lines: int = 200) -> Dict[str, Any]:
        from winws import logs
        try:
            text = logs.tail(limit_chars=200_000)
            rows = (text or "").splitlines()
            count = max(1, int(lines))
            return {"ok": True, "lines": rows[-count:]}
        except Exception as exc:
            return {"ok": False, "lines": [], "error": str(exc)}

    # ─── WinDivert / winws health (Health subsystem) ──────────────────

    def get_windivert_health(self) -> Dict[str, Any]:
        from winws.health.diagnostics import get_windivert_health as _run
        try:
            return _run()
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def run_winws_diagnostics(self) -> Dict[str, Any]:
        from winws.health.diagnostics import run_winws_diagnostics as _run
        try:
            return _run()
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def windivert_cleanup(self, level: str = "standard") -> Dict[str, Any]:
        from winws.health.diagnostics import windivert_cleanup as _run
        try:
            return _run(level or "standard")
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def kill_conflicting_processes(self) -> Dict[str, Any]:
        from winws.health.diagnostics import kill_conflicting_processes as _run
        try:
            return _run()
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def get_winws_health(self) -> Dict[str, Any]:
        from winws.health.diagnostics import get_winws_health as _run
        try:
            return _run()
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ─── Diagnostics & Windows tools (Phase 3) ─────────────────────

    def run_diagnostics(self) -> Dict[str, Any]:
        from tools import run_diagnostics as _run
        proxy = self.get_proxy_status()
        from winws import runner
        try:
            dpi = runner.status()
        except Exception:
            dpi = {}
        return _run(
            proxy_running=bool(proxy.get("running")),
            proxy_port=proxy.get("port", 1443),
            dpi_status=dpi,
        )

    def get_windows_tool_status(self) -> Dict[str, Any]:
        from tools.windows_tools import get_windows_tool_status
        return get_windows_tool_status()

    def windows_cleanup(self) -> Dict[str, Any]:
        from tools.windows_tools import windows_cleanup
        return windows_cleanup()

    def defender_exclude(self, path: str = "") -> Dict[str, Any]:
        from tools.windows_tools import defender_exclude
        return defender_exclude(path)

    def get_zapret_user_profiles(self) -> List[Dict[str, Any]]:
        from winws import profiles as pfp
        pfp.ensure_recommended()
        return pfp.list_user_profiles()

    def get_zapret_user_profile(self, name: str) -> Dict[str, Any]:
        from winws.profiles import get_user_profile_text
        return get_user_profile_text(name or "")

    def save_zapret_user_profile(self, name: str, text: str) -> Dict[str, Any]:
        from winws.profiles import save_user_profile
        return save_user_profile(name or "", text or "")

    def delete_zapret_user_profile(self, name: str) -> Dict[str, Any]:
        from winws import profiles as pfp
        return pfp.delete_user_profile(name or "")

    # ─── Zapret profile engine (профильный редактор) ───────────────────

    def profile_list(self) -> Dict[str, Any]:
        from winws import profiles as pfp
        return pfp.profile_list()

    def profile_read(self, name: str) -> Dict[str, Any]:
        from winws import profiles as pfp
        return pfp.profile_read(name or "")

    def profile_write(self, name: str, content: str) -> Dict[str, Any]:
        from winws import profiles as pfp
        return pfp.profile_write(name or "", content or "")

    def profile_reset(self, name: str) -> Dict[str, Any]:
        from winws import profiles as pfp
        return pfp.profile_reset(name or "")

    def profile_delete(self, name: str) -> Dict[str, Any]:
        from winws import profiles as pfp
        return pfp.profile_delete(name or "")

    def profile_validate_paste(self, content: str) -> Dict[str, Any]:
        from winws import profiles as pfp
        return pfp.validate_profile(content or "")

    # ─── BlockCheck (Проверка сайтов) ────────────────────────────────────

    def get_blockcheck_presets(self) -> Dict[str, Any]:
        from blockcheck.data_lists import HTTPS_TARGETS
        from blockcheck.service import CONTROL_HOSTS
        from blockcheck.targets import load_user_domains
        return {
            "control_hosts": list(CONTROL_HOSTS),
            "user_domains": load_user_domains(),
            "default_targets": [dict(target) for target in HTTPS_TARGETS],
        }

    def start_blockcheck(self, domain: str) -> Dict[str, Any]:
        global _blockcheck_thread
        from blockcheck.hosts import host_of
        from blockcheck.service import run_single_domain_check

        name = host_of(str(domain or "").strip())
        if not name:
            return {"ok": False, "error": "empty domain"}

        with _blockcheck_lock:
            if _blockcheck_state["status"] == "running":
                return {"ok": False, "error": "already running"}
            _blockcheck_state.update(
                {"status": "running", "message": "", "lines": [], "report": None}
            )
            _blockcheck_cancel.clear()

        def _worker() -> None:
            lines: List[str] = []

            def _log(message: str) -> None:
                lines.append(str(message))
                if len(lines) > 500:
                    del lines[:50]
                with _blockcheck_lock:
                    _blockcheck_state["lines"] = list(lines)

            def _is_cancelled() -> bool:
                return _blockcheck_cancel.is_set()

            try:
                report = run_single_domain_check(
                    name,
                    log=_log,
                    is_cancelled=_is_cancelled,
                    deadline_seconds=90.0,
                )
                payload = _to_plain(report)
                with _blockcheck_lock:
                    _blockcheck_state["status"] = "cancelled" if report.cancelled else "done"
                    _blockcheck_state["message"] = "Отменено" if report.cancelled else "Готово"
                    _blockcheck_state["report"] = payload
                    _blockcheck_state["lines"] = lines
            except Exception as exc:  # noqa: BLE001 — вернём ошибку наверх
                log.warning("blockcheck run failed", exc_info=True)
                with _blockcheck_lock:
                    _blockcheck_state["status"] = "error"
                    _blockcheck_state["message"] = str(exc)
                    _blockcheck_state["lines"] = lines

        _blockcheck_thread = threading.Thread(
            target=_worker, args=(), daemon=True, name="blockcheck"
        )
        _blockcheck_thread.start()
        return {"ok": True, "domain": name}

    def get_blockcheck_status(self) -> Dict[str, Any]:
        with _blockcheck_lock:
            return json.loads(json.dumps(_blockcheck_state))

    def stop_blockcheck(self) -> Dict[str, Any]:
        _blockcheck_cancel.set()
        return {"ok": True}

    def add_blockcheck_domain(self, domain: str) -> Dict[str, Any]:
        from blockcheck.targets import add_user_domain
        try:
            added = add_user_domain(domain)
            return {"ok": added, "added": added, "message": "" if added else "duplicate"}
        except Exception as exc:
            return {"ok": False, "added": False, "message": str(exc)}

    def remove_blockcheck_domain(self, domain: str) -> Dict[str, Any]:
        from blockcheck.targets import remove_user_domain
        try:
            removed = remove_user_domain(domain)
            return {"ok": removed, "removed": removed, "message": "" if removed else "not found"}
        except Exception as exc:
            return {"ok": False, "removed": False, "message": str(exc)}

    # ─── Orchestra (Авто-выбор стратегии) ────────────────────────────────

    def list_strategies(self) -> Dict[str, Any]:
        from blockcheck.orchestra import available_strategies
        return {"ok": True, "strategies": available_strategies()}

    def orchestra_recommend(self, symptoms_text: str = "") -> Dict[str, Any]:
        from blockcheck.orchestra import orchestra_recommend
        with _blockcheck_lock:
            report = _blockcheck_state.get("report")
        try:
            return orchestra_recommend(symptoms_text=symptoms_text or "", report=report)
        except Exception as exc:
            log.warning("orchestra recommend failed", exc_info=True)
            return {"ok": False, "error": "recommend_failed", "detail": str(exc)}

    def apply_strategy(
        self, strategy_id: str, profile_name: str = "", section_name: str = ""
    ) -> Dict[str, Any]:
        from blockcheck.orchestra import (
            apply_strategy_to_profile,
            backup_profile,
            find_strategy_by_id,
        )
        from winws import profiles as pfp
        from winws import runner as wrunner

        strategy = find_strategy_by_id(str(strategy_id or "").strip())
        if strategy is None:
            return {"ok": False, "error": "unknown_strategy"}

        name = str(profile_name or "").strip()
        active = pfp.get_active_profile()
        if not name:
            if active.get("group") in ("winws1", "winws2"):
                return {"ok": False, "error": "active_is_builtin"}
            name = active.get("profile") or ""
        if not name:
            return {"ok": False, "error": "profile_not_found"}

        read = pfp.profile_read(name)
        if not read.get("ok"):
            return {"ok": False, "error": read.get("error", "profile_not_found")}

        applied = apply_strategy_to_profile(
            read["content"], strategy, section_name=section_name or None
        )
        if not applied.get("ok"):
            out = {"ok": False, "error": applied.get("error", "no_change")}
            if "plan" in applied:
                out["plan"] = applied["plan"]
            return out

        backup = backup_profile(name)
        written = pfp.profile_write(name, applied["content"])
        if not written.get("ok"):
            return {"ok": False, "error": written.get("error", "write_failed")}

        is_active = (
            bool(active.get("enabled"))
            and (active.get("profile") or "").lower() == name.lower()
        )
        return {
            "ok": True,
            "strategy": strategy["id"],
            "profile": name,
            "was_recommended": read.get("is_recommended", False),
            "needs_restart_notice": bool(wrunner.is_running()) and is_active,
            "diff": applied["diff"],
            "n_removed": applied["n_removed"],
            "n_added": applied["n_added"],
            "mode": applied.get("mode"),
            "round_robin": applied.get("round_robin"),
            "section_name": applied.get("section_name", ""),
            "validation": written["validation"],
            "backup": backup.get("file", "") if backup.get("ok") else "",
        }

    # ─── Orchestra LEARNING (авто-закрепление стратегий) ─────────────

    def get_orchestra_status(self) -> Dict[str, Any]:
        from winws import runner

        with _orchestra_lock:
            auto = bool(_orchestra_state.get("auto_learning"))
            started_at = _orchestra_state.get("started_at")
            message = _orchestra_state.get("message", "")
        running = runner.status().get("state") == "running"

        if auto and running:
            state = "learning"
        elif running:
            state = "running"
        elif auto:
            state = "idle"
        else:
            state = "unlocked"

        return {
            "state": state,
            "auto_learning": auto,
            "started_at": started_at,
            "message": message,
            "running": running,
        }

    def start_orchestra_learning(self) -> Dict[str, Any]:
        """Запускает LEARNING winws с круговым профилем и включает авто-закрепление."""
        from config import get_store as _store
        from utils.zapret_profiles import list_profiles
        from winws import paths as wp
        from winws import profiles as pfp
        from winws import runner

        cfg = _store().get("zapret") or {}
        group = (cfg.get("profile_group") or "winws2").strip()

        profiles = list_profiles(group, self._lang())
        circular = next((p for p in profiles if "circular" in (p.get("tags") or [])), None)
        if circular is None:
            return {"ok": False, "error": "circular_not_found",
                    "detail": f"Круговой профиль не найден в группе {group}."}
        file_name = circular["file"]

        res = pfp.resolve_profile(group, file_name)
        if not res.get("ok"):
            return res

        mode = pfp.engine_mode_for(group, cfg.get("mode", "auto"))
        mode = wp.preferred_mode(mode) or (mode if mode in ("winws1", "winws2") else None)
        exe_path = wp.resolve_mode_exe(mode or "auto")
        if not exe_path:
            return {"ok": False, "error": "engine_missing",
                    "detail": "Поместите winws.exe или winws2.exe в папку exe/ рядом с приложением"}

        work_dir = wp.engine_dir()
        result = runner.start(mode=mode or "winws2", exe_path=exe_path, work_dir=str(work_dir),
                              text=res.get("text", ""), label=res.get("file", file_name))
        if not result.get("ok"):
            return result

        with _orchestra_lock:
            _orchestra_state["auto_learning"] = True
            _orchestra_state["started_at"] = result.get("started_at") or datetime.now().isoformat(timespec="seconds")
            _orchestra_state["message"] = ""

        _store().set_section("zapret", {
            "enabled": True,
            "profile_group": group,
            "profile": file_name,
            "mode": mode or "auto",
        })
        return {"ok": True, "detail": "learning_started", "profile": file_name, "mode": mode or "auto"}

    def stop_orchestra_learning(self) -> Dict[str, Any]:
        from winws import runner

        result = runner.stop()
        with _orchestra_lock:
            was_auto = bool(_orchestra_state.get("auto_learning"))
            _orchestra_state["auto_learning"] = False
            _orchestra_state["started_at"] = None
            _orchestra_state["message"] = ""
        from config import get_store as _store
        _store().set("zapret", "enabled", False)
        return {"ok": result.get("ok", True), "was_learning": was_auto}

    def clear_orchestra_learning(self) -> Dict[str, Any]:
        """Сбрасывает накопленные закрепления стратегий (SLM-таблицы)."""
        from pathlib import Path
        from winws.paths import log_path

        try:
            lua_dir = Path(log_path()).parent.parent / "lua"
            removed: List[str] = []
            for name in ("strategy-lock-manager.lua", "learned-strategies.lua"):
                for target in (lua_dir / ("user_" + name), lua_dir / "user" / name):
                    if target.is_file():
                        target.write_text("", encoding="utf-8")
                        removed.append(target.name)
            with _orchestra_lock:
                _orchestra_state["message"] = "cleared"
            return {"ok": True, "removed": removed}
        except Exception as exc:
            log.warning("clear_orchestra_learning failed: %s", repr(exc))
            return {"ok": False, "error": str(exc)}

    def list_locked_strategies(self) -> Dict[str, Any]:
        """Извлекает закрепления из winws-лога (slm_set_locked / circular_quality)."""
        import re
        from winws import logs

        try:
            text = logs.tail(limit_chars=200_000)
        except Exception as exc:
            return {"ok": False, "locked": [], "error": str(exc)}

        locked: List[Dict[str, str]] = []
        seen = set()
        pat_set = re.compile(
            r"slm_set_locked:\s*\[([^\]]*)\]\s*(\S+)\s*->\s*strat=(\d+)\s+reason=(.+)"
        )
        pat_lock = re.compile(
            r"circular_quality:\s*LOCKED\s*strat\s+(\d+).*?\sfor\s+(\S+)"
        )
        for m in pat_set.finditer(text or ""):
            key = (m.group(3), m.group(2))
            if key in seen:
                continue
            seen.add(key)
            locked.append({
                "strategy": m.group(3),
                "host": m.group(2),
                "askey": m.group(1),
                "reason": m.group(4).strip(),
            })
        for m in pat_lock.finditer(text or ""):
            key = ("quality", m.group(2))
            if key in seen:
                continue
            seen.add(key)
            locked.append({
                "strategy": m.group(1),
                "host": m.group(2),
                "askey": "quality",
                "reason": "auto",
            })
        locked.sort(key=lambda r: r["host"].lower())
        return {"ok": True, "locked": locked}

    # ─── Autopilot (авто-pilot «Обход Zapret») ───────────────────────────

    def auto_status(self) -> Dict[str, Any]:
        """Текущее состояние автопилота (фаза, прогресс, стратегия, журнал)."""
        from blockcheck import autopilot
        return autopilot.status()

    def auto_start(self) -> Dict[str, Any]:
        """Запускает автопилот: сканирование -> стратегия -> профиль -> winws."""
        from blockcheck import autopilot
        return autopilot.start()

    def auto_stop(self) -> Dict[str, Any]:
        """Останавливает автопилот и гасит запущенный им winws."""
        from blockcheck import autopilot
        return autopilot.stop()

    def auto_reset(self) -> Dict[str, Any]:
        """Сбрасывает состояние автопилота в idle."""
        from blockcheck import autopilot
        return autopilot.reset()

    def auto_journal(self, limit: int = 250) -> Dict[str, Any]:
        """Журнал событий автопилота (для вкладки «Журнал»)."""
        from blockcheck import autopilot
        return autopilot.journal(limit)

    # ─── Lists (каталог списков / hostlists из ZapretGUI) ─────────────────

    def get_lists_status(self) -> Dict[str, Any]:
        from pathlib import Path
        from lists.core.paths import get_list_final_path, get_list_user_path
        from lists.hostlists_manager import _read_effective_entries
        user = Path(get_list_user_path("other"))
        final = Path(get_list_final_path("other"))
        return {
            "user_path": str(user),
            "user_exists": user.is_file(),
            "user_text": user.read_text(encoding="utf-8") if user.is_file() else "",
            "user_count": len(_read_effective_entries(str(user))),
            "final_count": len(_read_effective_entries(str(final))),
        }

    def save_user_list(self, text: str) -> Dict[str, Any]:
        from lists.hostlists_manager import rebuild_other_files, OTHER_USER_PATH
        try:
            from pathlib import Path
            p = Path(OTHER_USER_PATH)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text((text or ""), encoding="utf-8")
            rebuilt = rebuild_other_files()
            return {"ok": True, "rebuilt": bool(rebuilt)}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # ─── Logs ──────────────────────────────────────────────────────────────

    def get_log_tail(self, limit: int = 400) -> str:
        from config.paths import log_file
        try:
            log_path = log_file()
            if not log_path.is_file():
                return ""
            size = log_path.stat().st_size
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                if size > 200_000:
                    f.seek(size - 200_000)
                    return f.read()[-200_000:]
                return f.read()
        except OSError:
            return ""

    def report_ui_error(self, source: str = "ui", message: str = "") -> Dict[str, Any]:
        try:
            log.error("[ui:%s] %s", str(source or "ui")[:64], str(message or "")[:2000])
            return {"ok": True}
        except Exception:
            return {"ok": False}

    def open_devtools(self) -> Dict[str, Any]:
        """Enable and open WebView2 DevTools on demand (Shift+F1)."""
        try:
            import webview
            wins = getattr(webview, "windows", None) or []
            if not wins:
                return {"ok": False, "error": "no_window"}
            native = getattr(wins[0], "native", None)
            browser = getattr(native, "browser", None)
            control = getattr(browser, "webview", None)
            if control is None:
                return {"ok": False, "error": "no_control"}

            def _do():
                core = getattr(control, "CoreWebView2", None)
                if core is None:
                    return
                core.Settings.AreDevToolsEnabled = True
                core.OpenDevToolsWindow()

            try:
                from System import Action
                control.Invoke(Action(_do))
            except Exception:
                _do()
            return {"ok": True}
        except Exception as exc:
            log.error("[ui:devtools] %s", exc)
            return {"ok": False, "error": str(exc)}

    def open_logs_dir(self) -> bool:
        from config.paths import log_file
        try:
            import os
            from platform import system
            path = str(log_file().parent)
            if system() == "Windows":
                os.startfile(path)
            elif system() == "Darwin":
                os.system(f"open '{path}'")
            else:
                os.system(f"xdg-open '{path}'")
            return True
        except Exception:
            return False

    def get_lan_ip(self) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except OSError:
            return "127.0.0.1"
        finally:
            s.close()

    def _ensure_extension_dir(self) -> Optional[str]:
        from config.paths import app_dir, resources_dir
        try:
            target = app_dir() / "browser-ext"
            src = resources_dir() / "extension"
            files = ("manifest.json", "background.js", "popup.html", "popup.js", "options.html", "options.js")
            if (src / "manifest.json").is_file():
                target.mkdir(parents=True, exist_ok=True)
                for name in files:
                    (target / name).write_bytes((src / name).read_bytes())
            return str(target) if (target / "manifest.json").is_file() else None
        except Exception:
            return None

    def get_browser_ext_info(self) -> Dict[str, Any]:
        path = self._ensure_extension_dir()
        cfg = _get_config().get("telegram", {})
        return {
            "path": path,
            "host": "127.0.0.1",
            "port": int(cfg.get("port", 1353)),
            "installed": bool(path),
        }

    def open_browser(self, browser: str) -> Dict[str, Any]:
        import os
        import subprocess
        browser = browser.lower().strip()
        if browser not in ("chrome", "edge"):
            return {"ok": False, "error": f"unknown browser: {browser}"}
        exe = None
        pf = os.environ.get("PROGRAMFILES", "C:\\Program Files")
        pf86 = os.environ.get("PROGRAMFILES(X86)", "C:\\Program Files (x86)")
        laf = os.environ.get("LOCALAPPDATA", "")
        if browser == "chrome":
            for cand in (os.path.join(pf, "Google\\Chrome\\Application\\chrome.exe"),
                         os.path.join(pf86, "Google\\Chrome\\Application\\chrome.exe"),
                         os.path.join(laf, "Google\\Chrome\\Application\\chrome.exe")):
                if os.path.isfile(cand):
                    exe = cand
                    break
        else:
            for cand in (os.path.join(pf86, "Microsoft\\Edge\\Application\\msedge.exe"),
                         os.path.join(pf, "Microsoft\\Edge\\Application\\msedge.exe"),
                         os.path.join(laf, "Microsoft\\Edge\\Application\\msedge.exe")):
                if os.path.isfile(cand):
                    exe = cand
                    break
        if not exe:
            return {"ok": False, "error": f"{browser} not found"}
        path = self._ensure_extension_dir()
        if not path:
            return {"ok": False, "error": "extension files missing"}
        try:
            subprocess.Popen([exe, f"--load-extension={path}"])
            return {"ok": True}
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def get_public_ip(self) -> str:
        import urllib.request
        endpoints = [
            "https://api.ipify.org",
            "https://icanhazip.com",
            "https://ifconfig.me/ip",
            "https://checkip.amazonaws.com",
        ]
        for url in endpoints:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "swift-proxy/1.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    ip = resp.read(256).decode("utf-8", "replace").strip()
                if ip and not ip.startswith("127."):
                    return ip
            except Exception:
                continue
        return ""

    def get_upnp_status(self) -> bool:
        from utils.upnp import is_supported
        try:
            return bool(is_supported())
        except Exception:
            return False

    def upnp_map(self, ports) -> Dict[str, Any]:
        from utils.upnp import add_port_mapping
        results, ok_all = [], True
        for port in ports or []:
            r = add_port_mapping(int(port))
            results.append({"port": int(port), "ok": bool(r.get("ok")), "reason": r.get("reason")})
            ok_all = ok_all and bool(r.get("ok"))
        return {"ok": ok_all, "entries": results}

    def upnp_unmap(self, ports) -> Dict[str, Any]:
        from utils.upnp import delete_port_mapping
        results, ok_all = [], True
        for port in ports or []:
            r = delete_port_mapping(int(port))
            results.append({"port": int(port), "ok": bool(r.get("ok")), "reason": r.get("reason")})
            ok_all = ok_all and bool(r.get("ok"))
        return {"ok": ok_all, "entries": results}

    # ─── Autostart ──────────────────────────────────────────────────────

    def get_autostart_status(self) -> Dict[str, Any]:
        from autostart import get_autostart_status
        try:
            return get_autostart_status()
        except Exception as exc:
            log.warning("get_autostart_status failed: %s", repr(exc))
            return {"ok": False, "error": str(exc)}

    def autostart_install(self, method: str = "task", scope: str = "app") -> Dict[str, Any]:
        from autostart import install
        try:
            return install(method=method, scope=scope)
        except Exception as exc:
            log.warning("autostart_install failed: %s", repr(exc))
            return {"ok": False, "error": str(exc)}

    def autostart_remove(self, method: str = "task", scope: str = "app") -> Dict[str, Any]:
        from autostart import remove
        try:
            return remove(method=method, scope=scope)
        except Exception as exc:
            log.warning("autostart_remove failed: %s", repr(exc))
            return {"ok": False, "error": str(exc)}

    def autostart_start_service(self, scope: str = "app") -> Dict[str, Any]:
        from autostart import start_service
        try:
            return start_service(scope=scope)
        except Exception as exc:
            log.warning("autostart_start_service failed: %s", repr(exc))
            return {"ok": False, "error": str(exc)}

    def autostart_stop_service(self, scope: str = "app") -> Dict[str, Any]:
        from autostart import stop_service
        try:
            return stop_service(scope=scope)
        except Exception as exc:
            log.warning("autostart_stop_service failed: %s", repr(exc))
            return {"ok": False, "error": str(exc)}


def _noop_error(text: str, title: Optional[str] = None) -> None:
    log.error("Proxy error: %s", text)


def _running_thread():
    """Return the current active 'swift-proxy' Thread object, if any."""
    for t in threading.enumerate():
        if t.name == "proxy" and t.is_alive():
            return t
    return None