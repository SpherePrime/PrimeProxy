"""
pywebview window management for the PrimeProxy UI.

Launches a native window with HTML/CSS/JS frontend and a Python API bridge.
Supports window + tray mode on all platforms.
"""
from __future__ import annotations

import logging
import os
import sys
import threading
from typing import Optional

log = logging.getLogger("swift-ui")

_app_path = os.path.dirname(os.path.abspath(__file__))
_web_path = os.path.join(_app_path, "web")

_dark_css = os.path.join(_web_path, "theme", "dark.css")
_light_css = os.path.join(_web_path, "theme", "light.css")


def _entry_html() -> str:
    return os.path.join(_web_path, "index.html")


def _find_window_handle(title: str = "PrimeProxy"):
    try:
        import ctypes
        hwnd = ctypes.windll.user32.FindWindowW(None, title)
        return hwnd or None
    except Exception:
        return None


def _set_dwm_blur(hwnd, enabled: bool) -> bool:
    try:
        import ctypes

        class _BlurBehind(ctypes.Structure):
            _fields_ = [
                ("dwFlags", ctypes.c_uint),
                ("fEnable", ctypes.c_bool),
                ("hRgnBlur", ctypes.c_void_p),
                ("fTransitionOnMaximized", ctypes.c_bool),
            ]

        bb = _BlurBehind(0x1, bool(enabled), None, False)
        res = ctypes.windll.dwmapi.DwmEnableBlurBehindWindow(hwnd, ctypes.byref(bb))
        return res == 0
    except Exception:
        return False


def _ensure_layered(hwnd) -> bool:
    try:
        import ctypes
        u = ctypes.windll.user32
        ex = u.GetWindowLongW(hwnd, -20)
        if not (ex & 0x80000):
            u.SetWindowLongW(hwnd, -20, ex | 0x80000)
            u.SetWindowPos(hwnd, None, 0, 0, 0, 0, 0x27)
        return True
    except Exception:
        return False


def _set_dwm_backdrop(hwnd, kind: int) -> bool:
    """Set the DWM system backdrop type (Windows 11 22H2+).

    kind=2 -> DWMSBT_TRANSIENTWINDOW (Desktop Acrylic): DWM live-blurs the
    desktop behind the window. kind=0 -> none. Real-time, all monitors,
    no screen capture, no window hiding.
    """
    try:
        import ctypes
        value = ctypes.c_int(int(kind))
        res = ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 38, ctypes.byref(value), ctypes.sizeof(value)
        )
        return res == 0
    except Exception:
        return False


def _set_window_alpha(hwnd, alpha: int) -> bool:
    try:
        import ctypes
        alpha = max(1, min(255, int(alpha)))
        res = ctypes.windll.user32.SetLayeredWindowAttributes(hwnd, 0, alpha, 0x2)
        return bool(res)
    except Exception:
        return False


def apply_window_effect() -> dict:
    """Compatibility no-op: window effects are disabled.

    The window is a normal opaque window. Only CSS-level card transparency
    (rgba panels) remains — no DWM acrylic, no window alpha, no capture.
    """
    try:
        from config.store import get_store
        ap = get_store().get("appearance") or {}
        blur = ap.get("blur_enabled", True) is not False
    except Exception:
        blur = True
    hwnd = _find_window_handle()
    if not hwnd:
        return {"ok": False, "error": "no_window"}
    _set_dwm_backdrop(hwnd, 0)
    _set_dwm_blur(hwnd, False)
    return {"ok": True, "opacity": 1.0, "backdrop": False, "blur": bool(blur)}


def create_window(
    url: Optional[str] = None,
    width: int = 960,
    height: int = 680,
    title: str = "PrimeProxy",
    js_api=None,
    transparent: bool = False,
):
    """Create and return a pywebview window object (or raise if pywebview missing)."""
    import webview

    if url is None:
        url = _entry_html()

    window = webview.create_window(
        title,
        url=url,
        width=width,
        height=height,
        min_size=(720, 560),
        resizable=True,
        frameless=True,
        easy_drag=False,
        transparent=False,
        shadow=False,
        background_color="#1a1a2e",
        js_api=js_api,
    )
    return window


def _get_tray_icon():
    """Return a PIL Image for the tray icon (or None)."""
    try:
        from PIL import Image, ImageDraw
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        # Simple gradient circle
        for r in range(32, 0, -1):
            c = int(255 * (r / 32))
            draw.ellipse(
                [32 - r, 32 - r, 32 + r, 32 + r],
                fill=(0, 122, 255, c),
            )
        return img
    except Exception:
        return None


def start_app(
    title: str = "PrimeProxy",
    width: int = 960,
    height: int = 680,
    api=None,
    tray: bool = True,
):
    """Full app lifecycle: start pywebview (blocking)."""
    import webview

    if api is None:
        from ui.api import SwiftAPI
        api = SwiftAPI()

    window = create_window(
        width=width,
        height=height,
        title=title,
        js_api=api,
    )

    def _apply_native_backdrop(*_args):
        try:
            apply_window_effect()
        except Exception:
            pass

    try:
        ev = getattr(window, "events", None)
        if ev is not None:
            # Window effects are disabled: normal opaque window, CSS-level
            # card transparency only. apply_window_effect stays a no-op hook
            # for API compatibility.
            for name, handler in [
                ("loaded", _apply_native_backdrop),
                ("shown", _apply_native_backdrop),
            ]:
                ev_name = getattr(ev, name, None)
                if ev_name is not None:
                    try:
                        ev_name += handler
                    except Exception:
                        pass
    except Exception as exc:
        log.warning("window event hooks failed: %s", repr(exc))

    if tray:
        _start_tray(window, api, title)

    log.info("Starting PrimeProxy UI (pywebview)...")
    try:
        webview.settings["OPEN_DEVTOOLS_IN_DEBUG"] = False
    except Exception:
        pass
    try:
        webview.start(debug=False)
    finally:
        pass
    try:
        from config import get_store as _get_store
        zap = _get_store().get("zapret", {}) or {}
        if zap.get("cleanup_on_exit", True):
            from winws import runner
            runner.kill_all()
    except Exception:
        pass
    log.info("UI exited")


def _start_tray(window, api, title: str) -> None:
    """Start a background tray icon (non-blocking)."""
    from tray import start_tray, refresh_menu

    # Sync the Python-side UI locale with the saved language for tray labels.
    try:
        from config.store import get_store
        from ui import i18n as pyi18n
        lang = get_store().get("app", "language", "auto") or "auto"
        if lang == "auto":
            lang = pyi18n.detect_system_language().value
        pyi18n.set_language(lang)
    except Exception:
        pass

    def _tray_state() -> dict:
        mode = "socks5"
        try:
            mode = get_store().get("app", "proxy_mode", "mt") or "mt"
        except Exception:
            pass
        status = {}
        try:
            status = api.get_proxy_status() or {}
        except Exception:
            pass
        tg = {}
        try:
            tg = api.get_tg_proxy_status() or {}
        except Exception:
            pass
        running = bool(status.get("running")) if mode != "socks5" else bool(tg.get("running"))
        host = status.get("host", "127.0.0.1")
        port = status.get("port", 1443)
        if mode == "socks5":
            host = tg.get("host", host)
            port = tg.get("port", 1353)
        return {"host": host, "port": port, "running": running, "mode": mode}

    def _on_connect(icon, item):
        """Left click / default action → offer to connect Telegram via proxy."""
        try:
            state = _tray_state()
            if state["mode"] == "socks5":
                api.copy_text(f"{state['host']}:{state['port']}")
                log.info("SOCKS5 mode: copied %s:%s to clipboard", state["host"], state["port"])
                return
            import webbrowser
            webbrowser.open(api.get_tray_proxy_link())
        except Exception:
            pass

    def _on_toggle(icon, item):
        try:
            st = _tray_state()
            if st["running"]:
                api.stop_proxy() if st["mode"] != "socks5" else api.stop_tg_proxy()
            else:
                api.start_proxy() if st["mode"] != "socks5" else api.start_tg_proxy()
            refresh_menu(_cb)
        except Exception:
            pass

    def _on_set_mode(mode):
        try:
            get_store().set("app", "proxy_mode", mode)
            refresh_menu(_cb)
        except Exception:
            pass

    def _on_open_window(icon, item):
        try:
            window.show()
            window.restore()
        except Exception:
            pass

    def _on_exit(icon, item):
        try:
            from config import get_store
            zap = get_store().get("zapret", {}) or {}
            if zap.get("cleanup_on_exit", True):
                from winws import runner
                runner.kill_all()
        except Exception:
            pass
        try:
            window.destroy()
        except Exception:
            pass

    def _on_copy(icon, item):
        try:
            api.copy_proxy_link()
        except Exception:
            pass

    _cb = {
        "connect": _on_connect,
        "toggle": _on_toggle,
        "set_mode": _on_set_mode,
        "settings": _on_open_window,
        "copy": _on_copy,
        "logs": _on_open_window,
        "exit": _on_exit,
        "get_state": _tray_state,
    }

    start_tray(title, _cb)