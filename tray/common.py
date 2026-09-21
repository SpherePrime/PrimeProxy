"""
Cross-platform system tray for SwiftProxy (pystray-based).

One entry point on all OSes:
- Windows: anonymous tray icon (Win32)
- macOS:   accessory NSApplication icon
- Linux:   AppIndicator / libappindicator

Left click (default item) → offer to connect Telegram through the proxy.
Right-click menu → enable/disable proxy, switch MTProto/SOCKS5, open window,
copy link, logs, exit.
"""
from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

log = logging.getLogger("swift-tray")

_icon = None
_icon_thread: Optional[threading.Thread] = None
_APP = None
_pil_image = None


def _load_icon():
    global _pil_image
    if _pil_image is not None:
        return _pil_image
    try:
        from utils.icon import render_icon
        _pil_image = render_icon(64)
    except Exception:
        from PIL import Image, ImageDraw
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.ellipse((4, 4, 60, 60), fill=(0, 122, 255, 255))
        _pil_image = img
    return _pil_image


def _build_menu(callbacks: dict):
    import pystray
    from ui.i18n import t

    cb = callbacks or {}
    state = (cb.get("get_state") or (lambda: {}))() or {}
    host = state.get("host", "127.0.0.1")
    port = int(state.get("port", 1443))
    running = bool(state.get("running"))
    mode = state.get("mode", "mt")

    items = []
    if cb.get("connect"):
        items.append(pystray.MenuItem(
            t("tray.open_telegram").format(host=host, port=port),
            cb["connect"],
            default=True,
        ))
    if cb.get("toggle"):
        items.append(pystray.MenuItem(
            t("tray.stop_proxy") if running else t("tray.start_proxy"),
            cb["toggle"],
            checked=lambda item: running,
        ))
    if cb.get("set_mode"):
        mode_items = [
            pystray.MenuItem(
                "MTProto",
                (lambda m="mt": cb["set_mode"](m)),
                checked=lambda item, m="mt": mode == m,
            ),
            pystray.MenuItem(
                "SOCKS5",
                (lambda m="socks5": cb["set_mode"](m)),
                checked=lambda item, m="socks5": mode == m,
            ),
        ]
        items.append(pystray.MenuItem(t("tray.mode"), pystray.Menu(*mode_items)))
    items.append(pystray.Menu.SEPARATOR)
    if cb.get("settings"):
        items.append(pystray.MenuItem(t("tray.settings"), cb["settings"]))
    if cb.get("copy"):
        items.append(pystray.MenuItem(t("tray.copy_link"), cb["copy"]))
    if cb.get("logs"):
        items.append(pystray.MenuItem(t("tray.logs"), cb["logs"]))
    items.append(pystray.Menu.SEPARATOR)
    if cb.get("exit"):
        items.append(pystray.MenuItem(t("tray.exit"), cb["exit"]))
    return pystray.Menu(*items)


def start_tray(
    title: str,
    callbacks: dict,
    host: str = "127.0.0.1",
    port: int = 1443,
) -> bool:
    """Start the tray icon in a daemon thread. Returns True if started."""
    global _icon, _icon_thread
    try:
        import pystray
    except ImportError:
        return False
    try:
        that = _load_icon()
    except Exception:
        that = None
    if that is None:
        return False

    # macOS: keep an accessory NSApplication so the app doesn't appear in dock.
    try:
        from AppKit import NSApplication, NSApplicationActivationPolicyAccessory
        ns_app = NSApplication.sharedApplication()
        ns_app.setActivationPolicy_(NSApplicationActivationPolicyAccessory)
        global _APP
        _APP = ns_app
        icon_kwargs = {"darwin_nsapplication": ns_app}
    except Exception:
        icon_kwargs = {}

    base_state = {"host": host, "port": port, "running": False, "mode": "mt"}
    get_state = callbacks.get("get_state") or (lambda: base_state)
    callbacks["get_state"] = get_state

    _icon = pystray.Icon(
        "SwiftProxy",
        that,
        title,
        menu=_build_menu(callbacks),
        **icon_kwargs,
    )
    _icon_thread = threading.Thread(target=_icon.run, daemon=True, name="swift-tray")
    _icon_thread.start()
    return True


def refresh_menu(callbacks: dict) -> None:
    """Rebuild the tray menu after config / proxy state changes."""
    if _icon is None:
        return
    try:
        _icon.menu = _build_menu(callbacks)
    except Exception as exc:
        log.warning("Failed to refresh tray menu: %s", repr(exc))


def stop_tray() -> None:
    global _icon, _icon_thread
    if _icon is not None:
        try:
            _icon.stop()
        except Exception:
            pass
        _icon = None
    if _icon_thread is not None:
        _icon_thread = None


__all__ = ["refresh_menu", "start_tray", "stop_tray"]