"""
SwiftProxy — unified cross-platform desktop app entry point.

Starts:
1. unified settings store (config/)
2. optional proxies on startup
3. pywebview UI + system tray

Usage:
    python main.py            — GUI mode
    python main.py --headless — proxy engines only (no UI, no tray)
    python main.py --port 1443 --host 127.0.0.1
"""
from __future__ import annotations

import argparse
import logging
import sys
import threading
from typing import Optional


def _parse_args(argv: Optional[list] = None):
    parser = argparse.ArgumentParser(prog="swiftproxy")
    parser.add_argument("--headless", action="store_true",
                        help="Run proxy engines only (no UI / no tray)")
    parser.add_argument("--cli", action="store_true",
                        help="Run the command-line interface (see --cli --help)")
    parser.add_argument("--portable", action="store_true",
                        help="Keep config next to the executable")
    parser.add_argument("--port", type=int, default=None,
                        help="MTProto proxy port override")
    parser.add_argument("--host", default=None,
                        help="MTProto proxy bind host override")
    parser.add_argument("--no-tray", action="store_true",
                        help="Disable the system tray icon")
    parser.add_argument("--tray", action="store_true",
                        help="Explicitly enable the system tray icon (default)")
    parser.add_argument("--autostart-winws", action="store_true",
                        help="Also start the winws DPI engine (used with --headless)")
    parser.add_argument("--no-elevate", action="store_true",
                        help="Skip the UAC self-elevation at startup (winws may not start)")
    return parser.parse_args(argv)


def setup_logging() -> None:
    from config.paths import log_file
    from utils.logging_setup import build_log_handler

    log_file().parent.mkdir(parents=True, exist_ok=True)
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    handler = build_log_handler(str(log_file()), log_max_mb=5, backups=1)
    formatter = logging.Formatter(
        "%(asctime)s  %(levelname)-5s  %(name)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)
    handler.addFilter(_CensorFilter())
    root.addHandler(handler)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(asctime)s  %(levelname)-5s  %(name)s  %(message)s", datefmt="%H:%M:%S"))
    root.addHandler(console)


class _CensorFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        return True


def start_proxies_from_config() -> None:
    """Start MTProto and/or Telegram proxies if enabled in settings."""
    from config import get_store
    from utils.tray_common import start_proxy, stop_proxy

    cfg = get_store().snapshot()

    if cfg.get("app", {}).get("run_proxy_on_startup", True):
        try:
            start_proxy(cfg.get("proxy", {}), _noop_error)
        except Exception:
            logging.getLogger("swift-main").exception("Failed to auto-start MTProto proxy")

    tg = cfg.get("telegram", {})
    if tg.get("enabled", False):
        try:
            from ui.api import SwiftAPI
            api = SwiftAPI()
            api.start_tg_proxy()
        except Exception:
            logging.getLogger("swift-main").exception("Failed to auto-start Telegram proxy")

    zap = cfg.get("zapret", {})
    if zap.get("autostart", False):
        try:
            from ui.api import SwiftAPI
            res = SwiftAPI().start_dpi()
            if not res.get("ok"):
                logging.getLogger("swift-main").warning(
                    "winws autostart failed: %s", res.get("error", "?"))
        except Exception:
            logging.getLogger("swift-main").exception("Failed to auto-start winws DPI")


def _noop_error(text: str, title: Optional[str] = None) -> None:
    logging.getLogger("swift-main").error("Proxy error: %s", text)


def run_gui(args) -> None:
    from config import get_store

    get_store().load()
    start_proxies_from_config()
    sync_system_proxy_from_config()

    from ui.window import start_app
    start_app(title="SwiftProxy", tray=not args.no_tray)


def sync_system_proxy_from_config() -> None:
    """Re-apply the saved system proxy flag at every launch (best-effort)."""
    from config import get_store
    cfg = get_store().snapshot()
    if cfg.get("app", {}).get("system_proxy"):
        try:
            from ui.api import SwiftAPI
            SwiftAPI().set_system_proxy(True)
        except Exception:
            logging.getLogger("swift-main").exception("Failed to apply system proxy")


def run_headless(args) -> None:
    from config import get_store

    get_store().load()

    if getattr(args, "autostart_winws", False) or (get_store().snapshot().get("zapret") or {}).get("autostart", False):
        try:
            from ui.api import SwiftAPI
            res = SwiftAPI().start_dpi()
            if not res.get("ok"):
                logging.getLogger("swift-main").warning(
                    "winws autostart failed: %s", res.get("error", "?"))
        except Exception:
            logging.getLogger("swift-main").exception("Failed to auto-start winws DPI")

    from utils.tray_common import start_proxy, stop_proxy
    import time

    cfg = get_store().snapshot().get("proxy", {})
    start_proxy(cfg, _noop_error)
    logging.getLogger("swift-main").info("Headless mode: MTProto proxy on %s:%s", cfg.get("host"), cfg.get("port"))
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_proxy()


def apply_pending_restart() -> None:
    """Swap a staged update executable (.new) at the next launch, best-effort."""
    try:
        from utils import updater
        res = updater.apply_pending_restart()
        if res.get("ok"):
            logging.getLogger("swift-main").info("Applied staged update: %s", res.get("path"))
    except Exception:
        pass


def _set_dpi_aware() -> None:
    """Enable per-monitor DPI awareness so screen capture spans all monitors."""
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
        return
    except Exception:
        pass
    try:
        import ctypes
        ctypes.windll.user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))
    except Exception:
        pass


def main(argv: Optional[list] = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)

    _set_dpi_aware()

    if "--cli" in argv:
        from utils import updater
        try:
            updater.apply_pending_restart()
        except Exception:
            pass
        li = argv.index("--cli")
        from cli import main as cli_main
        sys.exit(cli_main(argv[li + 1:]))

    args = _parse_args(argv)
    setup_logging()
    apply_pending_restart()

    # Автоматическая self-elevation: winws (WinDivert) требует прав администратора.
    # Если процесса ещё не админ — перезапускаемся через UAC и выходим.
    # Отклонённый UAC не критичен: приложение продолжит работать без админа.
    if not args.no_elevate:
        from tools.windows_tools import ensure_elevated
        state = ensure_elevated(["--no-elevate", *argv])
        if state == "started":
            logging.getLogger("swift-main").info("Relaunching elevated via UAC")
            return
        if state in ("cancel", "no"):
            logging.getLogger("swift-main").warning(
                "Автоэлевация невозможна (%s): winws (WinDivert) может не запуститься", state)

    if args.port is not None:
        from config import get_store
        get_store().load().set("proxy", "port", args.port)
    if args.host is not None:
        from config import get_store
        get_store().load().set("proxy", "host", args.host)

    single = None
    try:
        from utils.tray_common import acquire_lock, release_lock
        single = acquire_lock()
        if single is False:
            logging.getLogger("swift-main").info("Another SwiftProxy instance is already running")
            return
    except Exception:
        single = None

    try:
        if args.headless:
            run_headless(args)
        else:
            run_gui(args)
    finally:
        try:
            from utils.tray_common import release_lock
            if single:
                release_lock()
        except Exception:
            pass


if __name__ == "__main__":
    main()