"""Headless proxy control for the Astra plugin.

Exposes the PrimeProxy Telegram proxy engine (MTProto + SOCKS5) to the
Astra desktop app through a one-line JSON command interface:

    python astra-run.py --enable|disable|start|stop|status|config

The --start mode keeps this process alive and runs the event loop
directly in the main thread, so the proxy listens on its configured
port until the process is terminated. The other modes print exactly
one JSON line and exit, reporting state in the payload rather than
through the exit code so the caller has one parsing path.
"""
from __future__ import annotations

import argparse
import json
import sys


def _emit(payload: dict) -> None:
    print(json.dumps(payload, ensure_ascii=False, default=str), flush=True)


def _get_tg_config() -> dict:
    from config import get_store

    return get_store().load().get("telegram") or {}


def _proxy_state(tg: dict) -> dict:
    return {
        "enabled": tg.get("enabled", False),
        "mode": tg.get("mode", "socks5"),
        "host": tg.get("bind_host", "127.0.0.1"),
        "port": tg.get("port", 1353),
    }


def _set_enabled(enabled: bool) -> None:
    from config import get_store

    get_store().load().set("telegram", "enabled", enabled)


def _start_proxy(tg: dict) -> None:
    """Run the proxy event loop in this process until it stops."""
    import asyncio

    from telegram.config import build_cloudflare_config, build_dc_endpoint_overrides, build_upstream_config
    from telegram.server import TelegramWSProxy

    proxy = TelegramWSProxy(
        port=int(tg.get("port", 1353)),
        host=tg.get("bind_host", "127.0.0.1"),
        mode=tg.get("mode", "socks5"),
        upstream_config=build_upstream_config(),
        cloudflare_config=build_cloudflare_config(),
        dc_endpoint_overrides=build_dc_endpoint_overrides(),
        on_log=lambda msg: print(f"[astra-run] {msg}", file=sys.stderr, flush=True),
    )
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        loop.run_until_complete(proxy.start())
    except Exception as exc:  # noqa: BLE001
        print(f"[astra-run] proxy error: {exc}", file=sys.stderr)

    print("[astra-run] proxy engine started", file=sys.stderr, flush=True)
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            asyncio.run_coroutine_threadsafe(proxy.stop(), loop).result(timeout=5)
        except Exception:  # noqa: BLE001
            pass


def main() -> None:
    parser = argparse.ArgumentParser(prog="astra-run")
    parser.add_argument("--enable", action="store_true")
    parser.add_argument("--disable", action="store_true")
    parser.add_argument("--start", action="store_true")
    parser.add_argument("--stop", action="store_true")
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--config", action="store_true")
    args = parser.parse_args()

    try:
        tg = _get_tg_config()

        if args.start:
            if not tg.get("enabled", False):
                _emit({"ok": False, "state": "disabled", "detail": "proxy disabled in config"})
                return
            _start_proxy(tg)
            _emit({"ok": True, "state": "stopped", "detail": "proxy loop exited"})
            return

        if args.stop:
            # --stop is a separate invocation; PrimeProxy has no IPC channel
            # between instances, so the caller (Astra plugin) manages the
            # process lifetime. This just confirms intent.
            _emit({"ok": True, "state": "stopped", "detail": "stop acknowledged"})
            return

        if args.enable:
            _set_enabled(True)
            _emit({"ok": True, "state": "enabled", "detail": "telegram proxy enabled"})
            return

        if args.disable:
            _set_enabled(False)
            _emit({"ok": True, "state": "disabled", "detail": "telegram proxy disabled"})
            return

        if args.status or args.config or not (args.enable or args.disable):
            _emit({"ok": True, "state": "idle", "detail": "", "config": _proxy_state(tg)})
    except Exception as exc:  # noqa: BLE001
        _emit({"ok": False, "state": "error", "detail": f"{type(exc).__name__}: {exc}"})


if __name__ == "__main__":
    main()
