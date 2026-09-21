# cli.py
"""Command-line interface for SwiftProxy (headless / Docker).

Применение:
    swift-proxy --cli status [--json]
    swift-proxy --cli start [--port N] [--host H]
    swift-proxy --cli stop
    swift-proxy --cli restart
    swift-proxy --cli server [--json]            # foreground (Docker)
    swift-proxy --cli config list
    swift-proxy --cli config get <proxy.port>
    swift-proxy --cli config set <proxy.port> 20001
    swift-proxy --cli link
    swift-proxy --cli dns list
    swift-proxy --cli dns check <id|all>
    swift-proxy --cli dns flush
    swift-proxy --cli hosts list
    swift-proxy --cli hosts apply <id> [id...] [--no-adobe]
    swift-proxy --cli hosts clear
    swift-proxy --cli presets list
    swift-proxy --cli presets apply <id> [--no-restart]
    swift-proxy --cli lists status
    swift-proxy --cli update check [--force]
    swift-proxy --cli update download
    swift-proxy --cli update list
    swift-proxy --cli update rollback <tag>
    swift-proxy --cli update apply-pending
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import socket
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

from config import __version__, get_store

log = logging.getLogger("swift-cli")

PID_FILE_NAME = ".swiftproxy-cli.pid"


def _pid_file() -> "object":
    from utils.tray_common import APP_DIR
    from pathlib import Path
    p = Path(APP_DIR)
    p.mkdir(parents=True, exist_ok=True)
    return p / PID_FILE_NAME


def _emit(data: Any, as_json: bool = False) -> None:
    if as_json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    else:
        if isinstance(data, dict):
            for k, v in data.items():
                print(f"{k}: {v}")
        elif isinstance(data, list):
            for it in data:
                if isinstance(it, dict):
                    print(json.dumps(it, ensure_ascii=False))
                else:
                    print(it)
        else:
            print(data)


def _store() -> "object":
    return get_store()


# ── status / proxy ─────────────────────────────────────────────────────────

def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=1.0):
            return True
    except OSError:
        return False


def cmd_status(args) -> Dict[str, Any]:
    cfg = _store().snapshot()
    pc = cfg.get("proxy", {})
    tg = cfg.get("telegram", {})
    mt_host = pc.get("host", "127.0.0.1")
    mt_port = int(pc.get("port", 1443))
    tg_host = tg.get("bind_host", "127.0.0.1")
    tg_port = int(tg.get("port", 1353))
    pid = None
    if _pid_file().exists():
        try:
            pid = int(_pid_file().read_text().strip())
        except ValueError:
            pid = None
    return {
        "version": __version__,
        "mtproto": {
            "running": _port_open(mt_host, mt_port),
            "host": mt_host,
            "port": mt_port,
            "autostart": cfg.get("app", {}).get("run_proxy_on_startup", True),
        },
        "telegram": {
            "enabled": tg.get("enabled", False),
            "running": _port_open(tg_host, tg_port) if tg.get("enabled", False) else False,
            "host": tg_host,
            "port": tg_port,
        },
        "pid": pid,
    }


def cmd_link(args) -> Dict[str, Any]:
    cfg = _store().snapshot().get("proxy", {})
    host = cfg.get("host", "127.0.0.1")
    port = cfg.get("port", 1443)
    secret = cfg.get("secret", "")
    from proxy.utils import get_link_host
    link = f"tg://proxy?server={get_link_host(host)}&port={port}&secret=dd{secret}"
    return {"link": link, "host": host, "port": port, "secret": secret}


def _spawn_headless(args) -> int:
    from utils.tray_common import APP_DIR
    base = [sys.executable]
    if not getattr(sys, "frozen", False):
        base.append(sys.argv[0])
    base.append("--headless")
    # A background MTProto daemon must not pop a UAC dialog on the user's
    # screen. Elevation is only required for the optional winws (WinDivert)
    # engine, which is separately started when actually needed.
    base.append("--no-elevate")
    if args.port:
        base += ["--port", str(args.port)]
    if args.host:
        base += ["--host", args.host]
    if getattr(args, "portable", False):
        base.append("--portable")
    creation = 0
    if sys.platform == "win32":
        creation = subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "DETACHED_PROCESS", 0)
    proc = subprocess.Popen(
        base,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        close_fds=True,
        creationflags=creation,
    )
    _pid_file().write_text(str(proc.pid))
    return proc.pid


def _stop_pid() -> bool:
    if not _pid_file().exists():
        return False
    try:
        pid = int(_pid_file().read_text().strip())
    except ValueError:
        return False
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"],
                           capture_output=True, timeout=15)
        else:
            os.kill(pid, signal.SIGTERM)
        for _ in range(20):
            if not _port_open("127.0.0.1", 1):
                pass
            if not _alive(pid):
                break
            time.sleep(0.25)
        try:
            _pid_file().unlink()
        except OSError:
            pass
        return True
    except Exception as exc:
        log.warning("stop failed: %s", repr(exc))
        return False


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def cmd_start(args) -> Dict[str, Any]:
    st = cmd_status(args)
    if st["mtproto"]["running"]:
        return {"ok": True, "detail": "already_running", "pid": st["pid"]}
    pid = _spawn_headless(args)
    for _ in range(30):
        if _port_open(st["mtproto"]["host"], st["mtproto"]["port"]) or not _alive(pid):
            break
        time.sleep(0.3)
    return {"ok": _port_open(st["mtproto"]["host"], st["mtproto"]["port"]),
            "pid": pid, "host": st["mtproto"]["host"], "port": st["mtproto"]["port"]}


def cmd_stop(args) -> Dict[str, Any]:
    stopped = _stop_pid()
    return {"ok": stopped, "detail": "stopped" if stopped else "no_pid"}


def cmd_restart(args) -> Dict[str, Any]:
    _stop_pid()
    time.sleep(0.6)
    pid = _spawn_headless(args)
    return {"ok": True, "pid": pid}


def cmd_server(args) -> Dict[str, Any]:
    """Foreground long-running mode (Docker entrypoint)."""
    from config import get_store
    from utils.tray_common import start_proxy, stop_proxy

    store = get_store()
    cfg = store.snapshot()
    if args.port is not None:
        store.set("proxy", "port", args.port)
        cfg = store.snapshot()

    def _err(text: str, title: Optional[str] = None) -> None:
        log.error("proxy error: %s", text)

    if cfg.get("app", {}).get("run_proxy_on_startup", True):
        start_proxy(cfg.get("proxy", {}), _err)

    tg = cfg.get("telegram", {})
    if tg.get("enabled", False) and args.tg:
        from ui.api import SwiftAPI
        SwiftAPI().start_tg_proxy()

    print(f"swiftproxy v{__version__} serving  (pid {os.getpid()})", flush=True)
    print(f"MTProto: {cfg.get('proxy', {}).get('host')}:{cfg.get('proxy', {}).get('port')}", flush=True)
    if args.json:
        import json as _j
        print(_j.dumps(cmd_status(args), ensure_ascii=False), flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_proxy()
    return {"ok": True}


# ── config ─────────────────────────────────────────────────────────────────

def cmd_config_get(args) -> Dict[str, Any]:
    store = _store()
    section, _, key = args.key.partition(".")
    val = store.get(section, key) if key else store.get(section)
    return {"key": args.key, "value": val}


def _coerce(value: str):
    v = value.strip()
    low = v.lower()
    if low in ("true", "false"):
        return low == "true"
    if low in ("null", "none"):
        return None
    if v.startswith("[") or v.startswith("{"):
        return json.loads(v)
    try:
        return int(v)
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return v


def cmd_config_set(args) -> Dict[str, Any]:
    store = _store()
    section, _, key = args.key.partition(".")
    val = _coerce(args.value)
    store.set(section, key, val)
    return {"key": args.key, "value": val, "saved": True}


def cmd_config_list(args) -> Dict[str, Any]:
    return _store().snapshot()


# ── DNS / hosts ────────────────────────────────────────────────────────────

def cmd_dns_list(args) -> List[Dict[str, Any]]:
    from dns import get_provider_list
    return get_provider_list()


def cmd_dns_check(args) -> Dict[str, Any]:
    from dns import get_provider_list, run_provider_tests
    provs = get_provider_list()
    if args.provider == "all":
        out = {}
        for p in provs:
            try:
                out[p["id"]] = run_provider_tests(p["id"])
            except Exception as exc:
                out[p["id"]] = {"ok": False, "error": str(exc)}
        return out
    return run_provider_tests(args.provider)


def cmd_dns_flush(args) -> Dict[str, Any]:
    from dns import flush_dns_cache
    return {"result": flush_dns_cache()}


def cmd_hosts_list(args) -> Dict[str, Any]:
    from hosts import services_snapshot, read_active_domains_map
    return {"services": services_snapshot(), "active_domains": read_active_domains_map()}


def cmd_hosts_apply(args) -> Dict[str, Any]:
    from hosts import apply_host_entries, merge_service_domains
    ids = args.ids or []
    merged = merge_service_domains(ids, not args.no_adobe)
    ok, count = apply_host_entries(merged)
    return {"ok": ok, "count": count, "services": ids}


def cmd_hosts_clear(args) -> Dict[str, Any]:
    from hosts import clear_host_entries
    ok, removed = clear_host_entries()
    return {"ok": ok, "removed": removed}


# ── presets / lists / clients ──────────────────────────────────────────────

def cmd_presets_list(args) -> List[Dict[str, Any]]:
    from utils.presets import list_presets, detect_active_preset
    out = list_presets(args.lang)
    active = detect_active_preset(_store().snapshot(), args.lang)
    for p in out:
        p["active"] = (p["id"] == active)
    return out


def cmd_presets_apply(args) -> Dict[str, Any]:
    from utils.presets import apply_preset
    return apply_preset(args.preset_id, _store(), restart=not args.no_restart)


def cmd_lists_status(args) -> Dict[str, Any]:
    from pathlib import Path
    from lists.core.paths import get_list_final_path, get_list_user_path
    from lists.hostlists_manager import _read_effective_entries
    user = Path(get_list_user_path("other"))
    final = Path(get_list_final_path("other"))
    return {
        "user_path": str(user),
        "user_exists": user.is_file(),
        "user_count": len(_read_effective_entries(str(user))),
        "final_count": len(_read_effective_entries(str(final))),
    }


# ── updates ────────────────────────────────────────────────────────────────

def cmd_update_check(args) -> Dict[str, Any]:
    from utils import update_check
    update_check.run_check(__version__)
    st = update_check.get_status()
    st["current"] = __version__
    return st


def cmd_update_download(args) -> Dict[str, Any]:
    from utils import updater
    releases = updater.list_releases(limit=1)
    if not releases:
        return {"ok": False, "error": "no releases"}
    res = updater.stage_release_update(releases[0])
    return res


def cmd_update_rollback(args) -> Dict[str, Any]:
    from utils import updater
    release = updater.release_by_tag(args.tag)
    if not release:
        return {"ok": False, "error": f"release not found: {args.tag}"}
    return updater.stage_release_update(release)


def cmd_update_list(args) -> List[Dict[str, Any]]:
    from utils import updater
    return updater.list_releases(args.limit)


def cmd_update_apply_pending(args) -> Dict[str, Any]:
    from utils import updater
    return updater.apply_pending_restart()


# ── argument parsing ───────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="swift-proxy --cli")
    sub = parser.add_subparsers(dest="command")

    def add_common(p):
        p.add_argument("--json", action="store_true", help="JSON output")
        p.add_argument("--lang", default=None, help="language for localized output (ru/uk/en)")

    add_common(parser)

    def _make(name, **kw):
        p = sub.add_parser(name, **kw)
        add_common(p)
        return p

    def _nested(parent, name, help=None, **kw):
        if not hasattr(parent, "_subp"):
            parent._subp = parent.add_subparsers(dest="op")
        p = parent._subp.add_parser(name, help=help, **kw)
        add_common(p)
        return p

    p_status = _make("status", help="proxy status")
    p_status.set_defaults(fn=cmd_status)

    p_link = _make("link", help="print proxy link")
    p_link.set_defaults(fn=cmd_link)

    p_start = _make("start", help="start proxy as background daemon")
    p_start.add_argument("--port", type=int, default=None)
    p_start.add_argument("--host", default=None)
    p_start.add_argument("--portable", action="store_true")
    p_start.set_defaults(fn=cmd_start)

    p_stop = _make("stop", help="stop background daemon")
    p_stop.set_defaults(fn=cmd_stop)

    p_restart = _make("restart", help="restart background daemon")
    p_restart.add_argument("--port", type=int, default=None)
    p_restart.add_argument("--host", default=None)
    p_restart.add_argument("--portable", action="store_true")
    p_restart.set_defaults(fn=cmd_restart)

    p_server = _make("server", help="foreground server (Docker entrypoint)")
    p_server.add_argument("--port", type=int, default=None)
    p_server.add_argument("--tg", action="store_true", help="also start Telegram WSS proxy if enabled")
    p_server.set_defaults(fn=cmd_server)

    p_config = _make("config")
    _nested(p_config, "list").set_defaults(fn=cmd_config_list)
    c2 = _nested(p_config, "get")
    c2.add_argument("key")
    c2.set_defaults(fn=cmd_config_get)
    c3 = _nested(p_config, "set")
    c3.add_argument("key")
    c3.add_argument("value")
    c3.set_defaults(fn=cmd_config_set)

    p_dns = _make("dns")
    _nested(p_dns, "list").set_defaults(fn=cmd_dns_list)
    d2 = _nested(p_dns, "check")
    d2.add_argument("provider")
    d2.set_defaults(fn=cmd_dns_check)
    _nested(p_dns, "flush").set_defaults(fn=cmd_dns_flush)

    p_hosts = _make("hosts")
    _nested(p_hosts, "list").set_defaults(fn=cmd_hosts_list)
    h2 = _nested(p_hosts, "apply")
    h2.add_argument("ids", nargs="+")
    h2.add_argument("--no-adobe", action="store_true")
    h2.set_defaults(fn=cmd_hosts_apply)
    _nested(p_hosts, "clear").set_defaults(fn=cmd_hosts_clear)

    p_pr = _make("presets")
    _nested(p_pr, "list").set_defaults(fn=cmd_presets_list)
    pr2 = _nested(p_pr, "apply")
    pr2.add_argument("preset_id")
    pr2.add_argument("--no-restart", action="store_true")
    pr2.set_defaults(fn=cmd_presets_apply)

    p_lists = _make("lists")
    sub_lists = p_lists.add_subparsers(dest="op", required=False)
    sl = sub_lists.add_parser("list")
    add_common(sl)
    sl.set_defaults(fn=cmd_lists_status)
    p_lists.set_defaults(fn=cmd_lists_status)

    p_up = _make("update")
    u1 = _nested(p_up, "check")
    u1.add_argument("--force", action="store_true")
    u1.set_defaults(fn=cmd_update_check)
    _nested(p_up, "download").set_defaults(fn=cmd_update_download)
    u3 = _nested(p_up, "rollback")
    u3.add_argument("tag")
    u3.set_defaults(fn=cmd_update_rollback)
    u4 = _nested(p_up, "list")
    u4.add_argument("--limit", type=int, default=10)
    u4.set_defaults(fn=cmd_update_list)
    _nested(p_up, "apply-pending").set_defaults(fn=cmd_update_apply_pending)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    from config import get_store

    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:
            pass

    get_store().load()
    parser = _build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "lang", None) is None:
        args.lang = "ru"

    if not getattr(args, "command", None) and not getattr(args, "op", None):
        parser.print_help()
        return 0

    fn = getattr(args, "fn", None)
    if fn is None:
        parser.print_help()
        return 0

    try:
        result = fn(args)
    except KeyboardInterrupt:
        return 0
    except Exception as exc:
        _emit({"ok": False, "error": str(exc)}, as_json=args.json)
        return 1
    _emit(result, as_json=args.json)
    return 0


if __name__ == "__main__":
    sys.exit(main())