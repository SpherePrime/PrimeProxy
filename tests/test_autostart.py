import os
import sys

import pytest

from autostart import (
    build_entry_for,
    default_entries,
    get_autostart_status,
    install,
    is_admin,
    remove,
    start_service,
    stop_service,
)
from autostart import scheduled_task_api, service_api


class _R:
    def __init__(self, returncode, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


# ─── entries ───────────────────────────────────────────────────────────


def test_build_entry_app():
    e = build_entry_for("app")
    assert e.name == "SwiftProxy Autostart"
    assert "--no-tray" in e.args
    assert e.run_level == "highest"


def test_build_entry_winws():
    e = build_entry_for("winws")
    assert e.name == "SwiftProxy winws"
    assert "--headless" in e.args
    assert "--autostart-winws" in e.args


def test_default_entries_pair():
    app, winws = default_entries()
    assert app.args and winws.args
    assert app.name != winws.name


def test_build_entry_unknown_scope():
    with pytest.raises(ValueError):
        build_entry_for("bogus")


# ─── is_admin ──────────────────────────────────────────────────────────


def test_is_admin_not_windows(monkeypatch):
    monkeypatch.setattr(os, "name", "posix")
    assert is_admin() is False


# ─── install / remove dispatch ─────────────────────────────────────────


def test_install_switches_providers(monkeypatch):
    removed = []
    calls = {}

    def fake_install(method, entry):
        calls[method] = True
        return {"ok": True}

    def fake_remove(method, entry):
        removed.append(method)
        return {"ok": True}

    monkeypatch.setattr(service_api, "install_service", fake_install)
    monkeypatch.setattr(service_api, "remove_service", fake_remove)
    res = install("task", "app")
    assert res["ok"] is True
    assert calls == {"task": True}
    assert removed == ["nssm", "shortcut"]


def test_install_failure_keeps_other_providers(monkeypatch):
    removed = []

    def fake_install(method, entry):
        return {"ok": False, "error": "nssm_missing"}

    def fake_remove(method, entry):
        removed.append(method)
        return {"ok": True}

    monkeypatch.setattr(service_api, "install_service", fake_install)
    monkeypatch.setattr(service_api, "remove_service", fake_remove)
    res = install("nssm", "app")
    assert res["ok"] is False
    assert res["error"] == "nssm_missing"
    assert removed == []


def test_install_unknown_method(monkeypatch):
    monkeypatch.setattr(service_api, "install_service", lambda m, e: {"ok": True})
    res = install("bogus", "app")
    assert res["ok"] is False
    assert res["error"] == "unknown_method"


def test_install_unknown_scope(monkeypatch):
    monkeypatch.setattr(service_api, "install_service", lambda m, e: {"ok": True})
    res = install("task", "bogus")
    assert res["ok"] is False
    assert res["error"] == "unknown_scope"


def test_remove_dispatch(monkeypatch):
    monkeypatch.setattr(service_api, "remove_service", lambda m, e: {"ok": True})
    res = remove("nssm", "winws")
    assert res["ok"] is True


def test_start_stop_service_dispatch(monkeypatch):
    monkeypatch.setattr(service_api, "start_service", lambda m, e: {"ok": True})
    monkeypatch.setattr(service_api, "stop_service", lambda m, e: {"ok": True})
    assert start_service("app")["ok"] is True
    assert stop_service("app")["ok"] is True


def test_start_stop_service_bad_scope(monkeypatch):
    monkeypatch.setattr(service_api, "start_service", lambda m, e: {"ok": True})
    assert start_service("bogus")["error"] == "unknown_scope"


# ─── get_autostart_status ──────────────────────────────────────────────


def test_status_shape(monkeypatch):
    import autostart.nssm_service as ns

    monkeypatch.setattr(ns, "nssm_present", lambda: True)

    def fake_path():
        return "C:\\nssm.exe"

    def fake_exists(name):
        return True

    def fake_run(args):
        return _R(0, stdout=b"SERVICE_RUNNING")

    monkeypatch.setattr(ns, "get_nssm_path", fake_path)
    monkeypatch.setattr(ns, "service_exists", fake_exists)
    monkeypatch.setattr(ns, "_run_nssm", fake_run)
    monkeypatch.setattr(
        scheduled_task_api, "get_task_info", lambda **kw: None)
    from autostart import startup_shortcut_api
    monkeypatch.setattr(
        startup_shortcut_api, "get_startup_shortcut_info", lambda **kw: None)

    st = get_autostart_status()
    assert set(st) >= {"unsupported", "platform", "is_admin", "nssm", "task", "shortcut"}
    assert st["task"]["app"]["installed"] is False
    assert st["nssm"]["app"]["installed"] is True
    assert st["nssm"]["app"]["running"] is True


def test_status_unsupported_platform(monkeypatch):
    monkeypatch.setattr(os, "name", "posix")
    monkeypatch.setattr(sys, "platform", "linux")
    st = get_autostart_status()
    assert st["unsupported"] is True
    for key in ("nssm", "task", "shortcut"):
        assert st[key]["present"] is False
        assert st[key]["app"]["installed"] is False


def test_status_nssm_missing(monkeypatch):
    import autostart.nssm_service as ns

    monkeypatch.setattr(ns, "nssm_present", lambda: False)
    monkeypatch.setattr(ns, "get_nssm_path", lambda: None)
    from autostart import startup_shortcut_api
    monkeypatch.setattr(
        startup_shortcut_api, "get_startup_shortcut_info", lambda **kw: None)
    monkeypatch.setattr(scheduled_task_api, "get_task_info", lambda **kw: None)
    st = get_autostart_status()
    assert st["nssm"]["present"] is False
    app_st = st["nssm"]["app"]
    assert app_st["installed"] is False
    assert app_st["running"] is None


# ─── scheduled task ────────────────────────────────────────────────────


def test_task_create_ok(monkeypatch):
    monkeypatch.setattr(
        scheduled_task_api, "_current_user_id", lambda: "TESTPC\\user")
    monkeypatch.setattr(
        scheduled_task_api, "_run_schtasks", lambda args: _R(0))
    e = build_entry_for("app")
    assert scheduled_task_api.create_or_update_autostart_task(e, task_name="X") is True
    assert scheduled_task_api.autostart_task_exists(task_name="X") is False


def test_task_create_fails(monkeypatch):
    monkeypatch.setattr(
        scheduled_task_api, "_current_user_id", lambda: "TESTPC\\user")
    monkeypatch.setattr(
        scheduled_task_api, "_run_schtasks", lambda args: _R(1, stderr=b"Access is denied"))
    e = build_entry_for("app")
    assert scheduled_task_api.create_or_update_autostart_task(e, task_name="X") is False


def test_task_exists_parses_xml(monkeypatch):
    xml = ('<?xml version="1.0" encoding="UTF-16"?>'
           "<Task><Actions><Exec><Command>C:\\p.exe</Command>"
           "<Arguments>--flag</Arguments></Exec></Actions></Task>")
    monkeypatch.setattr(
        scheduled_task_api, "_run_schtasks", lambda args: _R(0, stdout=xml.encode("utf-16")))
    assert scheduled_task_api.autostart_task_exists(task_name="X") is True
    info = scheduled_task_api.get_task_info(task_name="X")
    assert info["command"] == "C:\\p.exe"
    assert info["arguments"] == "--flag"


def test_task_not_exists(monkeypatch):
    monkeypatch.setattr(
        scheduled_task_api, "_run_schtasks", lambda args: _R(1, stderr=b"not found"))
    assert scheduled_task_api.autostart_task_exists(task_name="X") is False


def test_task_delete(monkeypatch):
    monkeypatch.setattr(
        scheduled_task_api, "_run_schtasks", lambda args: _R(0))
    assert scheduled_task_api.delete_autostart_task(task_name="X") is True


def test_task_xml_escapes_special_chars(monkeypatch):
    monkeypatch.setattr(
        scheduled_task_api, "_current_user_id", lambda: "PC&<>\\user")
    xml = scheduled_task_api._build_autostart_task_xml(build_entry_for("app"), "PC&<>\\user")
    decoded = xml.decode("utf-16", "surrogatepass")
    assert "&amp;" in decoded
    assert "&lt;" in decoded
    assert "<UserId>PC&amp;&lt;&gt;\\user</UserId>" in decoded
    assert "<Command>" in decoded


# ─── startup shortcut ──────────────────────────────────────────────────


def test_shortcut_create_via_powershell(monkeypatch, tmp_path):
    from autostart import startup_shortcut_api as ssa

    monkeypatch.setattr(os, "name", "nt")
    target = tmp_path / "SwiftProxy Autostart.lnk"
    monkeypatch.setattr(ssa, "_run_powershell", lambda script: 0)
    res = ssa.create_startup_shortcut(
        build_entry_for("app"), shortcut_path=str(target))
    assert res["ok"] is True
    assert res["path"] == str(target.resolve())


def test_shortcut_create_not_windows(monkeypatch):
    from autostart import startup_shortcut_api as ssa

    monkeypatch.setattr(os, "name", "posix")
    res = ssa.create_startup_shortcut(build_entry_for("app"))
    assert res["ok"] is False
    assert res["error"] == "not_windows"


def test_shortcut_info_and_delete(monkeypatch, tmp_path):
    from autostart import startup_shortcut_api as ssa

    monkeypatch.setattr(ssa, "get_user_startup_dir", lambda: str(tmp_path))
    target = tmp_path / "X.lnk"
    target.write_text("dummy")
    info = ssa.get_startup_shortcut_info(shortcut_path=str(target))
    assert info and info["exists"] is True
    assert ssa.delete_startup_shortcut(shortcut_path=str(target)) is True
    assert not target.exists()


def test_shortcut_delete_missing_ok(tmp_path):
    from autostart import startup_shortcut_api as ssa

    assert ssa.delete_startup_shortcut(shortcut_path=str(tmp_path / "none.lnk")) is True


# ─── nssm provider ─────────────────────────────────────────────────────


def test_nssm_missing_result(monkeypatch):
    import autostart.nssm_service as ns

    monkeypatch.setattr(ns, "get_nssm_path", lambda: None)
    assert ns.create_service_with_nssm(build_entry_for("app"))["error"] == "nssm_missing"
    assert ns.remove_service_with_nssm("X")["error"] == "nssm_missing"
    assert ns.start_service_with_nssm("X")["error"] == "nssm_missing"
    assert ns.stop_service_with_nssm("X")["error"] == "nssm_missing"


def test_nssm_status_not_installed(monkeypatch):
    import autostart.nssm_service as ns

    monkeypatch.setattr(ns, "get_nssm_path", lambda: "C:\\nssm.exe")
    monkeypatch.setattr(ns, "service_exists", lambda name: False)
    st = ns.get_service_status_nssm("X")
    assert st["installed"] is False


def test_nssm_status_running(monkeypatch):
    import autostart.nssm_service as ns

    monkeypatch.setattr(ns, "get_nssm_path", lambda: "C:\\nssm.exe")
    monkeypatch.setattr(ns, "service_exists", lambda name: True)
    monkeypatch.setattr(ns, "_run_nssm", lambda args: _R(0, stdout=b"SERVICE_RUNNING"))
    st = ns.get_service_status_nssm("X")
    assert st["installed"] is True
    assert st["running"] is True


def test_nssm_service_calls(monkeypatch):
    import autostart.nssm_service as ns

    calls = []

    def fake_run(args):
        calls.append(args[0])
        return _R(0)

    monkeypatch.setattr(ns, "get_nssm_path", lambda: "C:\\nssm.exe")
    monkeypatch.setattr(ns, "service_exists", lambda name: True)
    monkeypatch.setattr(ns, "_run_nssm", fake_run)
    assert ns.start_service_with_nssm("X")["ok"] is True
    assert ns.stop_service_with_nssm("X")["ok"] is True
    assert ns.remove_service_with_nssm("X")["ok"] is True
    assert calls == ["start", "stop", "remove"]


def test_nssm_create_not_windows(monkeypatch):
    import autostart.nssm_service as ns

    monkeypatch.setattr(os, "name", "posix")
    assert ns.create_service_with_nssm(build_entry_for("app"))["error"] == "not_windows"


# ─── service_api wiring ────────────────────────────────────────────────


def test_service_api_unknown_provider():
    e = build_entry_for("app")
    assert service_api.install_service("bogus", e)["error"] == "unknown_provider"
    assert service_api.remove_service("bogus", e)["error"] == "unknown_provider"
    assert service_api.start_service("task", e)["error"] == "unsupported_provider"
    assert service_api.stop_service("task", e)["error"] == "unsupported_provider"


def test_main_help_flag_present():
    from main import _parse_args

    args = _parse_args(["--headless", "--autostart-winws"])
    assert args.autostart_winws is True
    plain = _parse_args(["--headless"])
    assert plain.autostart_winws is False