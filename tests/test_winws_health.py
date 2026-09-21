import os
import unittest
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch

from winws.health import WINDIVERT_ERROR_TABLE
from winws.health.windivert_diagnostics import describe_windivert_error, format_windows_error_code
from winws.health.winws_exit_diagnosis import (
    build_winws_exit_diagnosis_entry,
    diagnose_winws_exit,
)
from winws.health.winws_output import is_banner_line, relevant_error_line
from winws.health.spawn_failure import classify_spawn_failure, is_silent_exit
from winws.health.system_ops import WinDivertRuntimeProbeResult
from winws.health.diagnostics import diagnose_log_text
from winws.health.silent_exit_probe import SilentExitFinding, format_silent_exit_message, probe_silent_exit
from winws.health.post_mortem import diagnose_unexpected_winws_exit


def _ready_probe(**overrides):
    defaults = dict(ready=True, installed=True, error_code=None, error_message=None, stage="ready")
    defaults.update(overrides)
    return WinDivertRuntimeProbeResult(**defaults)


def _not_ready_probe(code, **overrides):
    return _ready_probe(ready=False, error_code=code, **overrides)


class DescribeWindivertErrorTest(unittest.TestCase):
    def test_known_codes_have_description(self):
        for code in (5, 31, 87, 161, 433, 577, 654, 1058, 1060, 1067, 1068, 1072, 1275, 1753, 0x80320010):
            text = describe_windivert_error(code)
            self.assertIn(str(code), text)
            self.assertTrue(len(text) > 10)

    def test_table_includes_code_range(self):
        self.assertEqual(len(WINDIVERT_ERROR_TABLE), 16)
        for code in (5, 8, 31, 87, 161, 433, 577, 654, 1058, 1060, 1067, 1068, 1072, 1275, 1753, 0x80320010):
            self.assertIn(code, WINDIVERT_ERROR_TABLE)

    def test_unknown_code(self):
        self.assertIn("99999", describe_windivert_error(99999))

    def test_stage_prefix(self):
        text = describe_windivert_error(433, stage="ready")
        self.assertTrue(text.startswith("Проверка WinDivert на этапе «ready»:"))

    def test_format_windows_error_code(self):
        self.assertEqual(format_windows_error_code(433), "433")
        self.assertEqual(format_windows_error_code(0x80320010), "2150760464 / 0x80320010")


class EnsureWindivertReadyTest(unittest.TestCase):
    def test_ready_immediately_no_recovery(self):
        with patch("winws.health.system_ops.probe_windivert_state_runtime", return_value=_ready_probe()), \
             patch("winws.health.windivert_auto_fix._run_recovery") as recovery:
            ok, probe = winws_ensure_ready_before_spawn()
        self.assertTrue(ok)
        self.assertTrue(probe.ready)
        recovery.assert_not_called()

    def test_transient_recovers(self):
        probes = [_not_ready_probe(433), _ready_probe()]
        with patch("winws.health.system_ops.probe_windivert_state_runtime", side_effect=probes), \
             patch("winws.health.system_ops.time.sleep") as sleep, \
             patch("winws.health.windivert_auto_fix._run_recovery") as recovery:
            ok, probe = winws_ensure_ready_before_spawn()
        self.assertTrue(ok)
        self.assertTrue(probe.ready)
        recovery.assert_called_once()
        sleep.assert_called()

    def test_non_transient_skips_recovery(self):
        with patch("winws.health.system_ops.probe_windivert_state_runtime", return_value=_not_ready_probe(161)), \
             patch("winws.health.windivert_auto_fix._run_recovery") as recovery:
            ok, probe = winws_ensure_ready_before_spawn()
        self.assertFalse(ok)
        self.assertFalse(probe.ready)
        self.assertEqual(probe.error_code, 161)
        recovery.assert_not_called()

    def test_wait_for_ready_returns_ready_probe(self):
        with patch("winws.health.system_ops.probe_windivert_state_runtime", return_value=_ready_probe()):
            from winws.health.system_ops import wait_for_windivert_spawn_ready_runtime
            probe = wait_for_windivert_spawn_ready_runtime()
        self.assertTrue(probe.ready)


def winws_ensure_ready_before_spawn():
    from winws.health.windivert_auto_fix import ensure_windivert_ready_before_spawn
    return ensure_windivert_ready_before_spawn()


class DiagnoseWinwsExitTest(unittest.TestCase):
    def _patch_env(self):
        return patch.multiple(
            "winws.health.winws_exit_diagnosis",
            _check_windivert_files=lambda: [],
            _check_bfe_service=lambda: True,
            _find_disabled_windivert_driver_service=lambda: None,
            _check_network_adapters=lambda: True,
            _check_secure_boot=lambda: True,
        ), patch("winws.health.antivirus_detection._detect_active_antivirus", return_value=None)

    def test_exit_zero_returns_none(self):
        self.assertIsNone(diagnose_winws_exit(0, "bye"))

    def test_exit_1058_stderr_inference(self):
        with self._patch_env()[0], self._patch_env()[1]:
            entry = diagnose_winws_exit(1058, "winws2: the service cannot be started")
        self.assertIsNotNone(entry)
        self.assertEqual(entry["win32_error"], 1058)
        self.assertIn("Служба WinDivert", entry["cause"])

    def test_exit_1058_handler_cause(self):
        with self._patch_env()[0], self._patch_env()[1]:
            entry = diagnose_winws_exit(1058, "")
        self.assertIsNotNone(entry)
        base = WINDIVERT_ERROR_TABLE[1058]
        self.assertIn(str(base["cause"]), str(entry["cause"]))
        self.assertTrue(entry["solution"])

    def test_exit_1060(self):
        entry = diagnose_winws_exit(1060, "")
        self.assertIsNotNone(entry)
        self.assertIn("не существует", entry["cause"])

    def test_exit_1072(self):
        entry = diagnose_winws_exit(1072, "")
        self.assertIsNotNone(entry)
        self.assertIn("на удаление", entry["cause"])
        self.assertTrue(entry.get("wait_for_recovery_after_cleanup"))

    def test_exit_1753(self):
        entry = diagnose_winws_exit(1753, "")
        self.assertIsNotNone(entry)
        self.assertIn("RPC", entry["cause"])

    def test_exit_access_denied(self):
        import ctypes as _ctypes
        with patch.object(_ctypes, "windll") as windll:
            windll.shell32.IsUserAnAdmin.return_value = False
            entry = diagnose_winws_exit(5, "access is denied")
        self.assertIsNotNone(entry)
        self.assertIn("администратора", entry["cause"])

    def test_exit_31_with_holders(self):
        with patch("winws.health.system_ops.find_windivert_holder_processes_runtime",
                   return_value=[{"pid": "1", "name": "GoodbyeDPI.exe", "module_path": "x"}]):
            entry = diagnose_winws_exit(31, "")
        self.assertIsNotNone(entry)
        self.assertIn("GoodbyeDPI.exe", entry["cause"])

    def test_unknown_code(self):
        entry = diagnose_winws_exit(3, "")
        self.assertIsNotNone(entry)
        self.assertIn("(код 3)", entry["cause"])

    def test_build_entry_zero_success(self):
        entry = build_winws_exit_diagnosis_entry(0, "")
        self.assertIn("успешн", entry["cause"])


class LaunchConflictsTest(unittest.TestCase):
    RECORDS = [
        {"pid": 111, "name": "winws2.exe", "exe": "winws2.exe"},
        {"pid": 222, "name": "GoodbyeDPI.exe", "exe": "GoodbyeDPI.exe"},
        {"pid": 333, "name": "procexp64.exe", "exe": "procexp64.exe"},
        {"pid": 444, "name": "svchost.exe", "exe": "svchost.exe"},
    ]

    def test_check_conflicting_processes(self):
        from winws.health.launch_conflicts import check_conflicting_processes
        with patch("winws.health.launch_conflicts._iter_process_records_winapi",
                   return_value=list(self.RECORDS)):
            conflicts = check_conflicting_processes()
        self.assertEqual(len(conflicts), 2)
        names = {c["name"] for c in conflicts}
        self.assertNotIn("winws2.exe", names)
        self.assertIn("GoodbyeDPI.exe", names)

    def test_report_empty(self):
        from winws.health.launch_conflicts import get_conflicting_processes_report
        with patch("winws.health.launch_conflicts._iter_process_records_winapi", return_value=[]):
            self.assertIn("не найдены", get_conflicting_processes_report())

    def test_try_kill_auto(self):
        from winws.health.launch_conflicts import try_kill_conflicting_processes
        with patch("winws.health.launch_conflicts._iter_process_records_winapi",
                   return_value=list(self.RECORDS)), \
             patch("winws.health.launch_conflicts.kill_process_by_pid_runtime", return_value=True):
            self.assertTrue(try_kill_conflicting_processes(auto_kill=True))

    def test_try_kill_without_auto(self):
        from winws.health.launch_conflicts import try_kill_conflicting_processes
        with patch("winws.health.launch_conflicts._iter_process_records_winapi",
                   return_value=list(self.RECORDS)):
            self.assertFalse(try_kill_conflicting_processes(auto_kill=False))

    def test_conflict_hint_none(self):
        from winws.health.launch_conflicts import build_windivert_conflict_hint
        with patch("winws.health.launch_conflicts.find_windivert_holder_processes_runtime", return_value=[]), \
             patch("winws.health.launch_conflicts.find_foreign_windivert_service_paths_runtime", return_value=[]):
            self.assertIsNone(build_windivert_conflict_hint())

    def test_conflict_hint_found(self):
        from winws.health.launch_conflicts import build_windivert_conflict_hint
        with patch("winws.health.launch_conflicts.find_windivert_holder_processes_runtime",
                   return_value=[{"pid": "7", "name": "GoodbyeDPI.exe", "module_path": "x"}]):
            hint = build_windivert_conflict_hint()
        self.assertIsNotNone(hint)
        self.assertIn("конфликт WinDivert", hint)


class SystemOpsTest(unittest.TestCase):
    def test_force_kill_all(self):
        with patch("utils.process_killer.kill_winws_force", return_value=True):
            from winws.health.system_ops import force_kill_all_winws_processes
            self.assertTrue(force_kill_all_winws_processes())

    def test_force_kill_all_exception(self):
        with patch("utils.process_killer.kill_winws_force", side_effect=OSError("x")):
            from winws.health.system_ops import force_kill_all_winws_processes
            self.assertFalse(force_kill_all_winws_processes())

    def test_get_process_pids_by_name(self):
        with patch("utils.process_killer.get_process_pids", return_value=[1, 2]):
            from winws.health.system_ops import get_process_pids_by_name
            self.assertEqual(get_process_pids_by_name("winws.exe"), [1, 2])

    def test_get_all_winws_process_pids(self):
        with patch("winws.health.system_ops.get_process_pids_by_name", side_effect=[[1], [2, 3]]):
            from winws.health.system_ops import get_all_winws_process_pids
            self.assertEqual(get_all_winws_process_pids(), [1, 2, 3])

    def test_standard_cleanup(self):
        with patch("winws.health.system_ops.time.sleep") as sleep, \
             patch("winws.health.system_ops.force_kill_all_winws_processes", return_value=True), \
             patch("winws.health.system_ops.restore_known_windivert_services_demand_start_runtime", return_value=["WinDivert"]), \
             patch("winws.health.system_ops.find_stale_windivert_delete_pending_services_runtime", return_value=[]), \
             patch("winws.health.system_ops._stop_and_delete_known_runtime_services") as delete:
            from winws.health.system_ops import standard_windivert_cleanup_runtime
            self.assertTrue(standard_windivert_cleanup_runtime())
        delete.assert_not_called()
        sleep.assert_called()

    def test_aggressive_cleanup(self):
        with patch("winws.health.system_ops.time.sleep"), \
             patch("winws.health.antivirus_probe._is_kaspersky_present_safe", return_value=False), \
             patch("winws.health.system_ops.force_kill_all_winws_processes", return_value=True), \
             patch("winws.health.system_ops.wait_for_windivert_cleanup_settle_runtime") as settle, \
             patch("winws.health.system_ops.unload_known_windivert_drivers_runtime", return_value=["Monkey"]), \
             patch("winws.health.system_ops._stop_and_delete_known_runtime_services") as delete:
            from winws.health.system_ops import aggressive_windivert_cleanup_runtime
            self.assertTrue(aggressive_windivert_cleanup_runtime())
        settle.assert_called()
        delete.assert_called()

    def test_aggressive_cleanup_blocked_by_kaspersky(self):
        with patch("winws.health.antivirus_probe._is_kaspersky_present_safe", return_value=True), \
             patch("winws.health.system_ops.force_kill_all_winws_processes") as kill:
            from winws.health.system_ops import aggressive_windivert_cleanup_runtime
            self.assertFalse(aggressive_windivert_cleanup_runtime())
        kill.assert_not_called()

    def test_probe_non_installed(self):
        with patch("winws.health.system_ops._get_windivert_service_states", return_value={}), \
             patch("winws.health.system_ops._iter_windivert_dll_candidates_runtime", return_value=[]):
            from winws.health.system_ops import probe_windivert_state_runtime
            probe = probe_windivert_state_runtime()
        self.assertFalse(probe.ready)
        self.assertFalse(probe.installed)
        self.assertEqual(probe.error_code, 1060)

    def test_probe_disabled_service(self):
        with patch("winws.health.system_ops._get_windivert_service_states",
                   return_value={"WinDivert": {"start": 4, "image_path": "x\\Monkey64.sys", "delete_flag": 0}}), \
             patch("winws.health.system_ops._iter_windivert_dll_candidates_runtime", return_value=[r"Z:\dummy\WinDivert.dll"]), \
             patch("os.path.isfile", return_value=True):
            from winws.health.system_ops import probe_windivert_state_runtime
            probe = probe_windivert_state_runtime()
        self.assertFalse(probe.ready)
        self.assertEqual(probe.error_code, 1058)


class WindowsSystemDependenciesTest(unittest.TestCase):
    def test_has_wlanapi_missing(self):
        from winws.health.windows_system_dependencies import has_wlanapi_missing
        self.assertFalse(has_wlanapi_missing(["x"]))
        self.assertTrue(has_wlanapi_missing(["wlanapi.dll"]))

    def test_should_offer_on_server(self):
        from winws.health.windows_system_dependencies import should_offer_windows_server_wlanapi_install
        self.assertTrue(should_offer_windows_server_wlanapi_install(["wlanapi.dll"], is_windows_server=True))
        self.assertFalse(should_offer_windows_server_wlanapi_install(["wlanapi.dll"], is_windows_server=False))
        self.assertFalse(should_offer_windows_server_wlanapi_install(["other.dll"], is_windows_server=True))

    def test_mark_message(self):
        from winws.health.windows_system_dependencies import mark_windows_server_wlanapi_message
        with patch("winws.health.windows_system_dependencies.is_windows_server_os", return_value=True):
            message = mark_windows_server_wlanapi_message(["wlanapi.dll"])
        self.assertIn("wlanapi.dll", message)

    def test_install_non_server(self):
        from winws.health.windows_system_dependencies import run_windows_server_wlanapi_install
        with patch("winws.health.windows_system_dependencies.is_windows_server_os", return_value=False):
            ok, detail = run_windows_server_wlanapi_install()
        self.assertFalse(ok)
        self.assertIn("Server", detail)

    def test_preflight_all_ok(self):
        from winws.health.windows_system_dependencies import preflight_dependencies
        with patch("winws.health.windows_system_dependencies._preflight_bfe",
                   return_value={"ok": True, "state": 4, "detail": "bfe ok"}), \
             patch("winws.health.windows_system_dependencies._preflight_wlanapi",
                   return_value={"ok": True, "detail": "wlanapi ok"}), \
             patch("winws.health.windows_system_dependencies._preflight_driver",
                   return_value={"ok": True, "detail": "driver ok", "driver_files": []}):
            report = preflight_dependencies()
        self.assertTrue(report["ok"])
        self.assertEqual(set(report["checks"]), {"bfe", "wlanapi", "driver"})


class ServiceManagerTest(unittest.TestCase):
    def setUp(self):
        self._orig_enabled = None
        try:
            import utils.service_manager as sm
            self._orig_enabled = sm._ENABLE_WINAPI
            sm._ENABLE_WINAPI = False
        except AttributeError:
            pass

    def tearDown(self):
        if self._orig_enabled is not None:
            import utils.service_manager as sm
            sm._ENABLE_WINAPI = self._orig_enabled

    def _like(self, code, stdout="", stderr=""):
        return subprocess.CompletedProcess(["sc.exe"], code, stdout=stdout, stderr=stderr)

    def test_query_service_nonexistent(self):
        import utils.service_manager as sm
        with patch("utils.service_manager.service_registry_exists", return_value=False), \
             patch("utils.service_manager._sc_run", return_value=self._like(1060, "", "does not exist")):
            self.assertIsNone(sm.query_service("NoSuchSvc"))

    def test_query_service_running(self):
        import utils.service_manager as sm
        out = ("SERVICE_NAME: BFE\n"
               "        TYPE               : 20  WIN32_SHARE_PROCESS\n"
               "        STATE              : 4  RUNNING\n")
        with patch("utils.service_manager.service_registry_exists", return_value=True), \
             patch("utils.service_manager._registry_start_type", return_value=2), \
             patch("utils.service_manager._sc_run", return_value=self._like(0, out)):
            entry = sm.query_service("BFE")
        self.assertIsNotNone(entry)
        self.assertTrue(entry["exists"])
        self.assertEqual(entry["state"], 4)
        self.assertEqual(entry["state_text"], "running")

    def test_stop_service(self):
        import utils.service_manager as sm
        out = ("SERVICE_NAME: BFE\n        STATE              : 4  RUNNING\n")
        with patch("utils.service_manager.service_registry_exists", return_value=True), \
             patch("utils.service_manager._sc_run", side_effect=[
                 self._like(0, out),
                 self._like(0, "SERVICE_NAME: BFE\n        STATE              : 1  STOPPED\n"),
             ]):
            self.assertTrue(sm.stop_service("BFE"))

    def test_delete_service_nonexistent(self):
        import utils.service_manager as sm
        with patch("utils.service_manager.service_registry_exists", return_value=False), \
             patch("utils.service_manager._sc_run", return_value=self._like(1060)):
            self.assertTrue(sm.delete_service("NoSuchSvc"))

    def test_stop_and_delete(self):
        import utils.service_manager as sm
        out = ("SERVICE_NAME: X\n        STATE              : 4  RUNNING\n")
        with patch("utils.service_manager.service_registry_exists",
                   side_effect=[True, True, True, False]), \
             patch("utils.service_manager._sc_run", side_effect=[
                 self._like(0, out),
                 self._like(0, "STATE: 1"),
                 self._like(0, "delete: success"),
                 self._like(1060, "", "not exist"),
             ]):
            self.assertTrue(sm.stop_and_delete_service("X"))

    def test_get_service_state(self):
        import utils.service_manager as sm
        with patch("utils.service_manager._sc_run",
                   return_value=self._like(0, "STATE              : 4  RUNNING\n")):
            self.assertEqual(sm.get_service_state("BFE"), 4)

    def test_enumerate_services(self):
        import utils.service_manager as sm
        out = ("SERVICE_NAME: BFE\n        STATE              : 4  RUNNING\n"
               "SERVICE_NAME: Dnscache\n        STATE              : 1  STOPPED\n")
        with patch("utils.service_manager.service_registry_exists", return_value=False), \
             patch("utils.service_manager._registry_start_type", return_value=2), \
             patch("utils.service_manager._sc_run", return_value=self._like(0, out)):
            services = sm.enumerate_services()
        self.assertEqual([s["name"] for s in services], ["BFE", "Dnscache"])
        self.assertEqual(services[0]["state"], 4)


class SubprocTest(unittest.TestCase):
    def test_prepare_cmd_string(self):
        from utils.subproc import _prepare_cmd
        self.assertEqual(_prepare_cmd("echo hi"), ["echo", "hi"])
        self.assertEqual(_prepare_cmd(["a", "b"]), ["a", "b"])

    def test_run_hidden_passthrough(self):
        import utils.subproc as sp
        cp = subprocess.CompletedProcess(["cmd"], 0, stdout="out", stderr="")
        with patch("utils.subproc.subprocess.run", return_value=cp) as run:
            result = sp.run_hidden(["echo", "x"], capture_output=True, timeout=5)
        self.assertEqual(result, cp)
        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertEqual(kwargs["shell"], False)


class ProcessKillerTest(unittest.TestCase):
    def test_get_process_pids(self):
        from utils.process_killer import get_process_pids
        with patch("utils.windows_process_probe.get_process_ids_by_name", return_value=[4, 5]):
            self.assertEqual(get_process_pids("x.exe"), [4, 5])

    def test_kill_process_by_name(self):
        from utils.process_killer import kill_process_by_name
        records = [{"pid": 1, "name": "GoalDPI.exe"}]
        with patch("utils.windows_process_probe.iter_process_records", return_value=records), \
             patch("utils.process_killer.kill_process_by_pid_winapi", return_value=True):
            self.assertEqual(kill_process_by_name("GoalDPI.exe"), 1)

    def test_kill_process_by_name_no_match(self):
        from utils.process_killer import kill_process_by_name
        records = [{"pid": 1, "name": "Other.exe"}]
        with patch("utils.windows_process_probe.iter_process_records", return_value=records), \
             patch("utils.process_killer.kill_process_by_pid_winapi", return_value=True):
            self.assertEqual(kill_process_by_name("GoalDPI.exe"), 0)


class WindowsProcessProbeTest(unittest.TestCase):
    def test_iter_disabled_on_non_windows(self):
        from utils.windows_process_probe import _iter_process_records_winapi, iter_process_records_winapi
        with patch("utils.windows_process_probe._use_winapi", False):
            self.assertEqual(list(iter_process_records_winapi()), [])
            self.assertEqual(list(_iter_process_records_winapi()), [])

    def test_alias_identity(self):
        from utils.windows_process_probe import _iter_process_records_winapi, iter_process_records_winapi
        self.assertIs(_iter_process_records_winapi, iter_process_records_winapi)


class DiagnosticsAggregationTest(unittest.TestCase):
    LOG_TEXT = (
        "winws exited immediately (code 1058): winws2: the service cannot be started\n"
        "winws process exited (code 0)\n"
    )

    def _patch_exit_env(self):
        return patch.multiple(
            "winws.health.winws_exit_diagnosis",
            _check_windivert_files=lambda: [],
            _check_bfe_service=lambda: True,
            _find_disabled_windivert_driver_service=lambda: None,
            _check_network_adapters=lambda: True,
            _check_secure_boot=lambda: True,
        ), patch("winws.health.antivirus_detection._detect_active_antivirus", return_value=None)

    def test_diagnose_log_text(self):
        with self._patch_exit_env()[0], self._patch_exit_env()[1]:
            diagnosis = diagnose_log_text(self.LOG_TEXT)
        self.assertEqual(diagnosis["exit_codes"], [1058])
        self.assertIsNotNone(diagnosis["last_crash"])
        self.assertEqual(diagnosis["last_crash"]["exit_code"], 1058)
        self.assertEqual(diagnosis["windivert_error"]["code"], 1058)

    def test_run_winws_diagnostics(self):
        from winws.health.diagnostics import run_winws_diagnostics
        with self._patch_exit_env()[0], self._patch_exit_env()[1], \
             patch("winws.health.diagnostics._winws_log_text", return_value=self.LOG_TEXT), \
             patch("winws.health.diagnostics._engine_present", return_value=True), \
             patch("winws.health.diagnostics._winws_running", return_value=False):
            report = run_winws_diagnostics()
        self.assertTrue(report["engine_present"])
        self.assertFalse(report["running"])
        self.assertIsNotNone(report["last_crash_diagnosis"])
        self.assertEqual(report["exit_analysis"][0]["code"], 1058)
        self.assertEqual(report["windivert_error"]["code"], 1058)
        self.assertTrue(report["suggestions"])

    def test_get_windivert_health(self):
        from winws.health.diagnostics import get_windivert_health
        with patch("winws.health.system_ops.probe_windivert_state_runtime", return_value=_ready_probe()), \
             patch("winws.health.diagnostics.list_from_system_ops_foreign", return_value=[]), \
             patch("winws.health.launch_conflicts.check_conflicting_processes", return_value=[]), \
             patch("winws.health.launch_conflicts.build_windivert_conflict_hint", return_value=None), \
             patch("winws.health.windows_system_dependencies.preflight_dependencies",
                   return_value={"ok": True, "checks": {}}), \
             patch("tools.windows_tools.windivert_presence",
                   return_value={"driver": {"present": True}, "bundled": None}):
            report = get_windivert_health()
        self.assertTrue(report["readiness_probe"]["ready"])
        self.assertEqual(len(report["error_codes"]), 16)
        self.assertTrue(report["dependencies"]["ok"])
        self.assertEqual(report["conflict_report"]["processes"], [])

    def test_windivert_cleanup_standard(self):
        from winws.health.diagnostics import windivert_cleanup
        with patch("winws.health.system_ops.standard_windivert_cleanup_runtime", return_value=True):
            report = windivert_cleanup("standard")
        self.assertTrue(report["ok"])
        self.assertIn("cleanup_standard", report["performed"])
        self.assertIn("requires_admin", report)

    def test_windivert_cleanup_aggressive(self):
        from winws.health.diagnostics import windivert_cleanup
        with patch("winws.health.system_ops.aggressive_windivert_cleanup_runtime", return_value=False):
            report = windivert_cleanup("aggressive")
        self.assertFalse(report["ok"])
        self.assertIn("cleanup_aggressive", report["failed"])

    def test_kill_conflicting_processes(self):
        from winws.health.diagnostics import kill_conflicting_processes
        with patch("winws.health.launch_conflicts.check_conflicting_processes",
                   side_effect=[[{"name": "GoodbyeDPI.exe", "pid": 5}], []]), \
             patch("winws.health.launch_conflicts.try_kill_conflicting_processes", return_value=True):
            report = kill_conflicting_processes()
        self.assertTrue(report["ok"])
        self.assertEqual(report["killed"], ["GoodbyeDPI.exe"])

    def test_get_winws_health(self):
        from winws.health.diagnostics import get_winws_health
        with patch("winws.health.diagnostics._winws_log_text", return_value=""), \
             patch("winws.health.diagnostics._engine_present", return_value=True), \
             patch("winws.health.diagnostics._winws_running", return_value=False), \
             patch("winws.health.windivert_auto_fix.is_windivert_ready", return_value=True), \
             patch("winws.health.launch_conflicts.check_conflicting_processes", return_value=[]), \
             patch("tools.windows_tools.windivert_presence",
                   return_value={"driver": {"present": True, "path": "C:\\x"}}):
            report = get_winws_health()
        self.assertIn("windivert_ready", report)
        self.assertTrue(report["engine_present"])
        self.assertEqual(report["conflicts"], 0)


class SilentExitProbeTest(unittest.TestCase):
    def test_probe_missing_exe_confirms(self):
        missing = str(Path(__file__).with_name("no_such_winws_subfile.exe"))
        with patch("winws.health.silent_exit_probe._recent_defender_detection_within", return_value=False):
            report = probe_silent_exit(missing, exit_code=1)
        self.assertTrue(report.confirmed)
        self.assertTrue(report.source_exe_missing)

    def test_probe_with_existing_exe_not_confirmed(self):
        existing = __file__
        with patch("winws.health.silent_exit_probe._recent_defender_detection_within", return_value=False):
            report = probe_silent_exit(existing, exit_code=1)
        self.assertFalse(report.confirmed)
        self.assertFalse(report.source_exe_missing)

    def test_format_message(self):
        with patch("winws.health.silent_exit_probe.os.path.isfile", return_value=False), \
             patch("winws.health.silent_exit_probe._recent_defender_detection_within", return_value=False):
            message = format_silent_exit_message(probe_silent_exit("no_such_file.exe"))
        self.assertIn("молчалив", message)


class PostMortemTest(unittest.TestCase):
    def test_silent_exit_detected(self):
        with patch("winws.health.silent_exit_probe._recent_defender_detection_within", return_value=False), \
             patch("winws.health.post_mortem.probe_silent_exit", return_value=probe_silent_exit(
                 "missing_winws.exe")) as probe:
            entry = diagnose_unexpected_winws_exit("missing_winws.exe", 1, "")
        self.assertTrue(entry["silent_exit"])
        probe.assert_called_once()

    def test_non_silent_output(self):
        with patch("winws.health.post_mortem.probe_silent_exit", return_value=None):
            entry = diagnose_unexpected_winws_exit("x.exe", 5, "windivert: error")
        self.assertFalse(entry["silent_exit"])


class WinwsOutputTest(unittest.TestCase):
    def test_banner(self):
        self.assertTrue(is_banner_line("<<banner"))
        self.assertTrue(is_banner_line(">=>>>banner"))
        self.assertFalse(is_banner_line("normal"))

    def test_relevant_error_line(self):
        lines = ["normal line", "windivert: error opening filter"]
        self.assertEqual(relevant_error_line(lines), "windivert: error opening filter")
        self.assertIsNone(relevant_error_line(["ok"]))


class SpawnFailureTest(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(classify_spawn_failure(None, "windivert: handle is in use"), "windivert_conflict")
        self.assertIsNone(classify_spawn_failure(None, "some text"))

    def test_is_silent_exit(self):
        self.assertTrue(is_silent_exit(1, ""))
        self.assertFalse(is_silent_exit(1, "windivert: error"))
        self.assertFalse(is_silent_exit(0, ""))


if __name__ == "__main__":
    unittest.main()