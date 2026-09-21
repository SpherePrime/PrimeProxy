import tempfile
import unittest
from pathlib import Path
from unittest import mock

from logs import winws_log_analyzer as wla


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


class ABase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.log = Path(self._tmp.name) / "winws.log"

    def missing_path(self) -> Path:
        return Path(self._tmp.name) / "no-such.log"

    def write_log(self, text: str) -> None:
        _write(self.log, text)


class DetectRunStatusTest(ABase):
    def test_missing_file_is_no_log(self):
        res = wla.detect_run_status(self.missing_path())
        self.assertEqual(res["has_log"], False)
        self.assertEqual(res["status"], "no_log")
        self.assertEqual(res["reason"], "no_log")

    def test_empty_file_is_no_log(self):
        self.write_log("")
        res = wla.detect_run_status(self.log)
        self.assertEqual(res["has_log"], True)
        self.assertEqual(res["status"], "no_log")
        self.assertEqual(res["reason"], "no_content")

    def test_ok_session(self):
        self.write_log(
            "[2026-01-01 12:00:00] Starting C:\\\\exe\\\\winws2.exe @C:\\\\exe\\\\cfg.txt... (mode=winws2, pid=1000, cwd=C:\\\\exe)\n"
            "<< winws2 banner\n"
            "winws2: sleeping 20ms\n"
            "winws: bound to 0.0.0.0:730\n"
            "[2026-01-01 12:00:10] winws stopped (pid 1000)\n"
        )
        res = wla.detect_run_status(self.log)
        self.assertEqual(res["status"], "ok")
        self.assertEqual(res["reason"], "stopped")

    def test_no_config_error(self):
        self.write_log(
            "[2026-01-01 12:00:00] Starting C:\\\\exe\\\\winws2.exe @C:\\\\exe\\\\cfg.txt... (mode=winws2, pid=1001, cwd=C:\\\\exe)\n"
            "winws: error: can't read config file @C:\\\\exe\\\\cfg.txt\n"
            "[2026-01-01 12:00:01] winws exited immediately (code 1): winws: error: can't read config file @C:\\\\exe\\\\cfg.txt\n"
        )
        res = wla.detect_run_status(self.log)
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["reason"], "no_config")

    def test_appeared_and_disappeared(self):
        self.write_log(
            "[2026-01-01 12:00:00] Starting C:\\\\exe\\\\winws2.exe @C:\\\\exe\\\\cfg.txt... (mode=winws2, pid=1002, cwd=C:\\\\exe)\n"
            "winws: trying to init windivert\n"
            "winws: windivert: handle is in use\n"
            "[2026-01-01 12:00:01] winws exited immediately (code 31): winws: windivert: handle is in use\n"
        )
        res = wla.detect_run_status(self.log)
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["reason"], "appeared_disappeared")

    def test_not_appeared_no_output(self):
        self.write_log("[2026-01-01 12:00:00] Starting C:\\\\exe\\\\winws2.exe @C:\\\\exe\\\\cfg.txt... (mode=winws2, pid=999, cwd=C:\\\\exe)\n")
        res = wla.detect_run_status(self.log)
        self.assertEqual(res["status"], "error")
        self.assertEqual(res["reason"], "not_appeared")

    def test_booting_open_session(self):
        self.write_log(
            "[2026-01-01 12:00:00] Starting C:\\\\exe\\\\winws2.exe @C:\\\\exe\\\\cfg.txt... (mode=winws2, pid=1003, cwd=C:\\\\exe)\n"
            "winws: initialising engine\n"
        )
        res = wla.detect_run_status(self.log)
        self.assertEqual(res["status"], "warning")
        self.assertEqual(res["reason"], "booting")

    def test_pf_calc_warning(self):
        self.write_log(
            "[2026-01-01 12:00:00] Starting C:\\\\exe\\\\winws2.exe @C:\\\\exe\\\\cfg.txt... (mode=winws2, pid=1004, cwd=C:\\\\exe)\n"
            "winws: computing fragmentation policy\n"
        )
        res = wla.detect_run_status(self.log)
        self.assertEqual(res["status"], "warning")
        self.assertEqual(res["reason"], "pf_calc")


class ParseAndSummarizeTest(ABase):
    def test_counts_errors_and_warnings(self):
        self.write_log(
            "[2026-01-01 12:00:00] Starting exe... (mode=winws2, pid=1101, cwd=C:\\\\exe)\n"
            "winws: error: windivert handle is in use\n"
            "winws: warning: windivert deprecated\n"
            "[2026-01-01 12:00:05] winws exited immediately (code 31): winws: error: windivert handle is in use\n"
            "[2026-01-02 12:00:00] Starting exe... (mode=winws2, pid=1102, cwd=C:\\\\exe)\n"
            "winws2: sleeping 20ms\n"
            "[2026-01-02 12:00:20] winws process exited (code 0)\n"
        )
        parsed = wla.parse_session(self.log)
        self.assertEqual(parsed["sessions_count"], 2)
        self.assertEqual(parsed["ok_count"], 1)
        self.assertEqual(parsed["fail_count"], 1)
        self.assertEqual(len(parsed["errors"]), 1)
        self.assertEqual(len(parsed["warnings"]), 1)
        self.assertIn("windivert handle is in use", parsed["errors"][0])
        self.assertIn("windivert deprecated", parsed["warnings"][0])

    def test_last_session_and_lifetime(self):
        self.write_log(
            "[2026-01-01 12:00:00] Starting exe... (mode=winws2, pid=1201, cwd=C:\\\\exe)\n"
            "[2026-01-01 12:00:02] winws stopped (pid 1201)\n"
            "[2026-01-02 12:00:00] Starting exe... (mode=winws1, pid=1202, cwd=C:\\\\exe)\n"
            "[2026-01-02 12:00:08] winws stopped (pid 1202)\n"
        )
        parsed = wla.parse_session(self.log)
        last = parsed["last_session"]
        self.assertEqual(last["mode"], "winws1")
        self.assertEqual(last["pid"], 1202)
        self.assertEqual(last["lifetime_seconds"], 8)
        self.assertEqual(last["ok"], True)
        self.assertEqual(parsed["sessions_count"], 2)

    def test_summarize_merges_verdict(self):
        self.write_log(
            "[2026-01-01 12:00:00] Starting exe... (mode=winws2, pid=1301, cwd=C:\\\\exe)\n"
            "winws: error: can't read config\n"
            "[2026-01-01 12:00:01] winws exited immediately (code 1): winws: error: can't read config\n"
        )
        summary = wla.summarize_log(self.log)
        self.assertEqual(summary["sessions_count"], 1)
        self.assertEqual(summary["verdict"]["status"], "error")
        self.assertEqual(summary["verdict"]["reason"], "no_config")


class IPCAmbientTest(ABase):
    def test_get_winws_log_status_ipc(self):
        from ui.api import SwiftAPI

        fake = {
            "has_log": True,
            "lines_total": 3,
            "sessions_count": 1,
            "ok_count": 0,
            "fail_count": 1,
            "warn_count": 0,
            "open_count": 0,
            "sessions": [],
            "errors": ["boom"],
            "warnings": [],
            "last_session": None,
            "verdict": {"has_log": True, "status": "error", "reason": "no_config", "detail": "boom", "lines_total": 3},
        }
        with mock.patch("logs.winws_log_analyzer.summarize_log", return_value=fake) as m:
            result = SwiftAPI().get_winws_log_status()
        m.assert_called_once()
        self.assertEqual(result, fake)
        self.assertEqual(result["verdict"]["reason"], "no_config")


if __name__ == "__main__":
    unittest.main()