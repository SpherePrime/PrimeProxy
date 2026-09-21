import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from winws.args import launch_args_from_text, missing_references, split_launch_line, validate_profile_text
from winws.profiles import engine_mode_for, list_user_profiles, save_user_profile, delete_user_profile, _PROFILE_NAME_RE


class SplitLaunchLineTest(unittest.TestCase):
    def test_splits_inline_args(self):
        self.assertEqual(
            split_launch_line("--a=1 --b=2"),
            ["--a=1", "--b=2"],
        )

    def test_single_arg_untouched(self):
        self.assertEqual(split_launch_line("--blob=tls1:@bin/x.bin"), ["--blob=tls1:@bin/x.bin"])

    def test_empty_and_non_flag(self):
        self.assertEqual(split_launch_line("   "), [])
        self.assertEqual(split_launch_line("plain"), ["plain"])


class LaunchArgsFromTextTest(unittest.TestCase):
    def test_skips_comments_and_blank_lines(self):
        text = "# comment\n\n--lua-init=@lua/z.lua\n--dry-run\n"
        self.assertEqual(launch_args_from_text(text), ["--lua-init=@lua/z.lua", "--dry-run"])

    def test_empty_profile(self):
        self.assertEqual(launch_args_from_text("# only comments\n\n"), [])


class MissingReferencesTest(unittest.TestCase):
    def test_returns_missing_local_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "lists"
            path.mkdir()
            (path / "present.txt").write_text("x", encoding="utf-8")
            missing = missing_references("--hostlist=@lists/present.txt\n--hostlist=@lists/absent.txt\n", tmp)
            self.assertEqual(missing, ["@lists/absent.txt"])

    def test_absolute_and_missing_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            missing = missing_references("--lua-init=@lua/z.lua\n", tmp)
            self.assertEqual(missing, ["@lua/z.lua"])


class ValidateProfileTextTest(unittest.TestCase):
    def test_empty_invalid(self):
        self.assertEqual(validate_profile_text("# nope\n"), "profile_empty")

    def test_valid(self):
        self.assertIsNone(validate_profile_text("--dry-run\n"))


class UserProfilesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _patch_dir(self):
        from winws import profiles as p
        import winws.paths as wp
        real = wp.user_profiles_dir
        wp.user_profiles_dir = lambda: Path(self.tmp.name)
        self.addCleanup(setattr, wp, "user_profiles_dir", real)
        return p

    def test_save_list_delete_roundtrip(self):
        p = self._patch_dir()
        self.assertTrue(save_user_profile("My booster", "--dry-run\n").get("ok"))
        items = list_user_profiles()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["name"], "My booster")
        self.assertTrue(delete_user_profile("My booster").get("ok"))
        self.assertEqual(list_user_profiles(), [])

    def test_rejects_bad_names(self):
        p = self._patch_dir()
        for bad in ("../evil", "a\\b", "a/b", "", "x" * 81):
            self.assertTrue(_PROFILE_NAME_RE.match(bad) is None, bad)
            self.assertFalse(save_user_profile(bad, "x").get("ok"), bad)


class EngineModeForTest(unittest.TestCase):
    def test_groups_force_engine(self):
        self.assertEqual(engine_mode_for("winws2"), "winws2")
        self.assertEqual(engine_mode_for("winws1"), "winws1")

    def test_user_uses_cfg_mode(self):
        self.assertEqual(engine_mode_for("user", "winws1"), "winws1")
        self.assertEqual(engine_mode_for("user", "auto"), "auto")


class OrphanedEngineTest(unittest.TestCase):
    def test_detects_orphans_under_engine_dir(self):
        from winws import runner
        with tempfile.TemporaryDirectory() as td:
            exe_dir = Path(td) / "exe"
            exe_dir.mkdir()
            fake_exe = exe_dir / "winws2.exe"
            fake_exe.write_bytes(b"")

            recs = [{"pid": 111, "name": "winws2.exe"}, {"pid": 999, "name": "other.exe"}]
            paths_map = {111: [str(fake_exe)]}

            with patch("utils.windows_process_probe.iter_process_records", return_value=recs), \
                 patch("utils.windows_process_probe.iter_process_module_paths", side_effect=lambda p: paths_map.get(p, [])):
                orphaned = runner._orphaned_engine_pids(str(exe_dir))
            self.assertEqual(orphaned, [111])

    def test_ignores_procs_outside_engine_dir(self):
        from winws import runner
        with tempfile.TemporaryDirectory() as td:
            exe_dir = Path(td) / "exe"
            exe_dir.mkdir()
            outside_dir = Path(td) / "other"
            outside_dir.mkdir()
            fake_exe = outside_dir / "winws.exe"
            fake_exe.write_bytes(b"")

            recs = [{"pid": 222, "name": "winws.exe"}]
            paths_map = {222: [str(fake_exe)]}

            with patch("utils.windows_process_probe.iter_process_records", return_value=recs), \
                 patch("utils.windows_process_probe.iter_process_module_paths", side_effect=lambda p: paths_map.get(p, [])):
                orphaned = runner._orphaned_engine_pids(str(exe_dir))
            self.assertEqual(orphaned, [])

    def test_kill_orphans_calls_kill_api(self):
        from winws import runner
        with tempfile.TemporaryDirectory() as td:
            exe_dir = Path(td) / "exe"
            exe_dir.mkdir()
            fake_exe = exe_dir / "winws.exe"
            fake_exe.write_bytes(b"")

            recs = [{"pid": 333, "name": "winws.exe"}]
            paths_map = {333: [str(fake_exe)]}

            with patch("utils.windows_process_probe.iter_process_records", return_value=recs), \
                 patch("utils.windows_process_probe.iter_process_module_paths", side_effect=lambda p: paths_map.get(p, [])), \
                 patch("utils.process_killer.kill_process_by_pid_winapi", return_value=True) as kill_mock, \
                 patch("winws.runner.time.sleep"):
                killed = runner._kill_orphaned_engines(str(exe_dir))
            self.assertEqual(killed, 1)
            kill_mock.assert_called_once_with(333)

    def test_does_not_kill_own_proc(self):
        from winws import runner
        with tempfile.TemporaryDirectory() as td:
            exe_dir = Path(td) / "exe"
            exe_dir.mkdir()
            fake_exe = exe_dir / "winws2.exe"
            fake_exe.write_bytes(b"")

            recs = [{"pid": 777, "name": "winws2.exe"}]
            paths_map = {777: [str(fake_exe)]}

            with patch("utils.windows_process_probe.iter_process_records", return_value=recs), \
                 patch("utils.windows_process_probe.iter_process_module_paths", side_effect=lambda p: paths_map.get(p, [])), \
                 patch("utils.process_killer.kill_process_by_pid_winapi", return_value=True) as kill_mock, \
                 patch("winws.runner._proc") as mock_proc, \
                 patch("winws.runner.time.sleep"):
                mock_proc.poll.return_value = None
                mock_proc.pid = 777
                killed = runner._kill_orphaned_engines(str(exe_dir))
            self.assertEqual(killed, 0)
            kill_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()