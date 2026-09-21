import tempfile
import unittest
from pathlib import Path

from winws.profiles import (
    _PROFILE_NAME_RE,
    apply_strategy,
    classify_group,
    describe,
    detect_value_type,
    engine_mode_for,
    ensure_recommended,
    get_user_profile_text,
    is_recommended,
    list_user_profiles,
    parse_profile_text,
    profile_delete,
    profile_list,
    profile_read,
    profile_reset,
    profile_write,
    round_trip,
    save_user_profile,
    serialize_profile,
    validate_profile,
)
from winws.profiles.serializer import (
    GROUP_CONFIG,
    GROUP_FILTER,
    GROUP_HOSTLIST,
    GROUP_LUA,
    GROUP_PARAMS,
    VALUE_TYPE_AT,
    VALUE_TYPE_FLAG,
    VALUE_TYPE_INT,
    VALUE_TYPE_OPTIONS,
    VALUE_TYPE_STR,
    VALUE_TYPE_VECTOR,
)
from config.paths import resources_dir

BUNDLED = resources_dir() / "zapret" / "winws2" / "Default (circular) v2.txt"
RECOMMENDED = "Default (circular) v2.txt"


def _bundle_text():
    return BUNDLED.read_text(encoding="utf-8")


class RoundTripTest(unittest.TestCase):
    def test_bundled_round_trip_is_identity(self):
        text = _bundle_text()
        self.assertEqual(round_trip(text), text)

    def test_crlf_preserved(self):
        text = "--dry-run\r\n# c\r\n--new\r\n"
        self.assertEqual(round_trip(text), text)


class DetectValueTypeTest(unittest.TestCase):
    def test_int(self):
        self.assertEqual(detect_value_type("0", "--ctrack-disable"), VALUE_TYPE_INT)
        self.assertEqual(detect_value_type("-1000", "--x"), VALUE_TYPE_INT)
        self.assertEqual(detect_value_type("0x0F", "--x"), VALUE_TYPE_INT)

    def test_vector(self):
        self.assertEqual(detect_value_type("80,443-65535", "--filter-tcp"), VALUE_TYPE_VECTOR)

    def test_at_flag(self):
        self.assertEqual(detect_value_type("@lua/zapret-lib.lua", "--lua-init"), VALUE_TYPE_AT)

    def test_options(self):
        self.assertEqual(
            detect_value_type("circular:fails=1:time=300", "--lua-desync"), VALUE_TYPE_OPTIONS
        )
        self.assertEqual(detect_value_type("tls1:@bin/x.bin", "--blob"), VALUE_TYPE_OPTIONS)

    def test_str_and_flag(self):
        self.assertEqual(detect_value_type("Исключения домены (RU сайты)", "--name"), VALUE_TYPE_STR)
        self.assertEqual(detect_value_type("", "--new"), VALUE_TYPE_FLAG)


class ClassifyGroupTest(unittest.TestCase):
    def test_groups(self):
        self.assertEqual(classify_group("--filter-tcp"), GROUP_FILTER)
        self.assertEqual(classify_group("--lua-desync"), GROUP_LUA)
        self.assertEqual(classify_group("--hostlist"), GROUP_HOSTLIST)
        self.assertEqual(classify_group("--ipset"), GROUP_HOSTLIST)
        self.assertEqual(classify_group("--ctrack-disable"), GROUP_CONFIG)
        self.assertEqual(classify_group("--wf-raw-part"), GROUP_CONFIG)
        self.assertEqual(classify_group("--out-range"), GROUP_PARAMS)


class ModelEditTest(unittest.TestCase):
    def test_get_set_add_remove(self):
        model = parse_profile_text("--a=1\n--b=2\n--a=3\n")
        self.assertEqual(model.get("--a"), "1")
        self.assertEqual(model.get_values("--a"), ["1", "3"])
        self.assertTrue(model.set("--a", "9", 1))
        self.assertEqual(model.get("--a"), "1")
        self.assertEqual(model.get_values("--a"), ["1", "9"])
        self.assertTrue(model.add("--c", "42"))
        self.assertEqual(model.get_values("--c"), ["42"])
        self.assertEqual(model.remove("--a", 0), 1)
        self.assertEqual(model.get_values("--a"), ["9"])

    def test_serialize_affects_only_edited_lines(self):
        model = parse_profile_text("--a=1\n# keep\n--b=2")
        model.set("--b", "5")
        before = serialize_profile(model)
        self.assertIn("--a=1", before)
        self.assertIn("# keep", before)
        self.assertIn("--b=5", before)

    def test_apply_strategy(self):
        model = parse_profile_text("--dry-run\n")
        out = apply_strategy(model, {
            "set": {"--ctrack-disable": "1"},
            "add": {"--lua-init": "@lua/custom.lua"},
            "remove": ["--dry-run"],
        })
        self.assertEqual(out.get("--ctrack-disable"), "1")
        self.assertEqual(out.get_values("--lua-init"), ["@lua/custom.lua"])
        self.assertIsNone(out.get("--dry-run"))


class ValidateTest(unittest.TestCase):
    def test_valid_profile(self):
        v = validate_profile("--dry-run\n--filter-tcp=80,443\n")
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["param_count"], 2)
        self.assertEqual(v["parameters"]["--filter-tcp"], ["80,443"])

    def test_empty_profile(self):
        v = validate_profile("# только комментарий\n\n")
        self.assertFalse(v["ok"])
        self.assertIn("profile_empty", [e["message"] for e in v["errors"]])

    def test_broken_encoding(self):
        v = validate_profile("--ctrack-disable=\x00abc\n")
        self.assertFalse(v["ok"])
        self.assertIn("broken_encoding", [e["message"] for e in v["errors"]])

    def test_bad_int_value(self):
        v = validate_profile("--ctrack-disable=yes\n")
        self.assertFalse(v["ok"])
        self.assertIn("bad_int_value", [e["message"] for e in v["errors"]])

    def test_not_an_option_warning(self):
        v = validate_profile("plain line\n--dry-run\n")
        self.assertTrue(v["ok"], v)
        self.assertIn("not_an_option", [w["message"] for w in v["warnings"]])

    def test_bundled_valid(self):
        v = validate_profile(_bundle_text())
        self.assertTrue(v["ok"], v)
        self.assertEqual(v["warnings"], [])
        self.assertEqual(v["param_count"], 154)

    def test_describe_groups(self):
        model = parse_profile_text("--filter-tcp=443\n--lua-init=@lua/z.lua\n")
        desc = describe(model)
        self.assertEqual(len(desc[GROUP_FILTER]), 1)
        self.assertEqual(len(desc[GROUP_LUA]), 1)


class ProfileEngineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pf = Path(self.tmp.name)
        import winws.paths as wp
        real = wp.user_profiles_dir
        wp.user_profiles_dir = lambda: self.pf
        self.addCleanup(setattr, wp, "user_profiles_dir", real)

    def tearDown(self):
        self.tmp.cleanup()

    def _patch_active(self, active):
        import winws.profiles.instance as inst
        real = inst.get_active_profile
        inst.get_active_profile = lambda: active
        self.addCleanup(setattr, inst, "get_active_profile", real)

    def test_ensure_recommended_copies_bundle(self):
        path = ensure_recommended()
        self.assertIsNotNone(path)
        self.assertEqual(path.read_text(encoding="utf-8"), _bundle_text())
        self.assertTrue(is_recommended(path.name))

    def test_profile_write_read_list_delete(self):
        ensure_recommended()
        self.assertTrue(profile_write("My booster", "--dry-run\n").get("ok"))
        res = profile_read("My booster")
        self.assertTrue(res.get("ok"))
        self.assertEqual(res["content"], "--dry-run\n")
        self.assertTrue(res["validation"]["ok"])
        items = list_user_profiles()
        self.assertEqual([it["name"] for it in items], [RECOMMENDED[:-4], "My booster"])
        self.assertTrue(profile_delete("My booster").get("ok"))
        self.assertEqual([it["name"] for it in list_user_profiles()], [RECOMMENDED[:-4]])

    def test_profile_read_recommended(self):
        ensure_recommended()
        res = profile_read(RECOMMENDED)
        self.assertTrue(res.get("ok"))
        self.assertTrue(res["is_recommended"])
        self.assertTrue(res["validation"]["ok"])

    def test_profile_write_carries_verdict(self):
        res = profile_write("Broken", "--ctrack-disable=abc\n")
        self.assertTrue(res.get("ok"))
        self.assertFalse(res["validation"]["ok"])
        self.assertIn("bad_int_value", [e["message"] for e in res["validation"]["errors"]])

    def test_delete_recommended_protected(self):
        ensure_recommended()
        res = profile_delete(RECOMMENDED)
        self.assertFalse(res.get("ok"))
        self.assertEqual(res["error"], "protected_recommended")

    def test_reset_only_for_recommended(self):
        self.assertTrue(save_user_profile("Custom", "--dry-run\n").get("ok"))
        self.assertFalse(profile_reset("Custom").get("ok"))
        ensure_recommended()
        res = profile_reset(RECOMMENDED)
        self.assertTrue(res.get("ok"))
        self.assertEqual(res["content"], _bundle_text())

    def test_delete_active_protected(self):
        self.assertTrue(save_user_profile("Solo", "--dry-run\n").get("ok"))
        self._patch_active({"group": "user", "profile": "Solo", "enabled": True, "is_user": True})
        res = profile_delete("Solo")
        self.assertFalse(res.get("ok"))
        self.assertEqual(res["error"], "protected_active")

    def test_rejects_bad_names(self):
        for bad in ("../evil", "a\\b", "a/b", "", "x" * 81, "a<b"):
            self.assertTrue(_PROFILE_NAME_RE.match(bad) is None, bad)
            self.assertFalse(profile_write(bad, "--dry-run\n").get("ok"), bad)

    def test_profile_list_shape(self):
        ensure_recommended()
        self._patch_active({"group": "user", "profile": RECOMMENDED, "enabled": True, "is_user": True, "is_recommended": True})
        res = profile_list()
        self.assertTrue(res.get("ok"))
        self.assertEqual(res["recommended"], RECOMMENDED)
        names = [p["name"] for p in res["profiles"]]
        self.assertIn(RECOMMENDED[:-4], names)
        self.assertTrue(any(p["is_recommended"] for p in res["profiles"]))
        self.assertTrue(res["active"]["is_recommended"])

    def test_get_active_profile_store_pure(self):
        from winws.profiles.instance import _active_from_store
        self.assertEqual(_active_from_store({})["group"], "winws2")
        self.assertEqual(
            _active_from_store({"profile_group": "user", "profile": RECOMMENDED, "enabled": True})["is_recommended"],
            True,
        )


class ResolveApiTest(unittest.TestCase):
    def test_engine_mode(self):
        self.assertEqual(engine_mode_for("winws2"), "winws2")
        self.assertEqual(engine_mode_for("user", "winws1"), "winws1")
        self.assertEqual(engine_mode_for("user", "auto"), "auto")


class ApiProfileSmokeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.pf = Path(self.tmp.name)
        import winws.paths as wp
        real = wp.user_profiles_dir
        wp.user_profiles_dir = lambda: self.pf
        self.addCleanup(setattr, wp, "user_profiles_dir", real)
        import winws.profiles.instance as inst
        inst.get_active_profile = lambda: {"group": "user", "profile": "", "enabled": False, "is_user": True}
        self.addCleanup(delattr, inst, "get_active_profile")

    def tearDown(self):
        self.tmp.cleanup()

    def _api(self):
        from ui.api import SwiftAPI
        return SwiftAPI()

    def test_profile_flow_via_api(self):
        api = self._api()
        res = api.profile_write("Test", "--dry-run\n--filter-tcp=443\n")
        self.assertTrue(res.get("ok"))
        self.assertTrue(res["validation"]["ok"])
        self.assertEqual(res["validation"]["param_count"], 2)
        lst = api.profile_list()
        self.assertTrue(lst["ok"])
        names = [p["name"] for p in lst["profiles"]]
        self.assertIn("Test", names)
        read = api.profile_read("Test")
        self.assertTrue(read["ok"])
        self.assertEqual(read["content"], "--dry-run\n--filter-tcp=443\n")
        verdict = api.profile_validate_paste("--ctrack-disable=oops\n")
        self.assertFalse(verdict["ok"])
        self.assertIn("bad_int_value", [e["message"] for e in verdict["errors"]])
        deleted = api.profile_delete("Test")
        self.assertTrue(deleted["ok"])
        gone = api.get_zapret_user_profile("Test")
        self.assertFalse(gone.get("ok"))
        self.assertEqual(gone["error"], "not_found")

    def test_profile_reset_via_api(self):
        api = self._api()
        res = api.profile_reset(RECOMMENDED)
        self.assertTrue(res.get("ok"))
        self.assertEqual(res["content"], _bundle_text())
        self.assertTrue(res["is_recommended"])


if __name__ == "__main__":
    unittest.main()