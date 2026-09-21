import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from config.paths import resources_dir
from winws.profiles import parse_profile_text, round_trip, validate_profile

from blockcheck.orchestra import (
    apply_strategy_to_profile,
    available_strategies,
    backup_profile,
    create_strategy_for_failure_type,
    extract_symptoms,
    find_strategy_by_id,
    orchestra_recommend,
    parse_symptoms_text,
    rank_recommendations,
)

BUNDLED = resources_dir() / "zapret" / "winws2" / "Default (circular) v2.txt"
RECOMMENDED = "Default (circular) v2.txt"


def _bundle_text():
    return BUNDLED.read_text(encoding="utf-8")


def _tls_report():
    return {
        "targets": [
            {
                "name": "example.com",
                "value": "example.com",
                "tests": [
                    {"target_name": "example.com", "test_type": "tcp_connect", "status": "ok",
                     "error_code": "", "detail": "", "time_ms": 10},
                    {"target_name": "example.com", "test_type": "tls12", "status": "fail",
                     "error_code": "TLS_RESET", "detail": "", "time_ms": 10},
                    {"target_name": "example.com", "test_type": "tls13", "status": "fail",
                     "error_code": "TLS_EOF_EARLY", "detail": "", "time_ms": 10},
                ],
                "classification": "tls_dpi",
                "classification_detail": "",
                "outcome": "blocked",
                "inconclusive_reason": None,
                "informational": False,
            }
        ],
        "dns_integrity": [
            {
                "domain": "example.com", "udp_ips": ["1.2.3.4"], "doh_ips": ["1.2.3.4"],
                "is_comparable": True, "is_consistent": False, "is_stub": True,
                "verdict": "fake", "evidence": [],
            }
        ],
        "baseline": {
            "probed": True, "internet_ok": True, "tls_ok": True, "icmp_usable": True,
            "ipv6_usable": False, "http80_usable": True, "doh_usable": True,
            "control_hosts": ["example.com"], "detail": "",
        },
        "verdict": {
            "code": "signatures", "headline": "tls_dpi",
            "confirmed": [{"classification": "tls_dpi", "targets": ["example.com"], "share": 1.0}],
            "isolated": [], "valid_targets": 5, "blocked_targets": 1,
            "inconclusive_targets": 0, "detail": "",
        },
    }


def _stun_report():
    return {
        "targets": [
            {
                "name": "discord.com", "value": "discord.com",
                "tests": [
                    {"target_name": "discord.com", "test_type": "stun", "status": "fail",
                     "error_code": "", "detail": "", "time_ms": 10},
                ],
                "classification": "stun_block",
                "classification_detail": "",
                "outcome": "blocked",
                "inconclusive_reason": None,
                "informational": False,
            }
        ],
        "dns_integrity": [],
        "baseline": {"probed": True, "internet_ok": True, "tls_ok": True},
        "verdict": {
            "code": "signatures", "headline": "stun_block",
            "confirmed": [], "isolated": [], "valid_targets": 5,
            "blocked_targets": 1, "inconclusive_targets": 0, "detail": "",
        },
    }


class CatalogTest(unittest.TestCase):
    def test_strategies_have_unique_ids(self):
        ids = [s["id"] for s in available_strategies()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_strategy_has_lane(self):
        for s in available_strategies():
            full = find_strategy_by_id(s["id"])
            lanes = full["parameters"]["add"].get("--lua-desync")
            self.assertTrue(lanes, s["id"])

    def test_find_known(self):
        self.assertEqual(find_strategy_by_id("gs_tls_fake_only")["id"], "gs_tls_fake_only")

    def test_find_unknown(self):
        self.assertIsNone(find_strategy_by_id("gs_missing"))

    def test_failure_type_mapping(self):
        rec = create_strategy_for_failure_type("sni")
        self.assertEqual(rec["id"], "gs_tls_fake_only")
        self.assertTrue(create_strategy_for_failure_type("quic"))
        self.assertIsNone(create_strategy_for_failure_type("bogus"))


class RankRecommendationsTest(unittest.TestCase):
    def test_single_symptom_probability(self):
        top = rank_recommendations(["tls_reset"], limit=5)
        self.assertTrue(top)
        self.assertEqual(top[0]["strategy"], "gs_tls_fake_only")
        self.assertEqual(top[0]["probability"], 0.6)
        self.assertEqual(top[0]["matched_symptoms"][0]["symptom"], "tls_reset")

    def test_probability_grows_with_matches(self):
        top = rank_recommendations(["tls_reset", "tcp_reset", "http_inject"], limit=5)
        by_id = {t["strategy"]: t for t in top}
        self.assertGreaterEqual(by_id["gs_hostfakesplit_multi"]["probability"], 0.75)

    def test_probability_cap(self):
        top = rank_recommendations(["tls_reset", "tcp_reset", "http_inject", "just_block"], limit=20)
        for entry in top:
            self.assertLessEqual(entry["probability"], 0.95)

    def test_limit(self):
        top = rank_recommendations(["tls_reset"], limit=3)
        self.assertLessEqual(len(top), 3)

    def test_unknown_symptom(self):
        self.assertEqual(rank_recommendations(["bogus"], limit=5), [])

    def test_sorted_by_probability(self):
        top = rank_recommendations(["tls_reset", "tcp_reset", "http_inject"], limit=20)
        probs = [t["probability"] for t in top]
        self.assertEqual(probs, sorted(probs, reverse=True))


class ParseSymptomsTextTest(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(parse_symptoms_text(""), [])
        self.assertEqual(parse_symptoms_text(None), [])

    def test_english_tokens(self):
        keys = parse_symptoms_text("dns poisoning, tls reset, quic")
        self.assertIn("dns_poisoning", keys)
        self.assertIn("tls_reset", keys)
        self.assertIn("quic_drop", keys)

    def test_russian_tokens(self):
        keys = parse_symptoms_text("обрыв на 16-20 кб, discord стоп")
        self.assertIn("tcp_16_20", keys)
        self.assertIn("stun_block", keys)

    def test_mitm(self):
        self.assertIn("tls_mitm", parse_symptoms_text("tls mitm dpi"))

    def test_site_blocked(self):
        self.assertIn("just_block", parse_symptoms_text("сайт заблокирован"))


class ExtractSymptomsTest(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(extract_symptoms(None), [])
        self.assertEqual(extract_symptoms({}), [])

    def test_tls_report(self):
        keys = extract_symptoms(_tls_report())
        self.assertIn("dns_poisoning", keys)
        self.assertIn("tls_reset", keys)
        self.assertNotIn("full_block", keys)

    def test_no_internet(self):
        report = _tls_report()
        report["verdict"] = {"code": "no_internet", "headline": ""}
        self.assertEqual(extract_symptoms(report), [])

    def test_stun_report(self):
        keys = extract_symptoms(_stun_report())
        self.assertIn("stun_block", keys)

    def test_just_block(self):
        report = _stun_report()
        report["targets"][0]["classification"] = None
        report["targets"][0]["tests"] = []
        report["targets"][0]["classification_detail"] = ""
        keys = extract_symptoms(report)
        self.assertIn("just_block", keys)

    def test_quic_hint_from_detail(self):
        report = _stun_report()
        report["targets"][0]["classification"] = None
        report["targets"][0]["tests"] = []
        report["targets"][0]["classification_detail"] = "upstream quic filter"
        keys = extract_symptoms(report)
        self.assertIn("quic_drop", keys)


class ApplyStrategyTest(unittest.TestCase):
    def test_udp_round_robin_appends_lanes(self):
        text = _bundle_text()
        strategy = find_strategy_by_id("gs_fake_quic_x10_autottl")
        res = apply_strategy_to_profile(text, strategy)
        self.assertTrue(res["ok"])
        self.assertEqual(res["mode"], "section")
        self.assertTrue(res["round_robin"])
        self.assertEqual(res["n_removed"], 0)
        self.assertEqual(res["n_added"], 1)
        lane = "--lua-desync=fake:blob=quic_google:ip_autottl=-2,3-20:ip6_autottl=-2,3-20:repeats=10:payload=all"
        self.assertIn(lane, res["content"])
        self.assertEqual(res["content"].count("circular:"), text.count("circular:"))
        self.assertEqual(res["content"].count(":strategy="), text.count(":strategy="))

    def test_udp_applied_content_still_valid(self):
        text = _bundle_text()
        strategy = find_strategy_by_id("gs_fake_quic_x10_autottl")
        res = apply_strategy_to_profile(text, strategy)
        self.assertTrue(validate_profile(res["content"])["ok"])
        self.assertEqual(round_trip(res["content"]), res["content"])

    def test_tcp_linear_replaces_lane(self):
        text = _bundle_text()
        strategy = find_strategy_by_id("gs_tls_fake_only")
        res = apply_strategy_to_profile(text, strategy)
        self.assertTrue(res["ok"])
        self.assertEqual(res["mode"], "section")
        self.assertFalse(res["round_robin"])
        self.assertGreaterEqual(res["n_removed"], 1)
        self.assertEqual(res["n_added"], 1)
        self.assertTrue(validate_profile(res["content"])["ok"])

    def test_multi_lane_strategy(self):
        strategy = find_strategy_by_id("gs_hostfakesplit_multi_syndata")
        res = apply_strategy_to_profile(_bundle_text(), strategy)
        self.assertEqual(res["n_added"], 3)
        model = parse_profile_text(res["content"])
        lanes = model.get_values("--lua-desync")
        self.assertIn("syndata:blob=stun_pat", lanes)
        self.assertIn("hostfakesplit_multi:hosts=google.com,vimeo.com:tcp_ts=-1000:tcp_md5:repeats=2", lanes)

    def test_section_name_routing(self):
        profile = (
            "--filter-tcp=80\n"
            "--name=Main\n"
            "--lua-desync=pass\n"
            "--new\n"
            "--filter-udp=443\n"
            "--name=Voice\n"
            "--lua-desync=pass\n"
        )
        strategy = find_strategy_by_id("gs_fake_stun_x6")
        res = apply_strategy_to_profile(profile, strategy, section_name="Voice")
        self.assertTrue(res["ok"])
        self.assertEqual(res["mode"], "section")
        self.assertEqual(res["section_name"], "Voice")
        self.assertEqual(res["n_removed"], 1)
        section_main, section_voice = res["content"].split("--new")
        main_lanes = [l for l in section_main.splitlines() if l.startswith("--lua-desync")]
        voice_lanes = [l for l in section_voice.splitlines() if l.startswith("--lua-desync")]
        self.assertEqual(main_lanes, ["--lua-desync=pass"])
        self.assertIn("--lua-desync=fake:blob=0x00:repeats=6", voice_lanes)

    def test_section_name_missing_uses_whole_profile(self):
        profile = "--filter-tcp=80\n--lua-desync=pass\n"
        strategy = find_strategy_by_id("gs_tls_fake_only")
        res = apply_strategy_to_profile(profile, strategy, section_name="Nope")
        self.assertTrue(res["ok"])
        self.assertEqual(res["mode"], "whole")

    def test_no_strategy_lanes(self):
        strategy = {"id": "x", "category": "tcp", "parameters": {"add": {"--lua-desync": []}}}
        res = apply_strategy_to_profile("--filter-tcp=80\n", strategy)
        self.assertFalse(res["ok"])
        self.assertEqual(res["error"], "no_strategy_lanes")


class BackupProfileTest(unittest.TestCase):
    def test_backup_writes_copy(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch("blockcheck.orchestra.strategy_applier.profile_dir", return_value=Path(tmp)), \
                 patch(
                    "blockcheck.orchestra.strategy_applier.get_user_profile_text",
                    return_value={"ok": True, "name": "My Profile", "text": "--lua-desync=pass\n"},
                 ):
                res = backup_profile("My Profile")
            self.assertTrue(res["ok"])
            self.assertTrue(Path(tmp, res["file"]).is_file())
            self.assertTrue(res["path"].startswith(str(tmp)))

    def test_backup_missing_profile(self):
        with patch(
            "blockcheck.orchestra.strategy_applier.get_user_profile_text",
            return_value={"ok": False, "error": "not_found"},
        ):
            res = backup_profile("nope")
        self.assertFalse(res["ok"])


class OrchestraRecommendTest(unittest.TestCase):
    def test_recommend_from_report(self):
        res = orchestra_recommend(report=_tls_report())
        self.assertTrue(res["ok"])
        self.assertEqual(res["source"], "report")
        self.assertIn("tls_reset", [s["key"] for s in res["symptoms"]])
        self.assertTrue(res["recommendations"])
        self.assertEqual(res["failure_type"], "sni")

    def test_recommend_from_text_overrides_report(self):
        res = orchestra_recommend(symptoms_text="stun, discord", report=_tls_report())
        self.assertEqual(res["source"], "text")
        self.assertEqual([s["key"] for s in res["symptoms"]], ["stun_block"])

    def test_recommend_empty(self):
        res = orchestra_recommend(report=None)
        self.assertTrue(res["ok"])
        self.assertEqual(res["recommendations"], [])
        self.assertIsNone(res["failure_type"])


if __name__ == "__main__":
    unittest.main()