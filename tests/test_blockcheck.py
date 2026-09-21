import unittest
from unittest.mock import patch

from blockcheck import models as m
from blockcheck.dpi_classifier import classify_connect_error, classify_read_error, classify_ssl_error
from blockcheck.dns_integrity import judge_domain
from blockcheck.hosts import base_domain, host_candidates, host_of, is_pseudo_target
from blockcheck.models import (
    BlockcheckReport,
    DnsVerdict,
    DPIClassification,
    InconclusiveReason,
    NetworkBaseline,
    PreflightResult,
    PreflightVerdict,
    SingleTestResult,
    TargetOutcome,
    TargetResult,
    VerdictCode,
)
from blockcheck.preflight import _compute_verdict, check_one_domain
from blockcheck.service import build_targets, run_single_domain_check
from blockcheck.verdict import build_report_verdict, judge_target


def _ok(host="example.com", test_type=m.TestType.HTTP):
    return SingleTestResult(target_name=host, test_type=test_type, status=m.TestStatus.OK)


def _fail(host, code, test_type=m.TestType.HTTP):
    return SingleTestResult(
        target_name=host, test_type=test_type,
        status=m.TestStatus.FAIL, error_code=code,
    )


def _result(name="x", value="https://x.example", tests=None):
    tr = TargetResult(name=name, value=value)
    if tests:
        tr.tests = tests
    return tr


def _baseline(ok=True):
    return NetworkBaseline(
        probed=True, internet_ok=ok, tls_ok=ok,
        icmp_usable=True, ipv6_usable=False, doh_usable=True,
    )


class HostsTest(unittest.TestCase):
    def test_pseudo_targets(self):
        self.assertTrue(is_pseudo_target("PING:1.1.1.1"))
        self.assertTrue(is_pseudo_target("STUN:stun.l.google.com:19302"))
        self.assertTrue(is_pseudo_target("TCP:16-20KB"))
        self.assertFalse(is_pseudo_target("https://example.com"))

    def test_host_of(self):
        self.assertEqual(host_of("https://Example.COM:443/path?q=1"), "example.com")
        self.assertEqual(host_of("example.com:443"), "example.com")
        self.assertEqual(host_of("www.example.com."), "www.example.com")
        self.assertEqual(host_of("[2606:4700::1111]:443"), "2606:4700::1111")

    def test_base_domain(self):
        self.assertEqual(base_domain("bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(base_domain("www.bbc.co.uk"), "bbc.co.uk")
        self.assertEqual(base_domain("a.b.example.com"), "example.com")
        self.assertEqual(base_domain("example.com"), "example.com")
        self.assertEqual(base_domain("www.example.com"), "example.com")

    def test_host_candidates(self):
        candidates = host_candidates("https://www.facebook.com")
        self.assertIn("www.facebook.com", candidates)
        self.assertIn("facebook.com", candidates)
        self.assertEqual(candidates, {"www.facebook.com", "facebook.com"})
        self.assertEqual(host_candidates("1.1.1.1"), {"1.1.1.1", "1.1"})


class DPIClassifierTest(unittest.TestCase):
    def test_ssl_reset(self):
        label, detail, _ = classify_ssl_error(ConnectionResetError(0, "Connection reset"))
        self.assertEqual(label, "TLS_RESET")

    def test_ssl_eof_early(self):
        label, _, _ = classify_ssl_error(OSError(0, "unexpected eof occurred"))
        self.assertEqual(label, "TLS_EOF_EARLY")

    def test_ssl_mitm(self):
        label, _, _ = classify_ssl_error(ValueError("certificate verify failed"))
        self.assertIn(label, ("TLS_CERT_ERR", "TLS_MITM_SELF", "TLS_MITM_UNKNOWN_CA"))

    def test_ssl_unsupported(self):
        label, _, _ = classify_ssl_error(ValueError("no protocols available"))
        self.assertEqual(label, "TLS_UNSUPPORTED")

    def test_connect_reset(self):
        label, _, _ = classify_connect_error(ConnectionResetError())
        self.assertEqual(label, "TCP_RESET")

    def test_connect_timeout(self):
        label, _, _ = classify_connect_error(OSError(0, "timed out"))
        self.assertEqual(label, "TCP_TIMEOUT")

    def test_connect_unreach(self):
        label, _, _ = classify_connect_error(OSError(10065, "no route to host"))
        self.assertEqual(label, "HOST_UNREACH")

    def test_read_reset(self):
        label, _, _ = classify_read_error(ConnectionResetError(0, "Connection reset"))
        self.assertEqual(label, "READ_RESET")


class VerdictJudgeTest(unittest.TestCase):
    def test_ok(self):
        judgement = judge_target(_result(tests=[_ok()]), _baseline())
        self.assertEqual(judgement.outcome, TargetOutcome.OK)

    def test_tls_drop(self):
        judgement = judge_target(
            _result(tests=[_fail("x", "TLS_RESET")]), _baseline(),
        )
        self.assertEqual(judgement.outcome, TargetOutcome.BLOCKED)
        self.assertEqual(judgement.classification, DPIClassification.TLS_DPI)

    def test_resolution_failed(self):
        judgement = judge_target(
            _result(tests=[_fail("x", "DNS_ERR")]), _baseline(),
        )
        self.assertEqual(judgement.outcome, TargetOutcome.INCONCLUSIVE)
        self.assertEqual(judgement.reason, InconclusiveReason.HOST_NOT_RESOLVED)

    def test_no_baseline(self):
        judgement = judge_target(
            _result(tests=[_fail("x", "TLS_RESET")]), _baseline(ok=False),
        )
        self.assertEqual(judgement.outcome, TargetOutcome.INCONCLUSIVE)
        self.assertEqual(judgement.reason, InconclusiveReason.NO_BASELINE)

    def test_not_probed(self):
        judgement = judge_target(_result(tests=[]), _baseline())
        self.assertEqual(judgement.outcome, TargetOutcome.INCONCLUSIVE)
        self.assertEqual(judgement.reason, InconclusiveReason.NOT_PROBED)

    def test_full_block_requires_sample(self):
        judgement = judge_target(
            _result(tests=[_fail("x", "TLS_RESET")]), _baseline(),
        )
        self.assertNotEqual(judgement.classification, DPIClassification.FULL_BLOCK)

    def test_full_block(self):
        tests = [
            _fail("x", "TIMEOUT"),
            _fail("x", "TIMEOUT", m.TestType.TLS_12),
            _fail("x", "TIMEOUT", m.TestType.TLS_13),
        ]
        judgement = judge_target(_result(tests=tests), _baseline())
        self.assertEqual(judgement.outcome, TargetOutcome.BLOCKED)
        self.assertEqual(judgement.classification, DPIClassification.FULL_BLOCK)


class VerdictAggregateTest(unittest.TestCase):
    def test_clean(self):
        targets = [_result(name=f"t{i}", tests=[_ok()]) for i in range(3)]
        for t in targets:
            t.outcome = TargetOutcome.OK
        verdict = build_report_verdict(targets, _baseline())
        self.assertEqual(verdict.code, VerdictCode.CLEAN)
        self.assertEqual(verdict.valid_targets, 3)

    def test_signatures_quorum(self):
        targets = [
            _result(name=f"t{i}", tests=[_fail("x", "TLS_RESET")]) for i in range(3)
        ]
        for t in targets:
            t.outcome = TargetOutcome.BLOCKED
            t.classification = DPIClassification.TLS_DPI
        verdict = build_report_verdict(targets, _baseline())
        self.assertEqual(verdict.code, VerdictCode.SIGNATURES)
        self.assertEqual(verdict.headline, DPIClassification.TLS_DPI)
        self.assertEqual(verdict.blocked_targets, 3)

    def test_single_target_full_block(self):
        tests = [
            _fail("x", "TIMEOUT"),
            _fail("x", "TIMEOUT", m.TestType.TLS_12),
            _fail("x", "TIMEOUT", m.TestType.TLS_13),
        ]
        target = _result(tests=tests)
        target.outcome = TargetOutcome.BLOCKED
        target.classification = DPIClassification.FULL_BLOCK
        verdict = build_report_verdict([target], _baseline())
        self.assertEqual(verdict.code, VerdictCode.SIGNATURES)
        self.assertEqual(verdict.headline, DPIClassification.FULL_BLOCK)

    def test_partial_no_headline(self):
        ok_targets = [_result(name=f"ok{i}", tests=[_ok()]) for i in range(3)]
        for t in ok_targets:
            t.outcome = TargetOutcome.OK
        blocked = []
        for i in range(2):
            tests = [
                _fail("x", "TIMEOUT"),
                _fail("x", "TIMEOUT", m.TestType.TLS_12),
                _fail("x", "TIMEOUT", m.TestType.TLS_13),
            ]
            t = _result(name=f"bl{i}", tests=tests)
            t.outcome = TargetOutcome.BLOCKED
            t.classification = DPIClassification.FULL_BLOCK
            blocked.append(t)
        verdict = build_report_verdict(ok_targets + blocked, _baseline())
        self.assertEqual(verdict.code, VerdictCode.PARTIAL)
        self.assertIsNone(verdict.headline)

    def test_no_internet(self):
        targets = [_result(name="t", tests=[_ok()])]
        verdict = build_report_verdict(targets, _baseline(ok=False))
        self.assertEqual(verdict.code, VerdictCode.NO_INTERNET)

    def test_unreliable(self):
        targets = [_result(name="t", tests=[_fail("x", "DNS_ERR")])]
        verdict = build_report_verdict(targets, _baseline())
        self.assertEqual(verdict.code, VerdictCode.UNRELIABLE)
        self.assertEqual(verdict.inconclusive_targets, 1)

    def test_informational_excluded(self):
        ok_target = _result(name="ok", tests=[_ok()])
        ok_target.outcome = TargetOutcome.OK
        info = TargetResult(name="stun", value="STUN:x", informational=True)
        info.tests = [_fail("x", "TIMEOUT", m.TestType.STUN)]
        info.outcome = TargetOutcome.BLOCKED
        info.classification = DPIClassification.STUN_BLOCK
        verdict = build_report_verdict([ok_target, info], _baseline())
        self.assertEqual(verdict.code, VerdictCode.CLEAN)
        self.assertEqual(verdict.valid_targets, 1)


class DNSJudgeTest(unittest.TestCase):
    def test_stub_ip(self):
        result = judge_domain(
            "example.com", ["127.0.0.1"], ["93.184.216.34"],
            {"127.0.0.1", "10.10.10.10"},
        )
        self.assertEqual(result.verdict, DnsVerdict.FAKE)
        self.assertTrue(result.is_stub)
        self.assertEqual(result.stub_ip, "127.0.0.1")

    def test_matching_addresses(self):
        result = judge_domain(
            "example.com", ["93.184.216.34"], ["93.184.216.34"], set(),
        )
        self.assertEqual(result.verdict, DnsVerdict.OK)

    def test_valid_cert_differs_from_doh(self):
        result = judge_domain(
            "example.com", ["1.2.3.4"], ["5.6.7.8"], set(),
            verify=lambda domain, ip: True,
        )
        self.assertEqual(result.verdict, DnsVerdict.OK)

    def test_fake_cert(self):
        result = judge_domain(
            "example.com", ["1.2.3.4"], ["5.6.7.8"], set(),
            verify=lambda domain, ip: False if ip == "1.2.3.4" else True,
        )
        self.assertEqual(result.verdict, DnsVerdict.FAKE)
        self.assertFalse(result.is_consistent)

    def test_cert_intercept_both_invalid(self):
        result = judge_domain(
            "example.com", ["1.2.3.4"], ["5.6.7.8"], set(),
            verify=lambda domain, ip: False,
        )
        self.assertEqual(result.verdict, DnsVerdict.INCONCLUSIVE)


class PreflightVerdictTest(unittest.TestCase):
    def test_passed(self):
        pf = PreflightResult(domain="x")
        pf.dns_result = SingleTestResult("x", m.TestType.PREFLIGHT_DNS, m.TestStatus.OK)
        pf.tcp_443 = SingleTestResult("x", m.TestType.PREFLIGHT_TCP, m.TestStatus.OK)
        pf.ping = SingleTestResult("x", m.TestType.PREFLIGHT_PING, m.TestStatus.TIMEOUT)
        pf.http_check = SingleTestResult("x", m.TestType.PREFLIGHT_HTTP, m.TestStatus.OK)
        verdict, _ = _compute_verdict(pf)
        self.assertEqual(verdict, PreflightVerdict.PASSED)

    def test_block_ip(self):
        pf = PreflightResult(domain="x")
        pf.dns_result = SingleTestResult(
            "x", m.TestType.PREFLIGHT_DNS, m.TestStatus.FAIL,
            error_code="BLOCK_IP", detail="IP-заглушка Ростелеком",
        )
        pf.is_block_ip = True
        pf.block_ip_detail = pf.dns_result.detail
        pf.tcp_443 = SingleTestResult("x", m.TestType.PREFLIGHT_TCP, m.TestStatus.OK)
        pf.http_check = SingleTestResult("x", m.TestType.PREFLIGHT_HTTP, m.TestStatus.OK)
        verdict, detail = _compute_verdict(pf)
        self.assertEqual(verdict, PreflightVerdict.FAILED)
        self.assertIn("заглушка", detail)

    def test_http_inject(self):
        pf = PreflightResult(domain="x")
        pf.dns_result = SingleTestResult("x", m.TestType.PREFLIGHT_DNS, m.TestStatus.OK)
        pf.tcp_443 = SingleTestResult("x", m.TestType.PREFLIGHT_TCP, m.TestStatus.OK)
        pf.http_check = SingleTestResult(
            "x", m.TestType.PREFLIGHT_HTTP, m.TestStatus.FAIL,
            error_code="HTTP_INJECT",
        )
        verdict, _ = _compute_verdict(pf)
        self.assertEqual(verdict, PreflightVerdict.FAILED)

    def test_tcp_warning(self):
        pf = PreflightResult(domain="x")
        pf.dns_result = SingleTestResult("x", m.TestType.PREFLIGHT_DNS, m.TestStatus.OK)
        pf.tcp_443 = SingleTestResult(
            "x", m.TestType.PREFLIGHT_TCP, m.TestStatus.TIMEOUT,
            error_code="TIMEOUT",
        )
        pf.http_check = SingleTestResult("x", m.TestType.PREFLIGHT_HTTP, m.TestStatus.OK)
        verdict, _ = _compute_verdict(pf)
        self.assertEqual(verdict, PreflightVerdict.WARNING)

    def test_check_one_domain_passed(self):
        dns = SingleTestResult(
            "x", m.TestType.PREFLIGHT_DNS, m.TestStatus.OK,
            detail="2 адресов (1.1.1.1, 2.2.2.2)",
            raw_data={"ips": ["1.1.1.1", "2.2.2.2"]},
        )
        tcp = SingleTestResult("x", m.TestType.PREFLIGHT_TCP, m.TestStatus.OK)
        http = SingleTestResult("x", m.TestType.PREFLIGHT_HTTP, m.TestStatus.OK)
        ping = SingleTestResult("x", m.TestType.PREFLIGHT_PING, m.TestStatus.OK)
        with patch("blockcheck.preflight._check_dns", return_value=dns), \
             patch("blockcheck.preflight._check_tcp_443", return_value=tcp), \
             patch("blockcheck.preflight._check_http_get", return_value=http), \
             patch("blockcheck.preflight.ping_host", return_value=ping):
            pf = check_one_domain("example.com")
        self.assertEqual(pf.verdict, PreflightVerdict.PASSED)
        self.assertEqual(pf.resolved_ips, ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(pf.tcp_443, tcp)

    def test_check_one_domain_block_ip(self):
        dns = SingleTestResult(
            "x", m.TestType.PREFLIGHT_DNS, m.TestStatus.FAIL,
            error_code="BLOCK_IP", detail="IP-заглушка Ростелеком (81.19.72.32)",
            raw_data={"ips": ["81.19.72.32"]},
        )
        tcp = SingleTestResult("x", m.TestType.PREFLIGHT_TCP, m.TestStatus.OK)
        http = SingleTestResult("x", m.TestType.PREFLIGHT_HTTP, m.TestStatus.OK)
        ping = SingleTestResult("x", m.TestType.PREFLIGHT_PING, m.TestStatus.OK)
        with patch("blockcheck.preflight._check_dns", return_value=dns), \
             patch("blockcheck.preflight._check_tcp_443", return_value=tcp), \
             patch("blockcheck.preflight._check_http_get", return_value=http), \
             patch("blockcheck.preflight.ping_host", return_value=ping):
            pf = check_one_domain("example.com")
        self.assertEqual(pf.verdict, PreflightVerdict.FAILED)
        self.assertTrue(pf.is_block_ip)

    def test_check_one_domain_ipv6_only_warns(self):
        dns = SingleTestResult(
            "x", m.TestType.PREFLIGHT_DNS, m.TestStatus.OK,
            raw_data={"ips": ["::1"]},
        )
        with patch("blockcheck.preflight._check_dns", return_value=dns):
            pf = check_one_domain("example.com")
        self.assertEqual(pf.verdict, PreflightVerdict.WARNING)
        self.assertIn("IPv4", pf.verdict_detail)


class ServiceTest(unittest.TestCase):
    def test_build_targets(self):
        targets = build_targets("Example.COM:443", ["other.info", "Other.INFO"])
        self.assertEqual(targets[0]["name"], "[U] Example")
        self.assertEqual(targets[0]["value"], "https://example.com")
        names = [t["name"] for t in targets]
        self.assertEqual(names.count("[E] Other"), 1)
        self.assertIn("[C] Google", names)

    def test_build_targets_empty(self):
        targets = build_targets("")
        self.assertEqual([t["name"] for t in targets], ["[C] Google", "[C] Cloudflare", "[C] Yandex"])

    def test_run_single_domain_check(self):
        captured = {}

        class FakeRunner:
            def __init__(self, **kwargs):
                captured["kwargs"] = kwargs

            def run(self):
                report = BlockcheckReport()
                report.targets = [_result()]
                return report

        with patch("blockcheck.service.BlockcheckRunner", FakeRunner):
            report = run_single_domain_check("example.com")
        self.assertEqual(report.targets[0].name, "x")
        self.assertEqual(captured["kwargs"]["mode"], "dpi_only")
        self.assertEqual(captured["kwargs"]["targets"][0]["value"], "https://example.com")

    def test_run_single_empty_domain(self):
        with self.assertRaises(ValueError):
            run_single_domain_check("")


if __name__ == "__main__":
    unittest.main()