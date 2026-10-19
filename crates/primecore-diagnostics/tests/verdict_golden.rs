//! Золотой тест: вердикты `diagnostics.verdict` Rust-порта против python.
//!
//! Эталон собирается скриптом `verdict_golden.py`
//! (в /tmp/opencode; python-источник — `src/diagnostics/verdict.py`).

use serde_json::Value;

use primecore_diagnostics::verdict::{
    describe_reach, judge_dns, judge_reach, summarize_service, advice_geo_site, JudgeDnsArgs,
    TargetOutcome,
};
use primecore_diagnostics::probe_result::ProbeResult;

fn golden() -> Value {
    let text = include_str!("verdict_golden.json");
    serde_json::from_str(text).expect("valid golden json")
}

fn socket_args(args: &Value) -> JudgeDnsArgs {
    JudgeDnsArgs {
        system_ips: args["system_ips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ip| ip.as_str().unwrap().to_string())
            .collect(),
        system_status: args["system_status"].as_i64().unwrap(),
        reference_ips: args["reference_ips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ip| ip.as_str().unwrap().to_string())
            .collect(),
        hosts_ips: args["hosts_ips"]
            .as_array()
            .unwrap()
            .iter()
            .map(|ip| ip.as_str().unwrap().to_string())
            .collect(),
        check_kind: args["check_kind"].as_str().unwrap().to_string(),
        check_cert_problem: args["check_cert_problem"].as_str().unwrap().to_string(),
        nxdomain_count: args["nxdomain_count"].as_u64().unwrap() as u32,
        attempts: args["attempts"].as_u64().unwrap() as u32,
        control_kind: args["control_kind"].as_str().unwrap().to_string(),
    }
}

fn item_outcome(item: &Value) -> TargetOutcome {
    TargetOutcome {
        host: item["host"].as_str().unwrap().to_string(),
        purpose: item["purpose"].as_str().unwrap().to_string(),
        reach: item["reach"].as_str().unwrap().to_string(),
        dns: match item["dns"].as_str().unwrap() {
            "ok" => primecore_diagnostics::verdict::DnsState::Ok,
            "spoofed" => primecore_diagnostics::verdict::DnsState::Spoofed,
            "local" => primecore_diagnostics::verdict::DnsState::Local,
            _ => primecore_diagnostics::verdict::DnsState::Unknown,
        },
        main: item["main"].as_bool().unwrap_or(false),
        kind: item["kind"].as_str().unwrap_or("").to_string(),
        hosts_stale: item["hosts_stale"].as_bool().unwrap_or(false),
        unstable: item["unstable"].as_bool().unwrap_or(false),
        dns_blind: item["dns_blind"].as_bool().unwrap_or(false),
    }
}

fn probe(kind: &str, body_cut: bool, body_size: u64, cert_problem: &str, detail: &str) -> ProbeResult {
    ProbeResult {
        ip: "1.2.3.4".to_string(),
        kind: kind.to_string(),
        stage: "",
        status: None,
        body_size,
        body_cut,
        cert_problem: cert_problem.to_string(),
        tls_version: String::new(),
        elapsed_ms: 0.0,
        detail: detail.to_string(),
        body: Vec::new(),
        connect_fail: "",
    }
}

#[test]
fn golden_matches_python() {
    let gold = golden();

    for (index, case) in gold["dns"].as_array().unwrap().iter().enumerate() {
        let verdict = judge_dns(socket_args(&case["args"]));
        assert_eq!(verdict.state.value(), case["out"]["state"].as_str().unwrap(), "dns case {index} state");
        assert_eq!(verdict.reason, case["out"]["reason"].as_str().unwrap(), "dns case {index} reason");
    }

    let probes: [Option<ProbeResult>; 10] = [
        None,
        Some(probe("ok", false, 20000, "", "")),
        Some(probe("ok", true, 16000, "", "")),
        Some(probe("ok", true, 1000, "", "")),
        Some(probe("cert", false, 0, "", "")),
        Some(probe("connect", false, 0, "", "")),
        Some(probe("tls", false, 0, "", "")),
        Some(probe("reset", false, 0, "", "")),
        Some(probe("timeout", false, 0, "", "")),
        Some(probe("cancel__", false, 0, "", "")),
    ];
    for (index, result) in probes.iter().enumerate() {
        let expected = gold["reach"].as_array().unwrap()[index].as_str().unwrap();
        assert_eq!(judge_reach(result.as_ref()).value(), expected, "reach {index}");
    }

    // python: describe_reach вызывался без timeout (0.0); порядок исходов — как в скрипте
    // [None, ok, ok+cut16КБ, cert, connect, tls, reset, timeout, cancelled, error].
    let describes: [(&str, bool, u64, &str, &str); 9] = [
        ("ok", false, 20000, "", ""),
        ("ok", true, 16000, "", ""),
        ("cert", false, 20000, "", ""),
        ("connect", false, 0, "", ""),
        ("tls", false, 0, "", ""),
        ("reset", false, 0, "", ""),
        ("timeout", false, 0, "", ""),
        ("cancelled", false, 0, "", ""),
        ("error", false, 0, "", "магия"),
    ];
    let mut describe_cases = vec![None];
    for (kind, body_cut, body_size, cert_problem, detail) in describes {
        describe_cases.push(Some(probe(kind, body_cut, body_size, cert_problem, detail)));
    }
    for (index, result) in describe_cases.iter().enumerate() {
        let expected = gold["describe"].as_array().unwrap()[index].as_str().unwrap();
        assert_eq!(describe_reach(result.as_ref(), 0.0), expected, "describe {index}");
    }

    for (index, case) in gold["summarize"].as_array().unwrap().iter().enumerate() {
        let targets: Vec<TargetOutcome> =
            case["targets"].as_array().unwrap().iter().map(item_outcome).collect();
        let zapret = case["zapret"].as_bool();
        let verdict = summarize_service(case["label"].as_str().unwrap(), &targets, zapret);
        let expected = &case["verdict"];
        assert_eq!(
            verdict.level.value(),
            expected["level"].as_str().unwrap(),
            "summarize {index} level"
        );
        assert_eq!(verdict.headline, expected["headline"].as_str().unwrap(), "summarize {index} headline");
        assert_eq!(
            verdict.advice,
            expected["advice"]
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item.as_str().unwrap().to_string())
                .collect::<Vec<_>>(),
            "summarize {index} advice"
        );
        assert_eq!(verdict.dns_note, expected["dns_note"].as_str().unwrap(), "summarize {index} dns_note");
        assert_eq!(verdict.kind, expected["kind"].as_str().unwrap(), "summarize {index} kind");
    }

    assert_eq!(
        advice_geo_site("Meduza"),
        gold["geo_advice"].as_str().unwrap(),
        "geo advice text (python verdict.advice_geo_site)"
    );
}
