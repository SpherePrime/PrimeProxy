//! Золотой тест разборщика пресетов (profile/parser.py) против живого Python.

use std::sync::OnceLock;

use serde_json::{json, Value};

use primecore_profile::models::{Profile, Strategy, Winws1Strategy, Winws2Strategy};
use primecore_profile::parser::{parse_preset_text, preset_text_outline, ProfileOutline};

fn golden() -> &'static Value {
    static GOLDEN: OnceLock<Value> = OnceLock::new();
    GOLDEN.get_or_init(|| serde_json::from_slice(include_bytes!("golden_parser.json")).unwrap())
}

fn strategy_value(strategy: &Strategy) -> Value {
    match strategy {
        Strategy::Winws2(inner) => winws2_value(inner),
        Strategy::Winws1(inner) => winws1_value(inner),
    }
}

fn winws2_value(inner: &Winws2Strategy) -> Value {
    json!({
        "kind": "Winws2Strategy",
        "actions": inner.actions.iter().map(|action| json!({
            "raw_line": action.raw_line,
            "func_name": action.func_name,
            "args": action.args.iter().map(|arg| json!({
                "raw": arg.raw, "key": arg.key, "value": arg.value, "is_flag": arg.is_flag,
            })).collect::<Vec<_>>(),
            "flags": action.flags,
            "payload": action.payload,
            "in_range": action.in_range,
            "out_range": action.out_range,
        })).collect::<Vec<_>>(),
        "strategy_lines": inner.strategy_lines,
        "other_lines": inner.other_lines,
    })
}

fn winws1_value(inner: &Winws1Strategy) -> Value {
    json!({
        "kind": "Winws1Strategy",
        "dpi_desync_lines": inner.dpi_desync_lines,
        "dup_lines": inner.dup_lines,
        "wssize_lines": inner.wssize_lines,
        "ip_id_lines": inner.ip_id_lines,
        "strategy_lines": inner.strategy_lines,
        "other_lines": inner.other_lines,
    })
}

fn profile_value(profile: &Profile) -> Value {
    let matched = profile.match_section();
    json!({
        "id": profile.id,
        "index": profile.index,
        "engine": profile.engine,
        "display_name": profile.display_name,
        "enabled": profile.enabled,
        "name": profile.name,
        "new_line": profile.new_line,
        "match_signature": profile.match_signature,
        "persistent_key": profile.persistent_key,
        "match": json!({
            "filter_lines": matched.filter_lines,
            "hostlist_lines": matched.hostlist_lines,
            "ipset_lines": matched.ipset_lines,
            "hostlist_exclude_lines": matched.hostlist_exclude_lines,
            "hostlist_auto_lines": matched.hostlist_auto_lines,
            "ipset_exclude_lines": matched.ipset_exclude_lines,
            "hostlist_domains_lines": matched.hostlist_domains_lines,
            "inline_ipset_lines": matched.inline_ipset_lines,
            "other_lines": matched.other_lines,
        }),
        "strategy_data": strategy_value(profile.strategy.as_ref().expect("стратегия стоит")),
        "segments": profile.segments.iter().map(|segment| json!({
            "kind": segment.kind, "text": segment.text,
            "name": segment.name, "value": segment.value,
        })).collect::<Vec<_>>(),
    })
}

#[test]
fn parse_preset_text_matches_python() {
    for case in golden().as_array().unwrap() {
        let Some(preset) = case.get("preset") else {
            continue;
        };
        let text = case["text"].as_str().unwrap();
        let engine = case["engine"].as_str().unwrap();
        let parsed = parse_preset_text(text, engine, "").expect("пресет разбирается");
        assert_eq!(
            json!(parsed.engine),
            preset["engine"],
            "{}: движок",
            case["name"]
        );
        assert_eq!(
            json!(parsed.header_lines),
            preset["header_lines"],
            "{}: шапка",
            case["name"]
        );
        assert_eq!(
            json!(parsed.preamble_lines),
            preset["preamble_lines"],
            "{}: preamble",
            case["name"]
        );
        assert_eq!(
            json!(parsed.footer_lines),
            preset["footer_lines"],
            "{}: хвост",
            case["name"]
        );
        let expected_profiles = preset["profiles"].as_array().unwrap();
        assert_eq!(
            parsed.profiles.len(),
            expected_profiles.len(),
            "{}: профили",
            case["name"]
        );
        for (profile, expected) in parsed.profiles.iter().zip(expected_profiles) {
            assert_eq!(
                profile_value(profile),
                *expected,
                "{}: профиль {:?}",
                case["name"],
                profile.id
            );
        }
    }
}

fn outline_value(outline: &primecore_profile::parser::PresetOutline) -> Value {
    json!({
        "header": outline.header,
        "lua_init": outline.lua_init,
        "interception": outline.interception,
        "blobs": outline.blobs,
        "engine_options": outline.engine_options,
        "profiles": outline.profiles.iter().map(profile_outline_value).collect::<Vec<_>>(),
    })
}

fn profile_outline_value(outline: &ProfileOutline) -> Value {
    json!({
        "new_line": outline.new_line,
        "lines": outline.lines,
        "name": outline.name,
        "match": outline.match_lines,
        "packets": outline.packets,
        "strategy": outline.strategy,
    })
}

fn expected_outline(case: &Value) -> Value {
    json!({
        "header": case["outline"]["header"],
        "lua_init": case["outline"]["lua_init"],
        "interception": case["outline"]["interception"],
        "blobs": case["outline"]["blobs"],
        "engine_options": case["outline"]["engine_options"],
        "profiles": case["outline"]["profiles"],
    })
}

#[test]
fn preset_text_outline_matches_python() {
    for case in golden().as_array().unwrap() {
        if case["name"].as_str().unwrap() != "outline" {
            continue;
        }
        let text = case["text"].as_str().unwrap();
        let engine = case["engine"].as_str().unwrap();
        let outline = preset_text_outline(text, engine).expect("оглавление строится");
        assert_eq!(outline_value(&outline), expected_outline(case));
    }
}
