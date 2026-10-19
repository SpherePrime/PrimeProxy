//! Золотой тест формы стратегии (profile/strategy_shape.py) против Python.

use std::sync::OnceLock;

use serde_json::{json, Value};

use primecore_profile::strategy_shape::{composite_identity, strategy_shape, union_payload};

fn golden() -> &'static Value {
    static GOLDEN: OnceLock<Value> = OnceLock::new();
    GOLDEN.get_or_init(|| serde_json::from_slice(include_bytes!("golden_shape.json")).unwrap())
}

fn lines_from(case: &Value) -> Vec<String> {
    case["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn strategy_shape_matches_python() {
    for case in golden().as_array().unwrap() {
        let lines = lines_from(case);
        let shape = strategy_shape(&lines);
        assert_eq!(json!(shape.profile_range_lines), case["shape"]["profile_range_lines"], "{}", case["name"]);
        assert_eq!(json!(shape.body_lines), case["shape"]["body_lines"], "{}", case["name"]);
        assert_eq!(shape.composite, case["shape"]["composite"].as_bool().unwrap(), "{}", case["name"]);
        assert_eq!(json!(shape.payload_scopes), case["shape"]["payload_scopes"], "{}", case["name"]);
        assert_eq!(json!(shape.lua_lines()), case["shape"]["lua_lines"], "{}", case["name"]);
        if let Some(identity) = case.get("identity").filter(|v| v.as_array().is_some()) {
            let built: Vec<[String; 2]> = composite_identity(&shape.body_lines)
                .into_iter()
                .map(|(kind, value)| [kind, value])
                .collect();
            assert_eq!(json!(built), json!(identity), "{}: отпечаток", case["name"]);
        }
        assert_eq!(union_payload(&shape.payload_scopes), case["union"].as_str().unwrap(), "{}", case["name"]);
    }
}
