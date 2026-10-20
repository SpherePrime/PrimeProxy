//! Золотой тест разборщика WinWS2 против живого Python
//! (profile/winws2.py + profile/models.py).

use std::sync::OnceLock;

use serde_json::{json, Value};

use primecore_profile::winws2::{
    parse_winws2_strategy, split_lua_desync_lines, unescape_lua_token,
};
use primecore_profile::ProfileAction;

fn golden() -> &'static Value {
    static GOLDEN: OnceLock<Value> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        serde_json::from_slice::<Value>(include_bytes!("golden_winws2.json")).unwrap()
    })
}

fn action_json(action: &ProfileAction) -> Value {
    json!({
        "raw_line": action.raw_line,
        "func_name": action.func_name,
        "args": action.args.iter().map(|arg| json!({
            "raw": arg.raw, "key": arg.key, "value": arg.value, "is_flag": arg.is_flag,
        })).collect::<Vec<_>>(),
        "flags": action.flags,
        "payload": action.payload,
        "in_range": action.in_range,
        "out_range": action.out_range,
    })
}

#[test]
fn parse_winws2_strategy_matches_python() {
    for case in golden().as_array().unwrap() {
        let lines: Vec<String> = case["input"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect();
        let expected = &case["output"];
        let strategy = parse_winws2_strategy(&lines);
        assert_eq!(
            strategy.actions.len(),
            expected["actions"].as_array().unwrap().len(),
            "iền действий: {:?}",
            lines
        );
        for (action, expected_action) in strategy
            .actions
            .iter()
            .zip(expected["actions"].as_array().unwrap())
        {
            assert_eq!(
                action_json(action),
                *expected_action,
                "действие в {:?}",
                lines
            );
        }
        // strategy_lines: обрезались участки (python отдаёт list[str] без пустых).
        assert_eq!(
            json!(strategy.strategy_lines),
            expected["strategy_lines"],
            "стратегия в {:?}",
            lines
        );
        assert_eq!(
            json!(strategy.other_lines),
            expected["other_lines"],
            "прочие в {:?}",
            lines
        );
    }
}

#[test]
fn split_lua_desync_lines_matches_marker_semantics() {
    assert_eq!(
        split_lua_desync_lines("--lua-desync=a:x"),
        ["--lua-desync=a:x"]
    );
    // python обрезает каждый отрезок: `.strip()`.
    assert_eq!(
        split_lua_desync_lines("--lua-desync=a:x --lua-desync=b"),
        ["--lua-desync=a:x", "--lua-desync=b"]
    );
    assert_eq!(
        split_lua_desync_lines("--LUA-DESYNC=верх"),
        ["--LUA-DESYNC=верх"]
    );
    assert_eq!(split_lua_desync_lines("-x"), Vec::<String>::new());
}

#[test]
fn unescape_lua_token_plain() {
    assert_eq!(unescape_lua_token("a\\:b"), "a:b");
    assert_eq!(unescape_lua_token("a\\x"), "a\\x");
    assert_eq!(unescape_lua_token("обычный"), "обычный");
}
