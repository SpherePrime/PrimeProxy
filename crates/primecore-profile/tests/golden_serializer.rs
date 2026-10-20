//! Золотой тест операций serializer (profile/serializer.py) против Python.

use std::sync::OnceLock;

use serde_json::{json, Value};

use primecore_profile::parser::parse_preset_text;
use primecore_profile::serializer::{
    append_profile_from_template, with_profile_deleted, with_profile_duplicated,
    with_profile_enabled, with_profile_moved, with_profile_raw_text, with_profile_ready_strategy,
    with_profile_strategy_lines, with_profile_user_match, with_profile_whole_strategy, Position,
};
use primecore_profile::{Preset, Profile, Strategy};

fn golden() -> &'static Value {
    static GOLDEN: OnceLock<Value> = OnceLock::new();
    GOLDEN.get_or_init(|| serde_json::from_slice(include_bytes!("golden_serializer.json")).unwrap())
}

fn base_preset() -> (Preset, Preset) {
    let mut cases = golden().as_array().unwrap().iter();
    let base = cases.next().expect("первый шаг — base");
    let mut base1: Option<Preset> = None;
    for case in golden().as_array().unwrap() {
        if case["title"] == "base1" && base1.is_none() {
            break;
        }
    }
    // base1 строится по одинаковому тексту через parse_preset_text.
    let text = case_text("base");
    let winws1_text = case_text("base1");
    let engine = base["engine"].as_str().unwrap().to_string();
    let parsed = parse_preset_text(&text, &engine, "").expect("winws2 base");
    let parsed1 = parse_preset_text(&winws1_text, "winws1", "").expect("winws1 base");
    base1 = Some(parsed1);
    (parsed, base1.unwrap())
}

fn case_text(title: &str) -> String {
    let case = golden()
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["title"] == title)
        .expect("известный шаг");
    case["text"].as_str().unwrap().to_string()
}

fn step_result(title: &str) -> Option<Value> {
    golden()
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["title"].as_str().unwrap() == title)
        .cloned()
}

fn check_step(title: &str, preset: &Preset) {
    let expected = step_result(title).expect("шаг ожидается");
    assert_eq!(json!(preset.engine), expected["engine"], "{title}: движок");
    assert_eq!(
        json!(serialize(preset)),
        json!(expected["text"]),
        "{title}: текст"
    );
    assert_eq!(
        json!(preset
            .profiles
            .iter()
            .map(|p| p.name.clone())
            .collect::<Vec<_>>()),
        json!(expected["names"]),
        "{title}: имена"
    );
    assert_eq!(
        json!(preset
            .profiles
            .iter()
            .map(|p| p.display_name.clone())
            .collect::<Vec<_>>()),
        json!(expected["display"]),
        "{title}: показ"
    );
    assert_eq!(
        json!(preset
            .profiles
            .iter()
            .map(|p| p.enabled)
            .collect::<Vec<_>>()),
        json!(expected["enabled"]),
        "{title}: вкл"
    );
    assert_eq!(
        json!(preset
            .profiles
            .iter()
            .map(|p| p.persistent_key.clone())
            .collect::<Vec<_>>()),
        json!(expected["keys"]),
        "{title}: ключи"
    );
}

fn serialize(preset: &Preset) -> String {
    primecore_profile::serializer::serialize_preset(preset)
}

#[test]
fn serializer_operations_match_python() {
    let (base, _base1) = base_preset();

    // Включённость
    check_step(
        "disable0",
        &with_profile_enabled(&base, 0, false).expect("disable0"),
    );
    check_step(
        "enable1",
        &with_profile_enabled(&base, 1, true).expect("enable1"),
    );

    // Стратегии
    check_step(
        "strategy_lines0",
        &with_profile_strategy_lines(&base, 0, &lines(["--lua-desync=x:1", "--lua-desync=y"]))
            .expect("strategy_lines0"),
    );
    check_step(
        "strategy_lines_empty0",
        &with_profile_strategy_lines(&base, 0, &[]).expect("strategy_lines_empty0"),
    );
    check_step(
        "whole0",
        &with_profile_whole_strategy(&base, 0, &lines(["--in-range=i-ii", "--lua-desync=fake"]))
            .expect("whole0"),
    );
    check_step(
        "whole1",
        &with_profile_whole_strategy(&base, 1, &lines(["--in-range=i-ii", "--lua-desync=fake"]))
            .expect("whole1"),
    );
    let (ready0, whole0) = with_profile_ready_strategy(
        &base,
        0,
        &lines(["--payload=udp", "--lua-desync=a", "--lua-desync=b"]),
    )
    .expect("ready0");
    check_step("ready0_composite", &ready0);
    assert_eq!(whole0, None, "ready0 цельных строк не ждём");
    let (ready1, whole1) =
        with_profile_ready_strategy(&base, 1, &lines(["--lua-desync=f"])).expect("ready1");
    check_step("ready1_simple", &ready1);
    assert_eq!(
        whole1,
        Some(lines(["--payload=udp,tls", "--lua-desync=f"])),
        "ready1 поверх составной — пишет всю строку целиком"
    );

    // Match-данные
    check_step(
        "user_match0",
        &with_profile_user_match(&base, 0, "Новое", "udp", "53", "lists/all.txt", "9.9.9.9")
            .expect("user_match0"),
    );
    check_step(
        "user_match1",
        &with_profile_user_match(&base, 1, "Другое", "tcp", "80", "", "").expect("user_match1"),
    );

    // Шаблоны и границы
    check_step(
        "template_top",
        &append_profile_from_template(&base, &base.profiles[0], true, &Position::Top)
            .expect("template_top"),
    );
    check_step(
        "template_bottom",
        &append_profile_from_template(&base, &base.profiles[0], true, &Position::Bottom)
            .expect("template_bottom"),
    );
    check_step(
        "template_index",
        &append_profile_from_template(&base, &base.profiles[1], false, &Position::Index(1))
            .expect("template_index"),
    );
    check_step("delete0", &with_profile_deleted(&base, 0).expect("delete0"));
    check_step("dup0", &with_profile_duplicated(&base, 0).expect("dup0"));
    check_step("dup1", &with_profile_duplicated(&base, 1).expect("dup1"));
    let duplicated_twice =
        with_profile_duplicated(&with_profile_duplicated(&base, 1).expect("dup1"), 2)
            .expect("dupdup1");
    check_step("dupdup1", &duplicated_twice);
    check_step(
        "move1_to0",
        &with_profile_moved(&base, 1, 0).expect("move1_to0"),
    );
    check_step(
        "move0_to1",
        &with_profile_moved(&base, 0, 1).expect("move0_to1"),
    );
    check_step(
        "move_same",
        &with_profile_moved(&base, 1, 2).expect("move_same"),
    );
    check_step(
        "raw0",
        &with_profile_raw_text(
            &base,
            0,
            "# комментарий\n--in-range=5\n--lua-desync=rewrite:1",
        )
        .expect("raw0"),
    );
}

#[test]
fn serializer_errors_match_python() {
    let (base, _base1) = base_preset();
    let expected = step_result("errors").expect("ошибки есть");
    let errors = expected["errors"].as_array().unwrap();
    let actual: Vec<Option<String>> = vec![
        with_profile_user_match(&base, 0, "", "udp", "53", "", "").err(),
        with_profile_user_match(&base, 0, "n", "nope", "53", "", "").err(),
        with_profile_deleted(&base, 9).err(),
        with_profile_raw_text(&base, 0, "   ").err(),
        with_profile_raw_text(&base, 0, "# только комменты").err(),
        position_err("side").err(),
    ];
    for (actual_message, expected_message) in actual.iter().zip(errors) {
        match expected_message.as_str() {
            Some(expected_json) => {
                let actual_message = actual_message.as_ref().expect("ошибка нужна");
                assert_eq!(actual_message, expected_json, "сообщение об ошибке");
            }
            None => assert!(
                actual_message.is_none(),
                "должно пройти: {actual_message:?}"
            ),
        }
    }
}

fn position_err(value: &str) -> Result<Position, String> {
    match value.trim().to_lowercase().as_str() {
        "top" => Ok(Position::Top),
        "bottom" => Ok(Position::Bottom),
        side => Err(format!("Unsupported template profile position: {side}")),
    }
}

#[test]
fn serializer_winws1_matches_python() {
    let (_base, base1) = base_preset();
    check_step("base1", &base1);
    check_step(
        "strategy1",
        &with_profile_strategy_lines(&base1, 0, &lines(["--dpi-desync=ack,split", " extra "]))
            .expect("strategy1"),
    );
    check_step(
        "dup1_copy",
        &with_profile_duplicated(&base1, 0).expect("dup1_copy"),
    );
    check_step(
        "winws1_boundary",
        &with_profile_deleted(&base1, 0).expect("winws1_boundary"),
    );
}

fn lines<'text>(lines: impl IntoIterator<Item = &'text str>) -> Vec<String> {
    lines.into_iter().map(str_to_string).collect()
}

fn str_to_string(line: &str) -> String {
    line.to_string()
}

#[allow(dead_code)]
fn strategy_of(profile: &Profile) -> &Strategy {
    profile.strategy.as_ref().expect("стратегия стоит")
}
