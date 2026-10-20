//! Золото rows.py: строки списка из плана.

use std::collections::HashSet;

use once_cell::sync::Lazy;
use serde_json::Value;

use primecore_profile::strategy_plan::{default_open_group, visible_rows, StrategyListPlan};

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_rows.json"
    ))
    .expect("golden_rows.json");
    serde_json::from_str(&source).expect("json")
});

fn plan() -> StrategyListPlan {
    serde_json::from_value(GOLDEN["ops"]["plan"].clone()).expect("план")
}

#[test]
fn rows_match_python() {
    let plan = plan();

    for name in [
        "all_open",
        "closed",
        "open_fake",
        "one_group_only",
        "twins_open",
    ] {
        let key = format!("rows_{name}");
        let expected = GOLDEN["ops"][&key]
            .as_array()
            .unwrap_or_else(|| panic!("{key}"))
            .iter()
            .map(|entry| entry["row"].clone())
            .collect::<Vec<_>>();

        let open_groups: Option<HashSet<String>> = if name == "closed" {
            Some(HashSet::new())
        } else if name == "open_fake" {
            Some(["fake_split".to_string()].into_iter().collect())
        } else if name == "one_group_only" {
            Some(
                plan.groups
                    .get(1)
                    .map(|group| group.key.clone())
                    .map(|key| [key].into_iter().collect())
                    .unwrap_or_default(),
            )
        } else {
            None
        };
        let open_twins: Vec<String> = GOLDEN["ops"]["twin_keys"]
            .as_array()
            .expect("twin_keys")
            .iter()
            .filter_map(|value| value.as_str().map(|value| value.to_string()))
            .take(if name == "twins_open" { 1 } else { 0 })
            .collect();

        let rows = visible_rows(&plan, open_groups.as_ref(), &open_twins);
        assert_eq!(expected.len(), rows.len(), "{key}: число строк");
        for (index, (expected, row)) in expected.iter().zip(rows.iter()).enumerate() {
            assert_eq!(
                expected["kind"].as_str().expect("kind"),
                row.kind,
                "{key}[{index}]: kind"
            );
            assert_eq!(
                expected["key"].as_str().expect("ключ"),
                row.key,
                "{key}[{index}]: key"
            );
            assert_eq!(
                expected["expanded"], row.expanded,
                "{key}[{index}]: expanded"
            );
            assert_eq!(
                expected["twin_count"].as_u64().unwrap_or(0) as usize,
                row.twin_count,
                "{key}[{index}]: twin_count"
            );
            assert_eq!(
                expected["twin_open"], row.twin_open,
                "{key}[{index}]: twin_open"
            );
            assert_eq!(
                expected["strategy_id"].as_str().expect("id"),
                row.strategy_id(),
                "{key}[{index}]: strategy_id"
            );
            assert_eq!(
                expected["group_key"].as_str().expect("ключ"),
                row.group_key(),
                "{key}[{index}]: group_key"
            );
            assert_eq!(
                expected["selectable"],
                row.selectable(),
                "{key}[{index}]: selectable"
            );
            assert_eq!(
                expected["shown"].as_array().cloned().unwrap_or_default(),
                shown_array(&plan, row, expected),
                "{key}[{index}]: shown"
            );
        }
    }
}

/// shown в python-золоте: [.., значения..] с emoji-сверкой полей.
fn shown_array(
    plan: &StrategyListPlan,
    row: &primecore_profile::strategy_plan::VisibleRow,
    _expected: &Value,
) -> Vec<Value> {
    use primecore_profile::strategy_plan::Shown;
    let _ = plan;
    match row.shown() {
        Shown::Strategy(item, twin_count, twin_open) => vec![
            match &item {
                Some(item) => Value::String(format!("item:{}", item.strategy_id)),
                None => Value::Null,
            },
            Value::from(twin_count),
            Value::from(twin_open),
        ],
        Shown::SectionTitle(title, count) => vec![
            Value::String(format!("section:{title}")),
            Value::from(count),
        ],
        Shown::Group(title, description, icon_name, color, count, current_name, expanded) => vec![
            Value::String(title),
            Value::String(description),
            Value::String(icon_name),
            Value::String(color),
            Value::from(count),
            Value::String(current_name),
            Value::from(expanded),
        ],
    }
}

#[test]
fn default_open_matches_python() {
    let plan = plan();
    let expected = GOLDEN["ops"]["default_open_focused"]
        .as_array()
        .expect("массив");
    assert_eq!(
        expected[0].as_str().expect("ключ"),
        default_open_group(&plan, None)
    );
    assert_eq!(
        expected[1].as_str().expect("ключ"),
        default_open_group(&plan, Some(""))
    );
    assert_eq!(
        expected[2].as_str().expect("ключ"),
        default_open_group(&plan, Some("split"))
    );
    assert_eq!(
        expected[3].as_str().expect("ключ"),
        default_open_group(&plan, Some("bogus"))
    );
}

#[test]
fn constants_match_python() {
    assert_eq!(GOLDEN["ops"]["constants"][0], "group");
    assert_eq!(GOLDEN["ops"]["constants"][1], "section");
    assert_eq!(GOLDEN["ops"]["constants"][2], "strategy");
}
