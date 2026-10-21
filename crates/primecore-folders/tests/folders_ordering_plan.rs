//! Порт zapretgui/tests/test_folders_ordering_plan.py: контракт generic-ядра
//! порядка папок (resolve_folder_order + plan_view_move + plan_item_move).

use serde_json::{json, Value};

use primecore_folders::{plan_item_move, plan_view_move, resolve_folder_order};

fn state() -> Value {
    json!({
        "version": 1,
        "folders": {
            "alpha": {"name": "Alpha", "order": 0, "collapsed": false, "system": false},
            "beta": {"name": "Beta", "order": 1, "collapsed": true, "system": false},
            "common": {"name": "Общие", "order": 2, "collapsed": false, "system": true},
        },
        "items": {
            "a1": {"folder_key": "alpha", "order": 0, "rating": 0},
            "a2": {"folder_key": "alpha", "order": 1, "rating": 0},
            "b1": {"folder_key": "beta", "order": 0, "rating": 5},
        },
    })
}

fn live(keys: &[&str]) -> Vec<Value> {
    keys.iter()
        .map(|key| json!({"key": key, "name": key}))
        .collect()
}

#[test]
fn folders_sorted_by_saved_order_and_items_by_manual_then_auto() {
    let view = resolve_folder_order(&state(), &live(&["a1", "a2", "b1", "free-z", "free-a"]));

    assert_eq!(view.folder_keys, ["alpha", "beta", "common"]);
    assert_eq!(view.items_by_folder["alpha"], ["a1", "a2"]);
    // Элементы без meta падают в common (нет folder_key у live) и
    // сортируются по имени.
    assert_eq!(view.items_by_folder["common"], ["free-a", "free-z"]);
    assert!(view.collapsed["beta"]);
    assert_eq!(view.position_by_item["a2"], 1);
}

#[test]
fn rating_orders_auto_items_before_name() {
    let mut state = state();
    state["items"]["rated"] = json!({"folder_key": "common", "order": Value::Null, "rating": 9});
    let view = resolve_folder_order(&state, &live(&["rated", "aaa"]));

    // rating=9 выигрывает у имени "aaa" при отсутствии ручного order.
    assert_eq!(view.items_by_folder["common"], ["rated", "aaa"]);
}

#[test]
fn before_and_after_insert_relative_to_destination() {
    let view = resolve_folder_order(&state(), &live(&["a1", "a2"]));

    let planned = plan_view_move(&view, "before", "a2", "a1", "");
    assert_eq!(
        planned,
        Some((
            "alpha".to_string(),
            vec!["a2".to_string(), "a1".to_string()]
        ))
    );

    let planned_after = plan_view_move(&view, "after", "a1", "a2", "");
    assert_eq!(
        planned_after,
        Some((
            "alpha".to_string(),
            vec!["a2".to_string(), "a1".to_string()]
        ))
    );
}

#[test]
fn noop_when_display_order_unchanged() {
    let view = resolve_folder_order(&state(), &live(&["a1", "a2"]));

    assert!(plan_view_move(&view, "before", "a1", "a2", "").is_none());
    assert!(plan_view_move(&view, "end", "a2", "", "").is_none());
    assert!(plan_view_move(&view, "after", "a2", "a2", "").is_none());
}

#[test]
fn destination_rehomed_only_with_explicit_folder() {
    let view = resolve_folder_order(&state(), &live(&["a1", "a2", "b1"]));

    // Без явной папки источник переезжает в папку цели.
    assert_eq!(
        plan_view_move(&view, "before", "a1", "b1", ""),
        Some(("beta".to_string(), vec!["a1".to_string(), "b1".to_string()]))
    );
    // С явной папкой цель переезжает вместе с ходом (UI авторитетен).
    let planned = plan_view_move(&view, "after", "a1", "b1", "alpha");
    assert_eq!(
        planned,
        Some((
            "alpha".to_string(),
            vec!["a2".to_string(), "b1".to_string(), "a1".to_string()]
        ))
    );
}

#[test]
fn renumbers_only_target_folder_and_keeps_foreign_meta() {
    let state = state();
    let before_beta = state["items"]["b1"].clone();

    let planned = plan_item_move(&state, &live(&["a1", "a2"]), "before", "a2", "a1", "");
    let planned = planned.expect("planned");
    assert_eq!(planned["items"]["a2"]["order"], json!(0));
    assert_eq!(planned["items"]["a1"]["order"], json!(1));
    assert_eq!(planned["items"]["b1"], before_beta);
    // Исходное состояние не мутируется (план — чистая функция).
    assert_eq!(state["items"]["a1"]["order"], json!(0));
}

#[test]
fn cross_folder_move_sets_folder_key_only_for_moved_item() {
    let planned = plan_item_move(
        &state(),
        &live(&["a1", "a2", "b1"]),
        "folder",
        "a1",
        "",
        "beta",
    );
    let planned = planned.expect("planned");
    assert_eq!(planned["items"]["a1"]["folder_key"], json!("beta"));
    assert_eq!(planned["items"]["b1"]["folder_key"], json!("beta"));
    assert_eq!(planned["items"]["b1"]["order"], json!(0));
    assert_eq!(planned["items"]["a1"]["order"], json!(1));
    // Оставшийся в alpha элемент не тронут.
    assert_eq!(planned["items"]["a2"]["folder_key"], json!("alpha"));
    assert_eq!(planned["items"]["a2"]["order"], json!(1));
}

#[test]
fn unknown_target_folder_is_rejected() {
    assert!(plan_item_move(&state(), &live(&["a1"]), "folder", "a1", "", "ghost").is_none());
}

// Сверено с python: element с folder_key на отсутствующую папку уходит в
// common; доменные ранги (auto_rank/manual_tie) задают порядок до имени.
#[test]
fn ghost_folder_falls_back_to_common_and_domain_ranks_apply() {
    let state = json!({
        "version": 1,
        "folders": {"alpha": {"name": "Alpha", "order": 0, "collapsed": false, "system": false}},
        "items": {"x": {"folder_key": "ghost", "order": 2, "rating": 3}},
    });

    let view = resolve_folder_order(&state, &[json!({"key": "x", "name": "X"})]);
    assert_eq!(view.folder_by_item["x"], "common");
    assert_eq!(view.items_by_folder["common"], ["x"]);
    assert_eq!(view.position_by_item["x"], 0);

    // live folder_key без meta: элемент попадает в указанную папку.
    let view = resolve_folder_order(
        &state,
        &[json!({"key": "y", "name": "Y", "folder_key": "alpha", "rating": 4})],
    );
    assert_eq!(view.folder_by_item["y"], "alpha");
    assert_eq!(view.items_by_folder["alpha"], ["y"]);

    // auto_rank задан доменом: ранг 1 раньше ранга 2, имя не важно.
    let view = resolve_folder_order(
        &state,
        &[
            json!({"key": "z", "name": "Z", "auto_rank": [2]}),
            json!({"key": "w", "name": "W", "auto_rank": [1]}),
        ],
    );
    assert_eq!(view.items_by_folder["common"], ["w", "z"]);

    // manual_tie без ручного order не влияет: работает rating-семантика по
    // имени (W < Z).
    let view = resolve_folder_order(
        &state,
        &[
            json!({"key": "z", "name": "Z", "manual_tie": [1]}),
            json!({"key": "w", "name": "W", "manual_tie": [0]}),
        ],
    );
    assert_eq!(view.items_by_folder["common"], ["w", "z"]);
}

#[test]
fn plan_rejects_unknown_actions_and_empty_targets() {
    let view = resolve_folder_order(
        &json!({"version": 1, "folders": {"alpha": {"name": "A", "order": 0, "collapsed": false, "system": false}}, "items": {}}),
        &[json!({"key": "a1", "name": "a1"})],
    );

    assert!(plan_view_move(&view, "before", "a1", "ghost", "").is_none());
    assert!(plan_view_move(&view, "folder", "a1", "", "  ").is_none());
    assert!(plan_view_move(&view, "sideways", "a1", "", "").is_none());
    assert!(plan_item_move(
        &json!({"version": 1, "folders": {"alpha": {"name": "A", "order": 0, "collapsed": false, "system": false}}, "items": {}}),
        &[json!({"key": "a1", "name": "A1"})],
        "end",
        "a1",
        "",
        ""
    )
    .is_none());
}

// Сверено с python: материализация meta для элемента, отображённого по
// классификации, наследует rating и pinned из live-элемента.
#[test]
fn plan_item_move_materializes_meta_from_live_item() {
    let state = json!({
        "version": 1,
        "folders": {
            "alpha": {"name": "Alpha", "order": 0, "collapsed": false, "system": false},
            "beta": {"name": "Beta", "order": 1, "collapsed": false, "system": false},
        },
        "items": {},
    });

    let planned = plan_item_move(
        &state,
        &[json!({"key": "a1", "name": "A1", "rating": 2, "pinned": true})],
        "folder",
        "a1",
        "",
        "beta",
    )
    .expect("planned");

    assert_eq!(
        planned["items"]["a1"],
        json!({"folder_key": "beta", "order": 0, "rating": 2, "pinned": true})
    );

    // Перемещение без изменения отображаемого порядка — no-op.
    let no_op = plan_item_move(
        &state,
        &[json!({"key": "a1", "name": "A1"})],
        "end",
        "a1",
        "",
        "",
    );
    assert!(no_op.is_none());
}
