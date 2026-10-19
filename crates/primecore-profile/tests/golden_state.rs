//! Золотой тест отметок стратегий (profile/strategy_state.py) против Python.
//!
//! Python-стор пишет steps /tmp/opencode/state_py.py → golden file with ops
//! Использование: cargo test -p primecore-profile --test golden_state

use serde_json::{json, Map, Value};

use primecore_profile::strategy_state::{
    clear_strategy_state, get_grouping, migrate_profile_keys, open_group, set_grouping,
    set_open_group, set_strategy_state, strategy_experience, strategy_list_marks,
};
use primecore_settings::store::{get_settings_database_path, SettingsDatabase};

fn golden() -> &'static Value {
    static GOLDEN: once_cell::sync::OnceCell<Value> = once_cell::sync::OnceCell::new();
    GOLDEN.get_or_init(|| {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/golden_state.json"
        );
        let bytes = std::fs::read(path).expect("golden_state.json");
        serde_json::from_slice(&bytes).expect("json")
    })
}

fn default_section() -> Value {
    json!({})
}

#[test]
fn strategy_state_python_sequence_matches_rust() {
    let Some(db_dir) = std::env::var("PRIMECORE_STATE_DB_DIR").ok().map(std::path::PathBuf::from) else {
        eprintln!("PRIMECORE_STATE_DB_DIR не задан — пропуск (запусти через gen_golden_state.sh)");
        return;
    };
    let target = get_settings_database_path(&db_dir);
    let target = target.clone();
    let _ = default_section();
    let (mut database, _initial) =
        SettingsDatabase::open_with_recovery(&target).expect("открытие");

    let mut ops: Vec<Value> = Vec::new();

    let marks0 = strategy_list_marks(&mut database, "uid:l1", &["sx", "sy"]);
    ops.push(op_marks("marks0", &marks0.states, marks0.open_group.clone()));

    let sx = set_strategy_state(&mut database, "uid:l1", "sx", Some("work"), None).expect("set1");
    ops.push(op_state("set1", &sx));
    let sy = set_strategy_state(&mut database, "uid:l1", "sy", None, Some(true)).expect("setfav");
    ops.push(op_state("setfav", &sy));
    let bad = set_strategy_state(&mut database, "uid:l1", "sx", Some("bad"), None).expect("setbad");
    ops.push(op_state("setbad", &bad));
    let clear = set_strategy_state(&mut database, "uid:l1", "sx", None, Some(false)).expect("setclear");
    ops.push(op_state("setclear", &clear));

    let _ = set_strategy_state(&mut database, "uid:l2", "sx", Some("work"), None).expect("use2");
    let _ = set_strategy_state(&mut database, "uid:l2", "sy", Some("notwork"), None).expect("use3");
    let _ = set_strategy_state(&mut database, "uid:l2", "zz", Some("work"), None).expect("use4");
    let experience = strategy_experience(&mut database, "uid:l1");
    ops.push(Value::Array(
        vec![Value::String("experience".into())]
            .into_iter()
            .chain([Value::Array(experience.iter().map(|(id, (works, not_works))| json!([id, [works, not_works]])).collect())])
            .collect(),
    ));

    let opened = set_open_group(&mut database, "uid:l1", "fake_split").expect("open");
    ops.push(json!(["opengroup", opened]));
    let opened_again = set_open_group(&mut database, "uid:l1", "fake_split").expect("open2");
    ops.push(json!(["opengroup2", opened_again]));
    let bad_group = set_open_group(&mut database, "uid:l1", "Ключ!");
    let expected = vec!["opengroup_err".to_string(), bad_group.err().expect("ошибка")];
    ops.push(json!(expected));

    let grouping_set = set_grouping(&mut database, "series").expect("grouping");
    ops.push(json!(["grouping_set", grouping_set]));
    let grouping_repeat = set_grouping(&mut database, "series").expect("grouping2");
    ops.push(json!(["grouping_repeat", grouping_repeat]));
    let grouping_bogus = set_grouping(&mut database, "Some").expect("grouping3");
    ops.push(json!(["grouping_bogus", grouping_bogus]));

    let marks2 = strategy_list_marks(&mut database, "uid:l1", &[]);
    ops.push(op_marks("marks2", &marks2.states, marks2.open_group.clone()));
    clear_strategy_state(&mut database, "uid:l1", "zzzz");
    let marks3 = strategy_list_marks(&mut database, "uid:l1", &["sx", "sy", "zz"]);
    ops.push(op_marks("marks3", &marks3.states, marks3.open_group.clone()));

    let migrate_mapping: Vec<(String, String)> = [
        ("name:old", "uid:l1"),
        ("uid:l1", "uid:l2"),
        ("name:a", "name:b"),
        ("uid:x", "uid:x"),
        ("uid:y", "name:z"),
    ]
    .iter()
    .map(|(old, new)| (old.to_string(), new.to_string()))
    .collect();
    let migrated = migrate_profile_keys(&mut database, &migrate_mapping).expect("migrate");
    ops.push(json!(["migrate", migrated]));

    let marks4 = strategy_list_marks(&mut database, "uid:l2", &["sx"]);
    ops.push(op_marks("marks4", &marks4.states, marks4.open_group.clone()));
    let empty_profile = set_strategy_state(&mut database, "", "sx", Some("work"), None);
    ops.push(json!(["set_err", empty_profile.err().expect("ошибка пустого ключа")]));

    let grouping_now = get_grouping(&mut database);
    ops.push(json!(["grouping_now", grouping_now]));
    let group_now = open_group(&mut database, "uid:l2");
    ops.push(json!(["open_group_l2", group_now]));
    assert_eq!(json!(ops), golden()["ops"], "повтор операций у python");

    // Итоговое содержимое секции: python scrubbed updated_at.
    let final_section = database
        .read_raw_sections()
        .expect("секции")
        .get("profile_strategy_state")
        .cloned()
        .unwrap_or(Value::Null);
    assert_eq!(scrub_updated(final_section), golden()["final"].clone(), "итоговая секция");


}

fn op_state(name: &str, value: &primecore_profile::strategy_state::ProfileStrategyState) -> Value {
    json!([
        name,
        {"rating": value.rating, "favorite": value.favorite}
    ])
}

fn op_marks(
    name: &str,
    states: &[(String, primecore_profile::strategy_state::ProfileStrategyState)],
    open_group_value: Option<String>,
) -> Value {
    let states: Vec<Value> = states
        .iter()
        .map(|(id, state)| json!([id, {"rating": state.rating, "favorite": state.favorite}]))
        .collect();
    json!([
        name,
        {
            "states": states,
            "open_group": open_group_value,
        }
    ])
}

fn scrub_updated(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let mut clean: Map<String, Value> = Map::new();
            for (key, item) in object {
                if key == "updated_at" {
                    continue;
                }
                clean.insert(key, scrub_updated(item));
            }
            Value::Object(clean)
        }
        Value::Array(list) => Value::Array(list.into_iter().map(scrub_updated).collect()),
        other => other,
    }
}
