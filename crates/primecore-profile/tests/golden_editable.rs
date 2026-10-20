//! Золото editable_settings.py: правки фильтра и диапазонов профиля.

use once_cell::sync::Lazy;
use serde_json::Value;

use primecore_profile::editable_settings::{
    filter_value_is_file_reference, new_profile_insert_index, read_editable_profile_settings,
    read_profile_ranges, with_editable_profile_settings, EditableProfileSettings,
};
use primecore_profile::parser::parse_preset_text;

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_editable.json"
    ))
    .expect("golden_editable.json");
    serde_json::from_str(&source).expect("json")
});

static TEXT: &str = "--new=Peredovoy Bereg\n--filter-tcp=443\n--hostlist=steam.ru.txt\n--in-range=n1-d8\n--lua-desync=fakedsplit:4\n--lua-desync=split:2\n--out-range=x\n--new=Isklyuchenie RU\n--filter-tcp=80\n--ipset=ipset-ru.txt\n--hostlist-exclude=gov.ru.txt\n--in-range=a\n";

fn preset() -> primecore_profile::models::Preset {
    parse_preset_text(TEXT, "winws2", "alpha").expect("пресет")
}

fn preset_value(preset: &primecore_profile::models::Preset) -> Value {
    serde_json::json!({
        "engine": preset.engine,
        "header": preset.header_lines,
        "preamble": preset.preamble_lines,
        "footer": preset.footer_lines,
        "source_name": preset.source_name,
        "profiles": preset.profiles.iter().map(|profile| {
            serde_json::json!({
                "name": profile.name,
                "enabled": profile.enabled,
                "match": profile.match_section(),
                "segments": profile.segments.iter().map(|segment| {
                    serde_json::json!([segment.kind, segment.text])
                }).collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    })
}

#[test]
fn read_and_ranges_match_python() {
    let preset = preset();
    for entry in GOLDEN["ops"]["read"].as_array().expect("список") {
        let index = entry["index"].as_u64().expect("индекс") as usize;
        let profile = preset.profiles.get(index).expect("профиль");
        assert_eq!(
            &serde_json::to_value(read_editable_profile_settings(profile)).expect("сериализация"),
            &entry["settings"],
            "настройки {index}"
        );
    }
    let ranges: Vec<Value> = preset
        .profiles
        .iter()
        .map(|profile| {
            let (in_range, out_range) = read_profile_ranges(profile);
            serde_json::json!([in_range, out_range])
        })
        .collect();
    assert_eq!(
        serde_json::to_value(ranges).expect("сериализация"),
        GOLDEN["ops"]["ranges"],
        "диапазоны"
    );
}

#[test]
fn normalize_and_file_reference_match_python() {
    for case in GOLDEN["ops"]["normalize_filter_value"]
        .as_array()
        .expect("список")
    {
        let value = case[0].as_str().expect("значение");
        let kind = case[1].as_str().expect("тип");
        assert_eq!(
            primecore_profile::editable_settings::normalize_filter_value(value, kind, "primary"),
            case[2].as_str().expect("норм. значение"),
            "нормализация {value:?}"
        );
    }
    for case in GOLDEN["ops"]["file_reference"].as_array().expect("список") {
        let value = case[0].as_str().expect("значение");
        assert_eq!(
            filter_value_is_file_reference(value),
            case[1].as_bool().expect("флаг"),
            "файловая ссылка {value:?}"
        );
    }
}

#[test]
fn initial_preset_is_untouched() {
    let preset = preset();
    assert_eq!(
        preset_value(&preset),
        GOLDEN["ops"]["preset_initial"],
        "исходный пресет"
    );
}

#[test]
fn edits_match_python() {
    // Сценарий для каждого имени: правка настроек как в генераторе золота.
    for case in GOLDEN["ops"]["edits"].as_object().expect("правки") {
        let name = case.0.as_str();
        let index = case.1["index"].as_u64().expect("индекс") as usize;
        if case.1.get("error").is_some() {
            // Ошибочные сценарии покрыты тестом errors_match_python.
            continue;
        }
        let scenario = preset();
        let mut settings = read_editable_profile_settings(&scenario.profiles[index]);
        match name {
            "hostlist_change" => {
                settings.filter_kind = "ipset".to_string();
                settings.filter_value = "new.city.txt".to_string();
            }
            "value_change" => settings.filter_value = "other.list, 这个.txt".to_string(),
            "range_change" => {
                settings.in_range = "-n1".to_string();
                settings.out_range = "n8-".to_string();
            }
            "range_add" => {
                settings.in_range = "p2<d3".to_string();
                settings.out_range = "-n3".to_string();
            }
            "range_same_invalid" => settings.in_range = "n6".to_string(),
            other => panic!("неизвестная правка {other}"),
        }
        let updated = with_editable_profile_settings(&scenario, index, &settings)
            .unwrap_or_else(|error| panic!("сценарий {name} не применился: {error}"));
        assert_eq!(preset_value(&updated), case.1["preset"], "правка {name}");
    }
}

#[test]
fn exclude_role_on_primary_matches_python() {
    let scenario = preset();
    let mut settings = read_editable_profile_settings(&scenario.profiles[0]);
    settings.filter_role = "exclude".to_string();
    let updated = with_editable_profile_settings(&scenario, 0, &settings).expect("правка");
    assert_eq!(
        preset_value(&updated),
        GOLDEN["ops"]["exclude_role_on_primary"],
        "исключение из основного"
    );
}

#[test]
fn errors_match_python() {
    for (name, expected) in GOLDEN["ops"]["errors"].as_object().expect("ошибки") {
        let scenario = preset();
        let result = match name.as_str() {
            "bogus_kind" => with_editable_profile_settings(
                &scenario,
                0,
                &EditableProfileSettings {
                    filter_kind: "bogus".to_string(),
                    filter_value: "a.txt".to_string(),
                    ..EditableProfileSettings::default()
                },
            ),
            "empty_value" => with_editable_profile_settings(
                &scenario,
                0,
                &EditableProfileSettings {
                    filter_value: String::new(),
                    ..EditableProfileSettings::default()
                },
            ),
            "not_file" => with_editable_profile_settings(
                &scenario,
                0,
                &EditableProfileSettings {
                    filter_value: ":/not_file".to_string(),
                    ..EditableProfileSettings::default()
                },
            ),
            "bad_range" => {
                let mut settings = read_editable_profile_settings(&scenario.profiles[0]);
                settings.in_range = "n6".to_string();
                with_editable_profile_settings(&scenario, 0, &settings)
            }
            "wrong_index" => with_editable_profile_settings(
                &scenario,
                9,
                &EditableProfileSettings {
                    filter_kind: "hostlist".to_string(),
                    filter_value: "a.txt".to_string(),
                    ..EditableProfileSettings::default()
                },
            ),
            other => panic!("неизвестная ошибка {other}"),
        };
        assert_eq!(
            expected.as_str().expect("сообщение"),
            result.unwrap_err(),
            "ошибка {name}"
        );
    }
}

#[test]
fn insert_indexes_match_python() {
    // insert_index: профиль-исключение (ipset-ru.txt) ставится первым.
    let scenario = preset();
    let mut settings = read_editable_profile_settings(&scenario.profiles[0]);
    settings.filter_kind = "ipset".to_string();
    settings.filter_value = "new.city.txt".to_string();
    settings.in_range = "x".to_string();
    settings.out_range = "x".to_string();
    let updated = with_editable_profile_settings(&scenario, 0, &settings).expect("правка");
    assert_eq!(
        1,
        new_profile_insert_index(&updated),
        "вставка перед RU-исключением"
    );
    assert_eq!(
        GOLDEN["ops"]["insert_index"].as_u64().expect("индекс"),
        new_profile_insert_index(&updated) as u64,
        "индекс вставки"
    );
    assert_eq!(
        GOLDEN["ops"]["insert_index_initial"]
            .as_u64()
            .expect("индекс"),
        new_profile_insert_index(&scenario) as u64,
        "индекс вставки в исходный"
    );
}
