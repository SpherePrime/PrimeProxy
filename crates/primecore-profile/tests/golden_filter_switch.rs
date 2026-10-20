//! Золото filter_switch.py: переключение типа фильтра профиля.

use once_cell::sync::Lazy;
use serde_json::Value;
use std::path::PathBuf;

use primecore_profile::editable_settings::{
    read_editable_profile_settings, EditableProfileSettings,
};
use primecore_profile::filter_switch::{
    build_filter_kind_candidate, filter_kind_switch_creates_preset_duplicate,
    filter_kinds_without_preset_duplicates, resolve_filter_kind_switch, FilterKindSwitchCandidate,
};
use primecore_profile::models::Profile;
use primecore_profile::parser::parse_preset_text;

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_filter_switch.json"
    ))
    .expect("golden_filter_switch.json");
    serde_json::from_str(&source).expect("json")
});

const PLAIN_TEXT: &str = concat!(
    "--new=Peredovoy Bereg\n",
    "--filter-tcp=443\n",
    "--hostlist=other.txt\n",
    "--in-range=n1-d8\n",
    "--lua-desync=fakedsplit:4\n",
    "--lua-desync=split:2\n",
    "--out-range=x\n",
    "--new=Isklyuchenie RU\n",
    "--filter-tcp=80\n",
    "--ipset=ipset-ru.txt\n",
    "--hostlist-exclude=gov.ru.txt\n",
    "--in-range=a\n",
    "--new=Vse Sajty Hostlist\n",
    "--filter-tcp=443\n",
    "--hostlist-exclude=netrogat.txt\n",
    "--lua-desync=multisplit\n",
    "--new=Vse Sajty Ip\n",
    "--filter-tcp=443\n",
    "--ipset-exclude=ipset-ru.txt\n",
    "--lua-desync=multisplit\n",
);
const TWIN_TEXT: &str = concat!(
    "--new=Primojn\n",
    "--filter-tcp=443\n",
    "--hostlist=other.txt\n",
    "--lua-desync=multisplit\n",
    "--new=Parnej\n",
    "--filter-tcp=443\n",
    "--ipset=ipset-other.txt\n",
    "--lua-desync=multisplit\n",
);

fn user_root() -> PathBuf {
    // Каталог и файлы списков создаются по золоту: other.txt, ipset-all.txt,
    // steam.txt и ipset-other.txt существуют; user2/lists — нет вообще.
    // Каждый вызов — свой каталог: тесты идут параллельно.
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let id = NEXT.fetch_add(1, Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!("primecore_filter_switch_golden_{id}"));
    let lists = root.join("user").join("lists");
    std::fs::create_dir_all(&lists).expect("создать каталог списков");
    for (name, body) in [
        ("other.txt", "voorbeeld.nl\n"),
        ("ipset-all.txt", "1.2.3.4\n"),
        ("steam.txt", "steam.info\n"),
        ("ipset-other.txt", "1.2.3.4\n"),
    ] {
        std::fs::write(lists.join(name), body).expect("создать список");
    }
    root.join("user")
}

#[allow(dead_code)]
fn text_settings(json: &Value) -> EditableProfileSettings {
    serde_json::from_value(json.clone()).expect("настройки фильтра")
}

fn as_value(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("сериализация")
}

fn plain_preset() -> primecore_profile::models::Preset {
    parse_preset_text(PLAIN_TEXT, "winws2", "alpha").expect("пресет")
}

fn twin_preset() -> primecore_profile::models::Preset {
    parse_preset_text(TWIN_TEXT, "winws2", "twin").expect("пресет близнецов")
}

#[test]
fn candidates_and_resolutions_match_python() {
    let root = user_root();
    let preset = plain_preset();
    for (index, expected) in GOLDEN["candidates"].as_object().expect("кандидаты") {
        let profile = &preset.profiles[index.parse::<usize>().expect("индекс")];
        let settings = read_editable_profile_settings(profile);
        for (kind, expected_candidate) in expected.as_object().expect("типы") {
            assert_eq!(
                &as_value(
                    &build_filter_kind_candidate(
                        &settings,
                        // python Comparator String
                        kind.as_str()
                    ) // candidate
                ),
                expected_candidate,
                "кандидат {index}/{kind}"
            );
        }
    }
    for (index, expected) in GOLDEN["resolutions"].as_object().expect("разрешения") {
        let profile = &preset.profiles[index.parse::<usize>().expect("индекс")];
        let settings = read_editable_profile_settings(profile);
        for (kind, expected_resolution) in expected.as_object().expect("типы") {
            assert_eq!(
                &as_value(&resolve_filter_kind_switch(&settings, kind.as_str(), &root)),
                expected_resolution,
                "разрешение {index}/{kind}"
            );
        }
    }
}

#[test]
fn duplicates_match_python() {
    user_root();
    let preset = plain_preset();
    let twin = twin_preset();
    for (name, expected) in GOLDEN["duplicates"].as_object().expect("дубли") {
        let scenario = if name == "twin" {
            twin.clone()
        } else {
            preset.clone()
        };
        for (index, cases) in expected.as_object().expect("профили") {
            let profile_position = index.parse::<usize>().expect("индекс");
            let profile: Profile = scenario.profiles[profile_position].clone();
            let settings = read_editable_profile_settings(&profile);
            for (kind, expected_flag) in cases.as_object().expect("типы") {
                let candidate: FilterKindSwitchCandidate =
                    build_filter_kind_candidate(&settings, kind.as_str());
                let switched_settings = EditableProfileSettings {
                    filter_kind: candidate.filter_kind.clone(),
                    filter_value: candidate.filter_value.clone(),
                    filter_role: settings.filter_role.clone(),
                    in_range: settings.in_range.clone(),
                    out_range: settings.out_range.clone(),
                    ..EditableProfileSettings::default()
                };
                assert_eq!(
                    filter_kind_switch_creates_preset_duplicate(
                        &profile,
                        &scenario.profiles,
                        &switched_settings,
                        &primecore_profile::filter_switch::FilterKindSwitchResolution {
                            allowed: true,
                            filter_kind: candidate.filter_kind.clone(),
                            filter_value: candidate.filter_value.clone(),
                            reason: String::new(),
                        }
                    ),
                    expected_flag.as_bool().expect("флаг"),
                    "дубль {name}/{index}/{kind}"
                );
            }
        }
    }
}

#[test]
fn available_kinds_match_python() {
    let root = user_root();
    let preset = plain_preset();
    let twin = twin_preset();
    for (index, expected) in GOLDEN["available_kinds"].as_object().expect("типы") {
        let profile = preset.profiles[index.parse::<usize>().expect("индекс")].clone();
        let settings = read_editable_profile_settings(&profile);
        for (case_name, kinds) in [
            ("plain", vec!["hostlist", "ipset"]),
            ("aliases", vec![" hostlist ", " IpSet "]),
            ("empty", vec![]),
        ] {
            assert_eq!(
                as_value(&filter_kinds_without_preset_duplicates(
                    &settings,
                    &profile,
                    &preset.profiles,
                    &kinds,
                    &root
                )),
                expected[case_name],
                "доступные {index}/{case_name}"
            );
        }
    }
    for (index, expected) in GOLDEN["available_kinds_twin"]
        .as_object()
        .expect("типы близнецов")
    {
        let profile = twin.profiles[index.parse::<usize>().expect("индекс")].clone();
        let settings = read_editable_profile_settings(&profile);
        assert_eq!(
            as_value(&filter_kinds_without_preset_duplicates(
                &settings,
                &profile,
                &twin.profiles,
                &["hostlist", "ipset"],
                &root
            )),
            expected["plain"],
            "доступные близнецов {index}"
        );
    }
}

#[test]
fn special_cases_match_python() {
    let root = user_root();
    let special = &GOLDEN["special"];

    let multi = EditableProfileSettings {
        filter_kind: "hostlist".to_string(),
        filter_value: "steam.txt, other.txt".to_string(),
        filter_role: "primary".to_string(),
        filter_editable: true,
        filter_protocol: String::new(),
        in_range: "x".to_string(),
        out_range: "a".to_string(),
    };
    assert_eq!(
        as_value(&build_filter_kind_candidate(&multi, "ipset")),
        special["multi_value"],
        "много значений → ipset"
    );
    assert_eq!(
        as_value(&build_filter_kind_candidate(&multi, "hostlist")),
        special["multi_same"],
        "много значений → остаётся"
    );

    let exclude = EditableProfileSettings {
        filter_kind: "hostlist".to_string(),
        filter_value: "gov.ru.txt".to_string(),
        filter_role: "exclude".to_string(),
        filter_editable: true,
        filter_protocol: "tcp".to_string(),
        in_range: "x".to_string(),
        out_range: "a".to_string(),
    };
    assert_eq!(
        as_value(&build_filter_kind_candidate(&exclude, "ipset")),
        special["exclude_pair"],
        "exclude-пара"
    );

    let missing_root = root.join("user2");
    assert_eq!(
        as_value(&resolve_filter_kind_switch(&multi, "ipset", &missing_root)),
        special["missing_root"],
        "нет каталога lists"
    );

    let single = EditableProfileSettings {
        filter_kind: "hostlist".to_string(),
        filter_value: "steam.txt".to_string(),
        filter_role: "primary".to_string(),
        filter_editable: true,
        filter_protocol: String::new(),
        in_range: "x".to_string(),
        out_range: "a".to_string(),
    };
    assert_eq!(
        as_value(&resolve_filter_kind_switch(&single, "ipset", &root)),
        special["missing_file"],
        "нет файла для пары"
    );

    let other = EditableProfileSettings {
        filter_kind: "hostlist".to_string(),
        filter_value: "other.txt".to_string(),
        filter_role: "primary".to_string(),
        filter_editable: true,
        filter_protocol: String::new(),
        in_range: "x".to_string(),
        out_range: "a".to_string(),
    };
    assert_eq!(
        as_value(&build_filter_kind_candidate(&other, "ipset")),
        special["paired_other_to_ipset_all"],
        "other.txt → ipset-all.txt"
    );

    let ipset_all = EditableProfileSettings {
        filter_kind: "ipset".to_string(),
        filter_value: "ipset-all.txt".to_string(),
        filter_role: "primary".to_string(),
        filter_editable: true,
        filter_protocol: String::new(),
        in_range: "x".to_string(),
        out_range: "a".to_string(),
    };
    assert_eq!(
        as_value(&build_filter_kind_candidate(&ipset_all, "hostlist")),
        special["paired_ipset_all_to_hostlist"],
        "ipset-all.txt → other.txt"
    );

    let ipset_prefix = EditableProfileSettings {
        filter_kind: "ipset".to_string(),
        filter_value: "lists\\user\\ipset-heavy.lst".to_string(),
        filter_role: "primary".to_string(),
        filter_editable: true,
        filter_protocol: String::new(),
        in_range: "x".to_string(),
        out_range: "a".to_string(),
    };
    assert_eq!(
        as_value(&build_filter_kind_candidate(&ipset_prefix, "hostlist")),
        special["paired_ipset_prefix_stem"],
        "ipset-титул срезался"
    );

    let plain_path = EditableProfileSettings {
        filter_kind: "hostlist".to_string(),
        filter_value: "lists/base/steam.txt".to_string(),
        filter_role: "primary".to_string(),
        filter_editable: true,
        filter_protocol: String::new(),
        in_range: "x".to_string(),
        out_range: "a".to_string(),
    };
    assert_eq!(
        as_value(&build_filter_kind_candidate(&plain_path, "ipset")),
        special["paired_hostlist_plain"],
        "plain path → ipset"
    );

    assert_eq!(
        as_value(&build_filter_kind_candidate(
            &EditableProfileSettings {
                filter_editable: false,
                ..multi.clone()
            },
            "ipset"
        )),
        special["not_editable"],
        "не редактируемый"
    );

    assert_eq!(
        as_value(&build_filter_kind_candidate(
            &EditableProfileSettings {
                filter_kind: "ipset-ip".to_string(),
                ..multi.clone()
            },
            "hostlist"
        )),
        special["bogus_kind_from"],
        "текущий тип вне пары"
    );
    assert_eq!(
        as_value(&build_filter_kind_candidate(&multi, "hostlist-domains")),
        special["bogus_kind_target"],
        "целевой тип вне пары"
    );
}
