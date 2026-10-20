//! Золотой тест каталога стратегий (profile/strategy_catalog.py) против Python.

use serde_json::{json, Value};

use primecore_profile::strategy_catalog::{
    load_strategy_catalogs_with_signature, parse_catalog_payload,
};

fn golden() -> &'static Value {
    static GOLDEN: std::sync::OnceLock<Value> = std::sync::OnceLock::new();
    GOLDEN.get_or_init(|| serde_json::from_slice(include_bytes!("golden_catalog.json")).unwrap())
}

fn catalog_alpha() -> String {
    let mut payload = String::from("# Каталог услуг\n\n");
    payload.push_str("[Базовая Обхода]\nname = Разделение\nold_name = Актуальный Разделение\n");
    payload.push_str("description = Простое\nlabel = Stable\n--lua-desync=split:2\n\n");
    payload.push_str("[Композитный Тип]\nname = Дубли\nargs = Правило\n\n");
    payload.push_str("--lua-desync=fake\n--in-range=4-6\n--lua-desync=split\n\n");
    payload.push_str("[Опасный]\nlabel = Caution\nauthor = unknown_author\n");
    payload.push_str("--lua-desync=disorder\n--ipset=1.1.1.1\n\n");
    payload.push_str(
        "[--filter-tcp=2]\nname = Строка фильтра\n--filter-tcp=2\n--lua-desync=fake:1\n\n",
    );
    payload.push_str("[Пустой]\n\n[Ipset]\nipset= очиститель\n--lua-desync=tamper\n");
    payload
}

fn catalog_beta() -> String {
    let mut payload =
        String::from("[Первая Пара]\n\n--lua-desync=multisplit\n--ndpi-list=@C:\\fake.txt\n\n");
    payload.push_str(
        "--payload=udp\n--lua-desync=hop\n--unknown-option=5\n\n--lua-desync=fakeddisorder\n",
    );
    payload
}

fn entries_json(entries: &[primecore_profile::strategy_catalog::StrategyEntry]) -> Value {
    json!(entries)
}

fn direct_parse_cases() -> Vec<(&'static str, String)> {
    vec![("alpha", catalog_alpha()), ("beta", catalog_beta())]
}

#[test]
fn catalog_direct_parse_matches_python() {
    for (case_name, payload) in direct_parse_cases() {
        let parsed = parse_catalog_payload(&payload, case_name);
        assert_eq!(
            entries_json(&parsed),
            golden()["parse"][format!("direct{}", case_index(case_name))],
            "{case_name}: разбор файла каталога"
        );
    }
}

fn case_index(case_name: &str) -> usize {
    match case_name {
        "alpha" => 1,
        "beta" => 2,
        other => panic!("неизвестный канал {other}"),
    }
}

#[test]
fn catalog_loader_matches_python() {
    let temp_dir = std::env::temp_dir().join(format!("zapret_catalog_{}_load", std::process::id()));
    std::fs::create_dir_all(temp_dir.join("system/strategy_catalogs/winws2/Sub")).expect("fixture");
    std::fs::write(
        temp_dir.join("system/strategy_catalogs/winws2/Alpha.txt"),
        catalog_alpha(),
    )
    .expect("fixture alpha");
    std::fs::write(
        temp_dir.join("system/strategy_catalogs/winws2/Sub/nested.txt"),
        "# nested".to_string() + &catalog_beta(),
    )
    .expect("fixture nested");
    std::fs::write(
        temp_dir.join("system/strategy_catalogs/winws2/Beta.TXT"),
        catalog_beta(),
    )
    .expect("fixture upper");

    let (_cache_key, _signature, catalogs) =
        load_strategy_catalogs_with_signature(&temp_dir, "WINWS2");
    assert_eq!(
        json!(catalogs.keys().collect::<Vec<_>>()),
        golden()["catalog_keys"]
    );
    for (case_name, expected_key) in [("alpha", "direct1"), ("beta", "direct2")] {
        let loaded = catalogs.get(case_name).map(Vec::as_slice);
        let expected_list = golden()["parse"][expected_key]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .to_vec();
        let expected = if expected_list.is_empty() {
            None
        } else {
            Some(json!(expected_list))
        };
        assert_eq!(
            loaded.map(entries_json),
            expected,
            "{case_name}: загрузка каталогов"
        );
    }
    std::fs::remove_dir_all(temp_dir).ok();
}

#[test]
fn visual_descriptions_match_python() {
    let samples: Vec<String> = vec![
        "--lua-desync=fake\n--lua-desync=split".into(),
        "  --lua-desync= fakedsplit:1\n".into(),
        "--lua-desync=dht_dn=zero\n--lua-desync=multidisorder".into(),
        "-".into(),
        "--lua-desync=unknown_technique\n--lua-desync=fake".into(),
        "--payload=tcp\n--lua-desync=syndata".into(),
        "--lua-desync=hostfakesplit".into(),
        "--lua-desync=udplen\n\n\n--lua-desync=tcpseg\n--lua-desync=fake:1=2:3".into(),
    ];
    for (index, sample) in samples.iter().enumerate() {
        let expected = golden()["visuals"][index].clone();
        let visuals = primecore_profile::strategy_visuals::describe_strategy_visual(sample);
        let got = json!({
            "technique_keys": visuals.technique_keys,
            "icon_name": visuals.icon_name,
            "color": visuals.color,
            "colors": visuals.colors,
            "label": visuals.label,
            "description": visuals.description,
        });
        assert_eq!(got, expected.clone(), "визуал {index}");
        let plain = primecore_profile::strategy_visuals::strategy_plain_label(
            &visuals.technique_keys,
            "нет",
        );
        assert_eq!(
            json!(plain),
            golden()["plain"][index].clone(),
            "простым языком {index}"
        );
    }
    assert_eq!(
        json!(true),
        golden()["missing"][0][0].clone(),
        "несуществующий каталог"
    );
}
