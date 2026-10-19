//! Золото strategy_usage.py: как часто стратегии стоят в готовых пресетах.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use once_cell::sync::Lazy;
use serde_json::{json, Value};

use primecore_mode::AppPaths;

use primecore_profile::ENGINE_WINWS2;

use primecore_profile::parser::parse_preset_text;
use primecore_profile::strategy_catalog::{load_strategy_catalogs, StrategyEntry};
use primecore_profile::strategy_usage::{
    CatalogIndex, count_builtin_strategy_usage, load_builtin_strategy_usage, service_key,
    BuiltinStrategyUsage,
};

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_strategy_usage.json"
    ))
    .expect("golden_strategy_usage.json");
    serde_json::from_str(&source).expect("json")
});

const TCP_CATALOG: &str = concat!(
    "[simple]\n",
    "name = Простая midsld\n",
    "author = test\n",
    "label = recommended\n",
    "--lua-desync=multisplit:pos=midsld\n",
    "\n",
    "[composite]\n",
    "name = Составная ветки\n",
    "--payload=all\n",
    "--lua-desync=syndata\n",
    "--payload=tls_client_hello,http_req\n",
    "--lua-desync=multidisorder_legacy:pos=2\n",
    "\n",
    "[syndata]\n",
    "name = Только syndata\n",
    "--lua-desync=syndata\n",
);
const UDP_CATALOG: &str = concat!(
    "[udp_fake]\n",
    "name = Квик фейк\n",
    "--lua-desync=fake:blob=fake_default_quic:repeats=3\n",
);
const VOICE_CATALOG: &str = concat!(
    "[voice_udp]\n",
    "name = Голосовая\n",
    "--lua-desync=fake:blob=fake_default_quic:repeats=3\n",
);
const UDP1_CATALOG: &str = concat!(
    "[other]\n",
    "name = OtherSEQOVL\n",
    "--dpi-desync=multisplit\n",
    "--dpi-desync-split-seqovl=211\n",
);

const P1_TEXT: &str = concat!(
    "--new=YouTube простой\n",
    "--filter-tcp=443\n",
    "--hostlist=googlevideo.txt\n",
    "--lua-desync=multisplit:pos=midsld\n",
    "--new=Ветки YouTube\n",
    "--filter-tcp=443\n",
    "--hostlist=googlevideo.txt\n",
    "--payload=all\n",
    "--lua-desync=syndata\n",
    "--payload=tls_client_hello,http_req\n",
    "--lua-desync=multidisorder_legacy:pos=2\n",
);
const P2_TEXT: &str = concat!(
    "--new=YouTube простой 2\n",
    "--filter-tcp=443\n",
    "--hostlist=googlevideo.txt\n",
    "--lua-desync=multisplit:pos=midsld\n",
    "--new=Квик UDP\n",
    "--filter-udp=50000\n",
    "--lua-desync=fake:blob=fake_default_quic:repeats=3\n",
    "--new=Выключено\n",
    "--filter-tcp=443\n",
    "--hostlist=googlevideo.txt\n",
    "--lua-desync=multisplit:pos=midsld\n",
);
const P3_TEXT: &str = concat!(
    "--new=Отключенный пресет\n",
    "--filter-tcp=443\n",
    "--hostlist=other.txt\n",
    "--lua-desync=syndata\n",
);
const W1_PRESET_TEXT: &str = concat!(
    "--new=W1 профиль\n",
    "--filter-tcp=443\n",
    "--dpi-desync=multisplit\n",
    "--dpi-desync-split-seqovl=211\n",
);
const YT_TEXT: &str = concat!(
    "--new=Открытый\n",
    "--filter-tcp=443\n",
    "--hostlist=googlevideo.txt\n",
    "--lua-desync=multisplit:pos=midsld\n",
);

static FIXTURE: AtomicUsize = AtomicUsize::new(0);

fn set_user_root(suffix: &str, winws2_presets: &[(&str, &str)], winws1_presets: &[(&str, &str)]) -> AppPaths {
    let index = FIXTURE.fetch_add(1, Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!("primecore_usage_{index}_{suffix}"));
    let user = root.join("user");
    let winws2 = user.join("system/strategy_catalogs/winws2");
    std::fs::create_dir_all(&winws2).expect("winws2 каталоги");
    std::fs::write(winws2.join("tcp.txt"), TCP_CATALOG).expect("tcp.txt");
    std::fs::write(winws2.join("udp.txt"), UDP_CATALOG).expect("udp.txt");
    std::fs::write(winws2.join("voice.txt"), VOICE_CATALOG).expect("voice.txt");
    let winws1 = user.join("system/strategy_catalogs/winws1");
    std::fs::create_dir_all(&winws1).expect("winws1 каталоги");
    std::fs::write(winws1.join("udp.txt"), UDP1_CATALOG).expect("udp.txt");
    std::fs::write(winws1.join("tcp.txt"), UDP1_CATALOG).expect("tcp.txt");
    for (dir_name, presets) in [
        ("winws2_builtin", winws2_presets),
        ("winws1_builtin", winws1_presets),
    ] {
        let builtin = user.join("presets").join(dir_name);
        std::fs::create_dir_all(&builtin).expect("каталог пресетов");
        for (name, text) in presets {
            std::fs::write(builtin.join(format!("{name}.txt")), text).expect("пресет");
        }
    }
    AppPaths {
        user_root: user.clone(),
        local_root: user.join("local"),
    }
}

fn usage_record(usage: &BuiltinStrategyUsage) -> Value {
    json!({
        "by_service": usage.by_service
            .iter()
            .map(|(service, counts)| json!({
                "service": service,
                "counts": counts.iter().map(|((catalog, strategy), count)| json!({
                    "catalog": catalog,
                    "strategy": strategy,
                    "count": count,
                })).collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
        "services": usage.services
            .iter()
            .map(|((catalog, strategy), count)| json!({
                "catalog": catalog,
                "strategy": strategy,
                "count": count,
            }))
            .collect::<Vec<_>>(),
        "service_names": usage.service_names
            .iter()
            .cloned()
            .collect::<HashMap<String, String>>(),
        "service_match_lines": usage.service_match_lines
            .iter()
            .map(|(service, lines)| (service.clone(), lines.clone()))
            .collect::<HashMap<String, Vec<String>>>(),
    })
}

fn places_record(usage: &BuiltinStrategyUsage, catalog: &str, strategy: &str) -> Value {
    usage.places(catalog, strategy).first().map_or(Value::Null, |(service, name, count)| {
        json!({"service": service, "name": name, "count": count})
    })
}

fn for_profile_record(mapping: &[(String, primecore_profile::strategy_usage::StrategyUsage)]) -> Value {
    Value::Array(
        mapping
            .iter()
            .map(|(strategy, usage)| {
                json!({
                    "strategy": strategy,
                    "same_service": usage.same_service,
                    "services": usage.services,
                    "recommended": usage.recommended(),
                })
            })
            .collect(),
    )
}

fn entry(strategy_id: &str, args: &str, is_composite: bool) -> StrategyEntry {
    let mut value: StrategyEntry = serde_json::from_str(
        &format!(
            r#"{{"strategy_id":"{strategy_id}","catalog_name":"","name":"","args":"","visual":{{"technique_keys":[],"icon_name":"","color":"","colors":[],"label":"","description":""}}}}"#
        ),
    )
    .expect("стратегия");
    value.strategy_id = strategy_id.to_string();
    value.args = args.to_string();
    value.is_composite = is_composite;
    value
}

#[test]
fn builtin_usage_matches_python() {
    let paths = set_user_root(
        "w2",
        &[("p1", P1_TEXT), ("p2", P2_TEXT), ("p3", P3_TEXT)],
        &[("w1", W1_PRESET_TEXT)],
    );
    let catalogs = load_strategy_catalogs(&paths.user_root, ENGINE_WINWS2);
    let usage = count_builtin_strategy_usage(
        &[
            ("p1".to_string(), P1_TEXT.to_string()),
            ("p2".to_string(), P2_TEXT.to_string()),
            ("p3".to_string(), P3_TEXT.to_string()),
        ],
        ENGINE_WINWS2,
        &catalogs,
    );

    let yt_profile =
        parse_preset_text(YT_TEXT, ENGINE_WINWS2, "open").expect("профиль");
    let mut out = json!({
        "winws2": {
            "usage": usage_record(&usage),
            "places_simple": places_record(&usage, "tcp", "simple"),
            "places_syndata": places_record(&usage, "tcp", "syndata"),
            "places_composite": places_record(&usage, "tcp", "composite"),
            "places_voice": places_record(&usage, "voice", "voice_udp"),
            "places_fake": places_record(&usage, "udp", "udp_fake"),
            "places_other_catalog": places_record(&usage, "http80", "simple"),
            "service_key": service_key(&yt_profile.profiles[0]),
            "for_profile": for_profile_record(&usage.for_profile(&yt_profile.profiles[0], None)),
            "for_profile_udp_catalog": for_profile_record(&usage.for_profile(&yt_profile.profiles[0], Some("udp"))),
        },
        "winws1": {},
        "index": {},
        "load": {},
    });

    // winws1.
    let w1_catalogs = load_strategy_catalogs(&paths.user_root, "winws1");
    out["winws1"]["usage"] = usage_record(&count_builtin_strategy_usage(
        &[("w1".to_string(), W1_PRESET_TEXT.to_string())],
        "winws1",
        &w1_catalogs,
    ));

    // Index: неопределённые и многократные записи.
    let entries = vec![
        entry("dup_a", "--lua-desync=syndata", false),
        entry("dup_b", "--lua-desync=syndata", false),
        entry(
            "plain_multi",
            "--lua-desync=syndata\n--lua-desync=multisplit:pos=midsld",
            false,
        ),
        entry(
            "composite",
            "--payload=all\n--lua-desync=syndata\n--payload=tls_client_hello,http_req\n--lua-desync=multidisorder_legacy:pos=2",
            true,
        ),
    ];
    let index = CatalogIndex::new(ENGINE_WINWS2, &entries);
    out["index"] = json!({
        "ambiguous": index.strategy_id(&["--lua-desync=syndata".to_string()]),
        "multi": index.strategy_id(&["--lua-desync=syndata".to_string(), "--lua-desync=multisplit:pos=midsld".to_string()]),
        "composite": index.strategy_id(&[
            "--payload=all".to_string(),
            "--lua-desync=syndata".to_string(),
            "--payload=tls_client_hello,http_req".to_string(),
            "--lua-desync=multidisorder_legacy:pos=2".to_string(),
        ]),
        "empty": index.strategy_id(&["--filter-tcp=443".to_string()]),
        "unknown": index.strategy_id(&["--lua-desync=unknown_function".to_string()]),
    });

    // Нагрузка по подписи.
    let first = load_builtin_strategy_usage(&paths, ENGINE_WINWS2, &catalogs, "sig");
    let cached = load_builtin_strategy_usage(&paths, ENGINE_WINWS2, &catalogs, "sig");
    let w1_first = load_builtin_strategy_usage(&paths, "winws1", &w1_catalogs, "sig1");
    let w1_cached = load_builtin_strategy_usage(&paths, "winws1", &w1_catalogs, "sig1");
    out["load"]["first"] = usage_record(&first);
    out["load"]["cached"] = usage_record(&cached);
    out["load"]["w1_first"] = usage_record(&w1_first);
    out["load"]["w1_cached"] = usage_record(&w1_cached);
    std::fs::remove_file(
        paths
            .engine_paths(Some(ENGINE_WINWS2))
            .builtin_presets_dir
            .join("p2.txt"),
    )
    .expect("удаление");
    let after_delete = load_builtin_strategy_usage(&paths, ENGINE_WINWS2, &catalogs, "sig");
    out["load"]["after_delete"] = usage_record(&after_delete);

    let golden = &*GOLDEN;
    assert_eq!(out["winws2"], golden["winws2"], "winws2");
    assert_eq!(out["winws1"], golden["winws1"], "winws1");
    assert_eq!(out["index"], golden["index"], "индекс каталога");
    assert_eq!(out["load"], golden["load"], "нагрузка по подписи");
}
