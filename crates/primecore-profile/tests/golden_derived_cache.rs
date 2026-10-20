//! Золото derived_cache.py: контентное ядро профиля и его кэши.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use once_cell::sync::Lazy;
use serde_json::{json, Value};

use primecore_profile::derived_cache::{
    available_filter_kinds, basic_strategy_entries, build_profile_derived_core, visible_list_type,
    CatalogMap, PresetSourcesCache, ProfileDerivedCache,
};
use primecore_profile::editable_settings::read_editable_profile_settings;
use primecore_profile::parser::parse_preset_text;
use primecore_profile::strategy_catalog::{load_strategy_catalogs, StrategyEntry};

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_derived_cache.json"
    ))
    .expect("golden_derived_cache.json");
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

const S1_TEXT: &str = "--new=Simple\n--filter-tcp=443\n--hostlist=googlevideo.txt\n--lua-desync=multisplit:pos=midsld\n";
const CUSTOM_TEXT: &str = "--new=Custom\n--filter-tcp=443\n--hostlist=googlevideo.txt\n--lua-desync=mldisorder:fake=smtp:udplen=57\n";
const NONE_TEXT: &str = "--new=Пусто\n--filter-tcp=443\n--hostlist=googlevideo.txt\n";
const COMPOSITE_TEXT: &str = concat!(
    "--new=Ветки\n",
    "--filter-tcp=443\n",
    "--hostlist=googlevideo.txt\n",
    "--payload=all\n",
    "--lua-desync=syndata\n",
    "--payload=tls_client_hello,http_req\n",
    "--lua-desync=multidisorder_legacy:pos=2\n",
);
const VOICE_TEXT: &str =
    "--new=Голосова\n--filter-udp=50000\n--lua-desync=fake:blob=fake_default_quic:repeats=3\n";
const W1_TEXT: &str = "--new=W1\n--dpi-desync=multisplit\n--dpi-desync-split-seqovl=211\n";
const EXCLUDE_NOT_TEXT: &str = "--new=Защита игр\n--hostlist-exclude=gov.ru.txt\n";
const EXCLUDE_YES_TEXT: &str = "--new=Исключить RU\n--hostlist-exclude=gov.ru.txt\n";
const NO_FILTER_TEXT: &str = "--new=Без условий\n--lua-desync=multisplit:pos=midsld\n";
const RAW_TEXT_TEMPLATE: &str = concat!(
    "--new=  Развёрнут Test  \n",
    "\n",
    "--filter-tcp=443\n",
    "  \n",
    "--hostlist=other.txt \n",
    "--lua-desync=multisplit:pos=midsld\n",
);

static FIXTURE: AtomicUsize = AtomicUsize::new(0);

fn texts() -> Vec<(&'static str, &'static str)> {
    vec![
        ("simple_match", S1_TEXT),
        ("simple_custom", CUSTOM_TEXT),
        ("none_strategy", NONE_TEXT),
        ("composite_match", COMPOSITE_TEXT),
        ("voice_list", VOICE_TEXT),
        ("exclude_named", EXCLUDE_NOT_TEXT),
        ("exclude_role", EXCLUDE_YES_TEXT),
    ]
}

/// Пользовательский root с мини-каталогами и списками, как в python-генераторе.
fn user_root() -> PathBuf {
    let index = FIXTURE.fetch_add(1, Ordering::SeqCst);
    let root = std::env::temp_dir().join(format!("primecore_derived_{index}"));
    let user = root.join("user");
    let winws2 = user.join("system/strategy_catalogs/winws2");
    std::fs::create_dir_all(&winws2).expect("каталоги");
    std::fs::write(winws2.join("tcp.txt"), TCP_CATALOG).expect("tcp.txt");
    std::fs::write(winws2.join("voice.txt"), VOICE_CATALOG).expect("voice.txt");
    let winws1 = user.join("system/strategy_catalogs/winws1");
    std::fs::create_dir_all(&winws1).expect("winws1");
    std::fs::write(winws1.join("udp.txt"), UDP1_CATALOG).expect("udp.txt");
    let lists = user.join("lists");
    std::fs::create_dir_all(&lists).expect("lists");
    for (name, payload) in [
        ("other.txt", "google.com\n"),
        ("ipset-other.txt", "127.0.0.1\n"),
        ("ipset-all.txt", "127.0.0.0/8\n"),
        ("googlevideo.txt", "youtube.com\n"),
        ("ipset-googlevideo.txt", "216.0.0.0/8\n"),
    ] {
        std::fs::write(lists.join(name), payload).expect("список");
    }
    root
}

fn catalogs_map(user_root: &Path, engine: &str) -> (String, Vec<(String, Vec<StrategyEntry>)>) {
    let loaded = load_strategy_catalogs(user_root, engine);
    let mut names: Vec<String> = loaded.keys().cloned().collect();
    names.sort();
    let map: Vec<(String, Vec<StrategyEntry>)> = names
        .into_iter()
        .map(|name| {
            let entries = loaded.get(&name).expect("записи").clone();
            (name, entries)
        })
        .collect();
    (format!("sig:{engine}"), map)
}

fn catalog_ids(map: &CatalogMap, name: &str) -> Value {
    let entries = map
        .iter()
        .find(|(catalog_name, _)| catalog_name == name)
        .map(|(_, entries)| entries)
        .expect("каталог");
    json!(entries
        .iter()
        .map(|entry| entry.strategy_id.clone())
        .collect::<Vec<_>>())
}

fn core_record(core: &primecore_profile::derived_cache::ProfileDerivedCore) -> Value {
    json!({
        "strategy_entry_ids": core.strategy_entries.iter().map(|entry| entry.strategy_id.clone()).collect::<Vec<_>>(),
        "strategy_entry_names": core.strategy_entries.iter().map(|entry| entry.name.clone()).collect::<Vec<_>>(),
        "strategy_id": core.strategy_id,
        "strategy_name": core.strategy_name,
        "strategy_payload_scopes": core.strategy_payload_scopes,
        "list_type": core.list_type,
        "match_summary": core.match_summary,
        "raw_profile_text": core.raw_profile_text,
        "editable": {
            "filter_kind": core.editable.filter_kind,
            "filter_role": core.editable.filter_role,
            "filter_editable": core.editable.filter_editable,
        },
        "editable_filter_kinds": core.editable_filter_kinds,
    })
}

fn sources_record(sources: &[primecore_profile::list_interpreter::ProfileListSource]) -> Value {
    let rows: Vec<Value> = sources
        .iter()
        .map(|source| {
            json!({
                "profile_name": source.profile.name,
                "order": source.order,
                "in_preset": source.in_preset,
            })
        })
        .collect();
    Value::Array(rows)
}

#[test]
fn derived_core_matches_python() {
    let root = user_root();
    let user = root.join("user");
    let (signature, catalogs) = catalogs_map(&user, "winws2");

    let mut out = json!({"cores": {}, "visible": {}, "kinds": {}, "caches": {}});
    for (name, text) in texts() {
        let preset = parse_preset_text(text, "winws2", name).expect("профиль");
        let profile = &preset.profiles[0];
        let core = build_profile_derived_core(profile, &catalogs, &user, None);
        out["cores"][name] = core_record(&core);
        out["visible"][name] = json!({"visible_list_type": visible_list_type(profile, &user)});
    }

    // WinWS1.
    let (_, w1_catalogs) = catalogs_map(&user, "winws1");
    let w1 = parse_preset_text(W1_TEXT, "winws1", "w1").expect("winws1");
    out["catalog_ids"] = json!({
        "tcp": catalog_ids(&catalogs, "tcp"),
        "voice": catalog_ids(&catalogs, "voice"),
        "w1_udp": catalog_ids(&w1_catalogs, "udp"),
    });
    out["cores"]["winws1"] = core_record(&build_profile_derived_core(
        &w1.profiles[0],
        &w1_catalogs,
        &user,
        None,
    ));

    // Без фильтров.
    let no_filter = parse_preset_text(NO_FILTER_TEXT, "winws2", "nf").expect("фильтры");
    out["cores"]["no_filter"] = core_record(&build_profile_derived_core(
        &no_filter.profiles[0],
        &catalogs,
        &user,
        None,
    ));

    // Сырой текст с пробелами.
    let raw = parse_preset_text(RAW_TEXT_TEMPLATE, "winws2", "raw").expect("сырой");
    let raw_profile = &raw.profiles[0];
    out["cores"]["raw_text"] = core_record(&build_profile_derived_core(
        raw_profile,
        &catalogs,
        &user,
        None,
    ));
    out["visible"]["raw_text"] =
        json!({"visible_list_type": visible_list_type(raw_profile, &user)});

    // available_filter_kinds с обоими файлами.
    let k1 = parse_preset_text(S1_TEXT, "winws2", "k").expect("kinds");
    let settings = read_editable_profile_settings(&k1.profiles[0]);
    out["kinds"]["simple"] = json!(available_filter_kinds(&settings, &user));

    // --- Профильный кэш: LRU ---
    let mut cache = ProfileDerivedCache::with_limit(2);
    let mut sequence = Vec::new();
    for (name, text) in [
        ("simple_match", S1_TEXT),
        ("simple_custom", CUSTOM_TEXT),
        ("simple_match", S1_TEXT),
        ("none_strategy", NONE_TEXT),
        ("simple_custom", CUSTOM_TEXT),
        ("exclude_role", EXCLUDE_YES_TEXT),
    ] {
        let preset = parse_preset_text(text, "winws2", name).expect("профиль");
        let core = cache.core_for(&preset.profiles[0], &catalogs, &signature, &user);
        sequence.push(core_record(&core));
    }
    out["caches"]["sequence"] = Value::Array(sequence);

    // Два имени на том же сыром тексте.
    let mut rename_cache = ProfileDerivedCache::new();
    let not_excluded = parse_preset_text(EXCLUDE_NOT_TEXT, "winws2", "r1").expect("r1");
    let excluded = parse_preset_text(EXCLUDE_YES_TEXT, "winws2", "r2").expect("r2");
    let first = rename_cache.core_for(&not_excluded.profiles[0], &catalogs, &signature, &user);
    let second = rename_cache.core_for(&excluded.profiles[0], &catalogs, &signature, &user);
    out["caches"]["rename"] = json!([core_record(&first), core_record(&second)]);

    // Отпечаток папки lists.
    let mut ttl_cache = ProfileDerivedCache::new();
    let s1_preset = parse_preset_text(S1_TEXT, "winws2", "t").expect("ttl");
    let before = ttl_cache.core_for(&s1_preset.profiles[0], &catalogs, &signature, &user);
    std::fs::remove_file(user.join("lists/ipset-googlevideo.txt")).expect("удаление");
    let stale = ttl_cache.core_for(&s1_preset.profiles[0], &catalogs, &signature, &user);
    ttl_cache.forget_lists_signature();
    let fresh = ttl_cache.core_for(&s1_preset.profiles[0], &catalogs, &signature, &user);
    out["caches"]["lists_ttl"] = json!([
        core_record(&before),
        core_record(&stale),
        core_record(&fresh),
    ]);

    // --- Sources пресета ---
    let mut sources_cache = PresetSourcesCache::new();
    let combination =
        parse_preset_text(&format!("{S1_TEXT}{CUSTOM_TEXT}"), "winws2", "src").expect("sources");
    let sources_first = sources_cache.sources_for((7, 12), &combination, &[]);
    let sources_second = sources_cache.sources_for((7, 12), &combination, &[]);
    let sources_other = sources_cache.sources_for((8, 12), &combination, &[]);
    out["caches"]["preset_sources"] = json!([
        sources_record(&sources_first),
        sources_record(&sources_second),
        sources_record(&sources_other),
    ]);

    let golden = &*GOLDEN;
    assert_eq!(out["cores"], golden["cores"], "ядра профилей");
    assert_eq!(out["visible"], golden["visible"], "видимый тип списка");
    assert_eq!(out["kinds"], golden["kinds"], "доступные виды фильтров");
    assert_eq!(out["caches"], golden["caches"], "кэши");
    assert_eq!(
        out["catalog_ids"], golden["catalog_ids"],
        "каталоги для ядра"
    );
    let entries = basic_strategy_entries(
        &parse_preset_text(NONE_TEXT, "winws2", "b")
            .expect("base")
            .profiles[0],
        &catalogs,
    );
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.strategy_id.clone())
            .collect::<Vec<_>>(),
        golden["cores"]["none_strategy"]["strategy_entry_ids"]
            .as_array()
            .expect("ids")
            .clone(),
        "базовые записи"
    );

    std::fs::remove_dir_all(&root).ok();
}
