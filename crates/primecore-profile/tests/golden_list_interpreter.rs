//! Золото list_interpreter.py: список профилей пресета и шаблонов.

use once_cell::sync::Lazy;
use serde_json::Value;

use primecore_profile::list_interpreter::{build_profile_list_sources, ProfileListSource};
use primecore_profile::parser::parse_preset_text;

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_list_interpreter.json"
    ))
    .expect("golden_list_interpreter.json");
    serde_json::from_str(&source).expect("json")
});

const PRESET_TEXT: &str = concat!(
    "--new=Startup Advice\n",
    "--filter-tcp=443\n",
    "--hostlist=other.txt\n",
    "--lua-desync=multisplit\n",
    "--new=Задуман Пара\n",
    "--filter-tcp=443\n",
    "--ipset=ipset-other.txt\n",
    "--lua-desync=multisplit\n",
);
const TEMPLATES_TEXT: &str = concat!(
    "--new=googlevideo.com (CDN сервера)\n",
    "--filter-tcp=443\n",
    "--hostlist=googlevideo.com.txt\n",
    "--lua-desync=fakedsplit\n",
    "--new=YouTube · видео (googlevideo.com)\n",
    "--filter-tcp=443\n",
    "--hostlist=googlevideo.com.txt\n",
    "--lua-desync=fakedsplit\n",
    "--new=Discord UDP (обычно не нужно)\n",
    "--filter-udp=50000\n",
    "--log=1\n",
    "--lua-desync=multidisorder\n",
);
const DEDUP_TEXT: &str = concat!(
    "--new=googlevideo.com (CDN сервера)\n",
    "--filter-tcp=443\n",
    "--hostlist=googlevideo.com.txt\n",
    "--lua-desync=fakedsplit\n",
    "--new=YouTube · видео (googlevideo.com)\n",
    "--filter-tcp=443\n",
    "--hostlist=googlevideo.com.txt\n",
    "--lua-desync=fakedsplit\n",
);
const USER_TEMPLATES_TEXT: &str = concat!(
    "--new=Принт Пара\n",
    "--filter-tcp=443\n",
    "--ipset=styles.ipset\n",
    "--lua-desync=multisplit\n",
);

fn templates_pairs(preset: &primecore_profile::models::Preset, prefix: &str) -> Vec<(String, primecore_profile::models::Profile)> {
    preset
        .profiles
        .iter()
        .enumerate()
        .map(|(index, profile)| (format!("{prefix}:{index}"), profile.clone()))
        .collect()
}

fn as_value(sources: &[ProfileListSource]) -> Value {
    let rows: Vec<Value> = sources
        .iter()
        .map(|source| {
            serde_json::json!({
                "key": source.key,
                "in_preset": source.in_preset,
                "order": source.order,
                "user_template_key": source.user_template_key,
                "resolved_display_name": source.resolved_display_name,
                "profile_name": source.profile.name,
                "profile_display": source.profile.display_name,
                "profile_signature": source.profile.match_signature,
            })
        })
        .collect();
    Value::Array(rows)
}

#[test]
fn list_sources_match_python() {
    let preset = parse_preset_text(PRESET_TEXT, "winws2", "alpha").expect("пресет");
    let templates = parse_preset_text(TEMPLATES_TEXT, "winws2", "stock").expect("шаблоны");
    let dedup = parse_preset_text(DEDUP_TEXT, "winws2", "dedup").expect("дубли");
    let user_templates =
        parse_preset_text(USER_TEMPLATES_TEXT, "winws2", "user").expect("user-шаблон");

    // plain: пресет + шаблоны, дубль шаблона убирается.
    assert_eq!(
        as_value(&build_profile_list_sources(
            &preset.profiles,
            &templates_pairs(&templates, "stock")
        )),
        GOLDEN["plain"],
        "пресет и шаблоны"
    );

    // dedup: два профиля пресета одной логической группы не сливаются.
    assert_eq!(
        as_value(&build_profile_list_sources(&dedup.profiles, &[])),
        GOLDEN["dedup"],
        "дубли пресета"
    );

    // templates_only: без пресета выбираются по порядку и виду фильтра.
    assert_eq!(
        as_value(&build_profile_list_sources(
            &[],
            &templates_pairs(&templates, "stock")
        )),
        GOLDEN["templates_only"],
        "только шаблоны"
    );

    // dup_enabled: включенный профиль пресета предпочитается.
    let mut dup = parse_preset_text(
        &concat!(
            "--new=Startup Advice\n",
            "--filter-tcp=443\n",
            "--hostlist=other.txt\n",
            "--lua-desync=multisplit\n",
            "--new=Startup Advice (второй)\n",
            "--filter-tcp=443\n",
            "--hostlist=other.txt\n",
            "--lua-desync=multisplit\n",
        ),
        "winws2",
        "dup",
    )
    .expect("дубли");
    dup.profiles[0].enabled = true;
    dup.profiles[1].enabled = false;
    assert_eq!(
        as_value(&build_profile_list_sources(&dup.profiles, &[])),
        GOLDEN["dup_enabled"],
        "включенный предпочитается"
    );

    // user_template: user-ключ шаблона.
    assert_eq!(
        as_value(&build_profile_list_sources(
            &[],
            &[("user:styles".to_string(), user_templates.profiles[0].clone())]
        )),
        GOLDEN["user_template"],
        "user-шаблон"
    );

    // fallback_template: пресет + шаблон по тому же логическому ключу.
    assert_eq!(
        as_value(&build_profile_list_sources(
            &[preset.profiles[0].clone()],
            &[("stock:yt".to_string(), templates.profiles[0].clone())]
        )),
        GOLDEN["fallback_template"],
        "шаблон из пресета"
    );
}
