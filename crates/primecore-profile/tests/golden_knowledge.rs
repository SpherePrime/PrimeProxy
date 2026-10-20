//! Золото knowledge.py: шаги стратегии простыми словами.

use once_cell::sync::Lazy;
use serde::Serialize;
use serde_json::Value;

use primecore_profile::strategy_knowledge::{explain_strategy, position_words, StepNote};

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_knowledge.json"
    ))
    .expect("golden_knowledge.json");
    serde_json::from_str(&source).expect("json")
});

fn as_value(value: &impl Serialize) -> Value {
    serde_json::to_value(value).expect("сериализация")
}

fn strip_dc(value: &Value) -> Value {
    // Золото хранит шаги объекта-обёрткой с "__dc__"; снимаем её рекурсивно.
    match value {
        Value::Array(values) => Value::Array(
            values
                .iter()
                .collect::<Vec<_>>()
                .iter()
                .map(|item| strip_dc(item))
                .collect(),
        ),
        Value::Object(map) => {
            let mut cleaned = map.clone();
            cleaned.remove("__dc__");
            Value::Object(cleaned)
        }
        _ => value.clone(),
    }
}

#[test]
fn steps_match_python() {
    let cases = GOLDEN["ops"]["steps"].as_object().expect("шаги");
    for (name, expected) in cases {
        let args = args_of(name);
        let steps = explain_strategy(&args, false);
        let computed = serde_json::json!(steps);
        assert_eq!(
            steps.len(),
            expected.as_array().expect("массив").len(),
            "{name}: число шагов"
        );
        assert_eq!(&computed, &strip_dc(expected), "шаги {name}");
    }
    let udp_cases = GOLDEN["ops"]["steps_udp"].as_object().expect("udp");
    for (name, expected) in udp_cases {
        let args = args_of(name);
        let steps = explain_strategy(&args, true);
        assert_eq!(
            serde_json::json!(steps),
            strip_dc(expected),
            "шаги udp {name}"
        );
    }
    let expected = GOLDEN["ops"]["protections_all"]
        .as_array()
        .expect("protections_all");
    let steps = explain_strategy(PROTECTIONS_ALL, false);
    assert_eq!(
        serde_json::json!(steps),
        strip_dc(&Value::Array(expected.clone())),
        "все защиты"
    );
}

fn args_of(name: &str) -> String {
    match name {
        "fake_full" => "--lua-desync=fake:ip_ttl=9:tls_mod=rnd,sni=www.example.org,badseq=blob=fake_default_tls",
        "fake_udp_blob" => "--lua-desync=fake:blob=fake_default_quic",
        "fake_repeats" => "--lua-desync=fake:repeats=5",
        "fakedsplit_basic" => "--lua-desync=fakedsplit:pos=1,midsld:ip_autottl=1-5",
        "fakemultisplit" => "--lua-desync=fakemultisplit:pos=sniext+2",
        "fakeddisorder" => "--lua-desync=fakeddisorder:ip_ttl=9",
        "fakemultidisorder" => "--lua-desync=fakemultidisorder",
        "hostfakesplit" => "--lua-desync=hostfakesplit:hosts=nasa.gov,wikipedia.org",
        "hostfakesplit_multi" => "--lua-desync=hostfakesplit_multi:host=gh.hn",
        "multisplit" => "--lua-desync=multisplit",
        "multidisorder" => "--lua-desync=multidisorder:seqovl=1",
        "multidisorder_legacy" => "--lua-desync=multidisorder_legacy",
        "tcpseg" => "--lua-desync=tcpseg:pos=1:tcpseg_ttl=2",
        "oob" => "--lua-desync=oob",
        "wssize" => "--lua-desync=wssize:1:6",
        "udplen" => "--lua-desync=udplen:+2",
        "syndata" => "--lua-desync=syndata:tls_mod=rndsni",
        "send" => "--lua-desync=send:badseq=1:badack=2",
        "pass" => "--lua-desync=pass",
        "custom" => "--lua-desync=myownfunc:k=1",
        "empty_params" => "--lua-desync=fake:",
        "mixed_with_noise" => {
            "--filter-tcp=443\n--lua-desync=fake:ip_ttl=9\n\n--lua-desync=multisplit:pos=-1:tcpseg=1\ntimestamp\n--lua-desync= прерванные сентенции: пёс=mix\n"
        }
        other => panic!("неизвестный случай {other}"),
    }
    .to_string()
}

#[test]
fn step_meta_matches_python() {
    let expected = GOLDEN["ops"]["step_counts"].as_object().expect("counts");
    for (name, count) in expected {
        assert_eq!(
            explain_strategy(&args_of(name), false).len(),
            count.as_u64().expect("число") as usize,
            "методов {name}"
        );
    }
    let expected = GOLDEN["ops"]["step_caution"].as_object().expect("caution");
    for (name, caution) in expected {
        let steps = explain_strategy(&args_of(name), false);
        let computed = steps.first().map(|step| step.caution()).unwrap_or_default();
        assert_eq!(
            caution.as_str().expect("текст"),
            computed,
            "предупреждение {name}"
        );
    }
}

#[test]
fn position_words_match_python() {
    let expected = GOLDEN["ops"]["position_words"]
        .as_object()
        .expect("положения");
    for (value, phrase) in expected {
        let computed = if value.is_empty() {
            String::new()
        } else {
            position_words(value)
        };
        assert_eq!(phrase.as_str().expect("фраза"), computed, "место {value}");
    }
}

#[test]
fn note_methods_match_python() {
    let expected = GOLDEN["ops"]["note_methods"].as_array().expect("методы");
    for (expected, note) in expected.iter().zip(note_cases().iter()) {
        let text = if expected["text"].is_null() {
            String::new()
        } else {
            expected["text"].as_str().expect("text").to_string()
        };
        assert_eq!(text, note.text(), "метод text");
        assert_eq!(expected["chip"], as_value(&note.chip()), "метод chip");
        assert_eq!(as_value(&note.chips()), expected["chips"], "метод chips");
        assert_eq!(expected["hint"], as_value(&note.hint()), "метод hint");
    }
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)]
struct NoteCase {
    #[serde(flatten)]
    note: StepNote,
}

fn note_cases() -> Vec<StepNote> {
    vec![
        StepNote {
            kind: "protection".into(),
            label: "Защита подделки от сайта".into(),
            value: "Короткий путь".into(),
            detail: "как работает".into(),
        },
        StepNote {
            kind: "protection".into(),
            label: "Защита подделки от сайта".into(),
            value: "испорченный".into(),
            detail: String::new(),
        },
        StepNote {
            kind: "origin".into(),
            label: "Откуда приём".into(),
            value: "Добавлен в PrimeBypass".into(),
            detail: "В оригинальном Zapret 2 его нет.".into(),
        },
        StepNote {
            kind: "content".into(),
            label: "Что в подделке".into(),
            value: "стандартный запрос защищённого соединения к www.microsoft.com".into(),
            detail: String::new(),
        },
        StepNote {
            kind: "cut".into(),
            label: "Где режется запрос".into(),
            value: "после 1-го байта; посередине основной части имени сайта".into(),
            detail: String::new(),
        },
        StepNote {
            kind: "cut".into(),
            label: "Где режется запрос".into(),
            value: "белый шум; разрез".into(),
            detail: String::new(),
        },
        StepNote {
            kind: "repeats".into(),
            label: "Повторы".into(),
            value: "5 раз подряд".into(),
            detail: String::new(),
        },
        StepNote {
            kind: "tweak".into(),
            label: "Подделка подправлена".into(),
            value: "случайные служебные поля, имя сайта www.example.org".into(),
            detail: String::new(),
        },
        StepNote {
            kind: "names".into(),
            label: "Поддельные имена".into(),
            value: "nasa.gov, wikipedia.org".into(),
            detail: String::new(),
        },
        StepNote {
            kind: "overlap".into(),
            label: "Перекрытие".into(),
            value: "Заглушка перед первой частью".into(),
            detail: "Сайт отбросит её сам.".into(),
        },
    ]
}

const PROTECTIONS_ALL: &str = "--lua-desync=fake:ip_autottl=1:tcp_md5=1:badsum=1:tcp_seq=1:tcp_ack=1:tcp_ts=1:tcp_flags_unset=1:tcp_flags_set=1:ip6_hopbyhop=1:ip6_destopt=1:ip6_routing=1:ip6_ah=1:fool=1:ip6_ttl=4:ip6_autottl=2:tcp_ts_up=1";
