//! Золото identity.py: sidecar-реестр uid ↔ имя/сигнатура.

use once_cell::sync::Lazy;
use serde_json::{json, Value};

use primecore_profile::identity::resolve_profile_identities;

static GOLDEN: Lazy<Value> = Lazy::new(|| {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/golden_identity.json"
    ))
    .expect("golden_identity.json");
    serde_json::from_str(&source).expect("json")
});

const SIG_A: &str = "sig:list=gov|tcp=443";
const SIG_B: &str = "sig:list=googlevideo|tcp=443";
const SIG_C: &str = "sig:udp=50000";

fn registry() -> Value {
    json!({
        "uid:alpha": {"name": "Сводка", "sig": SIG_A},
        "uid:beta": {"name": "Слепок", "sig": ""},
        "uid:gamma": {"name": "OtherName", "sig": SIG_C},
        "uid:lonely": {"name": "Забытый", "sig": "sig:none"},
        "uid:none": "строка, не словарь",
        "": {"name": "Пустой ключ", "sig": "sig:x"},
        "uid:empty_name": {"sig": SIG_B},
        "uid:old": {"name": "Числовой", "sig": 42},
    })
}

/// Сценарии: (имя, профили парса, готовые uid по порядку генератора).
type UidCase = (&'static str, Vec<(String, String)>, Vec<String>);

fn uid_sets() -> Vec<UidCase> {
    vec![
        // 1. Полное совпадение имени и сигнатуры.
        (
            "exact",
            vec![
                ("Сводка".into(), SIG_A.into()),
                ("Голос UDP".into(), SIG_C.into()),
            ],
            vec![],
        ),
        // 2. Переименование: совпадает только сигнатура.
        (
            "renamed",
            vec![("Сводка Теперь Иначе".into(), SIG_A.into())],
            vec![],
        ),
        // 3. Правка match-строк: совпадает только имя.
        ("edit_match", vec![("Сводка".into(), SIG_B.into())], vec![]),
        // 4. Новый профиль.
        ("new", vec![("Совсем новый".into(), SIG_A.into())], vec![]),
        // 5. Пустые имя и сигнатура: только проход 1.
        (
            "empty_pair",
            vec![("".into(), "".into())],
            vec!["uid:fallback-empty_pair-0".into()],
        ),
        // 6. Одинаковая сигнатура в двух профилях: uid в порядке реестра.
        (
            "two_same_sig",
            vec![
                ("Первый Двойник".into(), SIG_A.into()),
                ("Второй Двойник".into(), SIG_A.into()),
            ],
            vec!["uid:fallback-two_same_sig-0".into()],
        ),
        // 7. Три одинаковых профиля: только первый уходит в реестр.
        (
            "clash",
            vec![
                ("Ранний".into(), SIG_A.into()),
                ("Ранний".into(), SIG_A.into()),
                ("Ранний".into(), SIG_A.into()),
            ],
            vec!["uid:duplicate-2".into(), "uid:duplicate-3".into()],
        ),
        // 8. Переименование и правка одновременно.
        (
            "mixed",
            vec![
                ("Ренейм Сигнатура".into(), SIG_A.into()),
                ("Сводка".into(), SIG_B.into()),
                ("Голос UDP".into(), SIG_C.into()),
            ],
            vec![],
        ),
        // 9. Пробелы чистятся.
        (
            "cleanup",
            vec![("   Слитно   ".into(), format!("  {SIG_B}  "))],
            vec![],
        ),
    ]
}

/// python generate_uid: последовательность, затем фоловбек по имени.
fn generator(name: &'static str, sequence: Vec<String>) -> impl FnMut() -> String {
    let mut counter = 0usize;
    move || {
        let index = counter;
        counter += 1;
        if index < sequence.len() {
            return sequence[index].clone();
        }
        format!("uid:fallback-{name}-{index}")
    }
}

#[test]
fn identity_matches_python() {
    let registry = registry();
    let mut out = json!({"resolutions": {}});
    for (name, profiles, generated) in uid_sets() {
        let resolution =
            resolve_profile_identities(&profiles, &registry, generator(name, generated));
        let registry_rows: Vec<Value> = resolution
            .registry
            .iter()
            .map(|(uid, (name, sig))| json!([uid, {"name": name, "sig": sig}]))
            .collect();
        out["resolutions"][name] = json!({
            "entries": profiles
                .iter()
                .map(|(name, sig)| json!([name, sig]))
                .collect::<Vec<_>>(),
            "uids": resolution.uids,
            "new_uids": resolution.new_uids.iter().collect::<Vec<_>>(),
            "registry": registry_rows,
        });
    }

    let normalized = primecore_profile::identity::normalize_identity_registry(&registry);
    out["normalized"] = json!(normalized
        .iter()
        .map(|(uid, (name, sig))| json!([uid, {"name": name, "sig": sig}]))
        .collect::<Vec<_>>());

    assert_eq!(out["resolutions"], GOLDEN["resolutions"], "разрешения");
    assert_eq!(
        out["normalized"], GOLDEN["normalized"],
        "нормализация реестра"
    );
}
