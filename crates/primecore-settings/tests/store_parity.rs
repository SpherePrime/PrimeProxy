//! Кросс-языковой тест sqlite-хранилища настроек.
//!
//! Запускается против живой базы, созданной питоновским settings.store:
//!   PYTHONPATH=src python3 - (fix /tmp/opencode/store_py, mutate, dump.json)
//! Rust-стор должен прочитать её и дописать секции так, чтобы python
//! прочитал результат Rust-письма. Переменная окружения
//! PRIMECORE_SETTINGS_DB_DIR указывает на каталог пользователя (root).
//! Без переменной тест пропускается.

use std::path::PathBuf;
use std::sync::OnceLock;

use serde_json::Value;

fn db_dir() -> Option<PathBuf> {
    std::env::var("PRIMECORE_SETTINGS_DB_DIR").ok().map(PathBuf::from)
}

#[test]
fn fresh_init_matches_python_defaults() {
    let Some(db_dir) = db_dir() else { return };
    let path = primecore_settings::store::get_settings_database_path(&db_dir);
    if path.exists() {
        std::fs::remove_file(&path).ok();
    }
    let (database, initial) =
        primecore_settings::store::SettingsDatabase::open_with_recovery(&path).expect("fresh open");
    assert_eq!(database.read_revision().ok(), Some(1), "первая инициализация даёт ревизию 1");
    assert_eq!(&initial, &primecore_settings::schema::build_default_settings(), "свежая база == дефолты");
    // Python-стор проверяется следующим шагом (fresh_dump.json).
    std::fs::write(
        db_dir.join("fresh_dump.json"),
        serde_json::to_vec_pretty(&initial).expect("json"),
    )
    .expect("write fresh_dump.json");
}

fn dump() -> &'static Value {
    static DUMP: OnceLock<Value> = OnceLock::new();
    DUMP.get_or_init(|| {
        let path = db_dir().unwrap().join("dump.json");
        let bytes = std::fs::read(&path).expect("dump.json от python");
        serde_json::from_slice(&bytes).expect("json")
    })
}

#[test]
fn python_db_reads_with_same_sections_revisions_and_settings() {
    let Some(db_dir) = db_dir() else {
        eprintln!("PRIMECORE_SETTINGS_DB_DIR не задан — пропуск");
        return;
    };
    if !db_dir.join("dump.json").exists() {
        eprintln!("dump.json нет (не python-фикстура) — пропуск");
        return;
    }
    let path = primecore_settings::store::get_settings_database_path(&db_dir);
    assert!(path.exists(), "нет базы: {}", path.display());
    let (database, initial) =
        primecore_settings::store::SettingsDatabase::open_with_recovery(&path).expect("open");
    assert_eq!(database.read_revision().ok(), Some(3), "ревизия после двух питоновских мутаций");
    assert_eq!(&initial, &dump()["settings"], "normalize_settings(parsed sections) == python dump");
    // сырые секции тоже должны совпасть: python пишет нормализованные payload
    let raw = database.read_raw_sections().expect("raw");
    assert_eq!(Value::Object(raw), dump()["settings"], "raw sections == python dump");
    let _ = database;
}

#[test]
fn rust_write_is_read_by_python_expectations() {
    let Some(db_dir) = db_dir() else { return };
    let path = primecore_settings::store::get_settings_database_path(&db_dir);
    let (mut database, _) =
        primecore_settings::store::SettingsDatabase::open_with_recovery(&path).expect("open");
    let revision_before = database.read_revision().expect("revision");
    let mutator = |working: &mut Value| {
        if let Value::Object(root) = working {
            if let Some(Value::Object(program)) = root.get_mut("program") {
                program.insert(
                    "last_seen_version".to_string(),
                    Value::String("21.1.8.0".to_string()),
                );
            }
            if let Some(Value::Object(ui)) = root.get_mut("ui_state") {
                ui.insert("sidebar_expanded".to_string(), Value::Bool(false));
            }
        }
    };
    let updated = database.update_settings(mutator).expect("update");
    let revision_after = database.read_revision().expect("revision");
    assert_eq!(revision_after, revision_before + 1, "ревизия инкрементируется");
    // Результат письма отдаём для проверки питоновской стороной.
    let out_path = db_dir.join("rust_write.json");
    std::fs::write(
        &out_path,
        serde_json::to_vec_pretty(&updated).expect("json"),
    )
    .expect("write rust_write.json");
    println!("записано {}", out_path.display());
}
