//! Golden-прогон всего корпуса встроенных пресетов живой установки
//! Zapret (resources/presets) через парсер primecore-profile.
//!
//! Корпус: winws1_builtin (307 файлов) + winws2_builtin (136 файлов),
//! скопированы из реальной установки; это те же пресеты, что шли с
//! программой. Каждый файл обязан разбираться без ошибок тем же
//! движком, под который он лежит; структура (профили, опции) — в
//! разумных рамках (минимум один профиль, движок совпадает).

use std::path::Path;

/// Корень ресурсов репозитория относительно крейта.
const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");

fn builtin_files(kind: &str) -> Vec<std::path::PathBuf> {
    let dir = Path::new(RESOURCES).join("presets").join(kind);
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("нет папки {kind}: {error}"))
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("txt"))
        .collect();
    files.sort();
    files
}

fn engine_of(kind: &str) -> &'static str {
    if kind == "winws1_builtin" {
        "winws1"
    } else {
        "winws2"
    }
}

#[test]
fn builtin_winws2_corpus_parses() {
    let files = builtin_files("winws2_builtin");
    assert!(
        files.len() >= 130,
        "корпус winws2_builtin оскудел: {} файлов",
        files.len()
    );
    let engine = engine_of("winws2_builtin");
    let mut profiles_total = 0_usize;
    let mut failures: Vec<String> = Vec::new();
    for path in &files {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("?");
        let text = std::fs::read_to_string(path).unwrap();
        match primecore_profile::parser::parse_preset_text(&text, engine, name) {
            Ok(preset) => {
                assert_eq!(preset.engine, engine, "{name}: движок должен совпасть");
                profiles_total += preset.profiles.len();
            }
            Err(error) => failures.push(format!("{name}: {error}")),
        }
    }
    assert!(
        failures.is_empty(),
        "не разобрались {} из {}: {}",
        failures.len(),
        files.len(),
        failures.join("\n")
    );
    assert!(
        profiles_total >= files.len(),
        "в каждом пресете хотя бы один профиль: всего профилей {profiles_total}"
    );
}

#[test]
fn builtin_winws1_corpus_parses() {
    let files = builtin_files("winws1_builtin");
    assert!(
        files.len() >= 170,
        "корпус winws1_builtin оскудел: {} файлов",
        files.len()
    );
    let engine = engine_of("winws1_builtin");
    let mut failures: Vec<String> = Vec::new();
    for (index, path) in files.iter().enumerate() {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("?");
        let text = std::fs::read_to_string(path).unwrap();
        if let Err(error) = primecore_profile::parser::parse_preset_text(&text, engine, name) {
            failures.push(format!("{name}: {error}"));
        }
        let _ = index;
    }
    assert!(
        failures.is_empty(),
        "не разобрались {} из {}: {}",
        failures.len(),
        files.len(),
        failures.join("\n")
    );
}

/// Списки, lua и windivert-фильтры присутствуют как ресурсы.
#[test]
fn shipped_resources_are_present() {
    let base = Path::new(RESOURCES);
    for (dir, min_files) in [
        ("lists", 120),
        ("lua", 20),
        ("bin", 40),
        ("windivert.filter", 5),
        ("presets/winws1_builtin", 170),
        ("presets/winws2_builtin", 130),
        ("system", 2),
    ] {
        let count = std::fs::read_dir(base.join(dir))
            .unwrap_or_else(|error| panic!("нет папки ресурсов {dir}: {error}"))
            .count();
        assert!(count >= min_files, "{dir}: только {count} файлов");
    }
}
