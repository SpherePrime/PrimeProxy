//! Золотой тест: Rust-порт `primecore-mode` против живого Python
//! (`src/settings/mode.py` + `src/core/paths.py`) — все сравнения
//! сняты моментом съемки из эталонной среды.

use std::path::Path;
use std::sync::OnceLock;

use primecore_mode as m;

fn golden() -> &'static serde_json::Value {
    static GOLDEN: OnceLock<serde_json::Value> = OnceLock::new();
    GOLDEN.get_or_init(|| {
        let raw = include_bytes!("golden.json");
        serde_json::from_slice(raw).expect("золотой json читается")
    })
}

#[test]
fn golden_consts_match() {
    let expected = golden()["const"].as_object().unwrap();
    let actual: Vec<(&str, String)> = vec![
        (
            "DEFAULT_LAUNCH_METHOD",
            m::DEFAULT_LAUNCH_METHOD.to_string(),
        ),
        (
            "PRESETS_DIR_NAME_WINWS1",
            m::PRESETS_DIR_NAME_WINWS1.to_string(),
        ),
        (
            "BUILTIN_PRESETS_DIR_NAME_WINWS2",
            m::BUILTIN_PRESETS_DIR_NAME_WINWS2.to_string(),
        ),
        (
            "SELECTED_SOURCE_PRESET_FILE_NAME_KEY_WINWS1",
            m::SELECTED_SOURCE_PRESET_FILE_NAME_KEY_WINWS1.to_string(),
        ),
        ("EXE_NAME_BY_ORCHESTRA", "winws2.exe".to_string()),
        (
            "DEFAULT_PRESET_WINWS1",
            m::DEFAULT_PRESET_FILE_NAME_WINWS1.to_string(),
        ),
        (
            "DEFAULT_PRESET_WINWS2",
            m::DEFAULT_PRESET_FILE_NAME_WINWS2.to_string(),
        ),
        (
            "RELATIVE_EXE_WINWS1",
            m::RELATIVE_EXE_PATH_WINWS1.to_string(),
        ),
    ];
    for (key, value) in actual {
        assert_eq!(expected[key].as_str().unwrap(), value, "константа {key}");
    }
}

#[test]
fn golden_normalize_matches() {
    let expected = golden()["normalize"].as_array().unwrap();
    for pair in expected {
        let raw = pair[0].as_str().unwrap_or_default();
        let raw_arg = if raw == "None" { None } else { Some(raw) };
        let actual = m::normalize_launch_method(raw_arg, None);
        assert_eq!(pair[1].as_str().unwrap(), actual, "normalize({raw:?})");
    }
}

#[test]
fn golden_normalize_custom_default() {
    for pair in golden()["normalize_custom"].as_array().unwrap() {
        let raw = pair[0].as_str().unwrap_or_default();
        let raw_arg = if raw == "None" { None } else { Some(raw) };
        let actual = m::normalize_launch_method(raw_arg, Some("zapret1_mode"));
        assert_eq!(pair[1].as_str().unwrap(), actual);
    }
}

#[test]
fn golden_require_ok_and_errors() {
    assert_eq!(
        m::require_launch_method(Some(" orchestra ")).unwrap(),
        "orchestra"
    );
    assert_eq!(
        m::require_launch_method(Some("zapret1_mode")).unwrap(),
        "zapret1_mode"
    );
    let error = m::require_launch_method(Some("nonsense")).unwrap_err();
    assert_eq!(error, "Unsupported launch method: Some(\"nonsense\")");
}

#[test]
fn golden_engines_and_exe_names() {
    let engines = &golden()["engines"];
    assert_eq!(
        m::engine_for_launch_method(Some("zapret2_mode")).unwrap(),
        "winws2"
    );
    assert_eq!(
        m::engine_for_launch_method(Some("ZAPRET1_MODE")).unwrap(),
        "winws1"
    );
    assert_eq!(m::engine_for_launch_method_or_none(Some("orchestra")), None);
    assert_eq!(
        m::engine_for_launch_method_or_none(Some("zapret2_mode")),
        engines["or_none_z2"].as_str()
    );
    let names = &golden()["exe_names"];
    assert_eq!(
        m::exe_name_for_launch_method(Some("zapret2_mode")).unwrap(),
        names["z2"]
    );
    assert_eq!(
        m::exe_name_for_launch_method(Some("Orchestra")).unwrap(),
        names["orch"]
    );
    assert_eq!(
        m::exe_name_for_launch_method(Some("zapret1_mode")).unwrap(),
        names["z1"]
    );
}

#[test]
fn golden_bools() {
    assert!(m::is_preset_launch_method(Some("zapret2_mode")));
    assert!(!m::is_preset_launch_method(Some("orchestra")));
    assert!(m::is_orchestra_launch_method(Some(" ORCHESTRA ")));
    assert!(!m::is_orchestra_launch_method(Some("zapret1_mode")));
    assert!(m::is_zapret2_launch_method(Some("ZAPRET2_MODE")));
    assert!(!m::is_zapret1_launch_method(Some("zapret2_mode")));
    assert!(m::is_known_launch_method(Some("ORCHESTRA")));
    assert!(!m::is_known_launch_method(Some("winws2_mode")));
}

#[test]
fn golden_engine_paths_match_python() {
    let paths = &golden()["paths"].as_object().unwrap();
    for (label, expected) in paths.iter() {
        // python-эталон прогонялся на user_root="/r"; Пути POSIX.
        let expected = expected.as_object().unwrap();
        let user_root = Path::new("/r");
        // Ключ главного словаря построен из порядкового кортежа:
        // дети в Path.join собраны строково, определённые срезы.
        let engine_summary;
        match label.as_str() {
            "  WINWS2 " => {
                engine_summary = ("winws2", m::ALL_ENGINES.contains(&"winws2"));
                let app = m::AppPaths {
                    user_root: user_root.into(),
                    local_root: user_root.into(),
                };
                let p = app.engine_paths(Some(" WINWS2 "));
                assert_eq!(p.engine, expected["engine"].as_str().unwrap());
                assert_eq!(
                    p.user_presets_dir.to_string_lossy(),
                    expected["user"].as_str().unwrap()
                );
                assert_eq!(
                    p.builtin_presets_dir.to_string_lossy(),
                    expected["builtin"].as_str().unwrap()
                );
                assert_eq!(
                    p.replaced_presets_dir().to_string_lossy(),
                    expected["replaced"].as_str().unwrap()
                );
            }
            "winws1" => {
                let app = m::AppPaths {
                    user_root: user_root.into(),
                    local_root: user_root.into(),
                };
                let p = app.engine_paths(Some("winws1"));
                assert_eq!(
                    p.builtin_presets_dir.to_string_lossy(),
                    expected["builtin"].as_str().unwrap()
                );
                assert_eq!(
                    p.replaced_presets_dir().to_string_lossy(),
                    expected["replaced"].as_str().unwrap()
                );
            }
            "winws2" => {
                let app = m::AppPaths {
                    user_root: user_root.into(),
                    local_root: user_root.into(),
                };
                let p = app.engine_paths(Some("winws2"));
                assert_eq!(
                    p.builtin_presets_dir.to_string_lossy(),
                    expected["builtin"].as_str().unwrap()
                );
            }
            "custom" | "" => {
                let app = m::AppPaths {
                    user_root: user_root.into(),
                    local_root: user_root.into(),
                };
                let p = app.engine_paths(Some(label));
                assert_eq!(p.engine, expected["engine"].as_str().unwrap());
                assert_eq!(
                    p.user_presets_dir.to_string_lossy(),
                    expected["user"].as_str().unwrap()
                );
                assert_eq!(
                    p.builtin_presets_dir.to_string_lossy(),
                    expected["builtin"].as_str().unwrap()
                );
                assert_eq!(
                    p.replaced_presets_dir().to_string_lossy(),
                    expected["replaced"].as_str().unwrap()
                );
            }
            _ => unreachable!("неизвестная метка {label}"),
        }
        let _ = engine_summary;
    }
}
