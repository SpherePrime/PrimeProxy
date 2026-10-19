//! Порт `src/profile/template_catalog.py` + `template_library.py` — UI-шаблоны.

use std::path::Path;
use std::path::PathBuf;

use crate::models::{Profile, Strategy};
use crate::parser::parse_preset_text;

/// python profile_template_root: templates рядом с программой.
pub fn profile_template_root(user_root: &Path) -> PathBuf {
    user_root.join("system").join("templates")
}

/// python load_profile_templates.
pub fn load_profile_templates(user_root: &Path, engine: &str) -> Vec<(String, Profile)> {
    let normalized_engine = engine.trim().to_lowercase();
    let path = profile_template_root(user_root).join("all_profiles.txt");
    let mut templates: Vec<(String, Profile)> = Vec::new();
    if !path.is_file() {
        return templates;
    }

    let mut seen_signatures: std::collections::HashSet<String> = std::collections::HashSet::new();
    let Ok(raw_text) = std::fs::read_to_string(&path) else {
        log_debug(&format!(
            "ProfileTemplateCatalog: не удалось прочитать {}: файл не читается",
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
        ));
        return templates;
    };
    let Ok(preset) = parse_preset_text(&raw_text, &normalized_engine, "all_profiles.txt") else {
        return templates;
    };

    for profile in &preset.profiles {
        let signature = profile.match_signature.clone();
        if signature.is_empty() || seen_signatures.contains(&signature) {
            continue;
        }
        let has_strategy = profile
            .strategy
            .as_ref()
            .map(|strategy| match strategy {
                Strategy::Winws1(w) => !w.strategy_lines.is_empty(),
                Strategy::Winws2(w) => !w.strategy_lines.is_empty(),
            })
            .unwrap_or(false);
        if has_strategy {
            log_debug("ProfileTemplateCatalog: all_profiles.txt содержит strategy, шаблон пропущен");
            continue;
        }
        let template_id = format!("all_profiles:{}", profile.index);
        templates.push((template_id, profile.clone()));
        seen_signatures.insert(signature);
    }

    templates
}

/// python load_profile_template_library: имя → Profile с порядком вставки.
pub fn load_profile_template_library(
    user_root: &Path,
    engine: &str,
    user_templates_dir: Option<&Path>,
) -> Vec<(String, Profile)> {
    let mut templates = load_profile_templates(user_root, engine);
    if let Some(user_dir) = user_templates_dir {
        for (template_id, profile) in load_user_profile_templates(user_dir, engine) {
            templates.push((template_id, profile));
        }
    }
    templates
}

/// pythonuctions: отдельный квант для каталога шаблонов пользователя (*-txt).
pub fn load_user_profile_templates(dir: &Path, engine: &str) -> Vec<(String, Profile)> {
    let mut templates: Vec<(String, Profile)> = Vec::new();
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    entries.sort();
    for path in entries {
        if path.extension().and_then(|ext| ext.to_str()) != Some("txt") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let Ok(preset) = parse_preset_text(&text, engine, name) else {
            continue;
        };
        for profile in preset.profiles {
            if profile.match_signature.is_empty() {
                continue;
            }
            templates.push((format!("user:{name}:{}", profile.index), profile));
        }
    }
    templates
}

/// python log(...) — DEBUG-строки python не падают; тут молчим (stderr).
fn log_debug(_message: &str) {}
