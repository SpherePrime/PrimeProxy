//! Порт profile/filter_switch.py:candidate/разрешение переключения типа
//! фильтра профиля между hostlist и ipset, проверка дублей и файлов списков.

use serde::{Deserialize, Serialize};

use std::path::Path;

use primecore_lists::layered::profile_list_file_exists;
use primecore_lists::winpath::PureWinPath;

use crate::editable_settings::{
    normalize_filter_value, with_editable_profile, EditableProfileSettings,
};
use crate::models::Profile;

/// python FilterKindSwitchCandidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterKindSwitchCandidate {
    pub filter_kind: String,
    pub filter_value: String,
    pub reason: String,
}

/// python FilterKindSwitchResolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilterKindSwitchResolution {
    pub allowed: bool,
    pub filter_kind: String,
    pub filter_value: String,
    pub reason: String,
}

/// python build_filter_kind_candidate.
pub fn build_filter_kind_candidate(
    settings: &EditableProfileSettings,
    filter_kind: &str,
) -> FilterKindSwitchCandidate {
    let current_kind = strip_lower(&settings.filter_kind, "hostlist");
    let target_kind = filter_kind.trim().to_lowercase();
    if !settings.filter_editable {
        return FilterKindSwitchCandidate {
            filter_kind: target_kind,
            filter_value: String::new(),
            reason: "not_editable".to_string(),
        };
    }
    if !matches!(current_kind.as_str(), "hostlist" | "ipset")
        || !matches!(target_kind.as_str(), "hostlist" | "ipset")
    {
        return FilterKindSwitchCandidate {
            filter_kind: target_kind,
            filter_value: String::new(),
            reason: "unsupported_kind".to_string(),
        };
    }

    let target_value = filter_value_for_kind_switch(settings, &target_kind);
    if target_value.is_empty() {
        return FilterKindSwitchCandidate {
            filter_kind: target_kind,
            filter_value: String::new(),
            reason: "missing_pair".to_string(),
        };
    }
    FilterKindSwitchCandidate { filter_kind: target_kind, filter_value: target_value, reason: String::new() }
}

/// python resolve_filter_kind_switch: разрешение с проверкой файлов списков.
///
/// python получает app_paths (объект с user_root); здесь — user_root.
pub fn resolve_filter_kind_switch(
    settings: &EditableProfileSettings,
    filter_kind: &str,
    user_root: &Path,
) -> FilterKindSwitchResolution {
    let current_kind = strip_lower(&settings.filter_kind, "hostlist");
    let candidate = build_filter_kind_candidate(settings, filter_kind);
    if !candidate.reason.is_empty() {
        return FilterKindSwitchResolution {
            allowed: false,
            filter_kind: candidate.filter_kind,
            filter_value: candidate.filter_value,
            reason: candidate.reason,
        };
    }

    if candidate.filter_kind != current_kind
        && !filter_files_available(user_root, &candidate.filter_value)
    {
        return FilterKindSwitchResolution {
            allowed: false,
            filter_kind: candidate.filter_kind,
            filter_value: candidate.filter_value,
            reason: "missing_file".to_string(),
        };
    }
    FilterKindSwitchResolution {
        allowed: true,
        filter_kind: candidate.filter_kind,
        filter_value: candidate.filter_value,
        reason: String::new(),
    }
}

fn strip_lower(value: &str, fallback: &str) -> String {
    let trimmed = value.trim().to_lowercase();
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed
    }
}

fn filter_value_for_kind_switch(settings: &EditableProfileSettings, filter_kind: &str) -> String {
    let current_kind = strip_lower(&settings.filter_kind, "hostlist");
    let current_value = settings.filter_value.trim().to_string();
    if filter_kind == current_kind {
        return normalize_filter_value(
            &current_value,
            filter_kind,
            &settings.filter_role,
        );
    }
    if settings.filter_role.trim().to_lowercase() == "exclude" {
        // Exclude-фильтры не переключаются между типами: у пары catch-all
        // профилей («Все сайты (хостлисты)» с netrogat.txt и «Все сайты
        // (айпи)» со служебными ipset-*) разные роли в пресете, и связка
        // netrogat ↔ ipset-ru/dns/exclude только путала (убрана по решению
        // пользователя 2026-07-06). Пустая пара → switch недоступен, комбо
        // типа на таких профилях скрывается.
        return String::new();
    }
    if current_value.contains(',') {
        return String::new();
    }
    paired_primary_filter_value(&current_value, &current_kind, filter_kind)
}

fn paired_primary_filter_value(value: &str, current_kind: &str, target_kind: &str) -> String {
    let raw = value.trim().to_string();
    let path = PureWinPath::new(&raw);
    let name = path.name();
    if name.is_empty() {
        return raw;
    }

    let lower_name = name.to_lowercase();
    if target_kind == "ipset" && lower_name == "other.txt" {
        return replace_filter_path_name(&raw, &path, "ipset-all.txt");
    }
    if target_kind == "hostlist" && lower_name == "ipset-all.txt" {
        return replace_filter_path_name(&raw, &path, "other.txt");
    }

    let suffix: String = path.suffixes().join("");
    let stem: String = if suffix.is_empty() {
        name.to_string()
    } else {
        name[..name.len() - suffix.len()].to_string()
    };
    let normalized_stem = stem.to_lowercase();
    if current_kind == "hostlist" && target_kind == "ipset" {
        if normalized_stem.starts_with("ipset-") || normalized_stem.starts_with("ipset_") {
            return raw;
        }
        return replace_filter_path_name(&raw, &path, &format!("ipset-{stem}{suffix}"));
    }
    if current_kind == "ipset" && target_kind == "hostlist" {
        if normalized_stem.starts_with("ipset-") || normalized_stem.starts_with("ipset_") {
            // «ipset-…» отрезается вместе с дефисом (6 символов).
            return replace_filter_path_name(&raw, &path, &format!("{}{suffix}", &stem[6..]));
        }
        return String::new();
    }
    normalize_filter_value(&raw, target_kind, "primary")
}

fn replace_filter_path_name(raw: &str, path: &PureWinPath, new_name: &str) -> String {
    let parent = path.parent_string();
    if parent.is_empty() || parent == "." {
        return new_name.to_string();
    }
    let separator = if raw.contains('\\') { "\\" } else { "/" };
    format!("{parent}{separator}{new_name}")
}

fn filter_files_available(user_root: &Path, filter_value: &str) -> bool {
    let lists_root = user_root.join("lists");
    // python Path(lists_root).exists() — каталог или файл.
    if !lists_root.exists() {
        return false;
    }
    for value in filter_reference_values(filter_value) {
        if !looks_like_list_file_reference(&value) {
            continue;
        }
        if !profile_list_file_exists(&lists_root, &value) {
            return false;
        }
    }
    true
}

fn filter_reference_values(filter_value: &str) -> Vec<String> {
    let mut values = Vec::new();
    for part in filter_value.split(',') {
        let value = part
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .trim_start_matches('@')
            .to_string();
        if !value.is_empty() {
            values.push(value);
        }
    }
    values
}

fn looks_like_list_file_reference(value: &str) -> bool {
    let normalized = value.trim().replace('\\', "/");
    normalized.starts_with("lists/")
        || normalized.contains('/')
        || normalized.to_lowercase().ends_with(".txt")
        || normalized.to_lowercase().ends_with(".lst")
        || normalized.to_lowercase().ends_with(".list")
}

/// python filter_kind_switch_creates_preset_duplicate: не появится ли тот же
/// match-подпись в другом профиле пресета после переключения.
///
/// Пресеты несут ПАРЫ catch-all профилей («Все сайты (хостлисты)» с
/// hostlist-exclude и «Все сайты (айпи)» с ipset-exclude) — это разные роли:
/// первый ловит соединения с известным hostname, второй — остальные по IP.
/// Переключение типа на одном из них дало бы второй профиль с той же
/// match-сигнатурой: winws2 отдаст трафик первому по порядку, а пара
/// развалится. Такое переключение запрещаем; для пресетов с единственным
/// catch-all профилем переключение остаётся доступным.
pub fn filter_kind_switch_creates_preset_duplicate(
    profile: &Profile,
    preset_profiles: &[Profile],
    settings: &EditableProfileSettings,
    resolution: &FilterKindSwitchResolution,
) -> bool {
    let switched_settings = EditableProfileSettings {
        filter_kind: resolution.filter_kind.clone(),
        filter_value: resolution.filter_value.clone(),
        filter_role: settings.filter_role.clone(),
        in_range: settings.in_range.clone(),
        out_range: settings.out_range.clone(),
        ..EditableProfileSettings::default()
    };
    let switched = match with_editable_profile(profile, &switched_settings) {
        Ok(preset) => preset,
        Err(_) => return false,
    };
    let target_signature = switched.match_signature.clone();
    if target_signature.is_empty() {
        return false;
    }
    let profile_persistent_key = profile.persistent_key.clone();
    for other in preset_profiles {
        if std::ptr::eq(other as *const Profile, profile as *const Profile) {
            continue;
        }
        if !profile_persistent_key.is_empty() && other.persistent_key == profile_persistent_key {
            continue;
        }
        if other.match_signature == target_signature {
            return true;
        }
    }
    false
}

/// python filter_kinds_without_preset_duplicates: убирает типы, дающие дубли.
pub fn filter_kinds_without_preset_duplicates(
    settings: &EditableProfileSettings,
    profile: &Profile,
    preset_profiles: &[Profile],
    kinds: &[impl AsRef<str>],
    user_root: &Path,
) -> Vec<String> {
    let current_kind = strip_lower(&settings.filter_kind, "hostlist");
    let mut result: Vec<String> = Vec::new();
    for kind in kinds {
        let normalized = kind.as_ref().trim().to_lowercase();
        if normalized == current_kind {
            result.push(normalized);
            continue;
        }
        let resolution = resolve_filter_kind_switch(settings, &normalized, user_root);
        if !resolution.allowed {
            continue;
        }
        if filter_kind_switch_creates_preset_duplicate(profile, preset_profiles, settings, &resolution) {
            continue;
        }
        result.push(normalized);
    }
    if result.is_empty() {
        vec![current_kind]
    } else {
        result
    }
}
