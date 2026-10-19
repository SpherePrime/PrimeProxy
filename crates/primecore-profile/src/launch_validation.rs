//! Порт `src/profile/launch_validation.py` — проверка готовности пресета к запуску.

use crate::parser::parse_preset_text;
use primecore_mode::{engine_for_launch_method, normalize_launch_method, ZAPRET1_MODE};

/// python preset_filter_flags_for_launch_method.
pub fn preset_filter_flags_for_launch_method(launch_method: &str) -> Vec<&'static str> {
    let method = normalize_launch_method(Some(launch_method), Some(""));
    if method == ZAPRET1_MODE {
        return vec!["--wf-tcp=", "--wf-udp="];
    }
    vec!["--wf-tcp-out", "--wf-udp-out", "--wf-raw-part"]
}

/// python preset_has_required_filter_flags.
pub fn preset_has_required_filter_flags(launch_method: &str, text: &str) -> bool {
    // Только строки-аргументы: «# --wf-tcp-out=443» в комментарии winws не
    // получает, и пресет без настоящего фильтра не готов.
    let flags = preset_filter_flags_for_launch_method(launch_method);
    for raw in text.replace("\r\n", "\n").replace('\r', "\n").split('\n') {
        let stripped = raw.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if flags.iter().any(|flag| stripped.contains(flag)) {
            return true;
        }
    }
    false
}

/// python preset_has_enabled_profiles.
pub fn preset_has_enabled_profiles(launch_method: &str, text: &str) -> bool {
    let method = normalize_launch_method(Some(launch_method), Some(""));
    let Ok(engine) = engine_for_launch_method(&method) else {
        return false;
    };
    let Ok(preset) = parse_preset_text(text, &engine, "") else {
        return false;
    };
    preset.profiles.iter().any(|profile| profile.enabled)
}

/// python preset_has_enabled_profiles_for_launch.
pub fn preset_has_enabled_profiles_for_launch(launch_method: &str, text: &str) -> bool {
    preset_has_required_filter_flags(launch_method, text)
        && preset_has_enabled_profiles(launch_method, text)
}
