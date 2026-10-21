//! Порт `presets/preset_text_ops.py` — чистые операции над текстом пресета.

use primecore_profile::ENGINE_WINWS2;
use regex::Regex;

use crate::errors::PresetError;
use crate::preset_contract::{relocate_legacy_debug_log_file, strip_utf8_bom, DEBUG_LOG_DIR};

/// Строки пресета так же, как их видит парсер: только по «\n».
///
/// python `str.splitlines()` режет ещё и по \x0b, \x0c, \x85, \u2028 — строка
/// с таким символом внутри значения выглядела бы для этих функций иначе, чем
/// для парсера и запуска. Хвостовой перевод строки не даёт пустой строки.
#[must_use]
pub fn split_preset_lines(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text.split('\n').map(str::to_string).collect();
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    lines
}

/// python `_rewrite_preset_headers`: переписывает шапку пресета —
/// `# Preset: <имя>` (и `# PresetKind: <kind>`, если задан), удаляя служебные
/// строки `# Modified:`/`# ActivePreset:`.
#[must_use]
pub fn rewrite_preset_headers(
    source_text: &str,
    preset_name: &str,
    preset_kind: Option<&str>,
) -> String {
    let text = normalize_line_endings(&strip_utf8_bom(source_text));
    let lines = split_preset_lines(&text);

    let mut header_end = lines.len();
    for (index, raw) in lines.iter().enumerate() {
        let stripped = raw.trim();
        if !stripped.is_empty() && !stripped.starts_with('#') {
            header_end = index;
            break;
        }
    }

    let header = &lines[..header_end];
    let body = &lines[header_end..];
    let mut out_header: Vec<String> = Vec::new();
    let mut saw_preset = false;
    let mut saw_preset_kind = false;

    for raw in header {
        let stripped = raw.trim();
        let lowered = stripped.to_lowercase();
        if lowered.starts_with("# preset:") {
            out_header.push(format!("# Preset: {preset_name}"));
            saw_preset = true;
            continue;
        }
        if lowered.starts_with("# presetkind:") {
            match preset_kind {
                Some(kind) => {
                    out_header.push(format!("# PresetKind: {kind}"));
                    saw_preset_kind = true;
                }
                None => {
                    out_header.push(raw.clone());
                    saw_preset_kind = true;
                }
            }
            continue;
        }
        if lowered.starts_with("# modified:") || lowered.starts_with("# activepreset:") {
            continue;
        }
        out_header.push(raw.clone());
    }

    if !saw_preset {
        out_header.insert(0, format!("# Preset: {preset_name}"));
    }

    let insert_index = if out_header
        .first()
        .is_some_and(|line| line.starts_with("# Preset:"))
    {
        1
    } else {
        0
    };
    if let Some(kind) = preset_kind {
        if !saw_preset_kind {
            out_header.insert(insert_index, format!("# PresetKind: {kind}"));
        }
    }

    let mut rewritten = out_header;
    rewritten.extend(body.iter().cloned());
    let joined = rewritten.join("\n");
    format!("{}\n", joined.trim_end_matches('\n'))
}

/// python `_header_preset_kind`: в шапку попадает только `# PresetKind: imported`;
/// для остальных видов существующая строка остаётся как есть.
#[must_use]
pub fn header_preset_kind(kind: Option<&str>) -> Option<&'static str> {
    let normalized = kind.unwrap_or("").trim().to_lowercase();
    if normalized == "imported" {
        Some("imported")
    } else {
        None
    }
}

/// Минимальная структурная проверка импортируемого пресета.
///
/// Возвращает `Ok(())` для валидного текста или человекочитаемую причину
/// отказа. Пресет winws состоит из строк-опций «--…», комментариев «#» и
/// пустых строк; любой другой текст (лог, JSON, случайный файл) не должен
/// превращаться в «пресет» при импорте.
///
/// Рабочему пресету нужны и содержательные опции: без фильтра «--wf…»
/// winws не перехватывает трафик, а пресет winws2 без единого «--lua-desync»
/// ничего не делает с перехваченным. Для winws1 опции --lua-desync не
/// существует, поэтому там требуется только фильтр.
pub fn validate_preset_source_text(source_text: &str, engine: &str) -> Result<(), PresetError> {
    let text = normalize_line_endings(source_text.trim_start_matches('\u{feff}'));
    let mut option_lines = 0usize;
    let mut has_wf_filter = false;
    let mut has_lua_desync = false;
    for (offset, raw) in split_preset_lines(&text).into_iter().enumerate() {
        let line_no = offset + 1;
        let stripped = raw.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if !stripped.starts_with("--") {
            let preview: String = if stripped.chars().count() <= 60 {
                stripped.to_string()
            } else {
                format!("{}\u{2026}", stripped.chars().take(57).collect::<String>())
            };
            return Err(PresetError(format!(
                "строка {line_no} не является опцией winws: «{preview}»"
            )));
        }
        option_lines += 1;
        let lowered = stripped.to_lowercase();
        if lowered.starts_with("--wf") {
            has_wf_filter = true;
        }
        if lowered.starts_with("--lua-desync") {
            has_lua_desync = true;
        }
    }
    if option_lines == 0 {
        return Err(PresetError(
            "в файле нет ни одной опции winws (строк вида «--…»)".to_string(),
        ));
    }
    if !has_wf_filter {
        return Err(PresetError(
            "нет ни одной опции фильтра «--wf…» — такой пресет не перехватывает трафик".to_string(),
        ));
    }
    if engine.trim().to_lowercase() == ENGINE_WINWS2 && !has_lua_desync {
        return Err(PresetError(
            "нет ни одной опции «--lua-desync» — такой пресет ничего не делает с трафиком"
                .to_string(),
        ));
    }
    Ok(())
}

/// python `_build_stable_debug_log_file`: стабильный путь debug-лога пресета
/// в `user/logs`, пригодный и для кириллических имён.
#[must_use]
pub fn build_stable_debug_log_file(preset_name: &str) -> String {
    static RE: once_cell::sync::Lazy<Regex> =
        once_cell::sync::Lazy::new(|| Regex::new(r"[^\w.-]+").expect("regexp"));
    let mut safe_name = RE
        .replace_all(preset_name.trim(), "_")
        .trim_matches(|c| c == '.' || c == '_')
        .to_string();
    if safe_name.is_empty() {
        safe_name = "preset".to_string();
    }
    // Путь относителен корня установки (cwd запуска winws2), где логи
    // живут в user\logs.
    format!("{DEBUG_LOG_DIR}/{safe_name}_debug.log")
}

/// python `_default_debug_insert_index`: куда ставить `--debug=`, если его
/// ещё нет — после последнего `--lua-init=`, иначе сразу после шапки.
fn default_debug_insert_index(lines: &[String]) -> usize {
    let mut insert_at = 0usize;
    for (index, raw) in lines.iter().enumerate() {
        if raw.trim().starts_with("--lua-init=") {
            insert_at = index + 1;
        }
    }
    if insert_at != 0 {
        return insert_at;
    }

    let mut header_end = 0usize;
    for (index, raw) in lines.iter().enumerate() {
        let stripped = raw.trim();
        if stripped.starts_with('#') || stripped.is_empty() {
            header_end = index + 1;
            continue;
        }
        break;
    }
    header_end
}

/// python `_rewrite_debug_log_setting`: включает или выключает `--debug=`.
///
/// Существующая строка переносится на своё место (первое вхождение) с
/// актуальным путём; старые пути `logs/...` переписываются в `user/logs/...`;
/// без включённого флага все строки `--debug=` убираются.
#[must_use]
pub fn rewrite_debug_log_setting(source_text: &str, preset_name: &str, enabled: bool) -> String {
    let text = normalize_line_endings(source_text);
    let lines = split_preset_lines(&text);

    let mut existing_value = String::new();
    let mut existing_insert_at: Option<usize> = None;
    let mut cleaned: Vec<String> = Vec::new();
    for raw in lines {
        let stripped = raw.trim();
        if stripped.to_lowercase().starts_with("--debug=") {
            if existing_value.is_empty() {
                existing_value = stripped
                    .split_once('=')
                    .map(|(_, value)| value.trim().to_string())
                    .unwrap_or_default();
                existing_value = existing_value
                    .trim_start_matches('@')
                    .replace('\\', "/")
                    .trim_start_matches('/')
                    .to_string();
                existing_insert_at = Some(cleaned.len());
            }
            continue;
        }
        cleaned.push(raw);
    }

    if enabled {
        let debug_file = {
            let relocated = relocate_legacy_debug_log_file(&existing_value);
            if relocated.is_empty() {
                build_stable_debug_log_file(preset_name)
            } else {
                relocated
            }
        };
        let insert_at = existing_insert_at
            .unwrap_or_else(|| default_debug_insert_index(&cleaned))
            .clamp(0, cleaned.len());
        cleaned.insert(insert_at, format!("--debug=@{debug_file}"));
    }

    format!("{}\n", cleaned.join("\n").trim_end_matches('\n'))
}

fn normalize_line_endings(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PRESET_TEXT: &str = concat!(
        "# Preset: Example\n",
        "\n",
        "--wf-tcp-out=80,443,8080\n",
        "--new\n",
        "--name=revive\n",
        "--filter-tcp=80,8080\n",
        "--hostlist-domains=main.txrevive.com\n",
        "--out-range=-d8\n",
        "--lua-desync=hostfakesplit:host=ozon.ru:tcp_ts=-1000\n"
    );

    #[test]
    fn headers_are_rewritten_like_python() {
        assert_eq!(
            rewrite_preset_headers("--a=1\n--b\n", "Имя X", None),
            "# Preset: Имя X\n--a=1\n--b\n"
        );
        assert_eq!(
            rewrite_preset_headers(
                "# Preset: Old\n# Modified: t\n--a=1\n",
                "New",
                Some("imported")
            ),
            "# Preset: New\n# PresetKind: imported\n--a=1\n"
        );
        assert_eq!(
            rewrite_preset_headers("# PresetKind: user\n# Preset: Old\n\n--a=1\n", "New", None),
            "# PresetKind: user\n# Preset: New\n\n--a=1\n"
        );
    }

    #[test]
    fn validation_messages_match_python() {
        assert!(validate_preset_source_text(VALID_PRESET_TEXT, "winws2").is_ok());
        assert!(validate_preset_source_text(
            "\u{feff}# Preset: X\r\n--wf-tcp-out=443\r\n--new\r\n--lua-desync=fake\r\n",
            "winws2"
        )
        .is_ok());

        let error =
            validate_preset_source_text("--new\n--filter-tcp=443\n--lua-desync=fake\n", "winws2")
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("--wf") && error.contains("не перехватывает"),
            "{error}"
        );

        let error = validate_preset_source_text(
            "--wf-tcp-out=443\n--filter-tcp=443\n--hostlist=x.txt\n",
            "winws2",
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("--lua-desync"), "{error}");

        assert!(
            validate_preset_source_text("--wf-tcp=443\n--dpi-desync=fake,split2\n", "winws1")
                .is_ok()
        );

        let log_file = concat!(
            "=== PrimeBypass Log - Started 2026-07-23 10:40:51 ===\n",
            "[10:40:51] [INFO] Запуск приложения\n",
            "[10:40:52] [SUCCESS] Всё работает\n"
        );
        let error = validate_preset_source_text(log_file, "winws2")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("не является опцией winws") && error.contains("строка 1"),
            "{error}"
        );

        assert!(validate_preset_source_text("", "winws2")
            .unwrap_err()
            .to_string()
            .contains("нет ни одной опции"));
        assert!(
            validate_preset_source_text("# только комментарий\n\n", "winws2")
                .unwrap_err()
                .to_string()
                .contains("нет ни одной опции")
        );

        let error =
            validate_preset_source_text("--new\nвнезапный мусор\n--filter-tcp=443\n", "winws2")
                .unwrap_err()
                .to_string();
        assert!(
            error.contains("строка 2") && error.contains("внезапный мусор"),
            "{error}"
        );

        let long = format!("{}\n", "x".repeat(200));
        let error = validate_preset_source_text(&long, "winws2")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains('\u{2026}') && error.chars().count() < 160,
            "{error}"
        );
    }

    #[test]
    fn debug_log_toggles_like_python() {
        let result = rewrite_debug_log_setting(VALID_PRESET_TEXT, "Мой пресет", true);
        assert!(result.contains("--debug=@user/logs/"));
        assert!(!result.contains("--debug=@logs/"));

        let text = format!("{VALID_PRESET_TEXT}--debug=@user/logs/Мой_debug.log\n");
        let result = rewrite_debug_log_setting(&text, "Мой", true);
        assert_eq!(result.matches("--debug=").count(), 1);
        assert!(
            result.contains("--debug=@user/logs/Мой_debug.log"),
            "{result}"
        );

        assert_eq!(rewrite_debug_log_setting("--a=1\n", "P", false), "--a=1\n");
        assert_eq!(
            rewrite_debug_log_setting("# c\n--lua-init=@lua/x.lua\n--filter-tcp=80\n", "P", true),
            "# c\n--lua-init=@lua/x.lua\n--debug=@user/logs/P_debug.log\n--filter-tcp=80\n"
        );
        assert_eq!(
            build_stable_debug_log_file("Мой пресет!"),
            "user/logs/Мой_пресет_debug.log"
        );
    }
}
