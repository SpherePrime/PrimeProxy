//! Порт `src/utils/circular_strategy_numbering.py` — перенумерация
//! `:strategy=N` у строк `--lua-desync=...` после circular-стратегий.
//!
//! Используется оркестрацией (`orchestra/runtime_config.py`).

use std::sync::LazyLock;

use regex::Regex;

/// python `_STRATEGY_TAG_RE` — метка стратегии на строке пресета.
static STRATEGY_TAG_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r":strategy=\d+").expect("regex"));

/// python `_CIRCULAR_RE` — строка включения circular/circular_quality
/// (без учёта регистра; на неё нумерация обнуляется).
static CIRCULAR_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^--lua-desync=(?:circular|circular_quality)(?::|$)").expect("regex")
});

/// python `strip_strategy_tags` — убирает все `:strategy=N` из текста.
#[must_use]
pub fn strip_strategy_tags(content: &str) -> String {
    if content.is_empty() {
        return String::new();
    }
    STRATEGY_TAG_RE.replace_all(content, "").into_owned()
}

/// python `renumber_circular_strategies` — назначает `:strategy=N`
/// строкам стратегий после circular/circular_quality.
///
/// Правила нумерации:
/// - счётчик обнуляется на каждом блоке `--new`;
/// - счётчик обнуляется при начале новой группы `--payload=...`
///   (python сравнивал с «маркером-объектом», а не с предыдущим
///   значением: строка circular сбрасывала и его — здесь это
///   `Option::None`);
/// - строки `--lua-desync=circular...`/`--lua-desync=circular_quality...`
///   сами не нумеруются;
/// - несколько `--lua-desync=...` на одной строке получают один номер.
#[must_use]
pub fn renumber_circular_strategies(content: &str) -> String {
    let lines: Vec<&str> = content.lines().collect();
    let mut result: Vec<String> = Vec::with_capacity(lines.len());

    let mut after_circular = false;
    let mut strategy_counter = 0;
    let mut current_payload: Option<String> = None;

    for raw in lines {
        let stripped = raw.trim();

        if stripped == "--new" {
            after_circular = false;
            strategy_counter = 0;
            current_payload = None;
            result.push((*raw).to_string());
            continue;
        }

        let cleaned = STRATEGY_TAG_RE.replace_all(stripped, "").into_owned();

        if CIRCULAR_RE.is_match(&cleaned) {
            after_circular = true;
            strategy_counter = 0;
            current_payload = None;
            result.push(cleaned);
            continue;
        }

        if after_circular && cleaned.starts_with("--payload=") {
            let payload = &cleaned["--payload=".len()..];
            if current_payload.as_deref() != Some(payload) {
                current_payload = Some(payload.to_string());
                strategy_counter = 0;
            }
            result.push(cleaned);
            continue;
        }

        if after_circular && cleaned.starts_with("--lua-desync=") {
            strategy_counter += 1;
            let parts = split_before_args(&cleaned);
            let tagged_parts: Vec<String> = parts
                .iter()
                .map(|part| {
                    let part_clean = STRATEGY_TAG_RE.replace_all(part, "").into_owned();
                    if part_clean.starts_with("--lua-desync=") {
                        format!("{part_clean}:strategy={strategy_counter}")
                    } else {
                        part_clean
                    }
                })
                .collect();
            result.push(tagged_parts.join(" "));
            continue;
        }

        // Остальные строки: метки убираются, но исходные пробелы по
        // краям сохраняются (python заменял в `raw`, не в `stripped`).
        result.push(STRATEGY_TAG_RE.replace_all(raw, "").into_owned());
    }

    result.join("\n")
}

/// python `re.split(r"(?<=\S)\s+(?=--)", line)` — разрезы перед
/// следующими `--`, где перед пробельным промежутком стоит непробельный
/// символ. Rust-regex не умеет lookaround — то же самое вручную:
/// граница — начало максимального пробельного промежутка, перед которым
/// непробельный символ, а сразу после которого идёт `--`.
fn split_before_args(line: &str) -> Vec<&str> {
    let bytes = line.as_bytes();
    // Границы (начало и конец пробельного промежутка) перед каждым "--".
    let mut cuts: Vec<(usize, usize)> = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            // После промежутка — "--", перед ним (если он не в начале
            // строки) — непробельный символ.
            if line[index..].starts_with("--")
                && start > 0
                && !bytes[start - 1].is_ascii_whitespace()
            {
                cuts.push((start, index));
            }
        } else {
            index += 1;
        }
    }
    // python re.split выбрасывает сам разделитель (пробельный промежуток).
    let mut parts = Vec::with_capacity(cuts.len() + 1);
    let mut previous = 0;
    for (start, end) in cuts {
        parts.push(&line[previous..start]);
        previous = end;
    }
    parts.push(&line[previous..]);
    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Эталон прогона от python (python3, circular_strategy_numbering).
    const SAMPLE: &str = "--new\n\
        --payload=t\n\
        --lua-desync=circular\n\
        --lua-desync=fake --dpi-desync=fake,split2\n\
        --lua-desync=multisplit --dpi-desync=multisplit:strategy=9\n\
        --payload=t\n\
        --lua-desync=multisplit\n\
        --payload=u\n\
        --lua-desync=fake\n\
        --new\n\
        --lua-desync=fake:strategy=3\n\
        --lua-desync=CIRCULAR_quality\n\
        --lua-desync=fake\n\
        --hostlist=.txt\n";

    #[test]
    fn strip_removes_every_tag() {
        assert_eq!(
            strip_strategy_tags("x:strategy=1 y:strategy=22:strategy=3"),
            "x y"
        );
        assert_eq!(strip_strategy_tags(""), "");
        assert_eq!(strip_strategy_tags("обычный текст"), "обычный текст");
    }

    #[test]
    fn renumber_matches_python_sample() {
        // Эталон целиком от python renumber_circular_strategies.
        assert_eq!(
            renumber_circular_strategies(SAMPLE),
            "--new\n\
             --payload=t\n\
             --lua-desync=circular\n\
             --lua-desync=fake:strategy=1 --dpi-desync=fake,split2\n\
             --lua-desync=multisplit:strategy=2 --dpi-desync=multisplit\n\
             --payload=t\n\
             --lua-desync=multisplit:strategy=1\n\
             --payload=u\n\
             --lua-desync=fake:strategy=1\n\
             --new\n\
             --lua-desync=fake\n\
             --lua-desync=CIRCULAR_quality\n\
             --lua-desync=fake:strategy=1\n\
             --hostlist=.txt"
        );
    }

    #[test]
    fn empty_content_is_empty() {
        assert_eq!(renumber_circular_strategies(""), "");
    }

    #[test]
    fn circular_line_resets_counter_and_payload_group() {
        // Строка circular сбрасывает и счётчик, и «текущий payload»
        // (python: current_payload = object()).
        let content = "--payload=t\n\
            --lua-desync=circular\n\
            --lua-desync=fake\n";
        assert_eq!(
            renumber_circular_strategies(content),
            "--payload=t\n--lua-desync=circular\n--lua-desync=fake:strategy=1"
        );
    }

    #[test]
    fn same_payload_group_keeps_counting() {
        // Повторный --payload=t с тем же значением не сбрасывает счётчик.
        let content = "--lua-desync=circular\n\
            --payload=t\n\
            --lua-desync=fake\n\
            --payload=t\n\
            --lua-desync=multisplit\n";
        assert_eq!(
            renumber_circular_strategies(content),
            "--lua-desync=circular\n\
             --payload=t\n\
             --lua-desync=fake:strategy=1\n\
             --payload=t\n\
             --lua-desync=multisplit:strategy=2"
        );
    }

    #[test]
    fn several_lua_desync_on_one_line_share_the_number() {
        let content = "--lua-desync=circular\n--lua-desync=fake --lua-desync=multisplit\n";
        assert_eq!(
            renumber_circular_strategies(content),
            "--lua-desync=circular\n\
             --lua-desync=fake:strategy=1 --lua-desync=multisplit:strategy=1"
        );
    }

    #[test]
    fn split_before_args_matches_python_re_split() {
        // python: re.split(r"(?<=\S)\s+(?=--)", ...)
        assert_eq!(split_before_args("--a --b  --c"), vec!["--a", "--b", "--c"]);
        // Разрез только перед "--", не перед обычным словом.
        assert_eq!(split_before_args("--a foo --b"), vec!["--a foo", "--b"]);
        // Пробел в начале строки не разрезает (?<=\S требует непробел).
        assert_eq!(split_before_args("  --a"), vec!["  --a"]);
        // Нет второго аргумента — одна часть.
        assert_eq!(split_before_args("--a "), vec!["--a "]);
    }

    #[test]
    fn without_circular_nothing_is_numbered() {
        // До circular-строки нумерации нет вовсе, метки снимаются.
        let content = "--lua-desync=fake:strategy=7\n--new\n--lua-desync=fake\n";
        assert_eq!(
            renumber_circular_strategies(content),
            "--lua-desync=fake\n--new\n--lua-desync=fake"
        );
    }
}
