//! Порт `src/diagnostics/compare.py` — сравнение двух проверок: с включённым
//! Zapret и без него.
//!
//! Одна проверка показывает сеть в одном состоянии. Что именно даёт обход,
//! видно только из пары: тот же набор сайтов, проверенный с Zapret и без.
//! Здесь такая пара находится в истории сама и раскладывается по сервисам:
//!
//! - без Zapret не открывался, с ним открылся — обход помог;
//! - не открывался ни так, ни так — выбранный пресет этот сервис не чинит;
//! - открывался и без Zapret — обход ему не нужен;
//! - без Zapret открывался, а с ним перестал — пресет мешает.
//!
//! «Пресет не чинит» — не то же самое, что «Zapret не может починить»: пресет
//! решает, для каких сайтов и какой обход включён. Поэтому вывод всегда
//! называет пресет и советует другой пресет или подбор стратегии, а не ставит
//! крест.
//!
//! Сравнивается только «открывается / не открывается». Сервис, про который в
//! одной из проверок ответа нет, в сравнение не попадает: неизвестное — не итог.
//!
//! Здесь только чистые функции: записи истории приходят снаружи.

use serde_json::{json, Value};

use crate::history::{parse_iso, same_run_kind};
use crate::levels::{is_open, FAIL};
use crate::report_upgrade::{text_scalar, truthy};

pub const ZAPRET_ON: &str = "on";
pub const ZAPRET_OFF: &str = "off";
/// Старше этого прошлую проверку не берём: блокировки меняются, и разницу дало
/// бы время, а не обход (python `timedelta(days=3)`).
pub const MAX_AGE_S: i64 = 3 * 24 * 60 * 60;

pub const NOTE_PRESET: &str = "Это итог для выбранного пресета, а не для Zapret вообще: пресет решает, для каких сайтов и какой обход \
     включён. Для сайтов, которые не открылись, попробуйте другой пресет или «Подбор стратегии».";
pub const NOTE_TOOLS: &str =
    "В одной из двух проверок работал VPN или другая программа обхода — разница может быть из-за них, а не из-за Zapret.";

/// Группы сравнения в порядке показа: (поле, значок, название).
const GROUPS: [(&str, &str, &str); 4] = [
    ("helped", "✅", "Обход помог"),
    ("not_helped", "❌", "Не открываются и с обходом"),
    ("broken", "⚠️", "Открывались без Zapret, а с ним перестали"),
    ("fine_anyway", "ℹ️", "Открываются и без Zapret"),
];

/// python `GROUP_TITLES`: поле → название группы.
#[must_use]
pub fn group_titles() -> Vec<(&'static str, &'static str)> {
    GROUPS
        .iter()
        .map(|(key, _, title)| (*key, *title))
        .collect()
}

const LEVEL_ICONS: [(&str, &str); 3] = [("ok", "✅"), ("warn", "⚠️"), ("fail", "❌")];

/// Отметка для записи истории. Пусто — узнать, запущен ли Zapret, не удалось.
#[must_use]
pub fn zapret_mark(zapret_running: Option<bool>) -> String {
    match zapret_running {
        None => String::new(),
        Some(true) => ZAPRET_ON.to_string(),
        Some(false) => ZAPRET_OFF.to_string(),
    }
}

/// Последняя проверка того же набора сайтов в противоположном состоянии Zapret.
#[must_use]
pub fn counterpart<'a>(history: &'a [Value], entry: &Value) -> Option<&'a Value> {
    let mark = text_scalar(entry.get("zapret"));
    if mark != ZAPRET_ON && mark != ZAPRET_OFF {
        return None;
    }
    let wanted = if mark == ZAPRET_ON {
        ZAPRET_OFF
    } else {
        ZAPRET_ON
    };
    let now = parse_iso(&text_scalar(entry.get("time")));
    for run in history.iter().rev() {
        if !same_run_kind(run, entry) {
            continue;
        }
        if text_scalar(run.get("zapret")) != wanted {
            continue;
        }
        let then = parse_iso(&text_scalar(run.get("time")));
        let (Some(now), Some(then)) = (now, then) else {
            return None;
        };
        if now - then > MAX_AGE_S {
            // История идёт от старых к новым: раньше этой записи только ещё более старые.
            return None;
        }
        return Some(run);
    }
    None
}

fn states_of(run: &Value) -> Vec<(String, String)> {
    run.get("states")
        .and_then(Value::as_object)
        .map(|states| {
            states
                .iter()
                .map(|(name, state)| (name.clone(), text_scalar(Some(state))))
                .collect()
        })
        .unwrap_or_default()
}

/// Что даёт обход, по сервисам. `None` — сравнивать не с чем или нечего.
#[must_use]
pub fn compare_runs(entry: &Value, other: Option<&Value>) -> Option<Value> {
    let other = other?;
    let current_on = text_scalar(entry.get("zapret")) == ZAPRET_ON;
    let (with_zapret, without) = if current_on {
        (entry, other)
    } else {
        (other, entry)
    };
    let on_states = states_of(with_zapret);
    let off_states = states_of(without);
    let mut helped: Vec<String> = Vec::new();
    let mut not_helped: Vec<String> = Vec::new();
    let mut fine_anyway: Vec<String> = Vec::new();
    let mut broken: Vec<String> = Vec::new();
    // Порядок сервисов — как в текущей проверке.
    for (name, _state) in states_of(entry) {
        let on = on_states
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str());
        let off = off_states
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str());
        let open_on = on.map(is_open).unwrap_or(false);
        let open_off = off.map(is_open).unwrap_or(false);
        let fail_on = on == Some(FAIL);
        let fail_off = off == Some(FAIL);
        if fail_off && open_on {
            helped.push(name);
        } else if fail_off && fail_on {
            not_helped.push(name);
        } else if open_off && open_on {
            fine_anyway.push(name);
        } else if open_off && fail_on {
            broken.push(name);
        }
    }
    if !(!helped.is_empty()
        || !not_helped.is_empty()
        || !fine_anyway.is_empty()
        || !broken.is_empty())
    {
        return None;
    }
    let preset = text_scalar(with_zapret.get("preset"));
    let named = if preset.is_empty() {
        "выбранный пресет".to_string()
    } else {
        format!("пресет «{preset}»")
    };
    let capitalize = |text: &str| {
        let mut chars = text.chars();
        match chars.next() {
            Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            None => String::new(),
        }
    };
    let (level, headline) = if !broken.is_empty() {
        (
            "warn",
            format!("С Zapret перестали открываться: {}", broken.join(", ")),
        )
    } else if !not_helped.is_empty() && !helped.is_empty() {
        let named = capitalize(&named);
        (
            "warn",
            format!(
                "{named} чинит не всё: помог {}, не помог {}",
                helped.len(),
                not_helped.len()
            ),
        )
    } else if !not_helped.is_empty() {
        let named = capitalize(&named);
        (
            "fail",
            format!("{named} не помог ни одному закрытому сервису"),
        )
    } else if !helped.is_empty() {
        let named = capitalize(&named);
        ("ok", format!("{named} чинит всё, что было закрыто"))
    } else {
        (
            "ok",
            "Всё открывается и без Zapret — обход этим сервисам не нужен".to_string(),
        )
    };
    let mut notes: Vec<String> = Vec::new();
    if !not_helped.is_empty() || !broken.is_empty() {
        notes.push(NOTE_PRESET.to_string());
    }
    let disturbed = truthy(entry.get("tools")) || truthy(other.get("tools"));
    if disturbed {
        notes.push(NOTE_TOOLS.to_string());
    }
    Some(json!({
        "level": level,
        "headline": headline,
        "preset": preset,
        // В какой из двух проверок работал Zapret: в этой ("current") или в прошлой ("past").
        "zapret_in": if current_on { "current" } else { "past" },
        "other_time": text_scalar(other.get("time")),
        // В одной из двух проверок на дороге стоял VPN или другой обход: сравнение неточное.
        "disturbed": disturbed,
        "helped": helped,
        "not_helped": not_helped,
        "fine_anyway": fine_anyway,
        "broken": broken,
        "notes": notes,
    }))
}

/// Сравнение строками для текста отчёта.
#[must_use]
pub fn lines(result: Option<&Value>) -> Vec<String> {
    let Some(result) = result else {
        return Vec::new();
    };
    if !truthy(Some(result)) {
        return Vec::new();
    }
    let state = if text_scalar(result.get("zapret_in")) == ZAPRET_IN_CURRENT {
        "без Zapret"
    } else {
        "с Zapret"
    };
    let mut out = vec![format!(
        "━━━━━━━━ С Zapret и без (прошлая проверка {state} — {}) ━━━━━━━━",
        text_scalar(result.get("other_time"))
    )];
    // python начинает с пустой строки-разделителя; для отчёта она не нужна — движок склеивает.
    out.insert(0, String::new());
    let level = text_scalar(result.get("level"));
    let icon = LEVEL_ICONS
        .iter()
        .find(|(name, _)| *name == level)
        .map(|(_, icon)| *icon)
        .unwrap_or("ℹ️");
    out.push(format!("{icon} {}", text_scalar(result.get("headline"))));
    for (key, icon, title) in GROUPS {
        let names = result.get(key).and_then(Value::as_array);
        if let Some(names) = names.filter(|names| !names.is_empty()) {
            let names: Vec<String> = names.iter().map(|name| text_scalar(Some(name))).collect();
            out.push(format!("{icon} {title}: {}", names.join(", ")));
        }
    }
    if let Some(notes) = result.get("notes").and_then(Value::as_array) {
        for note in notes {
            out.push(format!("ℹ️ {}", text_scalar(Some(note))));
        }
    }
    out
}

const ZAPRET_IN_CURRENT: &str = "current";

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn entry(zapret: &str, states: Value) -> Value {
        json!({
            "kind": "blockcheck",
            "title": "Discord и YouTube",
            "time": "2026-10-18T20:00:00",
            "zapret": zapret,
            "states": states,
            "preset": "Оттский",
            "tools": false,
        })
    }

    #[test]
    fn mark_python() {
        assert_eq!(zapret_mark(Some(true)), ZAPRET_ON);
        assert_eq!(zapret_mark(Some(false)), ZAPRET_OFF);
        assert_eq!(zapret_mark(None), "");
    }

    #[test]
    fn counterparty_in_history() {
        let history = vec![
            entry(ZAPRET_OFF, json!({"YouTube": "fail", "Discord": "ok"}))
                .as_object()
                .map(|obj| Value::Object(obj.clone()))
                .unwrap(),
        ];
        // Текущая — с Zapret, в истории ищем без.
        let good = json!({
            "kind": "blockcheck",
            "title": "Discord и YouTube",
            "time": "2026-10-19T20:00:00",
            "zapret": ZAPRET_ON,
        });
        let found = counterpart(&history, &good).unwrap();
        assert_eq!(
            found.get("zapret").and_then(Value::as_str),
            Some(ZAPRET_OFF)
        );
        // Другой набор сайтов — не пара.
        let wrong = json!({"kind": "blockcheck", "title": "Все сайты", "time": "2026-10-19T20:00:00", "zapret": ZAPRET_ON});
        assert!(counterpart(&history, &wrong).is_none());
        // Слишком старая проверка — не пара.
        let older = entry(ZAPRET_OFF, json!({"YouTube": "fail"}));
        let older = older
            .as_object()
            .map(|obj| {
                let mut copy = obj.clone();
                copy.insert("time".to_string(), json!("2026-10-10T20:00:00"));
                Value::Object(copy)
            })
            .unwrap();
        let old_entry = json!({"kind": "blockcheck", "title": "Discord и YouTube", "time": "2026-10-17T20:00:00", "zapret": ZAPRET_ON});
        assert!(counterpart(&[older], &old_entry).is_none());
        // Неизвестная отметка — не пара.
        let unmarked = json!({"kind": "blockcheck", "title": "Discord и YouTube", "zapret": ""});
        assert!(counterpart(&history, &unmarked).is_none());
    }

    #[test]
    fn compare_runs_all_paths() {
        // Zapret был в текущей проверке.
        let run = entry(
            ZAPRET_ON,
            json!({"YouTube": "fail", "Discord": "ok", "Twitch": "ok", "Google": "fail"}),
        );
        let other = json!({
            "kind": "blockcheck",
            "title": "Discord и YouTube",
            "time": "2026-10-18T20:00:00",
            "zapret": ZAPRET_OFF,
            "states": {"YouTube": "fail", "Discord": "ok", "Twitch": "fail", "Google": "ok"},
            "tools": true,
        });
        let result = compare_runs(&run, Some(&other)).unwrap();
        assert_eq!(result.get("level").and_then(Value::as_str), Some("warn"));
        assert_eq!(
            result.get("headline").and_then(Value::as_str),
            Some("С Zapret перестали открываться: Google")
        );
        assert_eq!(
            result.get("zapret_in").and_then(Value::as_str),
            Some("current")
        );
        let helped: Vec<String> =
            serde_json::from_value(result.get("helped").cloned().unwrap_or_default()).unwrap();
        assert_eq!(helped, vec!["Twitch".to_string()]);
        let not_helped: Vec<String> =
            serde_json::from_value(result.get("not_helped").cloned().unwrap_or_default()).unwrap();
        assert_eq!(not_helped, vec!["YouTube".to_string()]);
        let fine_anyway: Vec<String> =
            serde_json::from_value(result.get("fine_anyway").cloned().unwrap_or_default()).unwrap();
        assert_eq!(fine_anyway, vec!["Discord".to_string()]);
        let broken: Vec<String> =
            serde_json::from_value(result.get("broken").cloned().unwrap_or_default()).unwrap();
        assert_eq!(broken, vec!["Google".to_string()]);
        assert!(result
            .get("disturbed")
            .and_then(Value::as_bool)
            .unwrap_or(false));
        let notes: Vec<String> =
            serde_json::from_value(result.get("notes").cloned().unwrap_or_default()).unwrap();
        assert_eq!(notes.len(), 2);
        assert!(compare_runs(&run, None).is_none());
        let solo_off = entry(ZAPRET_OFF, json!({"YouTube": "fail"}));
        let solo_on = json!({"states": {"YouTube": "ok"}, "time": "2026-10-18T20:00:00", "zapret": ZAPRET_ON, "title": "YouTube", "kind": "blockcheck", "preset": ""});
        let result = compare_runs(&solo_off, Some(&solo_on)).unwrap();
        assert_eq!(result.get("level").and_then(Value::as_str), Some("ok"));
        assert_eq!(
            result.get("headline").and_then(Value::as_str),
            Some("Выбранный пресет чинит всё, что было закрыто")
        );
        assert_eq!(
            result.get("zapret_in").and_then(Value::as_str),
            Some("past")
        );
        // Нечего сравнивать: все состояния неизвестные.
        let silent = entry(ZAPRET_ON, json!({"YouTube": "unknown"}));
        let other = json!({"zapret": ZAPRET_OFF, "states": {"YouTube": "unknown"}});
        assert!(compare_runs(&silent, Some(&other)).is_none());
    }

    #[test]
    fn lines_python_layout() {
        let result = json!({
            "level": "fail",
            "headline": "Пресет «Оттский» не помог ни одному закрытому сервису",
            "preset": "Оттский",
            "zapret_in": "current",
            "other_time": "2026-10-18T20:00:00",
            "disturbed": true,
            "helped": [],
            "not_helped": ["YouTube"],
            "fine_anyway": [],
            "broken": [],
            "notes": [NOTE_PRESET, NOTE_TOOLS],
        });
        let got = lines(Some(&result));
        assert_eq!(got[0], "");
        assert_eq!(
            got[1],
            "━━━━━━━━ С Zapret и без (прошлая проверка без Zapret — 2026-10-18T20:00:00) ━━━━━━━━"
        );
        assert_eq!(
            got[2],
            "❌ Пресет «Оттский» не помог ни одному закрытому сервису"
        );
        assert_eq!(got[3], "❌ Не открываются и с обходом: YouTube");
        assert_eq!(got[4], format!("ℹ️ {NOTE_PRESET}"));
        assert_eq!(got[5], format!("ℹ️ {NOTE_TOOLS}"));
        assert_eq!(lines(None).len(), 0);
        assert_eq!(lines(Some(&Value::Null)).len(), 0);
    }

    #[test]
    fn group_titles_python() {
        let titles = group_titles();
        assert_eq!(
            titles,
            vec![
                ("helped", "Обход помог"),
                ("not_helped", "Не открываются и с обходом"),
                ("broken", "Открывались без Zapret, а с ним перестали"),
                ("fine_anyway", "Открываются и без Zapret"),
            ]
        );
    }
}
