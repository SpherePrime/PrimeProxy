//! Порт `src/diagnostics/crowd_probe.py` — заморозка от нескольких соединений
//! сразу: сайт открывается одним соединением и висит в браузере.
//!
//! Проверка открывает сайт одним соединением. Браузер открывает сразу шесть. По
//! описанию одного автора (другими измерениями не подтверждено) фильтр
//! «замораживает» сайт, когда видит больше трёх одновременных шифрованных
//! соединений с одним именем: соединение устанавливается, приветствие уходит, а
//! ответа нет — и так около двух минут. Тогда «открывается» у нас означает
//! «висит» у человека.
//!
//! Как проверяется. На одном сайте, который открылся:
//! 1. одно приветствие «как Chrome» — должно пройти, иначе сравнивать не с чем;
//! 2. четыре таких приветствия одновременно;
//! 3. сразу после — снова одно.
//!
//! Если после пачки сайт замолчал, а до неё отвечал, остаются два вопроса, и на
//! оба есть проба: молчит только этот сайт или вся линия (контрольный сайт), и
//! вернётся ли он сам (опрос раз в несколько секунд, пока не ответит).
//!
//! ВАЖНО. Проба сама может вызвать эту заморозку: сайт перестанет открываться у
//! человека на пару минут. Поэтому она идёт самой последней — когда всё
//! остальное уже проверено — делается на одном сайте, не делается при работающем
//! обходе, и её итог прямо говорит, если остановку вызвала она.
//!
//! Чего отсюда не узнать: действует ли заморозка на адрес, подсеть или имя; каков
//! настоящий порог; так ли фильтр реагирует на наш «почерк», как на настоящий
//! Chrome.
//!
//! Здесь нет сети: отправка приветствия передаётся снаружи. Сбор ([`collect`])
//! отделён от вывода ([`judge`]).

use crate::block_cause::{HELLO_ALERT, HELLO_CANCELLED, HELLO_OK, HELLO_RESET, HELLO_TIMEOUT};
use crate::report_text::py_round0;

/// Сколько соединений открыть разом: на одно больше порога из описания.
pub const CROWD: usize = 4;
/// Как долго ждать, пока замолчавший сайт вернётся, и как часто спрашивать.
pub const RECOVERY_WAIT_S: f64 = 150.0;
pub const RECOVERY_STEP_S: f64 = 10.0;

/// Пачка проходит: такой заморозки нет.
pub const CROWD_NONE: &str = "none";
/// После пачки сайт замолчал и сам вернулся.
pub const CROWD_FREEZE: &str = "freeze";
/// Замолчал и за время ожидания не вернулся.
pub const CROWD_STUCK: &str = "stuck";
/// Часть пачки получила отказ: так ограничивает сам сайт.
pub const CROWD_LIMIT: &str = "limit";
pub const CROWD_UNKNOWN: &str = "unknown";

/// Слово итога для карточки (python `STATUS`).
#[must_use]
pub fn status(code: &str) -> &'static str {
    match code {
        CROWD_NONE => "Не замирает",
        CROWD_FREEZE => "Замирает от нескольких соединений",
        CROWD_STUCK => "Замолчал и не вернулся",
        CROWD_LIMIT => "Сайт сам ограничивает",
        _ => "Не удалось проверить",
    }
}

/// Факты пробы (python `CrowdFacts`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CrowdFacts {
    pub host: String,
    pub ip: String,
    /// Одно приветствие до пачки.
    pub before: String,
    /// Исходы пачки, по одному на соединение. Пусто — до пачки не дошли.
    pub crowd: Vec<String>,
    /// Одно приветствие сразу после пачки.
    pub after: String,
    /// Контрольный сайт после пачки: жива ли линия. Пусто — не спрашивали.
    pub control: String,
    /// Через сколько секунд сайт снова ответил. None — не ждали или не дождались.
    pub recovered_s: Option<f64>,
    /// Сколько секунд ждали возвращения.
    pub waited_s: f64,
}

/// Вывод пробы (python `CrowdVerdict`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CrowdVerdict {
    pub code: &'static str,
    pub text: String,
    pub advice: String,
}

/// Отказ сервера — тоже ответ: приветствие до него дошло.
fn answered(kind: &str) -> bool {
    kind == HELLO_OK || kind == HELLO_ALERT
}

/// Одно приветствие, пачка, снова одно; если сайт замолчал — контроль и ожидание.
///
/// `together()` выполняет пачку приветствий одновременно; `control()` —
/// приветствие контрольному сайту; `wait(секунды)` — пауза, false — проверку
/// сняли; `clock()` — время в секундах; `max_wait` — сколько можно ждать
/// возвращения (у проверки есть общий срок).
#[allow(clippy::too_many_arguments)]
pub fn collect(
    host: &str,
    ip: &str,
    hello: impl Fn(&str, &str) -> String,
    together: impl FnOnce() -> Vec<String>,
    control: impl FnOnce() -> String,
    mut wait: impl FnMut(f64) -> bool,
    clock: impl Fn() -> f64,
    max_wait: f64,
) -> CrowdFacts {
    let before = hello(ip, host);
    if !answered(&before) {
        return CrowdFacts {
            host: host.to_string(),
            ip: ip.to_string(),
            before,
            ..Default::default()
        };
    }
    let crowd = together();
    let after = hello(ip, host);
    if answered(&after)
        || crowd
            .iter()
            .chain(std::iter::once(&after))
            .any(|kind| kind == HELLO_CANCELLED)
    {
        return CrowdFacts {
            host: host.to_string(),
            ip: ip.to_string(),
            before,
            crowd,
            after,
            ..Default::default()
        };
    }
    // Сайт отвечал и замолчал. Жива ли линия — и вернётся ли он сам?
    let line = control();
    let started = clock();
    let mut recovered: Option<f64> = None;
    while answered(&line) && clock() - started < RECOVERY_WAIT_S.min(max_wait) {
        if !wait(RECOVERY_STEP_S) {
            break;
        }
        if answered(&hello(ip, host)) {
            recovered = Some(clock() - started);
            break;
        }
    }
    CrowdFacts {
        host: host.to_string(),
        ip: ip.to_string(),
        before,
        crowd,
        after,
        control: line,
        recovered_s: recovered,
        waited_s: clock() - started,
    }
}

/// Строка ряда для экрана (python `_row` возвращает dict).
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub title: String,
    pub text: String,
    pub state: &'static str,
}

/// Слова итога вида приветствия (python `_OUTCOME_WORDS`).
fn outcome_words(kind: &str) -> (&'static str, &'static str) {
    match kind {
        HELLO_OK => ("ответило", "ok"),
        HELLO_ALERT => ("дошло до сервера", "ok"),
        HELLO_RESET => ("сброшено", "fail"),
        HELLO_TIMEOUT => ("без ответа", "fail"),
        _ => ("не установилось", "unknown"),
    }
}

fn row(title: &str, kind: &str) -> Row {
    let (word, state) = outcome_words(kind);
    Row {
        title: title.to_string(),
        text: word.to_string(),
        state,
    }
}

/// Что было с каждым соединением — строками для экрана: до пачки, пачка, после, контроль, возвращение.
#[must_use]
pub fn rows(facts: &CrowdFacts) -> Vec<Row> {
    let mut found = vec![row("Одно соединение до пачки", &facts.before)];
    for (index, kind) in facts.crowd.iter().enumerate() {
        found.push(row(
            &format!(
                "Соединение {} из {} одновременных",
                index + 1,
                facts.crowd.len()
            ),
            kind,
        ));
    }
    if !facts.after.is_empty() {
        found.push(row("Одно соединение сразу после пачки", &facts.after));
    }
    if !facts.control.is_empty() {
        let check = row("Контрольный сайт в это же время", &facts.control);
        found.push(Row {
            text: if check.state == "ok" {
                "отвечает".to_string()
            } else {
                "не отвечает".to_string()
            },
            ..check
        });
    }
    if let Some(recovered) = facts.recovered_s {
        found.push(Row {
            title: "Сайт снова ответил".to_string(),
            text: format!("через {} с", py_round0(recovered)),
            state: "info",
        });
    } else if !facts.control.is_empty() && facts.waited_s != 0.0 {
        found.push(Row {
            title: "Ждали возвращения сайта".to_string(),
            text: format!("{} с — не вернулся", py_round0(facts.waited_s)),
            state: "warn",
        });
    }
    found
}

pub const ADVICE_FREEZE: &str = "Так сайт ведёт себя и в браузере: он открывает несколько соединений сразу и натыкается на ту же остановку. Подберите стратегию Zapret для этого сайта. Остановку сейчас вызвала сама проверка — сайт уже вернулся.";
pub const ADVICE_STUCK: &str = "Остановку, скорее всего, вызвала сама проверка. Подождите несколько минут, не обновляя страницу сайта, и он должен вернуться. Если такое повторяется в браузере — подберите стратегию Zapret для этого сайта.";

/// Вывод. None — проверку сняли или её не было.
#[must_use]
pub fn judge(facts: Option<&CrowdFacts>) -> Option<CrowdVerdict> {
    let facts = facts?;
    if facts.before == HELLO_CANCELLED
        || facts.after == HELLO_CANCELLED
        || facts.crowd.iter().any(|kind| kind == HELLO_CANCELLED)
    {
        return None;
    }
    let site = format!("{} ({})", facts.host, facts.ip);
    if !answered(&facts.before) {
        return Some(CrowdVerdict {
            code: CROWD_UNKNOWN,
            text: format!(
                "{site}: одиночное соединение на этот раз не прошло — сравнивать не с чем"
            ),
            ..CrowdVerdict::default()
        });
    }
    let passed = facts.crowd.iter().filter(|kind| answered(kind)).count();
    if answered(&facts.after) {
        if passed == facts.crowd.len() {
            return Some(CrowdVerdict {
                code: CROWD_NONE,
                text: format!(
                    "{site}: {} соединения сразу проходят, и после них сайт отвечает — от числа соединений он не замирает",
                    facts.crowd.len()
                ),
                ..CrowdVerdict::default()
            });
        }
        let refused = facts
            .crowd
            .iter()
            .filter(|kind| **kind == HELLO_RESET)
            .count();
        let how = if refused != 0 {
            "получили сброс"
        } else {
            "остались без ответа"
        };
        return Some(CrowdVerdict {
            code: CROWD_LIMIT,
            text: format!(
                "{site}: из {} соединений сразу {} {}, но сайт после этого отвечает — похоже на ограничение самого сайта, а не на заморозку",
                facts.crowd.len(),
                facts.crowd.len() - passed,
                how
            ),
            ..CrowdVerdict::default()
        });
    }
    if facts.after != HELLO_TIMEOUT {
        return Some(CrowdVerdict {
            code: CROWD_UNKNOWN,
            text: format!(
                "{site}: после {} соединений сразу сайт ответил сбросом — так отказывает сервер, заморозка выглядит иначе",
                facts.crowd.len()
            ),
            ..CrowdVerdict::default()
        });
    }
    if !answered(&facts.control) {
        return Some(CrowdVerdict {
            code: CROWD_UNKNOWN,
            text: format!(
                "{site}: после пачки соединений сайт замолчал, но не отвечает и контрольный сайт — похоже, пропала сама связь"
            ),
            ..CrowdVerdict::default()
        });
    }
    if let Some(recovered) = facts.recovered_s {
        return Some(CrowdVerdict {
            code: CROWD_FREEZE,
            text: format!(
                "{site}: одно соединение проходит, а после {} сразу сайт замолчал и снова ответил через {} с — его \
                 замораживают, когда соединений несколько",
                facts.crowd.len(),
                py_round0(recovered)
            ),
            advice: ADVICE_FREEZE.to_string(),
        });
    }
    Some(CrowdVerdict {
        code: CROWD_STUCK,
        text: format!(
            "{site}: одно соединение проходило, а после {} сразу сайт замолчал и за {} с не вернулся; остальной \
             интернет при этом работает",
            facts.crowd.len(),
            py_round0(facts.waited_s)
        ),
        advice: ADVICE_STUCK.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(before: &str, crowd: Vec<&str>, after: &str) -> CrowdFacts {
        CrowdFacts {
            host: "vk.com".to_string(),
            ip: "5.61.23.11".to_string(),
            before: before.to_string(),
            crowd: crowd.into_iter().map(String::from).collect(),
            after: after.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn judge_none_limit_and_unknown() {
        let ok = judge(Some(&facts("ok", vec!["ok"; 4], "ok"))).unwrap();
        assert_eq!(ok.code, CROWD_NONE);
        assert_eq!(
            ok.text,
            "vk.com (5.61.23.11): 4 соединения сразу проходят, и после них сайт отвечает — от числа соединений он не замирает"
        );
        let silent = judge(Some(&facts("timeout", vec![], ""))).unwrap();
        assert_eq!(silent.code, CROWD_UNKNOWN);
        assert_eq!(
            silent.text,
            "vk.com (5.61.23.11): одиночное соединение на этот раз не прошло — сравнивать не с чем"
        );
        let limit = judge(Some(&facts(
            "ok",
            vec!["reset", "timeout", "timeout", "timeout"],
            "ok",
        )))
        .unwrap();
        assert_eq!(limit.code, CROWD_LIMIT);
        assert_eq!(
            limit.text,
            "vk.com (5.61.23.11): из 4 соединений сразу 4 получили сброс, но сайт после этого отвечает — похоже на ограничение самого сайта, а не на заморозку"
        );
        let alert = judge(Some(&facts("ok", vec!["ok", "ok", "ok", "ok"], "alert"))).unwrap();
        assert_eq!(alert.code, CROWD_NONE);
        let server_refused =
            judge(Some(&facts("ok", vec!["ok", "ok", "ok", "ok"], "reset"))).unwrap();
        assert_eq!(
            server_refused.text,
            "vk.com (5.61.23.11): после 4 соединений сразу сайт ответил сбросом — так отказывает сервер, заморозка выглядит иначе"
        );
        let no_link = judge(Some(&facts("ok", vec!["ok", "ok", "ok", "ok"], "timeout"))).unwrap();
        assert_eq!(
            no_link.text,
            "vk.com (5.61.23.11): после пачки соединений сайт замолчал, но не отвечает и контрольный сайт — похоже, пропала сама связь"
        );
        assert!(judge(Some(&facts("cancelled", vec![], ""))).is_none());
        assert!(judge(None).is_none());
    }

    #[test]
    fn judge_freeze_recommendations_python() {
        let mut frozen = facts("ok", vec!["ok", "ok", "ok", "ok"], "timeout");
        frozen.control = "ok".to_string();
        frozen.recovered_s = Some(22.4);
        frozen.waited_s = 60.0;
        let verdict = judge(Some(&frozen)).unwrap();
        assert_eq!(verdict.code, CROWD_FREEZE);
        assert_eq!(
            verdict.text,
            "vk.com (5.61.23.11): одно соединение проходит, а после 4 сразу сайт замолчал и снова ответил через 22 с — его замораживают, когда соединений несколько"
        );
        assert_eq!(verdict.advice, ADVICE_FREEZE);
        let mut stuck = frozen.clone();
        stuck.recovered_s = None;
        stuck.waited_s = 150.0;
        let verdict = judge(Some(&stuck)).unwrap();
        assert_eq!(verdict.code, CROWD_STUCK);
        assert_eq!(
            verdict.text,
            "vk.com (5.61.23.11): одно соединение проходило, а после 4 сразу сайт замолчал и за 150 с не вернулся; остальной интернет при этом работает"
        );
        assert_eq!(verdict.advice, ADVICE_STUCK);
    }

    #[test]
    fn rows_for_screen_python_text() {
        let sample = CrowdFacts {
            before: "ok".to_string(),
            crowd: vec![
                "ok".into(),
                HELLO_RESET.into(),
                HELLO_TIMEOUT.into(),
                "alert".into(),
            ],
            after: "ok".to_string(),
            control: HELLO_TIMEOUT.to_string(),
            waited_s: 150.0,
            host: "vk.com".to_string(),
            ip: "5.61.23.11".to_string(),
            ..Default::default()
        };
        let got = rows(&sample);
        let texts: Vec<String> = got
            .iter()
            .map(|row| format!("{} | {} | {}", row.title, row.text, row.state))
            .collect();
        assert_eq!(
            texts,
            vec![
                "Одно соединение до пачки | ответило | ok",
                "Соединение 1 из 4 одновременных | ответило | ok",
                "Соединение 2 из 4 одновременных | сброшено | fail",
                "Соединение 3 из 4 одновременных | без ответа | fail",
                "Соединение 4 из 4 одновременных | дошло до сервера | ok",
                "Одно соединение сразу после пачки | ответило | ok",
                "Контрольный сайт в это же время | не отвечает | fail",
                "Ждали возвращения сайта | 150 с — не вернулся | warn",
            ]
        );
        let mut recovered = CrowdFacts {
            crowd: vec!["ok".to_string()],
            recovered_s: Some(9.51),
            after: String::new(),
            control: String::new(),
            waited_s: 0.0,
            ..sample
        };
        let texts = rows(&recovered);
        assert_eq!(texts[2].text, "через 10 с");
        recovered.exit_recovered();
        assert_eq!(rows(&recovered).len(), 2);
    }

    impl CrowdFacts {
        fn exit_recovered(&mut self) {
            self.recovered_s = None;
            self.waited_s = 0.0;
        }
    }

    #[test]
    fn crowd_collect_python_branches() {
        // До пачки не дошло.
        let no_way = collect(
            "vk.com",
            "5.61.23.11",
            |_ip, _host| HELLO_TIMEOUT.to_string(),
            Vec::<String>::new,
            String::new,
            |_seconds| true,
            || 0.0,
            RECOVERY_WAIT_S,
        );
        assert_eq!(no_way.before, HELLO_TIMEOUT);
        assert!(no_way.crowd.is_empty());
        // Пачка прошла, сайт отвечает.
        let answers = vec!["ok"; 4];
        let passed = collect(
            "vk.com",
            "5.61.23.11",
            |ip, host| {
                assert_eq!((ip, host), ("5.61.23.11", "vk.com"));
                let _ = answers;
                "ok".to_string()
            },
            || vec!["ok".to_string(); CROWD],
            || "ok".to_string(),
            |_seconds| true,
            || 0.0,
            RECOVERY_WAIT_S,
        );
        assert_eq!(passed.crowd.len(), CROWD);
        assert_eq!(passed.after, HELLO_OK);
    }
}
