//! Порт `src/diagnostics/voice_check.py` — голосовые звонки: доходит ли UDP до
//! STUN-серверов.
//!
//! Discord и Telegram звонят по UDP. STUN-сервер — самый простой способ узнать,
//! проходит ли UDP: отправляем короткий запрос и ждём любой ответ.
//!
//! Раньше «ответ пришёл, но разобрать не удалось» записывалось как
//! «заблокирован», хотя сам факт ответа и значит, что UDP проходит. Здесь любой
//! ответ — «UDP работает», а «звонки могут не работать» пишется, только если не
//! ответил ни один сервер.

use crate::verdict::Level;

pub const GROUP_TELEGRAM: &str = "telegram";

/// Общий срок пробы одного сервера (python `blockcheck.config.STUN_TIMEOUT`).
pub const STUN_TIMEOUT_S: f64 = 5.0;

/// python `STUN_TARGETS` — список проверочных серверов: имя, `STUN:хост:порт`, группа.
pub const STUN_TARGETS: [(&str, &str, &str); 5] = [
    ("Google STUN", "STUN:stun.l.google.com:19302", "general"),
    ("CF STUN", "STUN:stun.cloudflare.com:3478", "general"),
    ("Twilio STUN", "STUN:global.stun.twilio.com:3478", "general"),
    ("Telegram STUN", "STUN:stun.telegram.org:3478", "telegram"),
    (
        "Telegram VoIP STUN",
        "STUN:stun.voip.telegram.org:3478",
        "telegram",
    ),
];

// Коды `error_code` поштучных проб STUN (blockcheck.stun_tester): как у python.
const ANSWERED_CODES: [&str; 2] = ["", "PARSE_ERR"];

/// Один STUN-сервер и ответ на вопросы о нём (python `VoiceServer`).
#[derive(Debug, Clone, PartialEq)]
pub struct VoiceServer {
    pub name: String,
    pub host: String,
    pub answered: bool,
    pub text: String,
    /// Проверка состоялась: сервер ответил или промолчал. False — до него не
    /// дошло дело (не узнали адрес, ошибка самой проверки): это не говорит ничего о UDP.
    pub decided: bool,
    /// Чьи это звонки: "telegram" или "general".
    pub group: String,
}

/// Итог по голосовым звонкам (python `VoiceReport`).
#[derive(Debug, Clone, PartialEq)]
pub struct VoiceReport {
    pub level: Level,
    pub headline: String,
    pub servers: Vec<VoiceServer>,
    pub advice: Vec<String>,
}

/// `STUN:`-адрес: `(хост, порт)`; порт по умолчанию — 3478 (python `_parse_target`).
///
/// Python: `host, _, port = raw.rpartition(":")`, `int(port)` — без двоеточия
/// хост пуст, а порт — вся строка; не числовая строка сваливается в (`raw`, 3478).
#[must_use]
pub fn parse_target(value: &str) -> (String, u16) {
    let mut raw = value.to_string();
    if raw.to_uppercase().starts_with("STUN:") {
        raw = raw[5..].to_string();
    }
    let (host, tail) = match raw.rfind(':') {
        Some(index) => (raw[..index].to_string(), raw[index + 1..].to_string()),
        None => (String::new(), raw.clone()),
    };
    match tail.parse::<u16>() {
        Ok(port) => (host, port),
        Err(_) => (raw, 3478),
    }
}

/// Итог одной попытки: (ответил ли, пояснение, состоялась ли проверка).
///
/// Python получает `blockcheck.stun_tester.SingleTestResult`; здесь же —
/// переносимый «снимок» результата: статус, код сбоя, деталь.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct StunOutcome {
    pub status: String,
    pub error_code: String,
    pub detail: String,
}

#[must_use]
pub fn describe(result: &StunOutcome) -> (bool, String, bool) {
    let status = result.status.to_lowercase();
    let code = result.error_code.as_str();
    if status == "ok" {
        return (true, "отвечает".to_string(), true);
    }
    if ANSWERED_CODES.contains(&code) {
        return (
            true,
            "отвечает (ответ необычный, но UDP проходит)".to_string(),
            true,
        );
    }
    match code {
        "TIMEOUT" => (
            false,
            "не ответил — UDP до него не доходит".to_string(),
            true,
        ),
        "DNS_ERR" => (
            false,
            "не удалось узнать адрес сервера — проверить его не вышло".to_string(),
            false,
        ),
        "RESET" => (
            false,
            "сервер отклонил запрос (порт закрыт)".to_string(),
            true,
        ),
        "CANCELLED" => (false, "проверку сняли".to_string(), false),
        "UNREACHABLE" => {
            // Нет маршрута (часто — нет IPv6 или сети вовсе): о закрытом UDP это ничего не говорит.
            (
                false,
                "до адреса сервера нет дороги — проверить его не вышло".to_string(),
                false,
            )
        }
        _ => (
            false,
            if result.detail.is_empty() {
                "ошибка проверки".to_string()
            } else {
                result.detail.clone()
            },
            false,
        ),
    }
}

/// План опроса: `(имя, хост, порт, группа)` — движок подаёт `STUN_TARGETS`.
pub type StunPlan = Vec<(String, String, u16, String)>;

/// Готовый план по `STUN_TARGETS`-строкам (python-порядок сохраняется).
#[must_use]
pub fn plan_targets(targets: &[(&str, &str, &str)]) -> StunPlan {
    // Python: target["name"], parse(target["value"]), target.get("group", "general")
    targets
        .iter()
        .map(|(name, value, group)| {
            let (host, port) = parse_target(value);
            (
                name.to_string(),
                host,
                port,
                if group.is_empty() {
                    "general".to_string()
                } else {
                    group.to_string()
                },
            )
        })
        .collect()
}

/// Вывод по серверам-планам: результат каждой пробы уже получен.
#[must_use]
pub fn collect_servers(
    plan: &[(String, String, u16, String)],
    outcome_of: impl Fn(&str, u16) -> Option<StunOutcome>,
) -> Vec<VoiceServer> {
    let mut servers = Vec::new();
    for (name, host, port, group) in plan {
        let outcome = outcome_of(host, *port);
        let Some(outcome) = outcome else {
            // Отдельный сервер не должен ронять отчёт: как python `except Exception`.
            servers.push(VoiceServer {
                name: name.clone(),
                host: host.clone(),
                answered: false,
                text: "ошибка проверки".to_string(),
                decided: false,
                group: group.clone(),
            });
            continue;
        };
        let (answered, text, decided) = describe(&outcome);
        servers.push(VoiceServer {
            name: name.clone(),
            host: host.clone(),
            answered,
            text,
            decided,
            group: group.clone(),
        });
    }
    servers
}

/// Итог по звонкам. Серверы Telegram судятся отдельно: если молчат только они,
/// это блокировка звонков Telegram, а не «UDP вообще не проходит».
#[must_use]
pub fn summarize_voice(servers: &[VoiceServer]) -> VoiceReport {
    let servers_owned = servers.to_vec();
    if servers.is_empty() {
        return VoiceReport {
            level: Level::Unknown,
            headline: "Голосовые серверы не проверялись".to_string(),
            servers: servers_owned,
            advice: Vec::new(),
        };
    }
    // Судим только по серверам, проверка которых состоялась: «не узнали адрес» — не «UDP закрыт».
    let decided: Vec<&VoiceServer> = servers.iter().filter(|item| item.decided).collect();
    if decided.is_empty() {
        return VoiceReport {
            level: Level::Unknown,
            headline: "Голосовые серверы проверить не удалось: не получилось узнать их адреса"
                .to_string(),
            servers: servers_owned,
            advice: vec![
                "Повторите проверку. Если повторяется — проверьте DNS в разделе «Настройка DNS»."
                    .to_string(),
            ],
        };
    }
    let telegram_list: Vec<&&VoiceServer> = decided
        .iter()
        .filter(|item| item.group == GROUP_TELEGRAM)
        .collect();
    let general: Vec<&&VoiceServer> = decided
        .iter()
        .filter(|item| item.group != GROUP_TELEGRAM)
        .collect();
    let general_ok = if general.is_empty() {
        true
    } else {
        general.iter().any(|item| item.answered)
    };
    let telegram_ok = if telegram_list.is_empty() {
        true
    } else {
        telegram_list.iter().any(|item| item.answered)
    };
    let strategy_advice =
        vec!["Нажмите «Подобрать стратегию для звонков» — нужный пункт «Голосовые звонки» выберется сам.".to_string()];
    if !general_ok {
        return VoiceReport {
            level: Level::Fail,
            headline:
                "Голосовые звонки могут не работать: проверочные серверы (STUN) не отвечают по UDP"
                    .to_string(),
            servers: servers_owned,
            advice: strategy_advice,
        };
    }
    if !telegram_ok {
        return VoiceReport {
            level: Level::Warn,
            headline: "Звонки в Telegram могут не работать: его проверочные серверы (STUN) не отвечают по UDP"
                .to_string(),
            servers: servers_owned,
            advice: strategy_advice,
        };
    }
    let answered_count = servers.iter().filter(|item| item.answered).count();
    VoiceReport {
        level: Level::Ok,
        headline: format!(
            "Проверочные серверы звонков отвечают по UDP ({} из {})",
            answered_count,
            servers.len()
        ),
        servers: servers_owned,
        advice: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stun(name: &str, host: &str, answered: bool, decided: bool, group: &str) -> VoiceServer {
        VoiceServer {
            name: name.to_string(),
            host: host.to_string(),
            answered,
            text: if answered {
                "отвечает".to_string()
            } else {
                "не ответил".to_string()
            },
            decided,
            group: group.to_string(),
        }
    }

    #[test]
    fn parse_python_cases() {
        assert_eq!(
            parse_target("stun:dns.google.com:443"),
            ("dns.google.com".to_string(), 443)
        );
        assert_eq!(parse_target("stun:1.2.3.4"), ("1.2.3.4".to_string(), 3478));
        assert_eq!(parse_target("12345"), (String::new(), 12345));
        assert_eq!(
            parse_target("dns.google.com"),
            ("dns.google.com".to_string(), 3478)
        );
    }

    #[test]
    fn describe_all_codes() {
        let ok = StunOutcome {
            status: "OK".to_string(),
            ..Default::default()
        };
        assert_eq!(describe(&ok), (true, "отвечает".to_string(), true));
        let parse_err = StunOutcome {
            error_code: "PARSE_ERR".to_string(),
            ..Default::default()
        };
        assert_eq!(
            describe(&parse_err),
            (
                true,
                "отвечает (ответ необычный, но UDP проходит)".to_string(),
                true
            )
        );
        for (code, text, decided) in [
            ("TIMEOUT", "не ответил — UDP до него не доходит", true),
            (
                "DNS_ERR",
                "не удалось узнать адрес сервера — проверить его не вышло",
                false,
            ),
            ("RESET", "сервер отклонил запрос (порт закрыт)", true),
            ("CANCELLED", "проверку сняли", false),
            (
                "UNREACHABLE",
                "до адреса сервера нет дороги — проверить его не вышло",
                false,
            ),
        ] {
            let outcome = StunOutcome {
                error_code: code.to_string(),
                ..Default::default()
            };
            assert_eq!(
                describe(&outcome),
                (false, text.to_string(), decided),
                "{code}"
            );
        }
        let strange = StunOutcome {
            error_code: "другой".to_string(),
            detail: "текст сбоя".to_string(),
            ..Default::default()
        };
        assert_eq!(describe(&strange), (false, "текст сбоя".to_string(), false));
        let empty_detail = StunOutcome {
            error_code: "другой".to_string(),
            ..Default::default()
        };
        assert_eq!(
            describe(&empty_detail),
            (false, "ошибка проверки".to_string(), false)
        );
    }

    #[test]
    fn plan_targets_table() {
        let plan = plan_targets(&[
            ("Telegram", "stun:tg.example:3479", "telegram"),
            ("Прочий", "stun:x.example", ""),
        ]);
        assert_eq!(plan[0].3, GROUP_TELEGRAM);
        assert_eq!(plan[0].1, "tg.example");
        assert_eq!(plan[0].2, 3479);
        assert_eq!(plan[1].3, "general");
    }

    #[test]
    fn summarize_python_matrix() {
        let general_fail = stun("Стандарт", "b", false, true, "general");
        let mute = summarize_voice(std::slice::from_ref(&general_fail));
        assert_eq!(mute.level, Level::Fail);
        assert_eq!(
            mute.headline,
            "Голосовые звонки могут не работать: проверочные серверы (STUN) не отвечают по UDP"
        );
        let only_telegram_fail = stun("Тлг", "c", false, true, GROUP_TELEGRAM);
        let general_ok_any = stun("Лин", "d", true, true, "general");
        let good = summarize_voice(std::slice::from_ref(&general_ok_any));
        assert_eq!(good.level, Level::Ok);
        assert_eq!(
            good.headline,
            "Проверочные серверы звонков отвечают по UDP (1 из 1)"
        );
        assert!(good.advice.is_empty());
        let alive = stun("Telegram", "a", true, true, GROUP_TELEGRAM);
        assert_eq!(
            summarize_voice(std::slice::from_ref(&alive)).level,
            Level::Ok
        );
        let sync: Vec<VoiceServer> = vec![alive.clone(), general_fail.clone()];
        assert_eq!(summarize_voice(&sync).level, Level::Fail);
        let unsync = vec![general_ok_any, only_telegram_fail.clone()];
        let warn = summarize_voice(&unsync);
        assert_eq!(warn.level, Level::Warn);
        assert_eq!(warn.headline, "Звонки в Telegram могут не работать: его проверочные серверы (STUN) не отвечают по UDP");
        assert_eq!(warn.advice.len(), 1);
        let mute_pair = vec![general_fail, only_telegram_fail];
        let fail_pair = summarize_voice(&mute_pair);
        assert_eq!(fail_pair.level, Level::Fail);
        assert_eq!(
            summarize_voice(&[]).headline,
            "Голосовые серверы не проверялись"
        );
        let undecided = vec![stun("x", "y", false, false, "general")];
        let cannot = summarize_voice(&undecided);
        assert_eq!(cannot.level, Level::Unknown);
        assert_eq!(
            cannot.headline,
            "Голосовые серверы проверить не удалось: не получилось узнать их адреса"
        );
    }

    #[test]
    fn collect_servers_pipeline_exception() {
        let plan = vec![(
            "One".to_string(),
            "a".to_string(),
            3478,
            "general".to_string(),
        )];
        let servers = collect_servers(&plan, |host, port| {
            assert_eq!(host, "a");
            assert_eq!(port, 3478);
            None
        });
        assert!(!servers[0].decided);
        assert_eq!(servers[0].text, "ошибка проверки");
        let servers = collect_servers(&plan, |_host, _port| {
            Some(StunOutcome {
                status: "OK".to_string(),
                ..Default::default()
            })
        });
        assert!(servers[0].answered);
        assert_eq!(servers[0].text, "отвечает");
    }
}
