//! Порт `src/diagnostics/problems.py` — что из найденного показать человеку и в каком порядке.
//!
//! На входе — готовые выводы по каждому сайту и по отдельным проверкам (звонки,
//! обрыв, IPv6, компьютер, Telegram). На выходе — строки итога: что не так, чем
//! это подтверждено, что делать и какая кнопка нужна.
//!
//! Здесь же два общих правила, которые отменяют частные советы:
//!
//! - «нет интернета» — до контрольных сайтов нет дороги вовсе;
//! - «белые списки» — дорога есть только до российских сайтов.
//!
//! Оба требуют, чтобы не ответил ни один эталонный DNS-сервер: это зарубежные
//! адреса, к которым программа ходит напрямую. В сеть модуль не ходит.
use crate::block_cause::{CAUSE_BY_ADDRESS, CAUSE_NAME_WHITELIST};
use crate::block_kind::{self, KIND_DNS, KIND_DOWN, KIND_OTHER};
use crate::ipv6_check::{Ipv6Verdict, IPV6_BROKEN};
use crate::levels::level_rank;
use crate::quic_probe::{QUIC_BLOCKED_BY_NAME, QUIC_OK, QUIC_SILENT};
use crate::report_text::sentence;
use crate::run_context::{Probe, ReferenceReport};
use crate::services::Service;
use crate::subnet_whitelist::{SubnetVerdict, CODE_CONFIRMED, CODE_REFUTED};
use crate::system_state::{problem_level, SystemItem};
use crate::telegram_check::TelegramReport;
use crate::verdict::{advice_geo_site, DnsState, Level, ReachState, ServiceVerdict};

pub const ADVICE_IPV6: &str =
    "Из-за этого сайты могут открываться с задержкой: браузер сначала пробует IPv6. Перезагрузите роутер; \
     если не поможет — снимите галочку «IP версии 6» в свойствах сетевого адаптера Windows.";
/// Сайты, которые QUIC поддерживают наверняка: по ним отличают
/// «у сайта нет QUIC» от «UDP 443 закрыт». python `QUIC_CONTROL_HOSTS`.
pub const QUIC_CONTROL_HOSTS: [&str; 3] =
    ["www.google.com", "www.youtube.com", "www.cloudflare.com"];
pub const ADVICE_QUIC: &str =
    "В пресете должен быть profile для UDP 443 (QUIC) с этими сайтами. Проще всего выбрать готовый пресет, \
     где он есть, или отключить QUIC в браузере (в Chrome: chrome://flags → Experimental QUIC protocol).";
pub const ADVICE_BLOCKED_REFERENCE: &str =
    "Похоже, этот сервер закрыт у вашего провайдера. Не выбирайте его для защищённого DNS: \
     Windows молча вернётся к обычным запросам, которые видны и подменяются.";

use crate::verdict::ADVICE_DNS;

/// python `ADVICE_VIA_ZAPRET` (у verdict).
use crate::verdict::ADVICE_VIA_ZAPRET;

/// Блокировки, которые обходит стратегия Zapret.
const BYPASSABLE: [ReachState; 2] = [ReachState::Dpi, ReachState::Freeze];

/// Разделы отчёта, из которых выводятся строки итога.
pub const SECTION_SERVICES: &str = "services";
pub const SECTION_FREEZE: &str = "freeze";
pub const SECTION_VOICE: &str = "voice";
pub const SECTION_TELEGRAM: &str = "telegram";
pub const SECTION_NETWORK: &str = "network";
pub const SECTION_IPV6: &str = "ipv6";
pub const SECTION_SYSTEM: &str = "system";
pub const SECTION_DNS: &str = "dns";
pub const SECTION_DNS_SERVERS: &str = "dns_servers";
pub const SECTION_QUIC: &str = "quic";
pub const SECTION_SPEED: &str = "speed";
pub const SECTION_CROWD: &str = "crowd";

/// Ключ сайта Telegram в `services`: закрытому по адресу Telegram помогает встроенный прокси.
pub const TELEGRAM_SITE: &str = "telegram";

/// python `no_geo_service(host)`.
fn no_geo_service(_host: &str) -> String {
    String::new()
}

/// python `_zapret_action` — кнопка у обходимой блокировки. «Запустить» — только
/// когда точно известно, что Zapret не запущен.
fn zapret_action(zapret_running: Option<bool>) -> &'static str {
    if zapret_running == Some(false) {
        "start_zapret"
    } else {
        "strategy"
    }
}

/// python `Problem` — строка итога. `kind` — вид блокировки.
#[derive(Debug, Clone, PartialEq)]
pub struct Problem {
    pub level: Level,
    pub text: String,
    pub advice: Vec<String>,
    pub action: String,
    pub target: String,
    pub kind: String,
    pub title: String,
    /// На чём основан вывод; эти же фразы стоят первыми в `advice`.
    pub evidence: Vec<String>,
    /// Та же фраза готовыми частями у находок про DNS-серверы (не используется здесь).
    pub parts: Option<std::collections::BTreeMap<String, String>>,
    /// Ключ сайта из отчёта (у которого подробности), если строка про сайт.
    pub site: String,
    /// Раздел отчёта, из которого выведена строка (`freeze`, `voice`, `ipv6`…).
    pub section: String,
}

impl Problem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        level: Level,
        text: impl Into<String>,
        advice: Vec<String>,
        action: impl Into<String>,
        target: impl Into<String>,
        kind: impl Into<String>,
        title: impl Into<String>,
        evidence: Vec<String>,
        site: impl Into<String>,
        section: impl Into<String>,
    ) -> Self {
        Self {
            level,
            text: text.into(),
            advice,
            action: action.into(),
            target: target.into(),
            kind: kind.into(),
            title: title.into(),
            evidence,
            parts: None,
            site: site.into(),
            section: section.into(),
        }
    }
}

/// python `burst_problems(burst)` — проблема «UDP замирает после первых пакетов».
/// Пусто — заморозки нет или вывода нет.
pub fn burst_problems(burst: Option<&crate::udp_burst::BurstVerdict>) -> Vec<Problem> {
    let Some(burst) = burst else {
        return Vec::new();
    };
    if burst.code != crate::udp_burst::BURST_FREEZE {
        return Vec::new();
    }
    vec![Problem::new(
        Level::Warn,
        format!("UDP замирает: {}", burst.text),
        vec![
            "Нажмите «Подобрать стратегию для звонков» — нужный пункт «Голосовые звонки» выберется сам.".to_string(),
        ],
        "strategy_voice",
        "",
        block_kind::KIND_VOICE,
        "",
        Vec::new(),
        "",
        SECTION_VOICE,
    )]
}

/// python `_whitelist_kind(foreign, collected)` — как именно устроен «белый список»
/// — по прямым пробам к зарубежным контрольным сайтам.
fn whitelist_kind(collected: &Entries<Vec<Probe>>, foreign: &[String]) -> String {
    let mut causes: std::collections::BTreeSet<String> = Default::default();
    for key in foreign {
        for probe in collected.get(key).unwrap_or(&Vec::new()) {
            if let Some(cause) = probe.cause.as_ref() {
                causes.insert(cause.code.clone());
            }
        }
    }
    if causes.iter().map(String::as_str).collect::<Vec<_>>() == [CAUSE_NAME_WHITELIST] {
        return "к зарубежным адресам проходят только соединения с разрешёнными именами сайтов — \
                с такими именами те же серверы отвечают"
            .to_string();
    }
    if causes.contains(CAUSE_BY_ADDRESS) {
        return "соединение с зарубежными адресами устанавливается, но шифрование не проходит ни с каким именем, \
                даже с разрешённым, — пропускают только разрешённые адреса"
            .to_string();
    }
    "провайдер пропускает только разрешённые адреса".to_string()
}

/// «Не открывается» у контрольного сайта — только когда до него нет дороги.
/// Обрыв после 16 КБ или чужой сертификат — это блокировка, которую лечат
/// иначе, а не «закрыты все зарубежные адреса».
fn no_road(probe: &Probe) -> bool {
    matches!(probe.reach_state, ReachState::IpBlock | ReachState::Dpi)
}

/// python `_control_keys(services)` — (все контрольные, зарубежные, российские) ключи.
fn control_keys(services: &Entries<Service>) -> (Vec<String>, Vec<String>, Vec<String>) {
    let controls: Vec<String> = services
        .iter()
        .filter(|(_key, service)| service.control)
        .map(|(key, _service)| key.clone())
        .collect();
    let foreign: Vec<String> = controls
        .iter()
        .filter(|key| {
            !services
                .get(key)
                .map(|service| service.domestic)
                .unwrap_or_default()
        })
        .cloned()
        .collect();
    let domestic: Vec<String> = controls
        .iter()
        .filter(|key| {
            services
                .get(key)
                .map(|service| service.domestic)
                .unwrap_or_default()
        })
        .cloned()
        .collect();
    (controls, foreign, domestic)
}

/// python `_control_down(collected, key)` — только настоящий провал контрольного
/// сайта: «не успели проверить» (лимит времени) — не «нет интернета», иначе
/// такой прогон спрятал бы найденные блокировки остальных сайтов.
fn control_down(collected: &Entries<Vec<Probe>>, key: &str) -> bool {
    match collected.get(key) {
        Some(probes) => !probes.is_empty() && probes.iter().all(no_road),
        None => false,
    }
}

/// python `_foreign_reachable(reference)` — если хоть один эталонный сервер
/// ответил, зарубежные адреса не закрыты и интернет есть.
fn foreign_reachable(reference: &[ReferenceReport]) -> bool {
    reference.iter().any(|item| item.ok)
}

/// python `whitelist_suspected(...)` — признак «белых списков» по контрольным
/// сайтам: российские открываются, зарубежные нет. Движок по нему решает,
/// звать ли проверку подсетей (`subnet_whitelist`).
pub fn whitelist_suspected(
    services: &Entries<Service>,
    verdicts: &Entries<ServiceVerdict>,
    collected: &Entries<Vec<Probe>>,
    reference: &[ReferenceReport],
) -> bool {
    let (_controls, foreign, domestic) = control_keys(services);
    let foreign_down = !foreign.is_empty()
        && foreign.iter().all(|key| control_down(collected, key))
        && !foreign_reachable(reference);
    let domestic_up = !domestic.is_empty()
        && domestic.iter().all(|key| {
            verdicts
                .get(key)
                .map(|verdict| verdict.level == Level::Ok)
                .unwrap_or_default()
        });
    foreign_down && domestic_up
}

/// python `blocked_references(reference)` — эталонные серверы, которые не
/// ответили ни разу, хотя другие отвечали.
pub fn blocked_references(reference: &[ReferenceReport]) -> Vec<ReferenceReport> {
    let down: Vec<&ReferenceReport> = reference.iter().filter(|item| !item.ok).collect();
    if down.len() < reference.len() {
        down.into_iter().cloned().collect()
    } else {
        Vec::new()
    }
}

/// python `reference_text(item)`.
pub fn reference_text(item: &ReferenceReport) -> String {
    let reason = if item.reason.is_empty() {
        String::new()
    } else {
        format!(": {}", item.reason)
    };
    format!(
        "Шифрованный DNS {} ({}) недоступен{}",
        item.label, item.address, reason
    )
}

#[derive(Debug, Default)]
pub struct CollectOutput {
    pub problems: Vec<Problem>,
    pub working: Vec<String>,
    pub spoofed: Vec<String>,
}

#[allow(clippy::too_many_arguments)]
/// python `collect_problems(...)`.
pub fn collect_problems(
    services: &Entries<Service>,
    verdicts: &Entries<ServiceVerdict>,
    collected: &Entries<Vec<Probe>>,
    voice: Option<&VerdictSays>,
    freeze: Option<&VerdictSays>,
    zapret_running: Option<bool>,
    geo_service_for: Option<&dyn Fn(&str) -> String>,
    reference: &[ReferenceReport],
    ipv6: Option<&Ipv6Verdict>,
    system: &[SystemItem],
    telegram: Option<&TelegramReport>,
    subnets: Option<&SubnetVerdict>,
) -> CollectOutput {
    let mut problems: Vec<Problem> = Vec::new();

    let (controls, foreign, domestic) = control_keys(services);
    let mut whitelisted = whitelist_suspected(services, verdicts, collected, reference);
    if let Some(subnets) = subnets {
        if whitelisted && subnets.code == CODE_REFUTED {
            // Зарубежные сети отвечают: закрыты именно контрольные сайты, а не всё зарубежное.
            whitelisted = false;
        }
    }
    let offline = !controls.is_empty()
        && controls.iter().all(|key| control_down(collected, key))
        && !foreign_reachable(reference);

    let names = foreign
        .iter()
        .map(|key| {
            services
                .get(key)
                .map(|service| service.label.clone())
                .unwrap_or_default()
        })
        .collect::<Vec<_>>()
        .join(", ");
    if whitelisted {
        let confirmed = subnets.is_some()
            && subnets
                .map(|subnets| subnets.code == CODE_CONFIRMED)
                .unwrap_or_default();
        let domestic_labels = domestic
            .iter()
            .map(|key| {
                services
                    .get(key)
                    .map(|service| service.label.clone())
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join(", ");
        let sites = format!(
            "Открываются только российские сайты ({domestic_labels}), а зарубежные контрольные ({names}) — нет."
        );
        let how = whitelist_kind(collected, &foreign);
        let text = match (confirmed, subnets) {
            (true, Some(subnets)) => format!(
                "{sites} Это режим «белых списков»: {}; {how}",
                subnets.text()
            ),
            _ => format!("{sites} Похоже на режим «белых списков»: {how}"),
        };
        problems.push(Problem::new(
            Level::Fail,
            text,
            vec![
                "В таком режиме Zapret не помогает: закрыты сами адреса, а не отдельные сайты. \
                 Обычно это временное ограничение, чаще в мобильных сетях — проверьте другую сеть."
                    .to_string(),
            ],
            "",
            "",
            block_kind::KIND_NETWORK,
            "",
            Vec::new(),
            "",
            SECTION_NETWORK,
        ));
    } else if offline {
        let controls_labels = controls
            .iter()
            .map(|key| {
                services
                    .get(key)
                    .map(|service| service.label.clone())
                    .unwrap_or_default()
            })
            .collect::<Vec<_>>()
            .join(", ");
        problems.push(Problem::new(
            Level::Fail,
            format!(
                "Не открываются даже контрольные сайты ({controls_labels}) — \
                 похоже, нет интернета или всё соединение режет антивирус, прокси или VPN"
            ),
            vec!["Проверьте подключение к интернету и повторите проверку.".to_string()],
            "",
            "",
            block_kind::KIND_NETWORK,
            "",
            Vec::new(),
            "",
            SECTION_NETWORK,
        ));
    }
    // В обоих случаях причина общая и уже названа: совет «подберите стратегию»
    // у каждого сайта был бы неправдой и шумом.
    let offline = offline || whitelisted;

    // Сервисы идут в том же порядке, что и в отчёте: «Открываются: …» не должен
    // начинаться с сайтов, у которых просто подменён DNS. Проблемы по важности
    // сортируются в конце, и внутри одного уровня этот порядок сохраняется.
    let mut working: Vec<String> = Vec::new();
    for (key, service) in services.iter() {
        if service.control {
            continue;
        }
        let Some(verdict) = verdicts.get(key) else {
            continue;
        };
        let empty: Vec<Probe> = Vec::new();
        let probes = collected.get(key).unwrap_or(&empty);
        let hits: Vec<&Probe> = probes
            .iter()
            .filter(|probe| probe.reach_state != ReachState::Ok)
            .collect();
        // Сайт открылся по настоящему адресу, а запись в hosts ведёт на нерабочий: для человека это поломка.
        let stale: Vec<&Probe> = if hits.is_empty() {
            probes.iter().filter(|probe| probe.hosts_stale).collect()
        } else {
            Vec::new()
        };
        // Сайт открылся, но через раз: это тоже повод для строки в итоге, и лечится он как блокировка.
        let shaky: Vec<&Probe> = if hits.is_empty() && stale.is_empty() {
            probes
                .iter()
                .filter(|probe| !probe.unstable.is_empty())
                .collect()
        } else {
            Vec::new()
        };
        // python: broken = broken or stale or shaky.
        let broken: Vec<&Probe> = if !hits.is_empty() {
            hits
        } else if !stale.is_empty() {
            stale.clone()
        } else {
            shaky.clone()
        };
        if (verdict.level == Level::Fail || verdict.level == Level::Warn) && !broken.is_empty() {
            if offline {
                // Без интернета «Zapret не обходит блокировку» у каждого сайта —
                // неправда и шум: причина одна, она уже написана первой строкой.
                continue;
            }
            let mut advice: Vec<String> = verdict
                .advice
                .iter()
                .filter(|item| item.as_str() != ADVICE_DNS)
                .cloned()
                .collect();
            // Стратегия помогает только от DPI и обрыва. При чужом сертификате,
            // недоступном адресе или без адреса кнопка подбора увела бы не туда.
            // Сайт, который не открылся и из-за рубежа, не блокируют — он лежит сам: подбор не поможет.
            let bypass_probe = broken
                .iter()
                .find(|probe| BYPASSABLE.contains(&probe.reach_state) && probe.kind() != KIND_DOWN)
                .copied();
            let mut action: String = if bypass_probe.is_some() {
                zapret_action(zapret_running).to_string()
            } else {
                String::new()
            };
            let mut target: String = bypass_probe
                .map(|probe| probe.host.clone())
                .unwrap_or_else(|| broken[0].host.clone());
            if !stale.is_empty() {
                action = "hosts".to_string();
            }
            if !shaky.is_empty() {
                action = zapret_action(zapret_running).to_string();
            }
            // Гео-сайт сам ограничивает доступ из России: стратегия его не
            // чинит, и совет «подберите стратегию» увёл бы пользователя не туда.
            let geo = broken.iter().find_map(|probe| {
                let name = geo_service_for
                    .map(|call| call(&probe.host))
                    .unwrap_or_else(|| no_geo_service(&probe.host));
                (!name.is_empty()).then(|| (probe.host.clone(), name))
            });
            if let Some((geo_target, geo_service)) = geo {
                target = geo_target;
                advice.insert(0, advice_geo_site(&geo_service));
                advice.retain(|item| !ADVICE_VIA_ZAPRET.contains(&item.as_str()));
                action = "hosts".to_string();
            }
            if action.is_empty() && verdict.kind == KIND_DNS {
                // Адрес сайта не узнать — помогает другой DNS: кнопка ведёт в его настройку.
                action = "dns".to_string();
            }
            if action.is_empty() && key == TELEGRAM_SITE {
                let kind = if verdict.kind.is_empty() {
                    KIND_OTHER.to_string()
                } else {
                    verdict.kind.clone()
                };
                if TELEGRAM_PROXY_KINDS.contains(&kind.as_str()) {
                    // Telegram закрывают по адресу: стратегия тут бессильна, а у программы есть свой прокси.
                    action = "telegram_proxy".to_string();
                }
            }
            let mut causes: Vec<String> = broken
                .iter()
                .filter_map(|probe| probe.cause.as_ref())
                .map(|cause| format!("{}.", sentence(&cause.text)))
                .collect();
            dedup(&mut causes);
            // Чужой сертификат: кто именно ответил вместо сайта и что с этим делать — первым делом.
            let mut shaky_lines: Vec<String> = shaky
                .iter()
                .map(|probe| format!("{}.", sentence(&probe.unstable)))
                .collect();
            dedup(&mut shaky_lines);
            causes.extend(shaky_lines);
            let certs: Vec<&crate::cert_owner::CertVerdict> = broken
                .iter()
                .filter_map(|probe| probe.cert.as_ref())
                .collect();
            let mut cert_lines: Vec<String> = certs
                .iter()
                .map(|cert| format!("{}.", sentence(&cert.text)))
                .collect();
            dedup(&mut cert_lines);
            let mut cert_advice: Vec<String> = certs
                .iter()
                .filter(|cert| !cert.advice.is_empty())
                .map(|cert| cert.advice.clone())
                .collect();
            dedup(&mut cert_advice);
            let causes: Vec<String> = cert_lines.into_iter().chain(causes).collect();
            advice.splice(0..0, cert_advice);
            problems.push(Problem::new(
                verdict.level,
                verdict.headline.clone(),
                causes
                    .iter()
                    .cloned()
                    .chain(advice.iter().cloned())
                    .collect(),
                action,
                target,
                if verdict.kind.is_empty() {
                    KIND_OTHER
                } else {
                    verdict.kind.as_str()
                },
                // Сервис не открывается целиком — в группе хватит названия;
                // «открывается, но не работают картинки» нужно сказать полностью.
                if verdict.level == Level::Fail {
                    service.label.clone()
                } else {
                    String::new()
                },
                causes,
                key,
                SECTION_SERVICES,
            ));
        } else if verdict.level == Level::Unknown {
            if !offline {
                problems.push(Problem::new(
                    Level::Unknown,
                    verdict.headline.clone(),
                    verdict.advice.clone(),
                    "",
                    "",
                    KIND_OTHER,
                    "",
                    Vec::new(),
                    key,
                    SECTION_SERVICES,
                ));
            }
        } else {
            working.push(service.label.clone());
        }
    }

    if let Some(freeze) = freeze {
        if freeze.level == Level::Fail || freeze.level == Level::Warn {
            problems.push(Problem::new(
                freeze.level,
                freeze.headline.clone(),
                freeze.advice.clone(),
                zapret_action(zapret_running),
                "",
                block_kind::KIND_CUT,
                "",
                Vec::new(),
                "",
                SECTION_FREEZE,
            ));
        } else if freeze.level == Level::Unknown && !offline {
            problems.push(Problem::new(
                freeze.level,
                freeze.headline.clone(),
                freeze.advice.clone(),
                "",
                "",
                KIND_OTHER,
                "",
                Vec::new(),
                "",
                "",
            ));
        }
    }
    if let Some(voice) = voice {
        if voice.level != Level::Ok && !offline {
            problems.push(Problem::new(
                voice.level,
                voice.headline.clone(),
                voice.advice.clone(),
                "strategy_voice",
                "",
                block_kind::KIND_VOICE,
                "",
                Vec::new(),
                "",
                SECTION_VOICE,
            ));
        }
    }
    // Один молчащий дата-центр — не проблема для человека: приложение возьмёт другой.
    if let Some(telegram) = telegram {
        if telegram.level == Level::Fail && !offline {
            problems.push(Problem::new(
                telegram.level,
                telegram.headline.clone(),
                telegram.advice.clone(),
                "telegram_proxy",
                "",
                KIND_OTHER,
                "Telegram",
                Vec::new(),
                "",
                SECTION_TELEGRAM,
            ));
        }
    }

    let spoofed = collected
        .iter()
        .flat_map(|(_key, probes)| probes.iter())
        .filter_map(|probe| {
            probe
                .judgement
                .as_ref()
                .filter(|judgement| judgement.state == DnsState::Spoofed)
                .map(|_judgement| probe.host.clone())
        })
        .collect::<Vec<_>>();
    if !spoofed.is_empty() {
        let shown = if spoofed.len() > 5 {
            format!("{}, и ещё {}", spoofed[..5].join(", "), spoofed.len() - 5)
        } else {
            spoofed.join(", ")
        };
        problems.push(Problem::new(
            Level::Warn,
            format!(
                "DNS подменяет ответы для {shown}. Браузер с защищённым DNS этого не замечает, а программы, \
                 которые спрашивают адрес у Windows, эти сайты не откроют"
            ),
            vec![ADVICE_DNS.to_string()],
            "dns",
            "",
            KIND_DNS,
            "",
            Vec::new(),
            "",
            SECTION_DNS,
        ));
    }
    // Сайты, которые QUIC заведомо поддерживают, — контроль: если молчат и они,
    // закрыт весь UDP 443, а не QUIC отдельных сайтов.
    let quic_known = collected
        .iter()
        .flat_map(|(_key, probes)| probes.iter())
        .filter(|probe| QUIC_CONTROL_HOSTS.contains(&probe.host.as_str()))
        .filter(|probe| probe.quic.is_some())
        .collect::<Vec<_>>();
    let quic_answers = collected
        .iter()
        .flat_map(|(_key, probes)| probes.iter())
        .any(|probe| {
            probe
                .quic
                .as_ref()
                .is_some_and(|verdict| verdict.code == QUIC_OK)
        });
    if quic_known.len() >= 2
        && quic_known
            .iter()
            .all(|probe| probe.quic.as_ref().map(|quic| quic.code.as_str()) == Some(QUIC_SILENT))
        && !quic_answers
        && !offline
    {
        let mut known_hosts = quic_known
            .iter()
            .map(|probe| probe.host.as_str())
            .collect::<Vec<_>>();
        known_hosts.sort_unstable();
        problems.push(Problem::new(
            Level::Warn,
            format!(
                "QUIC (UDP 443) не отвечает ни у одного сайта, включая {}, которые его точно поддерживают, — \
                 похоже, UDP 443 закрыт целиком: провайдером, роутером или пресетом Zapret. Сайты открываются \
                 обычным соединением, но браузер сначала пробует QUIC и теряет на этом время",
                known_hosts.join(", ")
            ),
            vec![ADVICE_QUIC.to_string()],
            "",
            "",
            block_kind::KIND_QUIC,
            "",
            Vec::new(),
            "",
            SECTION_QUIC,
        ));
    }

    // QUIC заблокирован, а сам сайт открывается: это не «сайт не работает», но
    // браузер сначала пробует QUIC и переходит на обычное соединение с задержкой.
    let quic_blocked_keys = collected
        .iter()
        .filter(|(_key, probes)| {
            probes.iter().any(|probe| {
                probe
                    .quic
                    .as_ref()
                    .is_some_and(|verdict| verdict.code == QUIC_BLOCKED_BY_NAME)
                    && probe.reach_state == ReachState::Ok
            })
        })
        .map(|(key, _probes)| key.clone())
        .collect::<Vec<_>>();
    let quic_blocked: Vec<String> = quic_blocked_keys
        .iter()
        .map(|key| {
            services
                .get(key)
                .map(|service| service.label.clone())
                .unwrap_or_default()
        })
        .collect();
    if !quic_blocked.is_empty() && !offline {
        let mut text = format!(
            "QUIC (UDP 443) не проходит по имени для: {}. Сайты открываются обычным \
             соединением, но браузер сначала пробует QUIC, поэтому открытие и начало видео могут запаздывать",
            quic_blocked.join(", ")
        );
        if zapret_running == Some(true) {
            text.push_str(". Так режет провайдер, но так же действует и сам Zapret, если в пресете QUIC отключён намеренно");
        }
        problems.push(Problem::new(
            Level::Warn,
            text,
            vec![ADVICE_QUIC.to_string()],
            "",
            "",
            block_kind::KIND_QUIC,
            "",
            Vec::new(),
            quic_blocked_keys[0].clone(),
            SECTION_QUIC,
        ));
    }
    // Неполадки самого компьютера показываются всегда: они объясняют и «нет интернета».
    for item in system {
        let Some(level) = problem_level(&item.level) else {
            continue;
        };
        problems.push(Problem::new(
            level,
            format!("{}: {}", item.title, item.text),
            if item.advice.is_empty() {
                Vec::new()
            } else {
                vec![item.advice.clone()]
            },
            "",
            "",
            block_kind::KIND_SYSTEM,
            "",
            Vec::new(),
            "",
            SECTION_SYSTEM,
        ));
    }
    if let Some(ipv6) = ipv6 {
        if ipv6.code == IPV6_BROKEN && !offline {
            problems.push(Problem::new(
                Level::Warn,
                format!("IPv6 {}", ipv6.text),
                vec![ADVICE_IPV6.to_string()],
                "",
                "",
                block_kind::KIND_NETWORK,
                "",
                Vec::new(),
                "",
                SECTION_IPV6,
            ));
        }
    }
    for item in blocked_references(reference) {
        problems.push(Problem::new(
            Level::Warn,
            reference_text(&item),
            vec![ADVICE_BLOCKED_REFERENCE.to_string()],
            "dns",
            "",
            KIND_DNS,
            "",
            Vec::new(),
            "",
            SECTION_DNS,
        ));
    }
    problems.sort_by_key(|item| level_rank(item.level.value()));
    CollectOutput {
        problems,
        working,
        spoofed,
    }
}

/// python `_TELEGRAM_PROXY_KINDS`.
const TELEGRAM_PROXY_KINDS: [&str; 3] =
    [block_kind::KIND_IP, KIND_OTHER, block_kind::KIND_NO_CONNECT];

fn dedup(values: &mut Vec<String>) {
    let mut seen: std::collections::HashSet<String> = Default::default();
    values.retain(|value| seen.insert(value.clone()));
}

/// python `VerdictSays` — общий вид у freeze и voice (level, headline, advice).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictSays {
    pub level: Level,
    pub headline: String,
    pub advice: Vec<String>,
}

/// python `Entries` — упрощённая замена dict с сохранением порядка,
/// которую дала бы python-структура `services` / `verdicts` / `collected`.
#[derive(Debug, Clone, Default)]
pub struct Entries<T> {
    pub items: Vec<(String, T)>,
}

impl<T> Entries<T> {
    pub fn new(items: Vec<(String, T)>) -> Self {
        Self { items }
    }

    pub fn get(&self, key: &str) -> Option<&T> {
        self.items
            .iter()
            .find_map(|(other, item)| (other == key).then_some(item))
    }

    pub fn iter(&self) -> impl Iterator<Item = &(String, T)> {
        self.items.iter()
    }
}
