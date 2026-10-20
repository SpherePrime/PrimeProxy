//! Порт `src/diagnostics/verdict.py` — выводы диагностики: открывается ли
//! сервис и честен ли DNS.
//!
//! Здесь нет сети — только правила. Движок (`diagnostics::engine`) собирает
//! факты, а этот модуль решает, что они значат.
//!
//! Два вопроса разделены:
//!
//! * **Открывается ли сервис.** Движок подключается к правильному адресу
//!   (из hosts, из DNS системы, если он подлинный, или из эталона
//!   DNS-over-HTTPS) так же, как браузер. Итог по сервису строится только
//!   отсюда: если сайт открывается, красного «❌» быть не должно.
//! * **Честен ли DNS.** Адрес, не похожий на эталон, сам по себе не подмена:
//!   Anycast и CDN отдают разным резолверам разные адреса, а DNS для обхода
//!   блокировок (Comss, Xbox DNS и т. п.) специально возвращает адрес своего
//!   прокси. Решает сертификат по адресу из DNS: настоящий сервер (или честный
//!   прокси) предъявит подлинный сертификат сайта, заглушка провайдера — нет.
//!   Подмена DNS — отдельное предупреждение: браузер с защищённым DNS её
//!   не замечает, а программы Windows — да.

use crate::{
    address_kinds::{address_kind, is_stub_address, AddressKind},
    block_kind::{
        kind_info_or_other, site_kind, KIND_CUT, KIND_DNS, KIND_DOWN, KIND_NO_CONNECT,
        KIND_UNSTABLE,
    },
    limits::{FREEZE_MAX_BYTES, FREEZE_MIN_BYTES},
    probe_result::{
        ProbeResult, KIND_CANCELLED, KIND_CERT, KIND_CONNECT, KIND_OK, KIND_RESET, KIND_TIMEOUT,
        KIND_TLS,
    },
};

/// Статусы Windows DNS (`utils.windows_dns_query`), нужные вердикту.
pub const DNS_STATUS_NAME_ERROR: i64 = 9003;
pub const DNS_STATUS_NO_RECORDS: i64 = 9501;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DnsState {
    Ok,
    Spoofed,
    Local,
    #[default]
    Unknown,
}

impl DnsState {
    pub fn value(self) -> &'static str {
        match self {
            DnsState::Ok => "ok",
            DnsState::Spoofed => "spoofed",
            DnsState::Local => "local",
            DnsState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsJudgement {
    pub state: DnsState,
    pub reason: String,
}

/// Уровень итога по сервису (`diagnostics.verdict.Level`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Fail,
    Unknown,
}

impl Level {
    pub fn value(self) -> &'static str {
        match self {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Fail => "fail",
            Level::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReachState {
    Ok,
    Dpi,
    Freeze,
    IpBlock,
    Cert,
    NoAddress,
    #[default]
    Unknown,
}

impl ReachState {
    pub fn value(self) -> &'static str {
        match self {
            ReachState::Ok => "ok",
            ReachState::Dpi => "dpi",
            ReachState::Freeze => "freeze",
            ReachState::IpBlock => "ip_block",
            ReachState::Cert => "cert",
            ReachState::NoAddress => "no_address",
            ReachState::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TargetOutcome {
    pub host: String,
    pub purpose: String,
    pub reach: String,
    pub dns: DnsState,
    pub main: bool,
    /// Вид блокировки (`diagnostics.block_kind`), если его уточнили пробами.
    /// Пусто — берётся тот, что следует из одного исхода `reach`.
    pub kind: String,
    /// Сам сайт открылся, но адрес, записанный для него в файле hosts, не работает.
    pub hosts_stale: bool,
    /// Сайт открылся, но не каждый раз или не по каждому своему адресу.
    pub unstable: bool,
    /// DNS компьютера адреса не дал вовсе («такого сайта нет»), хотя сайт существует: проверка
    /// дошла до него по адресу из шифрованного DNS, а браузер и программы спросят Windows.
    pub dns_blind: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceVerdict {
    pub level: Level,
    pub headline: String,
    /// Что сделать, по пунктам. Первый пункт — главный.
    pub advice: Vec<String>,
    pub dns_note: String,
    /// Вид блокировки сервиса: по нему экран собирает проблемы в группы.
    pub kind: String,
}

const BROKEN: [&str; 4] = ["dpi", "freeze", "ip_block", "cert"];

const ADVICE_STRATEGY: &str =
    "Подберите другую стратегию: вкладка «Подбор стратегии» найдёт рабочую для вашего провайдера.";
const ADVICE_START: &str = "Запустите Zapret на странице «Управление Zapret 2».";
/// Адрес принимает соединение, но шифрование не проходит ни с каким именем:
/// иногда стратегия справляется, но обещать этого нельзя.
const ADVICE_STRATEGY_OR_ADDRESS: &str = {
    "Попробуйте подобрать стратегию во вкладке «Подбор стратегии». Если ни одна не подойдёт — закрыт сам адрес: \
     поможет DNS-профиль в «Редакторе hosts», другой DNS или VPN."
};
/// Советы «почини через Zapret»: движок убирает их у гео-сайтов, которым Zapret не помогает.
pub const ADVICE_VIA_ZAPRET: [&str; 3] =
    [ADVICE_STRATEGY, ADVICE_START, ADVICE_STRATEGY_OR_ADDRESS];

/// Совет для сервиса, который сам ограничивает доступ из России (каталог hosts).
pub fn advice_geo_site(service: &str) -> String {
    format!(
        "{service} сам ограничивает доступ из России, поэтому стратегия Zapret его не чинит. \
         Включите для него DNS-профиль на странице «Редактор hosts» или смените DNS в разделе «Настройка DNS»."
    )
}

/// Общий текст совета: движок убирает его из строк сайтов и оставляет одну
/// общую строку про DNS, сравнивая именно с этой константой.
pub const ADVICE_DNS: &str = {
    "Включите DNS с шифрованием (DoH) в разделе «Настройка DNS» — провайдер не сможет подменять ответы."
};
const ADVICE_DNS_AS_STR: &str = ADVICE_DNS;
const ADVICE_CERT: &str =
    "Проверьте антивирус (проверку HTTPS-трафика), прокси и VPN: кто-то подменяет сертификаты сайтов.";
const ADVICE_HOSTS: &str = {
    "Удалите или исправьте запись этого сайта в файле hosts (страница «Редактор hosts») — адрес в ней устарел."
};
pub const ADVICE_UNSTABLE: &str = {
    "Так выглядит фильтр, который срабатывает не на каждое соединение, или линия, теряющая пакеты. \
     Повторите проверку через несколько минут: если сайт снова «через раз» — это фильтр."
};
pub const ADVICE_HOSTS_STALE: &str = {
    "Откройте «Редактор hosts», выключите и снова включите этот сервис или выберите для него другой \
     профиль — запишется рабочий адрес. Если сервис вам там не нужен, просто выключите его: сайт \
     откроется по своему настоящему адресу."
};
const ADVICE_IP: &str =
    "Серверы недоступны по адресу. Zapret в таком случае помогает не всегда — попробуйте другой DNS или VPN.";
const ADVICE_NO_CONNECT: &str = {
    "Повторите проверку: соединиться не удалось, но подтверждения, что закрыт сам адрес, нет. \
     Если повторяется — посмотрите записи этого сайта в «Редакторе hosts» и попробуйте другой DNS."
};

const FOREIGN_CERT_EVERYWHERE: &str = {
    "чужой сертификат приходит и по адресу из DNS, и по настоящему адресу сайта — HTTPS подменяет \
     программа на компьютере (антивирус, прокси) или сеть, а DNS тут ни при чём"
};

/// python `_cert_cause(items)` — откуда чужой сервер: из файла hosts, из
/// подменённого DNS или «по пути».
fn cert_cause(items: &[&TargetOutcome]) -> Option<DnsState> {
    let has = |state: DnsState| {
        items
            .iter()
            .any(|item| item.reach == "cert" && item.dns == state)
    };
    if has(DnsState::Local) {
        Some(DnsState::Local)
    } else if has(DnsState::Spoofed) {
        Some(DnsState::Spoofed)
    } else {
        None
    }
}

fn kind_of(item: &TargetOutcome) -> String {
    if item.kind.is_empty() {
        site_kind(&item.reach, "", false)
    } else {
        item.kind.clone()
    }
}

/// Вид блокировки сервиса: у первого сломанного адреса (главный идёт первым).
fn leading_kind(items: &[&TargetOutcome]) -> String {
    items
        .iter()
        .find_map(|item| Some(kind_of(item)).filter(|kind| !kind.is_empty()))
        .unwrap_or_default()
}

fn reason_for(items: &[&TargetOutcome], cert_state: Option<DnsState>) -> String {
    if let Some(first) = items.first() {
        if first.reach == "cert" {
            return match cert_state {
                Some(DnsState::Local) => "запись в файле hosts ведёт на чужой сервер".to_string(),
                Some(DnsState::Spoofed) => "DNS подсовывает адрес чужого сервера".to_string(),
                _ => "вместо настоящего сервера отвечает чужой".to_string(),
            };
        }
    }
    let kind = leading_kind(items);
    if kind.is_empty() {
        "проверка не дала ответа".to_string()
    } else {
        kind_info_or_other(&kind).reason.to_string()
    }
}

fn advice_for(
    states: &[String],
    zapret_running: Option<bool>,
    cert_state: Option<DnsState>,
    kind: &str,
) -> Vec<String> {
    let cert_advice = match cert_state {
        Some(DnsState::Local) => ADVICE_HOSTS,
        Some(DnsState::Spoofed) => ADVICE_DNS_AS_STR,
        _ => ADVICE_CERT,
    };
    if kind == "down" {
        return vec![kind_info_or_other("down").cure.to_string()];
    }
    if states.first().map(|state| state == "cert").unwrap_or(false) {
        return vec![cert_advice.to_string()];
    }
    if states.iter().any(|state| state == "cert") {
        // Чужой сертификат только у побочного адреса: сначала совет по главной причине, потом про него.
        let rest: Vec<String> = states
            .iter()
            .filter(|state| *state != "cert")
            .cloned()
            .collect();
        let mut advice = advice_for(&rest, zapret_running, cert_state, kind);
        advice.push(cert_advice.to_string());
        return advice;
    }
    if states
        .iter()
        .any(|state| state == "dpi" || state == "freeze")
    {
        // Вид блокировки важнее: закрытому адресу «запустите Zapret» обещал бы лишнее.
        if kind == "ip" {
            return vec![ADVICE_STRATEGY_OR_ADDRESS.to_string()];
        }
        // «Не удалось узнать, запущен ли Zapret» — не «не запущен»: запускать не советуем.
        if zapret_running == Some(false) {
            return vec![ADVICE_START.to_string()];
        }
        return vec![ADVICE_STRATEGY.to_string()];
    }
    if states.iter().any(|state| state == "ip_block") {
        return vec![(if kind == "ip" {
            ADVICE_IP
        } else {
            ADVICE_NO_CONNECT
        })
        .to_string()];
    }
    vec!["Повторите проверку через минуту.".to_string()]
}

fn append_dns_advice(mut advice: Vec<String>, spoofed: &[String]) -> Vec<String> {
    if !spoofed.is_empty() && !advice.iter().any(|item| item == ADVICE_DNS) {
        advice.push(ADVICE_DNS.to_string());
    }
    advice
}

/// python `judge_dns(...)` — вердикт по одному домену.
///
/// `system_ips` — ответ DNS-серверов системы (без кэша и hosts),
/// `reference_ips` — эталон по DNS-over-HTTPS, `check_kind` — исход
/// HTTPS-запроса к адресу из hosts или DNS системы (пусто, если запрос
/// не делался: адрес совпал с эталоном). `control_kind` — исход того же запроса
/// к эталонному адресу; его делают, когда по адресу из DNS пришёл чужой
/// сертификат: чужой сертификат и там значит, что HTTPS подменяют на компьютере
/// или в сети (антивирус, прокси), а DNS тут ни при чём.
#[allow(clippy::too_many_arguments)]
pub fn judge_dns(args: JudgeDnsArgs) -> DnsJudgement {
    let JudgeDnsArgs {
        system_ips,
        system_status,
        reference_ips,
        hosts_ips,
        check_kind,
        check_cert_problem,
        nxdomain_count,
        attempts,
        control_kind,
    } = args;
    let foreign_everywhere = check_kind == KIND_CERT && control_kind == KIND_CERT;
    if !hosts_ips.is_empty() {
        let note = format!(
            "адрес задан в файле hosts ({}), программы берут его оттуда, а не у DNS",
            hosts_ips.join(", ")
        );
        if check_kind == KIND_CERT {
            return DnsJudgement {
                state: DnsState::Local,
                reason: format!(
                    "{note}; сервер по этому адресу предъявил чужой сертификат — запись в hosts устарела или неверна"
                ),
            };
        }
        return DnsJudgement {
            state: DnsState::Local,
            reason: note,
        };
    }

    // Провайдер подсовывает «сайта нет» наперегонки с настоящим ответом: иногда
    // первым приходит настоящий. Хоть один такой ответ при существующем сайте —
    // подмена, даже если в остальных попытках адрес пришёл правильный.
    // Хватает и одного раза: исправный DNS-сервер при сбое молчит или отвечает
    // ошибкой сервера, а «такого сайта нет» про существующий сайт сам не скажет.
    if !system_ips.is_empty() && nxdomain_count > 0 && !reference_ips.is_empty() {
        return DnsJudgement {
            state: DnsState::Spoofed,
            reason: format!(
                "DNS отвечает то правильно, то «такого сайта нет» ({nxdomain_count} из {attempts} раз) — \
                 провайдер перехватывает часть запросов"
            ),
        };
    }

    if system_ips.is_empty() {
        if (system_status == DNS_STATUS_NAME_ERROR || system_status == DNS_STATUS_NO_RECORDS)
            && !reference_ips.is_empty()
        {
            return DnsJudgement {
                state: DnsState::Spoofed,
                reason: "DNS отвечает, что такого сайта нет, хотя он существует — сайт заблокирован через DNS"
                    .to_string(),
            };
        }
        // Адреса не пришло ни разу, и первый ответ — молчание или ошибка сервера, но в
        // одной из попыток прозвучало «такого сайта нет». То же правило, что выше:
        // исправный сервер про существующий сайт так не скажет даже один раз.
        if nxdomain_count > 0 && !reference_ips.is_empty() {
            return DnsJudgement {
                state: DnsState::Spoofed,
                reason: format!(
                    "DNS не дал адрес, а в {nxdomain_count} из {attempts} попыток ответил «такого сайта нет», \
                     хотя сайт существует — сайт заблокирован через DNS"
                ),
            };
        }
        return DnsJudgement {
            state: DnsState::Unknown,
            reason: "DNS-сервер не дал адрес, сравнить не с чем".to_string(),
        };
    }

    let fake_ips: Vec<&String> = system_ips
        .iter()
        .filter(|ip| address_kind(ip) == AddressKind::FAKE_IP)
        .collect();
    if !fake_ips.is_empty() {
        return DnsJudgement {
            state: DnsState::Local,
            reason: format!(
                "адрес {} выдал VPN-клиент (режим fake-ip) — это не провайдер",
                fake_ips[0]
            ),
        };
    }

    // Адрес домашней сети возвращают домашние фильтры: роутер с родительским контролем,
    // Pi-hole, AdGuard Home. Это настройка сети человека, а не провайдер. Адрес «никуда»
    // (0.0.0.0, 127.0.0.1) сюда не входит: им отвечают и DNS-серверы провайдеров.
    let home: Vec<&String> = system_ips
        .iter()
        .filter(|ip| address_kind(ip) == AddressKind::LOCAL)
        .collect();
    if !home.is_empty()
        && !system_ips
            .iter()
            .any(|ip| address_kind(ip) == AddressKind::BLOCK_STUB)
    {
        return DnsJudgement {
            state: DnsState::Local,
            reason: format!(
                "DNS вернул адрес домашней сети {} — так отвечают фильтры на роутере или компьютере \
                 (родительский контроль, Pi-hole, AdGuard Home), это не провайдер",
                home[0]
            ),
        };
    }

    let stubs: Vec<&String> = system_ips.iter().filter(|ip| is_stub_address(ip)).collect();
    if !stubs.is_empty() {
        return DnsJudgement {
            state: DnsState::Spoofed,
            reason: format!(
                "DNS вернул адрес-заглушку {} вместо настоящего сервера",
                stubs[0]
            ),
        };
    }

    if !reference_ips.is_empty() && system_ips.iter().any(|ip| reference_ips.contains(ip)) {
        // Кроме настоящего адреса DNS дал и другой. `check_kind` здесь —
        // проверка именно этого другого адреса: чужой сертификат на нём значит,
        // что часть ответов подменена.
        if foreign_everywhere {
            return DnsJudgement {
                state: DnsState::Unknown,
                reason: FOREIGN_CERT_EVERYWHERE.to_string(),
            };
        }
        if check_kind == KIND_CERT {
            let problem = if check_cert_problem.is_empty() {
                "сертификат не прошёл проверку".to_string()
            } else {
                check_cert_problem.clone()
            };
            return DnsJudgement {
                state: DnsState::Spoofed,
                reason: format!(
                    "DNS отвечает то правильным адресом, то адресом чужого сервера ({problem}) — \
                     провайдер перехватывает часть запросов"
                ),
            };
        }
        return DnsJudgement {
            state: DnsState::Ok,
            reason: "адрес совпадает с эталоном".to_string(),
        };
    }

    if check_kind == KIND_OK {
        if !reference_ips.is_empty() {
            return DnsJudgement {
                state: DnsState::Ok,
                reason: (
                    "адрес отличается от эталона, но сервер предъявил подлинный сертификат сайта — \
                     так работают CDN и DNS для обхода блокировок, это не подмена"
                )
                    .to_string(),
            };
        }
        return DnsJudgement {
            state: DnsState::Ok,
            reason: "эталон недоступен, но сервер предъявил подлинный сертификат сайта".to_string(),
        };
    }

    if check_kind == KIND_CERT {
        let problem = if check_cert_problem.is_empty() {
            "сертификат не прошёл проверку".to_string()
        } else {
            check_cert_problem.clone()
        };
        if reference_ips.is_empty() {
            // Сравнить не с чем: чужой сертификат даёт и подмена DNS, и антивирус с проверкой HTTPS.
            return DnsJudgement {
                state: DnsState::Unknown,
                reason: format!(
                    "по адресу из DNS отвечает чужой сервер ({problem}), но эталон недоступен — \
                     подмену DNS доказать нечем: так же выглядит антивирус или прокси, проверяющий HTTPS"
                ),
            };
        }
        if foreign_everywhere {
            return DnsJudgement {
                state: DnsState::Unknown,
                reason: FOREIGN_CERT_EVERYWHERE.to_string(),
            };
        }
        return DnsJudgement {
            state: DnsState::Spoofed,
            reason: format!("по адресу из DNS отвечает чужой сервер: {problem}"),
        };
    }

    DnsJudgement {
        state: DnsState::Unknown,
        reason: (
            "адрес отличается от эталона (у CDN и видеосерверов так бывает), а сертификат проверить \
             не удалось — соединение не установилось"
        )
            .to_string(),
    }
}

/// Аргументы python `judge_dns` — именованный набор.
#[derive(Debug, Clone, Default)]
pub struct JudgeDnsArgs {
    pub system_ips: Vec<String>,
    pub system_status: i64,
    pub reference_ips: Vec<String>,
    pub hosts_ips: Vec<String>,
    pub check_kind: String,
    pub check_cert_problem: String,
    pub nxdomain_count: u32,
    pub attempts: u32,
    pub control_kind: String,
}

/// python `judge_reach(result)` — открывается ли адрес.
pub fn judge_reach(result: Option<&ProbeResult>) -> ReachState {
    let Some(result) = result else {
        return ReachState::NoAddress;
    };
    match result.kind.as_str() {
        KIND_OK => {
            if result.body_cut && (FREEZE_MIN_BYTES..=FREEZE_MAX_BYTES).contains(&result.body_size)
            {
                ReachState::Freeze
            } else {
                ReachState::Ok
            }
        }
        KIND_CERT => ReachState::Cert,
        KIND_CONNECT => ReachState::IpBlock,
        x if x == KIND_TLS || x == KIND_RESET || x == KIND_TIMEOUT => ReachState::Dpi,
        _ => ReachState::Unknown,
    }
}

/// python `describe_reach(result, timeout=0.0)` — короткое объяснение, почему адрес не открылся.
pub fn describe_reach(result: Option<&ProbeResult>, timeout: f64) -> String {
    let state = judge_reach(result);
    let Some(result) = result else {
        return "не удалось узнать адрес сервера".to_string();
    };
    if state == ReachState::NoAddress {
        return "не удалось узнать адрес сервера".to_string();
    }
    if state == ReachState::Freeze {
        return format!(
            "ответ оборвался на {} КБ — так ТСПУ режет соединения с зарубежными серверами",
            result.body_size / 1024
        );
    }
    if state == ReachState::Cert {
        let problem = if result.cert_problem.is_empty() {
            "не прошёл проверку"
        } else {
            &result.cert_problem
        };
        return format!(
            "чужой сертификат ({problem}) — трафик перехватывает антивирус, прокси или провайдер"
        );
    }
    if state == ReachState::IpBlock {
        return "не удалось соединиться с сервером".to_string();
    }
    if result.kind == KIND_TLS {
        return "соединение рвётся при установке шифрования — так обычно режет фильтр провайдера"
            .to_string();
    }
    if result.kind == KIND_RESET {
        return "соединение сброшено — так обычно режет фильтр провайдера".to_string();
    }
    if result.kind == KIND_TIMEOUT {
        return format!(
            "подключение есть, но сервер не ответил за {timeout:.0} с — похоже на блокировку провайдером"
        );
    }
    if result.kind == KIND_CANCELLED {
        return "проверка прервана — не хватило времени или нажата «Стоп»".to_string();
    }
    if result.detail.is_empty() {
        "не удалось выполнить запрос".to_string()
    } else {
        result.detail.clone()
    }
}

/// Итог по сервису: открывается ли он и что делать, если нет.
pub fn summarize_service(
    label: &str,
    targets: &[TargetOutcome],
    zapret_running: Option<bool>,
) -> ServiceVerdict {
    let unknown_verdict = |headline: String| ServiceVerdict {
        level: Level::Unknown,
        headline,
        advice: vec!["Повторите проверку.".to_string()],
        dns_note: String::new(),
        kind: String::new(),
    };
    let main = targets
        .iter()
        .find(|item| item.main)
        .or_else(|| targets.first());
    let Some(main) = main else {
        return unknown_verdict(format!("{label}: проверка не выполнилась"));
    };

    let spoofed: Vec<String> = targets
        .iter()
        .filter(|item| item.dns == DnsState::Spoofed)
        .map(|item| item.host.clone())
        .collect();
    let mut dns_note = String::new();
    if !spoofed.is_empty() {
        dns_note = format!(
            "DNS подменяет адрес {} — провайдер перехватывает обычные DNS-запросы. \
             Браузер с защищённым DNS этого не замечает, а программы, которые спрашивают адрес у Windows, \
             сайт не откроют.",
            spoofed.join(", ")
        );
    }

    let broken = |item: &TargetOutcome| BROKEN.contains(&item.reach.as_str());
    let secondary_broken: Vec<&TargetOutcome> = targets
        .iter()
        .filter(|item| *item != main && broken(item))
        .collect();

    if main.reach == "ok" {
        let mut own_kind = String::new();
        let stale: Vec<String> = targets
            .iter()
            .filter(|item| item.hosts_stale && item.reach == "ok")
            .map(|item| item.host.clone())
            .collect();
        let (level, headline, advice);
        if !stale.is_empty() && secondary_broken.is_empty() {
            // Проверка дошла до сайта по настоящему адресу, а браузер и программы возьмут адрес из
            // hosts и упрутся в нерабочий сервер. «Открывается» было бы неправдой для человека.
            level = Level::Warn;
            headline = format!(
                "{label}: сам сайт доступен, но в файле hosts для него записан нерабочий адрес — \
                 браузер пойдёт на него и сайт не откроет"
            );
            advice = vec![ADVICE_HOSTS_STALE.to_string()];
        } else if secondary_broken.is_empty()
            && targets
                .iter()
                .any(|item| item.unstable && item.reach == "ok")
        {
            // Не «открывается» и не «заблокирован»: третий исход, которого человеку и не хватает,
            // когда сайт то грузится, то нет.
            level = Level::Warn;
            headline = format!("{label} открывается через раз");
            advice = vec![
                (if zapret_running == Some(false) {
                    ADVICE_START
                } else {
                    ADVICE_STRATEGY
                })
                .to_string(),
                ADVICE_UNSTABLE.to_string(),
            ];
            own_kind = KIND_UNSTABLE.to_string();
        } else if secondary_broken.is_empty() && main.dns_blind {
            // «Открывается» было бы неправдой: по адресу из шифрованного DNS сайт доступен,
            // а компьютеру его адрес не называют. Так выглядит «проверка проходит, а в браузере пусто».
            level = Level::Warn;
            headline = format!(
                "{label}: сам сайт доступен, но DNS компьютера отвечает, что такого сайта нет — \
                 браузер без защищённого DNS и программы его не откроют"
            );
            advice = Vec::new();
        } else if secondary_broken.is_empty() {
            level = if spoofed.is_empty() {
                Level::Ok
            } else {
                Level::Warn
            };
            headline = format!("{label} открывается");
            advice = Vec::new();
        } else {
            level = Level::Warn;
            let parts: Vec<&str> = secondary_broken
                .iter()
                .map(|item| item.purpose.as_str())
                .collect();
            let states: Vec<String> = secondary_broken
                .iter()
                .map(|item| item.reach.clone())
                .collect();
            let cause = cert_cause(&secondary_broken);
            headline = format!(
                "{label} открывается, но не работают {}: {}",
                parts.join(", "),
                reason_for(&secondary_broken, cause)
            );
            advice = advice_for(
                &states,
                zapret_running,
                cause,
                &leading_kind(&secondary_broken),
            );
        }
        let advice = append_dns_advice(advice, &spoofed);
        // python: `own_kind or _leading_kind(secondary_broken)`.
        let kind = if own_kind.is_empty() {
            leading_kind(&secondary_broken)
        } else {
            own_kind
        };
        return ServiceVerdict {
            level,
            headline,
            advice,
            dns_note,
            kind,
        };
    }

    if broken(main) {
        let mut broken_items: Vec<&TargetOutcome> = vec![main];
        broken_items.extend(secondary_broken.iter().copied());
        let states: Vec<String> = broken_items.iter().map(|item| item.reach.clone()).collect();
        let cause = cert_cause(&broken_items);
        let kind = leading_kind(&broken_items);
        // При обрыве сайт «открывается» на первые килобайты: честнее сказать, что он не догружается.
        let opens = if kind == KIND_CUT {
            "грузится не до конца"
        } else {
            "не открывается"
        };
        let mut headline = format!("{label} {opens}: {}", reason_for(&broken_items, cause));
        if (main.reach == "dpi" || main.reach == "freeze")
            && zapret_running == Some(true)
            && kind != KIND_DOWN
        {
            headline.push_str(" — Zapret запущен, но эту блокировку не обходит");
        }
        let advice = append_dns_advice(advice_for(&states, zapret_running, cause, &kind), &spoofed);
        // «Причина не ясна» и «не работает сам» — не установленная блокировка: замечание, а не тревога.
        let level = if kind == KIND_NO_CONNECT || kind == KIND_DOWN {
            Level::Warn
        } else {
            Level::Fail
        };
        return ServiceVerdict {
            level,
            headline,
            advice,
            dns_note,
            kind,
        };
    }

    if main.reach == "no_address" {
        // Адреса нет — это дело DNS: такой сайт идёт в группу «DNS» с кнопкой настройки DNS.
        return ServiceVerdict {
            level: Level::Fail,
            headline: format!("{label} не открывается: не удалось узнать адрес сервера"),
            advice: vec![
                "Проверьте подключение к интернету.".to_string(),
                ADVICE_DNS.to_string(),
            ],
            dns_note,
            kind: KIND_DNS.to_string(),
        };
    }
    ServiceVerdict {
        level: Level::Unknown,
        headline: format!("{label}: проверка не дала ответа"),
        advice: vec!["Повторите проверку через минуту.".to_string()],
        dns_note,
        kind: String::new(),
    }
}

impl Level {
    /// python `Level(value)` из строки отчёта.
    #[must_use]
    pub fn from_ascii(value: &str) -> Self {
        match value {
            "ok" => Level::Ok,
            "warn" => Level::Warn,
            "fail" => Level::Fail,
            "unknown" => Level::Unknown,
            _ => Level::Unknown,
        }
    }
}

impl DnsState {
    /// python `DnsState(value)` из строки отчёта.
    #[must_use]
    pub fn from_ascii(value: &str) -> Self {
        match value {
            "ok" => DnsState::Ok,
            "spoofed" => DnsState::Spoofed,
            "local" => DnsState::Local,
            _ => DnsState::Unknown,
        }
    }
}

impl ReachState {
    /// python `ReachState(value)` из строки отчёта.
    #[must_use]
    pub fn from_ascii(value: &str) -> Self {
        match value {
            "ok" => ReachState::Ok,
            "dpi" => ReachState::Dpi,
            "freeze" => ReachState::Freeze,
            "ip_block" => ReachState::IpBlock,
            "cert" => ReachState::Cert,
            "no_address" => ReachState::NoAddress,
            _ => ReachState::Unknown,
        }
    }
}
