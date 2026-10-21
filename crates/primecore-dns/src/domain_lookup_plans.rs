//! Порт `src/dns/domain_lookup_plans.py` — чистые решения вкладки «Проверка
//! домена»: без интерфейса и без сети.
//!
//! Движок (`dns.domain_lookup`) отдаёт данные, а здесь они превращаются в то,
//! что видит человек: строки таблицы, подписи, статус и текстовый отчёт.
//! Вкладка только показывает готовое. Тоны строк — [`crate::info_line`].

use primecore_diagnostics::history;
use primecore_diagnostics::path_trace::{judge_filter, FILTER_FOUND};
use primecore_diagnostics::quic_probe::{QUIC_BLOCKED_BY_NAME, QUIC_OK, QUIC_SILENT};
use primecore_dnswire::{STATUS_EMPTY, STATUS_NXDOMAIN, STATUS_OK, STATUS_REFUSED, STATUS_TIMEOUT};
use serde_json::Value;

use crate::domain_lookup::{
    forged_answers, road_is_the_only_way, road_trouble, windows_blind, DomainLookupReport,
    NeighborSource, PingReport, ResolverAnswer, KIND_DOMAIN, KIND_INVALID, LEVEL_FAIL, LEVEL_OK,
    LEVEL_UNKNOWN, LEVEL_WARN, ROAD_DEAD, SERVER_DOH, SERVER_SYSTEM, SERVER_WINDOWS,
    SOURCE_CERT_DEFAULT, SOURCE_CERT_NAMED, SOURCE_EMPTY, SOURCE_ERROR, SOURCE_HACKERTARGET,
    SOURCE_LIMIT, SOURCE_OK, SOURCE_PTR, SOURCE_SHODAN, SOURCE_SKIPPED, SOURCE_THC,
};
use crate::info_line::InfoLine;
pub use crate::info_line::{TONE_ACCENT, TONE_ERROR, TONE_MUTED, TONE_SUCCESS, TONE_WARNING};

/// python `_SOURCE_TITLES` — подписи источников соседей.
#[must_use]
pub fn source_title(key: &str) -> String {
    match key {
        SOURCE_PTR => "Обратное имя адреса (PTR)",
        SOURCE_CERT_NAMED => "Сертификат сайта — на какие ещё домены он выдан",
        SOURCE_CERT_DEFAULT => "Сертификат адреса без имени сайта — кто здесь «хозяин»",
        SOURCE_THC => "Домены на этом адресе по базе THC (ip.thc.org)",
        SOURCE_HACKERTARGET => "Домены на этом адресе по базе HackerTarget (запасной)",
        SOURCE_SHODAN => "Имена и открытые порты по базе Shodan",
        other => return other.to_string(),
    }
    .to_string()
}

/// python `_PING_ERRORS` — коды пинга словами.
fn ping_error(code: &str) -> Option<&'static str> {
    match code {
        "TIMEOUT" => Some("не отвечает на пинг"),
        "UNSUPPORTED" => Some("пинг доступен только в Windows"),
        "ICMP_OPEN_FAILED" => Some("Windows не дала отправить пинг"),
        "ICMP_1231" => Some("нет связи по IPv6 (у вашего подключения нет IPv6)"),
        "ICMP_11002" => Some("сеть назначения недоступна"),
        "ICMP_11003" => Some("адрес назначения недоступен"),
        "ICMP_11013" => Some("пакет не дошёл: истёк счётчик пересылок (TTL)"),
        _ => None,
    }
}

/// python `AnswerRow` — строка таблицы ответов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnswerRow {
    pub server: String,
    pub address: String,
    pub result: String,
    pub time: String,
    pub level: String,
    pub tooltip: String,
}

/// python `_ms` — время ответа строкой.
#[must_use]
fn ms(value: Option<f64>) -> String {
    match value {
        None => "—".to_string(),
        Some(value) if value < 1.0 => "<1 мс".to_string(),
        Some(value) => format!("{value:.0} мс"),
    }
}

/// python `_server_name` — подпись сервера в таблице.
#[must_use]
fn server_name(answer: &ResolverAnswer) -> String {
    let kind = answer.server.kind.as_str();
    if kind == SERVER_WINDOWS {
        return "Windows (как видят программы)".to_string();
    }
    if kind == SERVER_SYSTEM {
        // Подпись — имя владельца сервера, если он известен; сам адрес показывается рядом.
        let label = if answer.server.label == answer.server.address {
            String::new()
        } else {
            answer.server.label.clone()
        };
        return if label.is_empty() {
            "Системный DNS".to_string()
        } else {
            format!("Системный DNS · {label}")
        };
    }
    answer.server.label.clone()
}

/// python `_answer_text` — что ответил сервер, словами.
#[must_use]
fn answer_text(answer: &ResolverAnswer) -> String {
    let mut text = if answer.status == STATUS_OK {
        answer.addresses().join(", ")
    } else if answer.status == STATUS_NXDOMAIN {
        "такого домена нет".to_string()
    } else if answer.status == STATUS_EMPTY {
        "адресов нет".to_string()
    } else if answer.status == STATUS_TIMEOUT {
        "сервер не ответил".to_string()
    } else if answer.status == STATUS_REFUSED {
        "сервер отказался отвечать".to_string()
    } else if answer.server.kind == SERVER_WINDOWS {
        "не удалось узнать адрес".to_string()
    } else {
        "ошибка запроса".to_string()
    };
    if !answer.note.is_empty() {
        text = format!("{} — {}", text, answer.note);
    }
    text
}

/// python `build_answer_rows` — строки таблицы ответов с подсказками.
#[must_use]
pub fn build_answer_rows(report: &DomainLookupReport) -> Vec<AnswerRow> {
    let mut rows: Vec<AnswerRow> = Vec::new();
    for answer in &report.answers {
        let mut tooltip_lines: Vec<String> = vec![server_name(answer)];
        if !answer.server.address.is_empty() {
            let protocol = if answer.server.kind == SERVER_DOH {
                "шифрованный запрос (DoH)"
            } else {
                "обычный запрос (UDP, порт 53)"
            };
            tooltip_lines.push(format!("Сервер {}, {}", answer.server.address, protocol));
        }
        if !answer.ipv4.is_empty() {
            tooltip_lines.push(format!("IPv4: {}", answer.ipv4.join(", ")));
        }
        if !answer.ipv6.is_empty() {
            tooltip_lines.push(format!("IPv6: {}", answer.ipv6.join(", ")));
        }
        if !answer.cnames.is_empty() {
            tooltip_lines.push(format!("Псевдонимы (CNAME): {}", answer.cnames.join(" → ")));
        }
        if let Some(ttl) = answer.ttl {
            tooltip_lines.push(format!("Ответ считается свежим ещё {ttl} с (TTL)"));
        }
        if !answer.tcp_ipv4.is_empty() {
            tooltip_lines.push(format!(
                "По TCP тот же сервер ответил: {}",
                answer.tcp_ipv4.join(", ")
            ));
        }
        if !answer.note.is_empty() {
            tooltip_lines.push(answer.note.clone());
        }
        rows.push(AnswerRow {
            server: server_name(answer),
            address: if answer.server.address.is_empty() {
                "—".to_string()
            } else {
                answer.server.address.clone()
            },
            result: answer_text(answer),
            time: ms(answer.elapsed_ms),
            level: answer.level.clone(),
            tooltip: tooltip_lines.join("\n"),
        });
    }
    rows
}

/// Обычный DNS (UDP, порт 53) идёт открытым текстом, и ответ на него можно
/// подделать по дороге; шифрованный запрос фильтр прочитать и подменить не
/// может.
pub const DNS_CURE: &str = "Помогает DNS с шифрованием: страница «Настройка DNS».";

/// python `own_dns_trouble` — главная беда с DNS на самом компьютере одной
/// фразой. Пусто — её нет.
///
/// Именно она отвечает на вопрос «проверка сайт открывает, а браузер нет»:
/// проверка берёт адрес по шифрованному каналу, а браузер спрашивает Windows.
#[must_use]
pub fn own_dns_trouble(report: &DomainLookupReport) -> String {
    if windows_blind(&report.answers) {
        return "Windows адрес сайта не получает — браузер и программы его не найдут".to_string();
    }
    if forged_answers(&report.answers)
        .iter()
        .any(|item| item.server.kind == SERVER_SYSTEM)
    {
        return "DNS этого компьютера получает подставной ответ «такого домена нет»".to_string();
    }
    String::new()
}

/// python `road_problem` — беда на дороге программ одной фразой. Пусто — её нет.
///
/// Windows при живом IPv6 ставит первым адрес IPv6, и программы идут на него.
/// Сайт при этом проверяется по IPv4 — и «открывается», хотя программы до него
/// не доходят.
#[must_use]
pub fn road_problem(report: &DomainLookupReport) -> String {
    let kind = road_trouble(report);
    if kind.is_empty() {
        return String::new();
    }
    let what = if kind == ROAD_DEAD {
        "соединение по IPv6 не устанавливается"
    } else {
        "по IPv6 сайт не открывается"
    };
    if road_is_the_only_way(report) {
        return format!("Windows отдаёт программам только адреса IPv6, а {what}");
    }
    format!("Windows первым отдаёт программам адрес IPv6, а {what}")
}

/// python `road_is_fatal` — программам некуда идти: Windows отдаёт одни адреса
/// IPv6, и они не работают.
///
/// Когда рядом есть адрес IPv4, браузер переходит на него сам — это помеха, а
/// не поломка.
#[must_use]
pub fn road_is_fatal(report: &DomainLookupReport) -> bool {
    !road_trouble(report).is_empty() && road_is_the_only_way(report)
}

/// python `road_cure` — что сделать, когда дорога программ не работает.
#[must_use]
pub fn road_cure(report: &DomainLookupReport) -> String {
    let road = report.road.as_ref();
    let service = &report.hosts_service;
    let ip = road.map_or(String::new(), |road| road.ip.to_lowercase());
    if !ip.is_empty() && report.hosts_managed.contains(&ip) {
        return format!(
            "Этот адрес записала программа. Выключите и снова включите тумблер «{service}» на странице \
             «Редактор hosts»: адреса перепроверятся, и останутся те, по которым сайт открывается."
        );
    }
    if !ip.is_empty() && report.hosts_rows.contains(&ip) {
        if !service.is_empty() && !report.hosts_managed.is_empty() {
            return format!(
                "Строка с этим адресом записана в файле hosts не программой и мешает сервису «{service}». Выключите и \
                 снова включите его тумблер на странице «Редактор hosts» — программа уберёт эту строку сама."
            );
        }
        if !service.is_empty() {
            return format!(
                "Строка с этим адресом записана в файле hosts не программой. Включите тумблер «{service}» на странице \
                 «Редактор hosts»: программа запишет рабочие адреса и уберёт эту строку сама."
            );
        }
        return "Строка с этим адресом записана в файле hosts не программой. \
                Удалите её сами: страница «Редактор hosts», раздел «Файл hosts»."
            .to_string();
    }
    if !service.is_empty() {
        return format!(
            "Включите тумблер «{service}» на странице «Редактор hosts»: программа запишет сайту адреса IPv4, \
             и программы пойдут по ним."
        );
    }
    "Помогает отключить IPv6 в свойствах сетевого адаптера Windows или починить его на роутере."
        .to_string()
}

/// python `hosts_advice` — совет включить тумблер «Редактора hosts», когда
/// доказано, что по его адресам сайт открывается. Пусто — совета нет.
#[must_use]
pub fn hosts_advice(report: &DomainLookupReport) -> String {
    let Some(road) = &report.hosts_road else {
        return String::new();
    };
    if road.opens != Some(true) || site_level(report) != "fail" {
        return String::new();
    }
    format!(
        "По адресу из «Редактора hosts» ({}) этот сайт открывается: включите там тумблер «{}».",
        road.ip, report.hosts_service
    )
}

/// python `hosts_try_note` — чем кончилась проба адреса из «Редактора hosts»,
/// когда совета она не дала. Пусто — пробы не было.
///
/// Без этой строки непонятно, пробовала ли проверка тумблер вообще: «не
/// советует» читалось как «не проверяет» (замечание владельца 2026-10-14).
#[must_use]
pub fn hosts_try_note(report: &DomainLookupReport) -> String {
    let Some(road) = &report.hosts_road else {
        return String::new();
    };
    if !hosts_advice(report).is_empty() {
        return String::new();
    }
    let what = if road.tcp.status != "ok" {
        "соединение не установилось"
    } else if road.opens == Some(false) {
        "приветствие с именем сайта тоже оборвали"
    } else {
        "проба ничего не показала"
    };
    format!(
        "Адрес из «Редактора hosts» ({}) тоже проверен — {}. Значит, сейчас дело не в адресе: \
         тумблер «{}» в этот раз не помог бы.",
        road.ip, what, report.hosts_service
    )
}

/// python `build_road_lines` — строки о дороге программ: вывод, что по ней
/// получается и что делать.
#[must_use]
pub fn build_road_lines(report: &DomainLookupReport) -> Vec<InfoLine> {
    let Some(road) = &report.road else {
        return Vec::new();
    };
    let kind = road_trouble(report);
    let mut lines: Vec<InfoLine> = Vec::new();
    if !kind.is_empty() {
        let what = if kind == ROAD_DEAD {
            "соединение с ним не устанавливается (порт 443, две попытки; пинг в этом выводе не участвует)"
        } else {
            "по нему сайт не открывается: соединение есть, но приветствие с именем сайта до сервера не доходит"
        };
        if road_is_the_only_way(report) {
            lines.push(InfoLine::new(
                format!(
                    "Программам некуда идти: Windows отдаёт им только адреса IPv6 (первый — {ip}), а {what}. \
                     По IPv4 сервер отвечает, но Windows этот адрес программам не называет — сайт не откроется ни в \
                     браузере, ни в программах. {cure}",
                    ip = road.ip,
                    what = what,
                    cure = road_cure(report)
                ),
                TONE_ERROR,
            ));
        } else {
            lines.push(InfoLine::new(
                format!(
                    "Программы сначала идут не туда: Windows первым отдаёт им адрес IPv6 {ip}, а {what}. \
                     Браузер обычно сам переходит на IPv4, а другие программы могут долго ждать или не открыть сайт. \
                     {cure}",
                    ip = road.ip,
                    what = what,
                    cure = road_cure(report)
                ),
                TONE_WARNING,
            ));
        }
    }
    let tcp = &road.tcp;
    if tcp.status == "ok" {
        lines.push(InfoLine::new(
            format!(
                "Подключение по IPv6 к порту {} ({}): успешно за {}.",
                tcp.port,
                road.ip,
                ms(tcp.elapsed_ms)
            ),
            TONE_SUCCESS,
        ));
    } else {
        let reason = match tcp.status.as_str() {
            "timeout" => "нет ответа".to_string(),
            "refused" => "порт закрыт".to_string(),
            _ => format!("ошибка — {}", tcp.detail),
        };
        lines.push(InfoLine::new(
            format!(
                "Подключение по IPv6 к порту {} ({}): {}.",
                tcp.port, road.ip, reason
            ),
            TONE_WARNING,
        ));
    }
    for (title, state, text) in &road.lines {
        let tone = match state.as_str() {
            "ok" => TONE_SUCCESS,
            "fail" => TONE_WARNING,
            _ => TONE_MUTED,
        };
        lines.push(InfoLine::new(format!("По IPv6 · {title}: {text}."), tone));
    }
    lines
}

/// python `build_dns_summary` — одна фраза над таблицей: сколько серверов
/// ответило и есть ли что-то подозрительное.
#[must_use]
pub fn build_dns_summary(report: &DomainLookupReport) -> InfoLine {
    let answers = &report.answers;
    if answers.is_empty() {
        return InfoLine::muted("Спрашиваем DNS-серверы…");
    }
    let resolved = answers
        .iter()
        .filter(|item| item.status == STATUS_OK)
        .count();
    let stubs: Vec<&ResolverAnswer> = answers
        .iter()
        .filter(|item| item.level == LEVEL_FAIL)
        .collect();
    let odd: Vec<&ResolverAnswer> = answers
        .iter()
        .filter(|item| item.level == LEVEL_WARN)
        .collect();
    let text = format!("Адрес назвали {resolved} из {} серверов.", answers.len());
    if !stubs.is_empty() {
        let names = stubs
            .iter()
            .take(4)
            .map(|item| server_name(item))
            .collect::<Vec<_>>()
            .join(", ");
        return InfoLine::new(
            format!("{text} Заглушку вместо настоящего адреса вернули: {names}."),
            TONE_ERROR,
        );
    }
    if report.intercepted {
        return InfoLine::new(
            format!(
                "{text} Внимание: обычные DNS-запросы перехватываются по пути (ответил даже несуществующий сервер), \
                 поэтому «разные» серверы — на деле один. Верьте строкам «шифрованный»."
            ),
            TONE_WARNING,
        );
    }
    let forged = forged_answers(answers);
    if !forged.is_empty() {
        let names = forged
            .iter()
            .take(4)
            .map(server_name)
            .collect::<Vec<_>>()
            .join(", ");
        let tail = if forged.iter().any(|item| item.server.kind == SERVER_SYSTEM) {
            format!(" Среди них DNS этого компьютера, поэтому браузер и программы сайт не находят. {DNS_CURE}")
        } else if windows_blind(answers) {
            format!(
                " Windows адрес тоже не получила: браузер и программы сайт не найдут. {DNS_CURE}"
            )
        } else {
            " DNS этого компьютера среди них нет.".to_string()
        };
        return InfoLine::new(
            format!(
                "{text} Вместо настоящего ответа пришёл подставной «такого домена нет» — его присылает фильтр по дороге, \
                 а не сам сервер: {names}.{tail}"
            ),
            TONE_WARNING,
        );
    }
    if windows_blind(answers) {
        return InfoLine::new(
            format!(
                "{text} Windows адрес не получила, хотя серверы его знают: браузер и программы сайт не найдут. {DNS_CURE}"
            ),
            TONE_WARNING,
        );
    }
    if !odd.is_empty() {
        let names = odd
            .iter()
            .take(4)
            .map(|item| server_name(item))
            .collect::<Vec<_>>()
            .join(", ");
        return InfoLine::new(
            format!("{text} Отвечают не как остальные: {names}."),
            TONE_WARNING,
        );
    }
    if resolved == 0 {
        return InfoLine::new(
            format!("{text} Похоже, такого домена не существует."),
            TONE_WARNING,
        );
    }
    InfoLine::new(
        format!("{text} Разные адреса у разных серверов — это нормально для крупных сайтов."),
        TONE_SUCCESS,
    )
}

/// python `_ping_line` — строка пинга.
#[must_use]
fn ping_line(ping: &PingReport, title: &str) -> InfoLine {
    if !ping.supported {
        let reason = ping_error(&ping.error_code).unwrap_or("пинг недоступен");
        return InfoLine::muted(format!("{title} {}: {reason}.", ping.ip));
    }
    if ping.received <= 0 {
        let reason = match ping_error(&ping.error_code) {
            Some(text) => text.to_string(),
            None if !ping.error_code.is_empty() => format!("нет ответа ({})", ping.error_code),
            None => "нет ответа".to_string(),
        };
        return InfoLine::new(
            format!(
                "{title} {}: {reason}. Отправлено {}, получено 0.",
                ping.ip, ping.sent
            ),
            TONE_WARNING,
        );
    }
    let tone = if ping.received == ping.sent {
        TONE_SUCCESS
    } else {
        TONE_WARNING
    };
    let ttl = if ping.ttl.is_some_and(|ttl| ttl != 0) {
        format!(", TTL {}", ping.ttl.expect("ttl есть"))
    } else {
        String::new()
    };
    InfoLine::new(
        format!(
            "{title} {}: отправлено {}, получено {}, потеряно {}%. Время: мин {}, средн {}, макс {}{ttl}.",
            ping.ip,
            ping.sent,
            ping.received,
            ping.lost_percent(),
            ms(ping.min_ms),
            ms(ping.avg_ms),
            ms(ping.max_ms)
        ),
        tone,
    )
}

/// python `FILTER_MARK` — отметка места фильтра в таблице узлов.
pub const FILTER_MARK: &str = "── здесь стоит фильтр ──";

/// python `_QUIC_TONES`.
fn quic_tone(code: &str) -> &'static str {
    match code {
        QUIC_OK => TONE_SUCCESS,
        QUIC_BLOCKED_BY_NAME => TONE_ERROR,
        QUIC_SILENT => TONE_MUTED,
        _ => TONE_MUTED,
    }
}

/// python `_hops_word` — «1 узел», «2 узла», «5 узлов».
#[must_use]
pub fn hops_word(count: usize) -> &'static str {
    let count = count as i64;
    if count % 10 == 1 && count % 100 != 11 {
        return "узел";
    }
    if matches!(count % 10, 2..=4) && ![12, 13, 14].contains(&(count % 100)) {
        return "узла";
    }
    "узлов"
}

/// python `_filter_verdict` — вывод о месте фильтра или None.
#[must_use]
fn filter_verdict(
    report: &DomainLookupReport,
) -> Option<primecore_diagnostics::path_trace::FilterVerdict> {
    let facts = report.filter_facts.as_ref()?;
    judge_filter(facts, report.route.as_ref(), "quic")
}

/// python `build_path_lines` — коротко: сколько узлов до сервера, что с QUIC и
/// где стоит фильтр.
#[must_use]
pub fn build_path_lines(report: &DomainLookupReport) -> Vec<InfoLine> {
    let mut lines: Vec<InfoLine> = Vec::new();
    if let Some(route) = &report.route {
        if route.supported {
            let answered = route
                .hops
                .iter()
                .filter(|hop| !hop.address.is_empty())
                .count();
            if route.reached {
                let count = route.hops.len();
                lines.push(InfoLine::muted(format!(
                    "До сервера {count} {}, ответили {answered}.",
                    hops_word(count)
                )));
            } else if !route.hops.is_empty() {
                let last = route.hops.last().expect("узлы есть");
                lines.push(InfoLine::muted(format!(
                    "Пинг до сервера не дошёл: последний ответивший узел — {}-й ({}). \
                     Многие серверы на пинг не отвечают, это ещё не блокировка.",
                    last.ttl, last.address
                )));
            } else {
                lines.push(InfoLine::new(
                    "Ни один узел по дороге не ответил на пинг.",
                    TONE_WARNING,
                ));
            }
        }
    }
    if let Some(quic) = &report.quic {
        lines.push(InfoLine::new(
            format!("QUIC (UDP 443): {}.", quic.text),
            quic_tone(&quic.code),
        ));
    }
    if let Some(verdict) = filter_verdict(report) {
        let tone = if verdict.code == FILTER_FOUND {
            TONE_ERROR
        } else {
            TONE_MUTED
        };
        let mut chars = verdict.text.chars();
        let upper = match chars.next() {
            Some(first) => format!("{}{}.", first.to_uppercase(), chars.collect::<String>()),
            None => String::new(),
        };
        lines.push(InfoLine::new(upper, tone));
    }
    lines
}

/// python `build_path_text` — таблица узлов; перед узлом, за которым уже
/// работает фильтр, стоит отметка.
#[must_use]
pub fn build_path_text(report: &DomainLookupReport) -> String {
    let Some(route) = &report.route else {
        return String::new();
    };
    if !route.supported || route.hops.is_empty() {
        return String::new();
    }
    let filter_hop = filter_verdict(report)
        .filter(|verdict| verdict.code == FILTER_FOUND)
        .and_then(|verdict| verdict.hop);
    let width = route
        .hops
        .iter()
        .map(|hop| hop.address.len())
        .max()
        .unwrap_or(0)
        .max(1);
    let field = width.max("не ответил".len());
    let mut rows: Vec<String> = Vec::new();
    for hop in &route.hops {
        if filter_hop == Some(hop.ttl) {
            rows.push(format!("    {FILTER_MARK}"));
        }
        let address = if hop.address.is_empty() {
            "не ответил".to_string()
        } else {
            hop.address.clone()
        };
        let time_text = match hop.rtt_ms {
            None => String::new(),
            Some(rtt) if rtt < 1.0 => "< 1 мс".to_string(),
            Some(rtt) => format!("{} мс", rtt.round() as i64),
        };
        rows.push(
            format!(
                "{:>2}  {:<width$}  {}",
                hop.ttl,
                address,
                time_text,
                width = field
            )
            .trim_end()
            .to_string(),
        );
    }
    if let Some(filter_hop) = filter_hop {
        if filter_hop > route.hops.last().expect("узлы есть").ttl {
            rows.push(format!("    {FILTER_MARK}"));
        }
    }
    rows.join("\n")
}

/// python `build_ping_lines` — строки пинга и соединения.
#[must_use]
pub fn build_ping_lines(report: &DomainLookupReport) -> Vec<InfoLine> {
    if report.primary_ip.is_empty() {
        if report.kind == KIND_DOMAIN && report.finished {
            return vec![InfoLine::new(
                "Пинговать нечего: ни один DNS-сервер не назвал адрес.",
                TONE_WARNING,
            )];
        }
        return Vec::new();
    }
    let mut lines: Vec<InfoLine> = Vec::new();
    match &report.ping {
        Some(ping) => lines.push(ping_line(ping, "Пинг")),
        None => lines.push(InfoLine::muted(format!(
            "Пинг {}: проверяем…",
            report.primary_ip
        ))),
    }
    if let Some(ping6) = &report.ping6 {
        lines.push(ping_line(ping6, "Пинг по IPv6"));
    }
    match &report.tcp {
        None => lines.push(InfoLine::muted(format!(
            "Подключение к порту 443 ({}): проверяем…",
            report.primary_ip
        ))),
        Some(tcp) if tcp.status == "ok" => lines.push(InfoLine::new(
            format!(
                "Подключение к порту {} (HTTPS): успешно за {}.",
                tcp.port,
                ms(tcp.elapsed_ms)
            ),
            TONE_SUCCESS,
        )),
        Some(tcp) if tcp.status == "refused" => lines.push(InfoLine::new(
            format!(
                "Подключение к порту {} (HTTPS): порт закрыт — сайта на этом адресе нет.",
                tcp.port
            ),
            TONE_WARNING,
        )),
        Some(tcp) if tcp.status == "timeout" => lines.push(InfoLine::new(
            format!("Подключение к порту {} (HTTPS): нет ответа.", tcp.port),
            TONE_WARNING,
        )),
        Some(tcp) => lines.push(InfoLine::new(
            format!(
                "Подключение к порту {} (HTTPS): ошибка — {}.",
                tcp.port, tcp.detail
            ),
            TONE_WARNING,
        )),
    }

    if let (Some(ping), Some(tcp)) = (&report.ping, &report.tcp) {
        if ping.supported && ping.received == 0 && tcp.status == "ok" {
            lines.push(InfoLine::muted(
                "Сервер просто не отвечает на пинг, но сам работает — это обычное дело."
                    .to_string(),
            ));
        }
    }
    let road = build_road_lines(report);
    // Вывод о дороге программ — первой строкой: он объясняет, почему «всё отвечает», а сайт не открывается.
    let head = if road_trouble(report).is_empty() {
        0
    } else {
        1
    };
    let mut result: Vec<InfoLine> = road.iter().take(head).cloned().collect();
    result.extend(lines);
    result.extend(road.into_iter().skip(head));
    result
}

/// python `build_network_lines` — владелец сети и её подробности.
#[must_use]
pub fn build_network_lines(report: &DomainLookupReport) -> Vec<InfoLine> {
    if report.primary_ip.is_empty() {
        return Vec::new();
    }
    let Some(network) = &report.network else {
        return Vec::new();
    };
    let mut lines: Vec<InfoLine> = Vec::new();
    let owners: Vec<String> = network
        .origins
        .iter()
        .map(|(asn, holder)| format!("AS{asn} {holder}").trim().to_string())
        .collect();
    if owners.len() > 1 {
        lines.push(InfoLine::new(
            format!(
                "Владельцы сети (адрес объявляют несколько сетей): {}",
                owners.join("; ")
            ),
            TONE_ACCENT,
        ));
    } else if !network.owner.is_empty() || !owners.is_empty() {
        lines.push(InfoLine::new(
            format!(
                "Владелец сети: {}",
                if network.owner.is_empty() {
                    owners[0].clone()
                } else {
                    network.owner.clone()
                }
            ),
            TONE_ACCENT,
        ));
    }
    let mut details: Vec<String> = Vec::new();
    if !network.asn.is_empty() {
        details.push(format!("ASN: AS{}", network.asn));
    }
    if !network.prefix.is_empty() {
        details.push(format!("подсеть: {}", network.prefix));
    }
    if !network.country.is_empty() {
        details.push(format!("страна: {}", network.country));
    }
    if !details.is_empty() {
        lines.push(InfoLine::muted(details.join(", ")));
    }
    lines
}

/// python `_source_state` — состояние источника соседей словами.
#[must_use]
fn source_state(source: &NeighborSource) -> String {
    if source.status == SOURCE_OK {
        if source
            .total
            .is_some_and(|total| total > source.names.len() as i64)
        {
            return format!(
                "показано {} из {}",
                source.names.len(),
                source.total.expect("total есть")
            );
        }
        if source.names.is_empty() {
            return "имён не найдено".to_string();
        }
        return format!("найдено: {}", source.names.len());
    }
    if source.status == SOURCE_EMPTY {
        return "ничего не найдено".to_string();
    }
    if source.status == SOURCE_LIMIT {
        return if source.detail.is_empty() {
            "лимит запросов исчерпан".to_string()
        } else {
            format!("лимит: {}", source.detail)
        };
    }
    if source.status == SOURCE_SKIPPED {
        return if source.detail.is_empty() {
            "пропущено".to_string()
        } else {
            format!("пропущено: {}", source.detail)
        };
    }
    if source.status == SOURCE_ERROR {
        return if source.detail.is_empty() {
            "не получилось".to_string()
        } else {
            format!("не получилось: {}", source.detail)
        };
    }
    source.status.clone()
}

/// python `Row` — строка для экрана: состояние (ok / warn / fail / info /
/// unknown), подпись и значение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub state: String,
    pub name: String,
    pub text: String,
}

impl Row {
    #[must_use]
    pub fn new(state: &str, name: impl Into<String>) -> Self {
        Self {
            state: state.to_string(),
            name: name.into(),
            text: String::new(),
        }
    }

    #[must_use]
    pub fn with_text(state: &str, name: impl Into<String>, text: impl Into<String>) -> Self {
        Self {
            state: state.to_string(),
            name: name.into(),
            text: text.into(),
        }
    }
}

/// python `RowGroup` — группа строк с заголовком.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowGroup {
    pub title: String,
    pub rows: Vec<Row>,
}

/// python `_LEVEL_STATES` — уровень ответа → состояние строки.
fn level_state(level: &str) -> &'static str {
    match level {
        LEVEL_OK => "ok",
        LEVEL_WARN => "warn",
        LEVEL_FAIL => "fail",
        LEVEL_UNKNOWN => "unknown",
        _ => "info",
    }
}

/// python `build_path_rows` — узлы дороги строками; перед узлом, за которым
/// уже работает фильтр, стоит отметка.
#[must_use]
pub fn build_path_rows(report: &DomainLookupReport) -> Vec<Row> {
    let Some(route) = &report.route else {
        return Vec::new();
    };
    if !route.supported || route.hops.is_empty() {
        return Vec::new();
    }
    let filter_hop = filter_verdict(report)
        .filter(|verdict| verdict.code == FILTER_FOUND)
        .and_then(|verdict| verdict.hop);
    let mut rows: Vec<Row> = Vec::new();
    for (index, hop) in route.hops.iter().enumerate() {
        if filter_hop == Some(hop.ttl) {
            rows.push(Row::new("fail", FILTER_MARK));
        }
        let time_text = match hop.rtt_ms {
            None => String::new(),
            Some(rtt) if rtt < 1.0 => "< 1 мс".to_string(),
            Some(rtt) => format!("{} мс", rtt.round() as i64),
        };
        let last = route.reached && index + 1 == route.hops.len();
        let parts: Vec<&str> = [
            if hop.address.is_empty() {
                "не ответил"
            } else {
                hop.address.as_str()
            },
            time_text.as_str(),
            if last { "сам сервер" } else { "" },
        ]
        .iter()
        .filter(|part| !part.is_empty())
        .copied()
        .collect();
        rows.push(Row::with_text(
            "info",
            format!("Узел {}", hop.ttl),
            parts.join(" · "),
        ));
    }
    if let Some(filter_hop) = filter_hop {
        if filter_hop > route.hops.last().expect("узлы есть").ttl {
            rows.push(Row::new("fail", FILTER_MARK));
        }
    }
    rows
}

/// python `build_answer_groups` — ответы DNS-серверов одной группой: сервер,
/// что ответил и за сколько.
#[must_use]
pub fn build_answer_groups(report: &DomainLookupReport) -> Vec<RowGroup> {
    let rows: Vec<Row> = build_answer_rows(report)
        .into_iter()
        .map(|row| {
            let name = if row.address.is_empty() || row.address == "—" {
                row.server.clone()
            } else {
                format!("{} · {}", row.server, row.address)
            };
            let text = [row.result.as_str(), row.time.as_str()]
                .iter()
                .filter(|part| !part.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join(" · ");
            Row::with_text(level_state(&row.level), name, text)
        })
        .collect();
    if rows.is_empty() {
        return Vec::new();
    }
    vec![RowGroup {
        title: "Что отвечают DNS-серверы".to_string(),
        rows,
    }]
}

/// На экране каждая строка — отдельный виджет: сотни имён делали бы вкладку
/// тяжёлой. Полный список остаётся в отчёте.
pub const NEIGHBOR_ROWS_LIMIT: usize = 40;

/// python `build_neighbor_groups` — «кто ещё на этом адресе»: по группе на
/// источник.
#[must_use]
pub fn build_neighbor_groups(report: &DomainLookupReport, limit: usize) -> Vec<RowGroup> {
    if report.primary_ip.is_empty() {
        return Vec::new();
    }
    let mut groups: Vec<RowGroup> = Vec::new();
    for source in &report.sources {
        let state = if source.status == SOURCE_OK {
            "info"
        } else {
            "unknown"
        };
        let mut rows = vec![Row::new(state, capital_first(&source_state(source)))];
        if !source.extra.is_empty() {
            rows.push(Row::new("info", source.extra.clone()));
        }
        rows.extend(
            source
                .names
                .iter()
                .take(limit)
                .map(|name| Row::new("info", name.clone())),
        );
        if source.names.len() > limit {
            rows.push(Row::new(
                "unknown",
                format!(
                    "… и ещё {} — полный список в отчёте (кнопка «Отчёт»)",
                    source.names.len() - limit
                ),
            ));
        }
        groups.push(RowGroup {
            title: source_title(&source.key),
            rows,
        });
    }
    groups
}

/// python `_capital_first`.
#[must_use]
pub fn capital_first(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// python `count_neighbors` — сколько разных доменов нашли все источники.
#[must_use]
pub fn count_neighbors(report: &DomainLookupReport) -> usize {
    let mut names: Vec<String> = Vec::new();
    for source in &report.sources {
        for name in &source.names {
            if !names.contains(name) {
                names.push(name.clone());
            }
        }
    }
    names.len()
}

/// python: запись сайта отчёта или пустой словарь.
fn site(report: &DomainLookupReport) -> Value {
    report.site.clone().unwrap_or(Value::Null)
}

/// python `str(site.get("level") or "")`.
fn site_level(report: &DomainLookupReport) -> String {
    site(report)
        .get("level")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// python `str(site.get("headline") or "")`.
fn site_headline(report: &DomainLookupReport) -> String {
    site(report)
        .get("headline")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// python `build_status` — строка состояния вкладки.
#[must_use]
pub fn build_status(report: &DomainLookupReport) -> InfoLine {
    if report.kind == KIND_INVALID {
        return InfoLine::new(report.error.clone(), TONE_ERROR);
    }
    if !report.finished {
        return InfoLine::new(format!("Проверяем {}…", report.target), TONE_ACCENT);
    }
    let seconds = format!("{:.1} с", report.elapsed_s);
    if report.stopped {
        return InfoLine::new(
            format!("Остановлено. Показано то, что успели узнать ({seconds})."),
            TONE_WARNING,
        );
    }
    if report.timed_out {
        return InfoLine::new(
            format!("Часть проверок не успела закончиться за отведённое время ({seconds})."),
            TONE_WARNING,
        );
    }
    if report.primary_ip.is_empty() {
        return InfoLine::new(
            format!("Готово за {seconds}: адрес узнать не удалось."),
            TONE_WARNING,
        );
    }
    // Строка итога называет главное: «адрес и число доменов» при закрытом сайте читалось как «всё хорошо».
    if site_level(report) == "fail" {
        let site_value = site(report);
        let headline = site_value
            .get("headline")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if !headline.is_empty() {
            let advice = hosts_advice(report);
            let tail = if advice.is_empty() {
                String::new()
            } else {
                format!(" {advice}")
            };
            return InfoLine::new(
                format!("Готово за {seconds}. {headline}.{tail}"),
                TONE_ERROR,
            );
        }
    }
    let road = road_problem(report);
    if !road.is_empty() {
        let tone = if road_is_fatal(report) {
            TONE_ERROR
        } else {
            TONE_WARNING
        };
        return InfoLine::new(
            format!("Готово за {seconds}. {road} (карточка «Пинг и сеть»)."),
            tone,
        );
    }
    let trouble = own_dns_trouble(report);
    if !trouble.is_empty() {
        return InfoLine::new(
            format!("Готово за {seconds}. {trouble} (карточка «Адреса с разных DNS-серверов»)."),
            TONE_WARNING,
        );
    }
    InfoLine::new(
        format!(
            "Готово за {seconds}: адрес {}, доменов найдено: {}.",
            report.primary_ip,
            count_neighbors(report)
        ),
        TONE_SUCCESS,
    )
}

/// python `build_history_entry` — запись для истории вкладки. None — проверку
/// прервали или цель не разобрана.
#[must_use]
pub fn build_history_entry(report: &DomainLookupReport) -> Option<Value> {
    if report.kind == KIND_INVALID || !report.finished || report.stopped {
        return None;
    }
    let mut problems: Vec<String> = build_answer_rows(report)
        .into_iter()
        .filter(|row| row.level == LEVEL_FAIL)
        .map(|row| format!("{}: {}", row.server, row.result))
        .collect();
    let verdict = filter_verdict(report);
    if let Some(verdict) = &verdict {
        if verdict.code == FILTER_FOUND {
            problems.push(capital_first(&verdict.text));
        }
    }
    // Сайт не открывается или открывается с оговорками — это главное, что нашла проверка.
    let site_level = site_level(report);
    let mut hard = !problems.is_empty() || site_level == "fail";
    let headline = site_headline(report);
    if (site_level == "fail" || site_level == "warn") && !headline.is_empty() {
        problems.insert(0, headline.clone());
    }
    let trouble = own_dns_trouble(report);
    if !trouble.is_empty() {
        // Сайт сам доступен, а компьютер его не находит: в истории первой строкой нужна причина,
        // а не «открывается». Закрытый сайт остаётся первым — это важнее.
        let at = if site_level == "fail" { 1 } else { 0 };
        problems.insert(at, format!("{}: {}", report.target, trouble));
    }
    let road = road_problem(report);
    if !road.is_empty() {
        // Сайт сам доступен, а программы до него не доходят: в истории это беда, а не «открывается».
        let at = if site_level == "fail" { 1 } else { 0 };
        problems.insert(
            at,
            format!("{}: {}. {}", report.target, road, road_cure(report)),
        );
        hard = hard || road_is_fatal(report);
    }
    let advice = hosts_advice(report);
    if !advice.is_empty() {
        problems.push(advice);
    }
    let level = if hard {
        "fail"
    } else if !problems.is_empty() || report.primary_ip.is_empty() || report.timed_out {
        "warn"
    } else if site_level == "unknown" {
        // Открывается ли сайт, проверка не узнала: это «не узнали», а не «всё хорошо».
        "unknown"
    } else {
        "ok"
    };
    let headline_text = if problems.is_empty() {
        build_status(report).text
    } else {
        problems[0].clone()
    };
    let refs: Vec<&str> = problems.iter().map(String::as_str).collect();
    Some(history::domain_entry(
        &report.target,
        level,
        &headline_text,
        &refs,
        None,
    ))
}

/// python `build_site_lines` — раздел текстового отчёта «как открывается
/// сайт»: те же пробы, что в BlockCheck.
#[must_use]
pub fn build_site_lines(report: &DomainLookupReport) -> Vec<String> {
    let Some(site) = &report.site else {
        return Vec::new();
    };
    if site.as_object().is_none_or(|map| map.is_empty()) {
        return Vec::new();
    }
    let empty_rows: Vec<Value> = Vec::new();
    let mut lines: Vec<String> = vec![
        String::new(),
        "=== Как открывается сайт ===".to_string(),
        site.get("headline")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
    ];
    for target in site
        .get("targets")
        .and_then(Value::as_array)
        .unwrap_or(&empty_rows)
    {
        lines.push(format!(
            "{}: {}",
            target.get("host").and_then(Value::as_str).unwrap_or(""),
            target.get("text").and_then(Value::as_str).unwrap_or("")
        ));
        for item in target
            .get("protocols")
            .and_then(Value::as_array)
            .unwrap_or(&empty_rows)
        {
            lines.push(format!(
                "    {}: {}",
                item.get("title").and_then(Value::as_str).unwrap_or(""),
                item.get("text").and_then(Value::as_str).unwrap_or("")
            ));
        }
        for (title, key) in [
            ("Как блокируют", "cause_text"),
            ("QUIC (UDP 443)", "quic_text"),
            ("DNS", "dns_reason"),
        ] {
            if let Some(text) = target.get(key).and_then(Value::as_str) {
                if !text.is_empty() {
                    lines.push(format!("    {title}: {text}"));
                }
            }
        }
        if let Some(listed) = target
            .get("registry")
            .and_then(|registry| registry.get("listed"))
            .and_then(Value::as_bool)
        {
            if listed {
                lines.push("    Реестр РКН: сайт в реестре".to_string());
            }
        }
    }
    if let Some(names) = site.get("names") {
        let items = names.get("items").and_then(Value::as_array);
        if items.is_some_and(|items| !items.is_empty()) {
            lines.push(format!(
                "Поток по имени: {}",
                names.get("headline").and_then(Value::as_str).unwrap_or("")
            ));
            lines.push(format!(
                "    контроль {} под своим именем: {}",
                names.get("server").and_then(Value::as_str).unwrap_or(""),
                names.get("control").and_then(Value::as_str).unwrap_or("")
            ));
            for item in items.expect("items есть") {
                lines.push(format!(
                    "    {}: {}",
                    item.get("host").and_then(Value::as_str).unwrap_or(""),
                    item.get("text").and_then(Value::as_str).unwrap_or("")
                ));
            }
        }
    }
    let advice = hosts_advice(report);
    if !advice.is_empty() {
        lines.push(format!("Что поможет: {advice}"));
    }
    let note = hosts_try_note(report);
    if !note.is_empty() {
        lines.push(note.clone());
        if let Some(road) = &report.hosts_road {
            for (title, _state, text) in &road.lines {
                lines.push(format!("    {title}: {text}"));
            }
        }
    }
    lines
}

/// python `build_text_report` — полный текстовый отчёт: для окна «Отчёт»,
/// копирования и поддержки.
#[must_use]
pub fn build_text_report(report: &DomainLookupReport) -> String {
    let mut lines: Vec<String> = vec![format!("Проверка: {}", report.target)];
    if report.kind == KIND_INVALID {
        lines.push(report.error.clone());
        return lines.join("\n");
    }
    lines.push(build_status(report).text);

    if report.kind == KIND_DOMAIN {
        lines.push(String::new());
        lines.push("=== Адреса с разных DNS ===".to_string());
        lines.push(build_dns_summary(report).text);
        // Строки идут в том же порядке, что и ответы: одна строка на сервер.
        for (row, answer) in build_answer_rows(report)
            .into_iter()
            .zip(report.answers.iter())
        {
            let ttl = answer
                .ttl
                .map(|ttl| format!(", TTL {ttl} с"))
                .unwrap_or_default();
            lines.push(format!(
                "{} [{}] ({}{}): {}",
                row.server, row.address, row.time, ttl, row.result
            ));
            if !answer.cnames.is_empty() {
                lines.push(format!("    CNAME: {}", answer.cnames.join(" → ")));
            }
        }
    }

    lines.extend(build_site_lines(report));

    let ping_lines = build_ping_lines(report);
    if !ping_lines.is_empty() {
        lines.push(String::new());
        lines.push("=== Пинг ===".to_string());
        lines.extend(ping_lines.into_iter().map(|line| line.text));
    }
    let path_lines = build_path_lines(report);
    if !path_lines.is_empty() {
        lines.push(String::new());
        lines.push("=== Путь до сервера ===".to_string());
        lines.extend(path_lines.into_iter().map(|line| line.text));
        let path_text = build_path_text(report);
        if !path_text.is_empty() {
            lines.push(path_text);
        }
    }

    let network_lines = build_network_lines(report);
    if !network_lines.is_empty() {
        lines.push(String::new());
        lines.push(format!("=== Сеть адреса {} ===", report.primary_ip));
        lines.extend(network_lines.into_iter().map(|line| line.text));
    }

    if !report.sources.is_empty() {
        lines.push(String::new());
        lines.push(format!("=== Кто ещё на адресе {} ===", report.primary_ip));
        for source in &report.sources {
            lines.push(format!(
                "{} — {}",
                source_title(&source.key),
                source_state(source)
            ));
            if !source.extra.is_empty() {
                lines.push(format!("    {}", source.extra));
            }
            for name in &source.names {
                lines.push(format!("    {name}"));
            }
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_lookup::{
        annotate_answers, DnsServer, HostsHelp, PingReport, ProgramRoad, TcpReport, LEVEL_FAIL,
        LEVEL_WARN,
    };
    use crate::domain_lookup_steps::test_fixtures as fx;
    use primecore_diagnostics::icmp::{HOP_ROUTER, HOP_SILENT, HOP_TARGET};
    use primecore_diagnostics::path_trace::{FilterFacts, Hop, RouteTrace};
    use primecore_diagnostics::quic_probe::{QuicVerdict, QUIC_BLOCKED_BY_NAME, QUIC_OK};
    use primecore_dnswire::{STATUS_NXDOMAIN, STATUS_OK, STATUS_TIMEOUT};
    use serde_json::json;

    const V6: &str = "2a00:1450:4010:c08::88";
    const V4: &str = "93.184.216.34";

    fn site_report(site: Option<Value>) -> DomainLookupReport {
        // python `_youtube_report`: фильтр отвечает «домена нет» вместо 8.8.8.8,
        // Windows верит и адрес не получает.
        let answers = annotate_answers(vec![
            crate::domain_lookup::ResolverAnswer {
                server: DnsServer::with_kind("Windows", "", SERVER_WINDOWS),
                status: STATUS_NXDOMAIN.to_string(),
                elapsed_ms: Some(8.0),
                ..Default::default()
            },
            crate::domain_lookup::ResolverAnswer {
                server: DnsServer::with_kind("Google", "8.8.8.8", SERVER_SYSTEM),
                status: STATUS_NXDOMAIN.to_string(),
                forged: true,
                elapsed_ms: Some(6.0),
                ..Default::default()
            },
            crate::domain_lookup::ResolverAnswer {
                server: DnsServer::with_kind("Google", "8.8.4.4", SERVER_SYSTEM),
                status: STATUS_OK.to_string(),
                ipv4: vec!["64.233.165.93".to_string()],
                ..Default::default()
            },
            crate::domain_lookup::ResolverAnswer {
                server: DnsServer::with_kind("Google (шифрованный)", "8.8.8.8", SERVER_DOH),
                status: STATUS_OK.to_string(),
                ipv4: vec!["64.233.165.190".to_string()],
                ..Default::default()
            },
        ]);
        DomainLookupReport {
            target: "youtube.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            primary_ip: crate::domain_lookup::pick_primary_ip(&answers),
            answers,
            site,
            finished: true,
            elapsed_s: 10.1,
            ..DomainLookupReport::default()
        }
    }

    #[test]
    fn rows_and_summary_point_at_the_stub() {
        // python `_report()` прогоном заменён на собранный вручную отчёт.
        let answers = annotate_answers(vec![
            crate::domain_lookup::ResolverAnswer {
                server: DnsServer::with_kind("Windows", "", SERVER_WINDOWS),
                status: STATUS_OK.to_string(),
                ipv4: vec![V4.to_string()],
                elapsed_ms: Some(10.0),
                ..Default::default()
            },
            fx::answer_with_ipv4(&fx::secure(), &["93.184.216.34"]),
            fx::answer_with_ipv4(&fx::good(), &["93.184.216.34"]),
            fx::answer_with_ipv4(&fx::stub(), &["195.82.146.214"]),
            crate::domain_lookup::ResolverAnswer {
                server: fx::dead(),
                status: STATUS_TIMEOUT.to_string(),
                ..Default::default()
            },
        ]);
        let report = DomainLookupReport {
            target: "example.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            primary_ip: V4.to_string(),
            answers,
            finished: true,
            ..DomainLookupReport::default()
        };

        let rows: std::collections::HashMap<String, AnswerRow> = build_answer_rows(&report)
            .into_iter()
            .map(|row| (row.server.clone(), row))
            .collect();
        let summary = build_dns_summary(&report);

        assert!(rows["Системный DNS · Провайдер"]
            .result
            .contains("заглушка (Ростелеком)"));
        assert_eq!(rows["Системный DNS · Провайдер"].level, LEVEL_FAIL);
        assert_eq!(rows["Молчун"].result, "сервер не ответил");
        assert!(rows["Шифрованный"].tooltip.contains("шифрованный запрос"));
        assert_eq!(rows["Windows (как видят программы)"].address, "—");
        assert_eq!(summary.tone, TONE_ERROR);
        assert!(summary.text.contains("4 из 5"), "{}", summary.text);
    }

    #[test]
    fn forged_denial_from_own_dns_is_named_with_the_cure() {
        let report = site_report(None);

        let summary = build_dns_summary(&report);
        let rows: std::collections::HashMap<(String, String), AnswerRow> =
            build_answer_rows(&report)
                .into_iter()
                .map(|row| ((row.server.clone(), row.address.clone()), row))
                .collect();

        assert_eq!(report.primary_ip, "64.233.165.93");
        assert_eq!(summary.tone, TONE_WARNING);
        assert!(
            summary.text.contains("подставной «такого домена нет»"),
            "{}",
            summary.text
        );
        assert!(summary.text.contains("Системный DNS · Google"));
        assert!(summary.text.contains("DNS этого компьютера"));
        assert!(summary.text.contains("«Настройка DNS»"));
        let forged = &rows[&("Системный DNS · Google".to_string(), "8.8.8.8".to_string())];
        assert!(forged.result.contains(crate::domain_lookup::NOTE_FORGED));
        let windows = &rows[&("Windows (как видят программы)".to_string(), "—".to_string())];
        assert_eq!(windows.level, LEVEL_WARN);
        assert!(
            windows
                .result
                .contains("браузер и программы сайт не найдут"),
            "{}",
            windows.result
        );
    }

    #[test]
    fn status_and_history_name_the_dns_trouble_instead_of_all_is_well() {
        let report = site_report(Some(
            json!({"level": "warn", "headline": "youtube.com открывается"}),
        ));

        let status = build_status(&report);
        let entry = build_history_entry(&report).expect("запись");

        assert_eq!(status.tone, TONE_WARNING);
        assert!(
            status.text.contains("Windows адрес сайта не получает"),
            "{}",
            status.text
        );
        assert_eq!(entry["level"], json!("warn"));
        assert!(entry["headline"]
            .as_str()
            .expect("текст")
            .contains("Windows адрес сайта не получает"));
    }

    #[test]
    fn closed_site_leads_the_status_and_the_history() {
        let report = site_report(Some(json!({
            "level": "fail",
            "headline": "youtube.com не открывается: блокировка по имени"
        })));

        let status = build_status(&report);
        let entry = build_history_entry(&report).expect("запись");

        assert_eq!(status.tone, TONE_ERROR);
        assert!(
            status.text.contains("не открывается: блокировка по имени"),
            "{}",
            status.text
        );
        assert_eq!(
            entry["headline"],
            json!("youtube.com не открывается: блокировка по имени")
        );
        assert!(entry["problems"][1]
            .as_str()
            .expect("текст")
            .contains("Windows адрес сайта не получает"));
    }

    #[test]
    fn site_that_could_not_be_checked_is_unknown_in_history_not_ok() {
        let answers = annotate_answers(vec![crate::domain_lookup::ResolverAnswer {
            server: DnsServer::new("Хороший", "9.9.9.9"),
            status: STATUS_OK.to_string(),
            ipv4: vec![V4.to_string()],
            elapsed_ms: Some(10.0),
            ..Default::default()
        }]);
        let report = DomainLookupReport {
            target: "example.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            primary_ip: V4.to_string(),
            answers,
            site: Some(
                json!({"level": "unknown", "headline": "Сайт проверить не удалось", "targets": []}),
            ),
            finished: true,
            elapsed_s: 1.5,
            ..DomainLookupReport::default()
        };
        let entry = build_history_entry(&report).expect("запись");
        assert_eq!(entry["level"], json!("unknown"));
    }

    #[test]
    fn forged_denial_at_foreign_server_is_not_blamed_on_this_computer() {
        let answers = annotate_answers(vec![
            crate::domain_lookup::ResolverAnswer {
                server: DnsServer::with_kind("Windows", "", SERVER_WINDOWS),
                status: STATUS_OK.to_string(),
                ipv4: vec!["1.2.3.4".to_string()],
                ..Default::default()
            },
            crate::domain_lookup::ResolverAnswer {
                server: DnsServer::new("OpenDNS", "208.67.222.222"),
                status: STATUS_NXDOMAIN.to_string(),
                tcp_ipv4: vec!["1.2.3.4".to_string()],
                ..Default::default()
            },
        ]);
        let report = DomainLookupReport {
            target: "example.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            answers,
            primary_ip: "1.2.3.4".to_string(),
            finished: true,
            ..DomainLookupReport::default()
        };

        assert!(build_dns_summary(&report)
            .text
            .contains("DNS этого компьютера среди них нет"));
        assert_eq!(own_dns_trouble(&report), "");
        assert_eq!(build_status(&report).tone, TONE_SUCCESS);
    }

    #[test]
    fn system_server_is_not_shown_with_its_address_twice() {
        let named = fx::answer_with_ipv4(
            &DnsServer::with_kind("Google", "8.8.8.8", SERVER_SYSTEM),
            &["1.1.1.1"],
        );
        let unnamed = fx::answer_with_ipv4(
            &DnsServer::with_kind("", "10.0.0.1", SERVER_SYSTEM),
            &["1.1.1.1"],
        );
        let legacy = fx::answer_with_ipv4(
            &DnsServer::with_kind("10.0.0.2", "10.0.0.2", SERVER_SYSTEM),
            &["1.1.1.1"],
        );
        let report = DomainLookupReport {
            target: "example.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            answers: vec![named, unnamed, legacy],
            ..DomainLookupReport::default()
        };

        assert_eq!(
            build_answer_rows(&report)
                .iter()
                .map(|row| row.server.as_str())
                .collect::<Vec<_>>(),
            vec!["Системный DNS · Google", "Системный DNS", "Системный DNS"]
        );
    }

    #[test]
    fn ping_lines_show_loss_and_times() {
        let report = DomainLookupReport {
            target: "example.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            primary_ip: V4.to_string(),
            ping: Some(PingReport {
                ip: V4.to_string(),
                supported: true,
                sent: 4,
                received: 3,
                min_ms: Some(10.0),
                avg_ms: Some(20.0),
                max_ms: Some(30.0),
                ttl: Some(57),
                ..PingReport::default()
            }),
            ping6: Some(PingReport {
                ip: V6.to_string(),
                supported: true,
                sent: 4,
                received: 4,
                ..PingReport::default()
            }),
            tcp: Some(TcpReport {
                ip: V4.to_string(),
                port: 443,
                status: "ok".to_string(),
                elapsed_ms: Some(5.0),
                ..TcpReport::default()
            }),
            ..DomainLookupReport::default()
        };

        let lines = build_ping_lines(&report);

        assert!(
            lines[0]
                .text
                .contains("отправлено 4, получено 3, потеряно 25%"),
            "{}",
            lines[0].text
        );
        assert!(
            lines[0]
                .text
                .contains("мин 10 мс, средн 20 мс, макс 30 мс, TTL 57"),
            "{}",
            lines[0].text
        );
        assert_eq!(lines[0].tone, TONE_WARNING);
        assert!(lines[1].text.contains("IPv6"));
        assert!(lines[2].text.contains("порту 443"));
    }

    #[test]
    fn silent_ping_with_open_port_is_explained() {
        let report = DomainLookupReport {
            target: "1.2.3.4".to_string(),
            kind: crate::domain_lookup::KIND_IP.to_string(),
            primary_ip: "1.2.3.4".to_string(),
            ping: Some(PingReport {
                ip: "1.2.3.4".to_string(),
                supported: true,
                sent: 4,
                received: 0,
                error_code: "TIMEOUT".to_string(),
                ..PingReport::default()
            }),
            tcp: Some(TcpReport {
                ip: "1.2.3.4".to_string(),
                port: 443,
                status: "ok".to_string(),
                elapsed_ms: Some(9.0),
                ..TcpReport::default()
            }),
            ..DomainLookupReport::default()
        };

        let lines = build_ping_lines(&report);

        assert!(lines[0].text.contains("не отвечает на пинг"));
        assert!(lines.last().expect("строки").text.contains("сам работает"));
    }

    #[test]
    fn text_report_has_all_sections() {
        let answers = annotate_answers(vec![
            crate::domain_lookup::ResolverAnswer {
                server: DnsServer::with_kind("Windows", "", SERVER_WINDOWS),
                status: STATUS_OK.to_string(),
                ipv4: vec![V4.to_string()],
                elapsed_ms: Some(10.0),
                ..Default::default()
            },
            fx::answer_with_ipv4(&fx::secure(), &["93.184.216.34"]),
            fx::answer_with_ipv4(&fx::good(), &["93.184.216.34"]),
            fx::answer_with_ipv4(&fx::stub(), &["195.82.146.214"]),
            crate::domain_lookup::ResolverAnswer {
                server: fx::dead(),
                status: STATUS_TIMEOUT.to_string(),
                ..Default::default()
            },
        ]);
        let report = DomainLookupReport {
            target: "example.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            primary_ip: V4.to_string(),
            answers,
            ping: Some(PingReport {
                ip: V4.to_string(),
                supported: true,
                sent: 4,
                received: 4,
                ..PingReport::default()
            }),
            tcp: Some(TcpReport {
                ip: V4.to_string(),
                port: 443,
                status: "ok".to_string(),
                elapsed_ms: Some(5.0),
                ..TcpReport::default()
            }),
            network: Some(crate::domain_lookup::NetworkInfo {
                asn: "64500".to_string(),
                prefix: "93.184.216.0/24".to_string(),
                country: "US".to_string(),
                owner: "EXAMPLE".to_string(),
                origins: vec![("64500".to_string(), "EXAMPLE".to_string())],
            }),
            sources: vec![
                fx::source_with_names(crate::domain_lookup::SOURCE_PTR, &["host.example.net"]),
                fx::source_with_names(
                    crate::domain_lookup::SOURCE_CERT_NAMED,
                    &["cn.example", "cert.example"],
                ),
                fx::source_with_names(
                    crate::domain_lookup::SOURCE_CERT_DEFAULT,
                    &["cn.example", "cert.example"],
                ),
                fx::source_with_names(
                    crate::domain_lookup::SOURCE_THC,
                    &["first.example", "second.example"],
                ),
                NeighborSource {
                    extra: "открытые порты: 80, 443".to_string(),
                    ..fx::source_with_names(
                        crate::domain_lookup::SOURCE_SHODAN,
                        &["shodan.example"],
                    )
                },
            ],
            finished: true,
            elapsed_s: 1.5,
            ..DomainLookupReport::default()
        };

        let text = build_text_report(&report);

        for expected in [
            "Проверка: example.com",
            "=== Адреса с разных DNS ===",
            "=== Пинг ===",
            "=== Сеть адреса 93.184.216.34 ===",
            "ASN: AS64500, подсеть: 93.184.216.0/24, страна: US",
            "=== Кто ещё на адресе 93.184.216.34 ===",
            "    first.example",
            "    открытые порты: 80, 443",
        ] {
            assert!(text.contains(expected), "нет {expected} в отчёте");
        }
        assert_eq!(count_neighbors(&report), 6);
        assert_eq!(build_status(&report).tone, TONE_SUCCESS);
    }

    #[test]
    fn long_lists_stay_whole_in_the_report() {
        let names: Vec<String> = (0..305)
            .map(|index| format!("host{index}.example"))
            .collect();
        let report = DomainLookupReport {
            target: "1.2.3.4".to_string(),
            kind: crate::domain_lookup::KIND_IP.to_string(),
            primary_ip: "1.2.3.4".to_string(),
            sources: vec![NeighborSource {
                names,
                total: Some(9000),
                ..NeighborSource::new(SOURCE_THC, SOURCE_OK)
            }],
            ..DomainLookupReport::default()
        };

        let text = build_text_report(&report);
        assert!(text.contains("host304.example"));
    }

    #[test]
    fn advice_depends_on_who_wrote_the_row() {
        let road = || {
            Some(ProgramRoad {
                ip: V6.to_string(),
                tcp: TcpReport {
                    ip: V6.to_string(),
                    port: 443,
                    status: "timeout".to_string(),
                    ..TcpReport::default()
                },
                ..ProgramRoad::default()
            })
        };
        let report_with = |help: HostsHelp| DomainLookupReport {
            target: "www.youtube.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            road: road(),
            hosts_service: help.service,
            hosts_rows: help.rows,
            hosts_managed: help.managed,
            hosts_offered: help.offered,
            ..DomainLookupReport::default()
        };

        let by_program = report_with(HostsHelp {
            service: "YouTube".to_string(),
            rows: vec![V6.to_string()],
            managed: vec![V6.to_string()],
            ..HostsHelp::default()
        });
        assert!(
            road_cure(&by_program).contains(
                "Этот адрес записала программа. Выключите и снова включите тумблер «YouTube»"
            ),
            "{}",
            road_cure(&by_program)
        );
        // Чужая строка при включённом сервисе: программа уберёт её сама при следующей записи.
        let fights = report_with(HostsHelp {
            service: "YouTube".to_string(),
            rows: vec![V4.to_string(), V6.to_string()],
            managed: vec![V4.to_string()],
            ..HostsHelp::default()
        });
        assert!(road_cure(&fights).contains("мешает сервису «YouTube»"));
        assert!(road_cure(&fights).contains("программа уберёт эту строку сама"));
        // Чужая строка, а тумблер выключен: включить — и строка уйдёт.
        let alone = report_with(HostsHelp {
            service: "YouTube".to_string(),
            rows: vec![V6.to_string()],
            ..HostsHelp::default()
        });
        assert!(road_cure(&alone).contains("Включите тумблер «YouTube»"));
        assert!(road_cure(&alone).contains("уберёт эту строку сама"));
        // Сервиса для имени нет — убирать строку придётся самому.
        let foreign = report_with(HostsHelp {
            rows: vec![V6.to_string()],
            ..HostsHelp::default()
        });
        assert!(road_cure(&foreign).contains("Удалите её сами"));
        let unknown = report_with(HostsHelp::default());
        assert!(road_cure(&unknown).contains("отключить IPv6"));
    }

    #[test]
    fn hop_count_is_declined_correctly() {
        let expected = [
            "узел",
            "узла",
            "узла",
            "узлов",
            "узлов",
            "узлов",
            "узел",
            "узла",
            "узлов",
            "узлов",
        ];
        let got: Vec<&str> = [1, 2, 4, 5, 11, 12, 21, 22, 25, 111]
            .iter()
            .map(|count| hops_word(*count))
            .collect();
        assert_eq!(got, expected);
    }

    fn route_with_mark() -> (DomainLookupReport, RouteTrace) {
        let ip = V4;
        let hops: Vec<Hop> = (1..=6)
            .map(|ttl| Hop {
                ttl,
                kind: HOP_ROUTER,
                address: format!("10.0.0.{ttl}"),
                rtt_ms: Some(f64::from(ttl)),
            })
            .collect();
        let route = RouteTrace {
            target: ip.to_string(),
            hops: [
                hops,
                vec![Hop {
                    ttl: 7,
                    kind: HOP_TARGET,
                    address: ip.to_string(),
                    rtt_ms: Some(40.0),
                }],
            ]
            .concat(),
            reached: true,
            supported: true,
        };
        let report = DomainLookupReport {
            target: "example.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            primary_ip: ip.to_string(),
            route: Some(route.clone()),
            quic: Some(QuicVerdict {
                code: QUIC_BLOCKED_BY_NAME.to_string(),
                text: "блокируется по имени сайта".to_string(),
            }),
            filter_facts: Some(FilterFacts {
                control_ok: Some(true),
                stateful: Some(true),
                first_blocked_ttl: Some(6),
                checked_up_to: 6,
                ..FilterFacts::default()
            }),
            finished: true,
            ..DomainLookupReport::default()
        };
        (report, route)
    }

    #[test]
    fn filter_place_is_marked_between_hops() {
        let (report, _route) = route_with_mark();

        let lines = build_path_lines(&report);
        assert_eq!(lines[0].text, "До сервера 7 узлов, ответили 7.");
        assert_eq!(lines[1].text, "QUIC (UDP 443): блокируется по имени сайта.");
        assert_eq!(
            lines[2].text,
            "Фильтр стоит между узлом 5 (10.0.0.5) и узлом 6 (10.0.0.6)."
        );
        assert_eq!(lines[2].tone, TONE_ERROR);
        let table: Vec<String> = build_path_text(&report)
            .lines()
            .map(str::to_string)
            .collect();
        let mark = format!("    {FILTER_MARK}");
        assert_eq!(table.iter().position(|row| row == &mark), Some(5));
        assert!(table[4].starts_with(" 5  10.0.0.5"));
        assert!(table[6].starts_with(" 6  10.0.0.6"));

        let rows = build_path_rows(&report);
        assert_eq!(rows[5].state, "fail");
        assert_eq!(rows[5].name, FILTER_MARK);
        assert_eq!(rows[6].text, "10.0.0.6 · 6 мс");
        assert_eq!(rows[7].text, "93.184.216.34 · 40 мс · сам сервер");
    }

    #[test]
    fn unreached_route_is_calmed_down() {
        let route = RouteTrace {
            target: V4.to_string(),
            hops: vec![
                Hop {
                    ttl: 1,
                    kind: HOP_ROUTER,
                    address: "10.0.0.1".to_string(),
                    rtt_ms: Some(1.0),
                },
                Hop {
                    ttl: 2,
                    kind: HOP_SILENT,
                    address: String::new(),
                    rtt_ms: None,
                },
                Hop {
                    ttl: 3,
                    kind: HOP_ROUTER,
                    address: "10.0.0.3".to_string(),
                    rtt_ms: Some(2.0),
                },
            ],
            supported: true,
            ..RouteTrace::default()
        };
        let report = DomainLookupReport {
            target: "example.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            route: Some(route),
            finished: true,
            ..DomainLookupReport::default()
        };

        let line = &build_path_lines(&report)[0];
        assert!(line
            .text
            .contains("последний ответивший узел — 3-й (10.0.0.3)"));
        assert!(line.text.contains("это ещё не блокировка"));
        assert_eq!(line.tone, TONE_MUTED);
        assert!(build_path_text(&report).contains(" 2  не ответил"));
    }

    #[test]
    fn quiet_quic_and_no_path_when_unsupported() {
        let mut report = DomainLookupReport {
            target: "example.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            finished: true,
            ..DomainLookupReport::default()
        };
        report.quic = Some(QuicVerdict {
            code: QUIC_OK.to_string(),
            text: "отвечает за 12 мс".to_string(),
        });
        let lines = build_path_lines(&report);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].text, "QUIC (UDP 443): отвечает за 12 мс.");
        assert_eq!(lines[0].tone, TONE_SUCCESS);
        // Трассировка недоступна — раздела пути нет вовсе.
        assert_eq!(build_path_text(&report), "");
        assert!(build_path_rows(&report).is_empty());
    }

    #[test]
    fn long_neighbour_list_is_cut_on_screen_and_points_to_the_report() {
        let source = NeighborSource {
            names: (0..100).map(|n| format!("s{n}.example")).collect(),
            ..NeighborSource::new(SOURCE_THC, SOURCE_OK)
        };
        let report = DomainLookupReport {
            primary_ip: "1.2.3.4".to_string(),
            sources: vec![source.clone()],
            ..DomainLookupReport::default()
        };
        let groups = build_neighbor_groups(&report, NEIGHBOR_ROWS_LIMIT);
        assert_eq!(groups.len(), 1);
        let group = &groups[0];

        assert_eq!(group.rows.len(), 1 + NEIGHBOR_ROWS_LIMIT + 1);
        assert!(
            group.rows[group.rows.len() - 1].name.contains("и ещё 60"),
            "{}",
            group.rows.last().expect("строка").name
        );
        assert_eq!(group.rows[0].name, "Найдено: 100");
        assert!(build_neighbor_groups(
            &DomainLookupReport {
                primary_ip: String::new(),
                sources: vec![source],
                ..DomainLookupReport::default()
            },
            NEIGHBOR_ROWS_LIMIT
        )
        .is_empty());
    }

    #[test]
    fn history_entry_reports_the_site_card() {
        // python `test_domain_gets_the_same_site_card_as_in_blockcheck` — не-Qt часть.
        let site = json!({
            "key": "user:example.com",
            "label": "example.com",
            "level": "fail",
            "kind": "sni",
            "headline": "example.com не открывается: блокировка по имени",
            "dns_note": "",
            "targets": [
                {
                    "host": "example.com", "purpose": "сайт", "main": true, "ok": false, "state": "dpi",
                    "short": "соединение сброшено", "text": "соединение сброшено (93.184.216.34)",
                    "cause": "by_name", "cause_text": "Блокировка по имени сайта.", "quic": "ok", "quic_text": "работает",
                    "dns_state": "ok", "registry": {"listed": true, "name": "", "network": ""},
                    "protocols": [
                        {"key": "tls12", "title": "TLS 1.2", "state": "fail", "word": "сброс", "text": "соединение сброшено"},
                        {"key": "tls13", "title": "TLS 1.3", "state": "fail", "word": "сброс", "text": "соединение сброшено"},
                        {"key": "chrome", "title": "Как Chrome", "state": "ok", "word": "проходит", "text": "проходит"},
                        {"key": "http", "title": "HTTP", "state": "info", "word": "переход", "text": "переход на HTTPS"}
                    ]
                }
            ]
        });
        let report = DomainLookupReport {
            target: "example.com".to_string(),
            kind: KIND_DOMAIN.to_string(),
            primary_ip: V4.to_string(),
            answers: annotate_answers(vec![crate::domain_lookup::ResolverAnswer {
                server: DnsServer::new("Хороший", "9.9.9.9"),
                status: STATUS_OK.to_string(),
                ipv4: vec![V4.to_string()],
                elapsed_ms: Some(10.0),
                ..Default::default()
            }]),
            ping: Some(PingReport {
                ip: V4.to_string(),
                supported: true,
                sent: 4,
                received: 4,
                min_ms: Some(1.0),
                avg_ms: Some(2.0),
                max_ms: Some(3.0),
                ..PingReport::default()
            }),
            tcp: Some(TcpReport {
                ip: V4.to_string(),
                port: 443,
                status: "ok".to_string(),
                elapsed_ms: Some(5.0),
                ..TcpReport::default()
            }),
            site: Some(site),
            finished: true,
            elapsed_s: 1.5,
            ..DomainLookupReport::default()
        };
        let entry = build_history_entry(&report).expect("запись");
        assert_eq!(entry["level"], json!("fail"));
        assert_eq!(
            entry["problems"][0],
            json!("example.com не открывается: блокировка по имени")
        );

        let text = build_text_report(&report);
        assert!(text.contains("=== Как открывается сайт ==="));
        assert!(text.contains("    TLS 1.2: соединение сброшено"), "{text}");
        assert!(text.contains("    Как блокируют: Блокировка по имени сайта."));
        assert!(text.contains("    Реестр РКН: сайт в реестре"));
    }
}
