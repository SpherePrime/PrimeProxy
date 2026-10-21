//! Порт `src/dns/server_check_plans.py` (часть 1) — как показывать отчёт
//! проверки DNS-серверов: константы, строки адресов и карточки серверов.
//!
//! Чистые функции над [`crate::server_check::ServerCheckReport`]: ни сети, ни
//! интерфейса. Подробности по адресам, сводка способов связи и текстовый
//! отчёт — в [`crate::server_check_plans_text`].

use crate::server_check::{
    Cell, Finding, Observation, ServerCheckReport, CODE_DEAD, CODE_DOH_BLOCKED,
    CODE_DOH_NAME_BLOCKED, CODE_DOT_BLOCKED, CODE_FOREIGN_ANSWERS, CODE_INTERCEPTED,
    CODE_SELF_FILTER, CODE_SPOOFED, CODE_TCP_BLOCKED, CODE_UDP_BLOCKED, CODE_UNSTABLE, LEVEL_FAIL,
    LEVEL_INFO, LEVEL_OK, LEVEL_WARN, STATE_FAIL, STATE_OK, STATE_SKIP, TRANSPORTS, TRANSPORT_ICMP,
};
use primecore_dnswire::{
    FAILURE_CERT, FAILURE_CLOSED, FAILURE_HTTP, FAILURE_MALFORMED, FAILURE_REFUSED, FAILURE_RESET,
    FAILURE_TIMEOUT, FAILURE_TLS, FAILURE_UNREACHABLE, TRANSPORT_DOH, TRANSPORT_DOT, TRANSPORT_TCP,
    TRANSPORT_UDP,
};

/// python `TRANSPORT_TITLES` — название способа связи в таблице.
#[must_use]
pub fn transport_title(transport: &str) -> &'static str {
    match transport {
        TRANSPORT_ICMP => "Пинг",
        TRANSPORT_UDP => "UDP 53",
        TRANSPORT_TCP => "TCP 53",
        TRANSPORT_DOT => "DoT 853",
        TRANSPORT_DOH => "DoH 443",
        _ => "",
    }
}

/// python `TRANSPORT_ABOUT` — что это за способ связи одной строкой для
/// новичка, на странице подробностей.
#[must_use]
pub fn transport_about(transport: &str) -> &'static str {
    match transport {
        TRANSPORT_ICMP => "Отклик сервера: жив ли адрес и далеко ли он",
        TRANSPORT_UDP => "Обычный DNS — так спрашивает Windows по умолчанию",
        TRANSPORT_TCP => "Обычный DNS по TCP — запасной путь для длинных ответов",
        TRANSPORT_DOT => "Шифрованный DNS на отдельном порту",
        TRANSPORT_DOH => "Шифрованный DNS внутри обычного HTTPS",
        _ => "",
    }
}

pub const CELL_OK: &str = "ok";
/// Отвечает, но не на каждый запрос.
pub const CELL_WARN: &str = "warn";
pub const CELL_FAIL: &str = "fail";
pub const CELL_MUTED: &str = "muted";

/// python `_FAILURE_WORDS` — коротко, чтобы помещалось в ячейку; полная
/// причина — в подсказке строки.
#[must_use]
pub fn failure_word(failure: &str) -> &'static str {
    match failure {
        FAILURE_TIMEOUT => "молчит",
        FAILURE_REFUSED => "порт закрыт",
        FAILURE_RESET | FAILURE_CLOSED => "обрыв",
        FAILURE_UNREACHABLE => "нет дороги",
        FAILURE_TLS => "нет шифрования",
        FAILURE_CERT => "чужой сертификат",
        FAILURE_HTTP => "ошибка сервера",
        FAILURE_MALFORMED => "не DNS",
        _ => "не отвечает",
    }
}

/// python `_LEVEL_TONES` — тон строки итога по важности вывода.
#[must_use]
pub fn level_tone(level: &str) -> &'static str {
    match level {
        LEVEL_OK => crate::info_line::TONE_SUCCESS,
        LEVEL_INFO => crate::info_line::TONE_MUTED,
        LEVEL_WARN => crate::info_line::TONE_WARNING,
        LEVEL_FAIL => crate::info_line::TONE_ERROR,
        _ => crate::info_line::TONE_MUTED,
    }
}

fn level_order(level: &str) -> u8 {
    match level {
        LEVEL_FAIL => 0,
        LEVEL_WARN => 1,
        LEVEL_INFO => 2,
        _ => 3,
    }
}

/// python `_LEVEL_MARKS` — значок вывода в подсказке и текстовом отчёте.
#[must_use]
pub fn level_mark(level: &str) -> &'static str {
    match level {
        LEVEL_FAIL => "✗",
        LEVEL_WARN => "!",
        LEVEL_INFO => "·",
        _ => "✓",
    }
}

/// Эти выводы уже видны в ячейках способов связи: в столбце замечаний они
/// только повторяли бы таблицу. В подсказке строки и в отчёте они остаются.
#[must_use]
fn shown_in_cells(code: &str) -> bool {
    code == CODE_UDP_BLOCKED
        || code == CODE_TCP_BLOCKED
        || code == CODE_DOT_BLOCKED
        || code == CODE_DOH_BLOCKED
        || code == CODE_UNSTABLE
}

/// python `_SHORT_NOTES` — в столбце замечаний два-три слова, чтобы текст
/// помещался целиком. Полная фраза с подробностями остаётся в подсказке
/// строки и в отчёте.
#[must_use]
fn short_note(code: &str) -> Option<&'static str> {
    match code {
        CODE_SPOOFED => Some("Ответы подменяются"),
        CODE_FOREIGN_ANSWERS => Some("Отвечает чужая сеть"),
        CODE_DOH_NAME_BLOCKED => Some("DoH закрыт по имени"),
        CODE_DEAD => Some("Не отвечает"),
        CODE_SELF_FILTER => Some("Сам не отдаёт часть сайтов"),
        _ => None,
    }
}

/// python `_CARD_NOTES` — на карточке сервера ячеек по способам связи не
/// видно, поэтому там называем и их.
#[must_use]
fn card_note(code: &str) -> Option<&'static str> {
    match code {
        CODE_UDP_BLOCKED => Some("Обычный DNS закрыт"),
        CODE_DOT_BLOCKED => Some("DoT закрыт"),
        CODE_DOH_BLOCKED => Some("DoH закрыт"),
        CODE_UNSTABLE => Some("Отвечает через раз"),
        _ => short_note(code),
    }
}

/// Что с сервером в целом — от этого зависят цвет карточки и её место в списке.
pub const CARD_NETWORK: &str = "network";
pub const CARD_SELF: &str = "self";
pub const CARD_PARTIAL: &str = "partial";
pub const CARD_OK: &str = "ok";
pub const CARD_SILENT: &str = "silent";
/// До адреса проверка не дошла (её остановили или вышло время): о нём ничего
/// не известно.
pub const CARD_UNKNOWN: &str = "unknown";

pub const CARD_ORDER: [&str; 6] = [
    CARD_NETWORK,
    CARD_PARTIAL,
    CARD_SELF,
    CARD_OK,
    CARD_SILENT,
    CARD_UNKNOWN,
];

/// python `CARD_TITLES` — название карточки.
#[must_use]
pub fn card_title(status: &str) -> &'static str {
    match status {
        CARD_NETWORK => "Блокируется по дороге",
        CARD_SELF => "Сам не отдаёт часть сайтов",
        CARD_PARTIAL => "Работает не полностью",
        CARD_OK => "Работает",
        CARD_SILENT => "Не отвечает",
        CARD_UNKNOWN => "Не проверен",
        _ => "",
    }
}

/// python `CARD_GROUPS` — короткие подписи для фильтра и полосы «насколько
/// всё плохо».
#[must_use]
pub fn card_group(status: &str) -> &'static str {
    match status {
        CARD_NETWORK => "Блокируются",
        CARD_SELF => "Сами фильтруют",
        CARD_PARTIAL => "Не полностью",
        CARD_OK => "Работают",
        CARD_SILENT => "Молчат",
        CARD_UNKNOWN => "Не проверены",
        _ => "",
    }
}

/// python `CARD_HINTS` — пояснение карточки для новичка.
#[must_use]
pub fn card_hint(status: &str) -> &'static str {
    match status {
        CARD_NETWORK => {
            "Мешает сеть — провайдер или его оборудование. Это доказано: сервер по обычному пути противоречит сам \
             себе, либо закрыто именно его имя, либо за него отвечает чужая сеть."
        }
        CARD_SELF => {
            "Так решил сам сервер: он не отдаёт эти сайты даже по шифрованному пути, который по дороге не подменить."
        }
        CARD_PARTIAL => {
            "Отвечает не всеми способами или через раз. Закрыть способ связи мог и провайдер, и сам сервер — \
             по одной проверке это не отличить. Если так же закрыто у многих разных серверов, дело в провайдере."
        }
        CARD_OK => "Отвечает всеми способами, ответы никто не подменяет.",
        CARD_SILENT => "Не отвечает ни одним способом: сервер выключен или закрыт для вашей сети целиком.",
        CARD_UNKNOWN => "Проверка закончилась раньше, чем дошла до этого адреса, — о нём ничего не известно.",
        _ => "",
    }
}

/// Находки, в которых сеть по дороге виновата доказанно: сервер сам себе
/// противоречит или без имени тот же адрес отвечает.
#[must_use]
fn network_code(code: &str) -> bool {
    code == CODE_SPOOFED || code == CODE_DOH_NAME_BLOCKED
}

/// Способ связи закрыт, но кем — провайдером или самим сервером — по фактам
/// не видно.
#[must_use]
fn closed_code(code: &str) -> bool {
    code == CODE_DOH_BLOCKED || code == CODE_DOT_BLOCKED || code == CODE_UDP_BLOCKED
}

/// python `ServerRow` — строка одного адреса в таблице отчёта.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerRow {
    pub server: String,
    pub address: String,
    pub cells: Vec<String>,
    pub cell_levels: Vec<String>,
    pub note: String,
    /// Важность показанного замечания — для его цвета.
    pub note_level: String,
    /// Важность строки целиком, с учётом закрытых способов связи.
    pub level: String,
    pub tooltip: String,
}

/// python `ServerCard` — один сервер целиком: все его адреса и общий вывод.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerCard {
    pub server: String,
    pub status: String,
    /// Коротко, что не так; пусто — замечаний нет.
    pub note: String,
    /// Лучшее время шифрованного запроса (DoH), а если его нет — обычного.
    pub best: String,
    /// По каждому способу связи — состояния по адресам ([`CELL_*`]), для точек
    /// на карточке.
    pub dots: Vec<Vec<String>>,
    pub addresses: Vec<ServerRow>,
    pub tooltip: String,
    /// Значок и цвет сервера из каталога; пусто — у своего сервера пользователя.
    pub icon: String,
    pub color: String,
}

impl ServerCard {
    /// python `spoken` — как карточка читается вслух.
    #[must_use]
    pub fn spoken(&self) -> String {
        let parts = [
            Some(self.server.clone()),
            Some(card_title(&self.status).to_string()),
            (!self.note.is_empty()).then(|| self.note.clone()),
            (!self.best.is_empty()).then(|| self.best.clone()),
            Some(format!("адресов: {}", self.addresses.len())),
        ];
        parts.into_iter().flatten().collect::<Vec<_>>().join(". ")
    }
}

/// python `AddressDetails` — всё, что известно об одном адресе, для окна
/// подробностей.
#[derive(Debug, Clone, PartialEq)]
pub struct AddressDetails {
    pub address: String,
    pub status: String,
    /// (способ связи, что показал, CELL_*, причина словами)
    pub cells: Vec<(String, String, String, String)>,
    /// (важность LEVEL_*, фраза целиком)
    pub findings: Vec<(String, String)>,
    /// Кто на самом деле выполняет запросы — строками.
    pub who: Vec<String>,
    /// (сайт, ответ обычным путём, ответ шифрованным, расходятся ли)
    pub domains: Vec<(String, String, String, bool)>,
    /// Время ответа каждым способом связи в миллисекундах; None — способ не
    /// ответил.
    pub times_ms: Vec<Option<f64>>,
}

/// python `TransportSummary` — один способ связи по всем адресам сервера, для
/// сводки на странице подробностей.
#[derive(Debug, Clone, PartialEq)]
pub struct TransportSummary {
    pub title: String,
    pub about: String,
    /// Сколько адресов ответило этим способом и у скольких он проверялся.
    pub answered: usize,
    pub total: usize,
    /// Худшее состояние среди адресов (CELL_*) — для цвета числа.
    pub level: String,
    /// Что с ним — словами.
    pub note: String,
    /// Состояние по каждому адресу (CELL_*), для точек.
    pub dots: Vec<String>,
}

/// python `ServerDetails` — подробности по одному серверу.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerDetails {
    pub card: ServerCard,
    pub addresses: Vec<AddressDetails>,
    /// Тот же рассказ простым текстом — для кнопки «Скопировать».
    pub text: String,
}

/// python `format_ms` — время ответа словами: «—», «< 1 мс» или «N мс».
#[must_use]
pub fn format_ms(value: Option<f64>) -> String {
    match value {
        None => "—".to_string(),
        Some(value) if value < 1.0 => "< 1 мс".to_string(),
        // python `round` округляет половинки к чётному — как формат `{:.0}`.
        Some(value) => format!("{value:.0} мс"),
    }
}

/// python `cell_text` — что видно в ячейке способа связи.
#[must_use]
pub fn cell_text(transport: &str, cell: &Cell) -> String {
    if cell.state == STATE_OK {
        if cell.unstable() {
            return format!(
                "{} · {} из {}",
                format_ms(cell.elapsed_ms),
                cell.answered(),
                cell.attempts()
            );
        }
        return format_ms(cell.elapsed_ms);
    }
    if cell.state == STATE_SKIP {
        return "—".to_string();
    }
    if cell.state == STATE_FAIL {
        if transport == TRANSPORT_ICMP {
            return "нет ответа".to_string();
        }
        return failure_word(&cell.failure).to_string();
    }
    "…".to_string()
}

/// python `cell_level` — цвет ячейки: CELL_OK/WARN/FAIL/MUTED.
#[must_use]
pub fn cell_level(transport: &str, cell: &Cell) -> &'static str {
    if cell.state == STATE_OK {
        return if cell.unstable() { CELL_WARN } else { CELL_OK };
    }
    // Молчание на пинг — обычное дело, красным его красить нельзя.
    if cell.state == STATE_FAIL && transport != TRANSPORT_ICMP {
        return CELL_FAIL;
    }
    CELL_MUTED
}

/// python `row_level` — важность строки целиком: худший её вывод.
#[must_use]
pub fn row_level(row: &Observation) -> String {
    let mut worst = LEVEL_OK;
    for finding in &row.findings {
        if level_order(&finding.level) < level_order(worst) {
            worst = finding.level.as_str();
        }
    }
    worst.to_string()
}

/// python `_sentence` — первая буква заглавная.
#[must_use]
pub(crate) fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// python `_owner_text` — «адрес (владелец)» или просто адрес.
#[must_use]
pub(crate) fn owner_text(report: &ServerCheckReport, ip: &str) -> String {
    if ip.is_empty() {
        return String::new();
    }
    let name = report
        .owner_of(ip)
        .map(|owner| {
            if owner.owner.is_empty() && !owner.asn.is_empty() {
                format!("AS{}", owner.asn)
            } else {
                owner.owner.clone()
            }
        })
        .unwrap_or_default();
    if name.is_empty() {
        ip.to_string()
    } else {
        format!("{ip} ({name})")
    }
}

/// python `_row_tooltip` — подсказка строки: все способы связи, кто отвечает
/// и выводы целиком.
#[must_use]
fn row_tooltip(report: &ServerCheckReport, row: &Observation) -> String {
    let mut lines = vec![format!("{} — {}", row.target.provider, row.target.address)];
    for transport in TRANSPORTS {
        let cell = row.cell(transport);
        let mut text = cell_text(transport, &cell);
        if (cell.state == STATE_FAIL || cell.state == STATE_SKIP) && !cell.reason.is_empty() {
            text = cell.reason.clone();
        } else if cell.unstable() {
            text = format!(
                "{}, ответил на {} из {} запросов (остальные: {})",
                format_ms(cell.elapsed_ms),
                cell.answered(),
                cell.attempts(),
                cell.reason
            );
        }
        lines.push(format!("{}: {}", transport_title(transport), text));
    }
    if !row.udp_egress.is_empty() || !row.secure_egress.is_empty() {
        let udp = owner_text(report, &row.udp_egress);
        let secure = owner_text(report, &row.secure_egress);
        lines.push(format!(
            "Кто выполняет обычные запросы: {}",
            if udp.is_empty() {
                "не узнали".to_string()
            } else {
                udp
            }
        ));
        lines.push(format!(
            "Кто выполняет шифрованные: {}",
            if secure.is_empty() {
                "не узнали".to_string()
            } else {
                secure
            }
        ));
    }
    for finding in &row.findings {
        lines.push(format!(
            "{} {}",
            level_mark(&finding.level),
            sentence(&finding.text)
        ));
    }
    lines.join("\n")
}

/// python `build_rows` — строки таблицы отчёта: по строке на адрес.
#[must_use]
pub fn build_rows(report: &ServerCheckReport) -> Vec<ServerRow> {
    let mut rows = Vec::new();
    for row in &report.rows {
        let mut shown: Vec<&Finding> = row
            .findings
            .iter()
            .filter(|finding| !shown_in_cells(&finding.code))
            .collect();
        shown.sort_by_key(|finding| level_order(&finding.level));
        let (note, note_level) = if !shown.is_empty() {
            let note = shown
                .iter()
                .map(|finding| match short_note(&finding.code) {
                    Some(short) => short.to_string(),
                    None => sentence(&finding.text),
                })
                .collect::<Vec<_>>()
                .join(" · ");
            (note, shown[0].level.clone())
        } else {
            let checked = TRANSPORTS.iter().any(|transport| {
                matches!(row.cell(transport).state.as_str(), STATE_OK | STATE_FAIL)
            });
            let note = if report.finished && checked && row.findings.is_empty() {
                "Без замечаний".to_string()
            } else {
                String::new()
            };
            (note, LEVEL_OK.to_string())
        };
        rows.push(ServerRow {
            server: row.target.provider.clone(),
            address: row.target.address.clone(),
            cells: TRANSPORTS
                .iter()
                .map(|transport| cell_text(transport, &row.cell(transport)))
                .collect(),
            cell_levels: TRANSPORTS
                .iter()
                .map(|transport| cell_level(transport, &row.cell(transport)).to_string())
                .collect(),
            note,
            note_level,
            level: row_level(row),
            tooltip: row_tooltip(report, row),
        });
    }
    rows
}

/// python `_address_status` — что с адресом: одна из CARD_*.
#[must_use]
pub(crate) fn address_status(row: &Observation, intercepted: bool) -> &'static str {
    let dns_cells: Vec<Cell> = TRANSPORTS
        .iter()
        .filter(|transport| **transport != TRANSPORT_ICMP)
        .map(|transport| row.cell(transport))
        .collect();
    if !dns_cells.iter().any(|cell| cell.state == STATE_OK) {
        // Не ответил ни одним способом — молчит; не спрашивали ни одним —
        // не проверен, а не «работает».
        return if dns_cells.iter().any(|cell| cell.state == STATE_FAIL) {
            CARD_SILENT
        } else {
            CARD_UNKNOWN
        };
    }
    let codes: Vec<&str> = row
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect();
    // Чужая сеть в ответах — вина дороги, только если перехват подтверждён
    // общим итогом.
    if codes.iter().any(|code| network_code(code))
        || (intercepted && codes.contains(&CODE_FOREIGN_ANSWERS))
    {
        return CARD_NETWORK;
    }
    if codes.iter().any(|code| closed_code(code))
        || row
            .findings
            .iter()
            .any(|finding| finding.code == CODE_UNSTABLE && finding.level == LEVEL_WARN)
    {
        return CARD_PARTIAL;
    }
    if codes.contains(&CODE_SELF_FILTER) {
        return CARD_SELF;
    }
    CARD_OK
}

/// python `_best_time` — лучшее время шифрованного (или обычного) запроса
/// словами.
#[must_use]
fn best_time(rows: &[&Observation]) -> String {
    for transport in [TRANSPORT_DOH, TRANSPORT_DOT, TRANSPORT_UDP] {
        let times: Vec<f64> = rows
            .iter()
            .filter_map(|row| {
                let cell = row.cell(transport);
                if cell.state == STATE_OK {
                    cell.elapsed_ms
                } else {
                    None
                }
            })
            .collect();
        if !times.is_empty() {
            let title = transport_title(transport)
                .split_whitespace()
                .next()
                .unwrap_or("");
            return format!(
                "{title} {}",
                format_ms(Some(times.iter().copied().fold(f64::INFINITY, f64::min)))
            );
        }
    }
    String::new()
}

/// python `build_cards` — карточки серверов: сначала те, кому доказанно мешает
/// сеть, в конце — молчащие; внутри группы — по скорости.
#[must_use]
pub fn build_cards(report: &ServerCheckReport) -> Vec<ServerCard> {
    let intercepted = report
        .findings
        .iter()
        .any(|finding| finding.code == CODE_INTERCEPTED);
    let shown = build_rows(report);
    // Строки адресов идут в том же порядке, что и сами адреса.
    let mut by_server: Vec<(String, Vec<usize>)> = Vec::new();
    for (index, row) in report.rows.iter().enumerate() {
        match by_server
            .iter_mut()
            .find(|(name, _)| *name == row.target.provider)
        {
            Some((_, indices)) => indices.push(index),
            None => by_server.push((row.target.provider.clone(), vec![index])),
        }
    }

    let mut cards: Vec<(usize, f64, ServerCard)> = Vec::new();
    for (server, indices) in &by_server {
        let rows: Vec<&Observation> = indices.iter().map(|&index| &report.rows[index]).collect();
        let statuses: Vec<&str> = rows
            .iter()
            .map(|row| address_status(row, intercepted))
            .collect();
        let alive: Vec<&str> = statuses
            .iter()
            .copied()
            .filter(|status| *status != CARD_SILENT)
            .collect();
        // Сервер жив, если отвечает хоть один его адрес; общий вывод — по
        // худшему из живых.
        let status = alive
            .iter()
            .copied()
            .min_by_key(|status| card_order_index(status))
            .unwrap_or(CARD_SILENT);
        // Выводы называются по одному разу, важные раньше.
        let mut notes: Vec<String> = Vec::new();
        for level in [LEVEL_FAIL, LEVEL_WARN, LEVEL_INFO] {
            for row in &rows {
                for finding in &row.findings {
                    if finding.level != level || finding.code == CODE_DEAD {
                        continue;
                    }
                    let Some(note) = card_note(&finding.code) else {
                        continue;
                    };
                    if !notes.iter().any(|shown| shown == note) {
                        notes.push(note.to_string());
                    }
                }
            }
        }
        let silent = statuses.len() - alive.len();
        if !alive.is_empty() && silent > 0 {
            notes.push(format!("Молчит адресов: {silent} из {}", rows.len()));
        }
        let best = best_time(&rows);
        // Для порядка внутри группы: чем быстрее шифрованный ответ, тем выше.
        let speed = rows
            .iter()
            .filter_map(|row| {
                let cell = row.cell(TRANSPORT_DOH);
                if cell.state == STATE_OK {
                    cell.elapsed_ms
                } else {
                    None
                }
            })
            .fold(f64::INFINITY, f64::min);
        let card = ServerCard {
            server: server.clone(),
            status: status.to_string(),
            note: notes.join(" · "),
            best,
            dots: TRANSPORTS
                .iter()
                .filter(|transport| **transport != TRANSPORT_ICMP)
                .map(|transport| {
                    rows.iter()
                        .map(|row| cell_level(transport, &row.cell(transport)).to_string())
                        .collect()
                })
                .collect(),
            addresses: indices.iter().map(|&index| shown[index].clone()).collect(),
            tooltip: format!(
                "{}. {}\nНажмите, чтобы открыть подробности по адресам.",
                card_title(status),
                card_hint(status)
            ),
            icon: rows[0].target.icon.clone(),
            color: rows[0].target.color.clone(),
        };
        cards.push((card_order_index(status), speed, card));
    }
    cards.sort_by(|(order_a, speed_a, card_a), (order_b, speed_b, card_b)| {
        order_a
            .cmp(order_b)
            .then(
                speed_a
                    .partial_cmp(speed_b)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
            .then(
                card_a
                    .server
                    .to_lowercase()
                    .cmp(&card_b.server.to_lowercase()),
            )
    });
    cards.into_iter().map(|(_, _, card)| card).collect()
}

fn card_order_index(status: &str) -> usize {
    CARD_ORDER
        .iter()
        .position(|known| *known == status)
        .unwrap_or(usize::MAX)
}

/// python `count_cards` — сколько карточек каждого статуса.
#[must_use]
pub fn count_cards(cards: &[ServerCard]) -> Vec<(String, usize)> {
    let mut counts: Vec<(String, usize)> = CARD_ORDER
        .iter()
        .map(|status| (status.to_string(), 0))
        .collect();
    for card in cards {
        if let Some((_, count)) = counts.iter_mut().find(|(status, _)| *status == card.status) {
            *count += 1;
        }
    }
    counts
}

#[cfg(test)]
pub(crate) mod support {
    //! Общие помощники тестов показа отчёта — как python `_report` и
    //! `_mixed_report` из test_dns_server_check_page.py.

    use crate::server_check::{
        Cell, CheckTarget, Finding, IpOwner, Observation, ServerCheckReport, CODE_BEST, CODE_DEAD,
        CODE_INTERCEPTED, STATE_FAIL, STATE_OK, TRANSPORTS,
    };
    use primecore_dnswire::{FAILURE_REFUSED, FAILURE_TIMEOUT};

    pub(crate) fn google() -> CheckTarget {
        CheckTarget {
            provider: "Google DNS".to_string(),
            address: "8.8.8.8".to_string(),
            dot_host: "dns.google".to_string(),
            doh_host: "dns.google".to_string(),
            ..Default::default()
        }
    }

    pub(crate) fn backup() -> CheckTarget {
        CheckTarget {
            provider: "Google DNS".to_string(),
            address: "8.8.4.4".to_string(),
            dot_host: "dns.google".to_string(),
            doh_host: "dns.google".to_string(),
            ..Default::default()
        }
    }

    pub(crate) fn ok_cell(ms: f64) -> Cell {
        Cell {
            state: STATE_OK.to_string(),
            elapsed_ms: Some(ms),
            ..Default::default()
        }
    }

    pub(crate) fn fail_cell(failure: &str, reason: &str) -> Cell {
        Cell {
            state: STATE_FAIL.to_string(),
            failure: failure.to_string(),
            reason: reason.to_string(),
            ..Default::default()
        }
    }

    /// python `_row` — адрес со всеми пятью способами связи.
    pub(crate) fn make_row(target: CheckTarget, cells: [Cell; 5]) -> Observation {
        Observation {
            target,
            cells: TRANSPORTS
                .iter()
                .map(|transport| transport.to_string())
                .zip(cells)
                .collect(),
            ..Default::default()
        }
    }

    pub(crate) fn silent_cell() -> Cell {
        fail_cell(FAILURE_TIMEOUT, "сервер молчит")
    }

    pub(crate) fn dead_finding() -> Finding {
        Finding {
            level: crate::server_check::LEVEL_FAIL.to_string(),
            code: CODE_DEAD.to_string(),
            text: "не отвечает ни одним способом".to_string(),
            ..Default::default()
        }
    }

    /// python `BLOCKED` — адрес, у которого закрыты шифрованные пути.
    pub(crate) fn blocked() -> Observation {
        let mut row = make_row(
            google(),
            [
                fail_cell(FAILURE_TIMEOUT, "не отвечает на пинг"),
                ok_cell(12.4),
                ok_cell(30.0),
                fail_cell(FAILURE_TIMEOUT, "сервер молчит"),
                fail_cell(FAILURE_REFUSED, "порт закрыт"),
            ],
        );
        row.udp_egress = "4.4.4.4".to_string();
        row.secure_egress = "2.2.2.2".to_string();
        row.findings = vec![
            Finding {
                level: crate::server_check::LEVEL_INFO.to_string(),
                code: crate::server_check::CODE_FOREIGN_ANSWERS.to_string(),
                text: "обычные запросы выполняет сеть NSDI, а шифрованные — GOOGLE".to_string(),
                ..Default::default()
            },
            Finding {
                level: crate::server_check::LEVEL_WARN.to_string(),
                code: crate::server_check::CODE_DOT_BLOCKED.to_string(),
                text: "шифрованный DNS по DoT закрыт: сервер молчит".to_string(),
                ..Default::default()
            },
            Finding {
                level: crate::server_check::LEVEL_WARN.to_string(),
                code: crate::server_check::CODE_DOH_BLOCKED.to_string(),
                text: "шифрованный DNS по DoH закрыт: порт закрыт".to_string(),
                ..Default::default()
            },
        ];
        row
    }

    /// python `HEALTHY` — адрес, который отвечает всеми способами.
    pub(crate) fn healthy() -> Observation {
        make_row(
            backup(),
            [
                ok_cell(0.4),
                ok_cell(9.0),
                ok_cell(20.0),
                ok_cell(60.0),
                ok_cell(55.0),
            ],
        )
    }

    /// python `_report` — отчёт с двумя адресами Google DNS и итогом.
    pub(crate) fn base_report(rows: Vec<Observation>) -> ServerCheckReport {
        ServerCheckReport {
            total: rows.len(),
            canary: Some(true),
            owners: vec![
                (
                    "4.4.4.4".to_string(),
                    IpOwner {
                        asn: "8492".to_string(),
                        owner: "NSDI".to_string(),
                        ..Default::default()
                    },
                ),
                (
                    "2.2.2.2".to_string(),
                    IpOwner {
                        asn: "15169".to_string(),
                        owner: "GOOGLE".to_string(),
                        ..Default::default()
                    },
                ),
            ],
            findings: vec![
                Finding {
                    level: crate::server_check::LEVEL_FAIL.to_string(),
                    code: CODE_INTERCEPTED.to_string(),
                    text: "Обычные DNS-запросы перехватываются по дороге.".to_string(),
                    ..Default::default()
                },
                Finding {
                    level: crate::server_check::LEVEL_OK.to_string(),
                    code: CODE_BEST.to_string(),
                    text: "Для защищённого DNS сейчас лучше всего подходит Google DNS (8.8.4.4)."
                        .to_string(),
                    ..Default::default()
                },
            ],
            finished: true,
            elapsed_s: 12.0,
            ..Default::default()
        }
        .with_rows(rows)
    }

    impl ServerCheckReport {
        pub(crate) fn with_rows(mut self, rows: Vec<Observation>) -> Self {
            self.rows = rows;
            self.total = self.rows.len();
            self
        }
    }

    /// python `_server` — один сервер с его адресами и ячейками.
    pub(crate) fn server_rows(
        name: &str,
        addresses: &[&str],
        findings: Vec<Finding>,
        cells: [Cell; 5],
    ) -> Vec<Observation> {
        addresses
            .iter()
            .map(|address| {
                let mut row = make_row(
                    CheckTarget {
                        provider: name.to_string(),
                        address: (*address).to_string(),
                        dot_host: "d".to_string(),
                        doh_host: "d".to_string(),
                        ..Default::default()
                    },
                    cells.clone(),
                );
                row.findings = findings.clone();
                row
            })
            .collect()
    }

    /// python `_mixed_report` — серверы на каждый вывод.
    pub(crate) fn mixed_report() -> ServerCheckReport {
        let spoofed = Finding {
            level: crate::server_check::LEVEL_FAIL.to_string(),
            code: crate::server_check::CODE_SPOOFED.to_string(),
            text: "обычные ответы подменяются: про rutor.info".to_string(),
            ..Default::default()
        };
        let doh_closed = Finding {
            level: crate::server_check::LEVEL_WARN.to_string(),
            code: crate::server_check::CODE_DOH_BLOCKED.to_string(),
            text: "шифрованный DNS по DoH закрыт: порт закрыт".to_string(),
            ..Default::default()
        };
        let mut rows = server_rows(
            "Быстрый",
            &["10.0.0.1"],
            vec![],
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(40.0),
                ok_cell(20.0),
            ],
        );
        rows.extend(server_rows(
            "Медленный",
            &["10.0.1.1", "10.0.1.2"],
            vec![],
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(40.0),
                ok_cell(300.0),
            ],
        ));
        rows.extend(server_rows(
            "Молчун",
            &["10.0.2.1"],
            vec![dead_finding()],
            [
                ok_cell(1.0),
                silent_cell(),
                silent_cell(),
                silent_cell(),
                silent_cell(),
            ],
        ));
        rows.extend(server_rows(
            "Фильтр",
            &["10.0.3.1"],
            vec![Finding {
                level: crate::server_check::LEVEL_INFO.to_string(),
                code: crate::server_check::CODE_SELF_FILTER.to_string(),
                text: "сам не отдаёт адреса сайтов: rutor.info".to_string(),
                ..Default::default()
            }],
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(40.0),
                ok_cell(50.0),
            ],
        ));
        rows.extend(server_rows(
            "Закрытый",
            &["10.0.4.1"],
            vec![spoofed, doh_closed.clone()],
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(40.0),
                fail_cell(FAILURE_REFUSED, "порт закрыт"),
            ],
        ));
        rows.extend(server_rows(
            "Без DoH",
            &["10.0.6.1"],
            vec![doh_closed],
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(40.0),
                fail_cell(FAILURE_REFUSED, "порт закрыт"),
            ],
        ));
        rows.extend(server_rows(
            "Шаткий",
            &["10.0.5.1"],
            vec![Finding {
                level: crate::server_check::LEVEL_WARN.to_string(),
                code: crate::server_check::CODE_UNSTABLE.to_string(),
                text: "отвечает через раз: DoH — 1 из 3 запросов".to_string(),
                ..Default::default()
            }],
            [
                ok_cell(1.0),
                ok_cell(2.0),
                ok_cell(3.0),
                ok_cell(40.0),
                ok_cell(50.0),
            ],
        ));
        ServerCheckReport {
            canary: Some(false),
            findings: vec![],
            finished: true,
            elapsed_s: 12.0,
            ..base_report(rows)
        }
    }
}
