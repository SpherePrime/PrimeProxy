//! Порт `src/dns/runtime.py` — слой «что сделать» пакета `dns`.
//!
//! Цепочка: `dns.winapi` (вызовы Windows) → `dns.adapters` (какие адаптеры
//! наши) → этот модуль (что сделать) → `dns.commands` (публичные команды для
//! фасада).
//!
//! Адаптеры опознаются по GUID. Всё здесь блокирующее и вызывается только из
//! фоновых воркеров.
//!
//! Windows-вызовы (`dns.winapi`) остаются платформенным слоем: они передаются
//! в функции как замыкания ([`DnsIo`]), поэтому чистая логика и решения —
//! какие адаптеры наши, что и куда писать, что показать пользователю —
//! тестируются и без Windows. Журналирование (python `log.log`) тоже остаётся
//! слою фасада: все неудачи и здесь, и в результатах команд — значения.
//!
//! Здесь же живёт запуск замены устаревших адресов провайдеров
//! (`dns.address_migration.migrate_outdated_dns_addresses`): в python он
//! пользуется этим модулем и `winapi`, в Rust ему тоже нужен ввод Windows.

use std::collections::HashMap;
use std::sync::Mutex;

use serde_json::Value;

use crate::adapters::{self, DnsAdapter, InternetRoute, RawInterface, StaticDns};
use crate::address_migration;
use crate::custom_servers;
use crate::local_proxy::{self, LocalProxySystem};
use crate::local_proxy_catalog::Upstream;
use crate::providers;
use crate::reachability::ServerReach;
use crate::state::{DnsCommandResult, DnsState, LineCheck};

/// python `winapi.write_dns` — запись DNS адаптеру: (GUID, серверы, это
/// IPv6?, шаблоны DoH). `Err` — Windows отказала (python `DnsWinApiError`).
/// python `winapi.read_static_dns` — чтение ручных DNS адаптера: `Err` —
/// Windows не отдала (адаптер остаётся с автоматическими DNS).
pub type ReadStaticDnsFn<'a> = Box<dyn Fn(&str) -> Result<StaticDns, String> + 'a>;

/// python `winapi.write_dns` — запись DNS адаптеру: (GUID, серверы, это
/// IPv6?, шаблоны DoH). `Err` — Windows отказала (python `DnsWinApiError`).
pub type WriteDnsFn<'a> =
    Box<dyn Fn(&str, &[String], bool, Option<&[(String, String)]>) -> Result<(), String> + 'a>;

/// python `check_servers` (dns.reachability): отвечает ли сервер из сети
/// пользователя. Живой ввод — [`live_check`]; тесты подставляют свои ответы.
pub type ReachFn<'a> =
    dyn Fn(&[String], &[String], Option<&[(String, String)]>) -> ServerReach + 'a;

/// Ввод Windows-слоя (python `dns.winapi` и соседи) для функций этого модуля.
///
/// Каждый вызов Windows — замыкание: подставив своё, функция проверяется на
/// Linux. `custom_servers` — чтение своих DNS из настроек (python
/// `settings.store.get_custom_dns_servers`, но без сбоев: сбой уже превращён
/// в пустой список — см. [`load_custom_servers`]). `local_proxy_mode`/
/// `local_proxy_server` — режим и плитка работающего шифрованного DNS
/// (dns.local_proxy). `line_check` — прошлая проверка серверов на линии
/// (dns.line_check); нужна только [`load_page_state`].
pub struct DnsIo<'a> {
    /// python `winapi.list_interfaces`.
    pub list_interfaces: Box<dyn Fn() -> Vec<RawInterface> + 'a>,
    /// python `winapi.internet_route`.
    pub internet_route: Box<dyn Fn() -> InternetRoute + 'a>,
    /// python `winapi.read_static_dns`: ручные DNS адаптера; `Err` — Windows
    /// не отдала (адаптер остаётся с автоматическими DNS).
    pub read_static_dns: ReadStaticDnsFn<'a>,
    /// python `winapi.is_doh_supported`.
    pub is_doh_supported: Box<dyn Fn() -> bool + 'a>,
    /// python `winapi.write_dns`.
    pub write_dns: WriteDnsFn<'a>,
    /// python `winapi.flush_resolver_cache`.
    pub flush_resolver_cache: Box<dyn Fn() -> bool + 'a>,
    /// python `runtime.load_custom_servers` — чтение своих DNS из настроек.
    pub custom_servers: Box<dyn Fn() -> Vec<Value> + 'a>,
    /// python `runtime._local_proxy_mode`.
    pub local_proxy_mode: Box<dyn Fn() -> String + 'a>,
    /// python `runtime._local_proxy_server`.
    pub local_proxy_server: Box<dyn Fn() -> String + 'a>,
    /// python `dns.line_check.load_line_check` — результат уже собран.
    pub line_check: Box<dyn Fn() -> Option<LineCheck> + 'a>,
}

// ── состояние ─────────────────────────────────────────────────────────────

/// python `load_state` — адаптеры для страницы DNS с их текущими DNS,
/// наличие IPv6 и DoH.
#[must_use]
pub fn load_state(io: &DnsIo<'_>) -> DnsState {
    let interfaces = (io.list_interfaces)();
    let route = (io.internet_route)();
    let mut static_dns: Vec<(String, StaticDns)> = Vec::new();
    for interface in &interfaces {
        if !adapters::is_dns_adapter(interface, &route) {
            continue;
        }
        // python при сбое чтения пишет в журнал и продолжает: у адаптера
        // останутся автоматические DNS.
        if let Ok(dns) = (io.read_static_dns)(&interface.guid) {
            static_dns.push((interface.guid.clone(), dns));
        }
    }
    DnsState {
        adapters: adapters::build_dns_adapters(&interfaces, &route, &static_dns),
        ipv6_available: route.has_ipv6(),
        doh_supported: (io.is_doh_supported)(),
        local_proxy_mode: (io.local_proxy_mode)(),
        local_proxy_server: (io.local_proxy_server)(),
        custom_servers: (io.custom_servers)(),
        line_check: None,
    }
}

/// python `load_custom_servers` — свои DNS-серверы пользователя из настроек;
/// при сбое чтения — пустой список.
pub fn load_custom_servers(read: impl FnOnce() -> Result<Vec<Value>, String>) -> Vec<Value> {
    read().unwrap_or_default()
}

/// python `write_doh_templates` — {адрес: шаблон DoH} для записи в адаптер
/// или `None`, если Windows DoH не умеет.
///
/// Шаблоны серверов программы и своих серверов пользователя; при совпадении
/// адреса главнее сервер программы.
#[must_use]
pub fn write_doh_templates(doh_supported: bool, custom: &[Value]) -> Option<Vec<(String, String)>> {
    if !doh_supported {
        return None;
    }
    let mut merged = custom_servers::custom_doh_templates(custom);
    for (address, template) in providers::doh_templates() {
        if let Some(item) = merged.iter_mut().find(|(known, _)| *known == address) {
            item.1 = template;
        } else {
            merged.push((address, template));
        }
    }
    Some(merged)
}

/// python `templates[адрес]` — шаблон DoH адреса или `None`.
#[must_use]
pub fn template_for<'t>(templates: &'t [(String, String)], address: &str) -> Option<&'t str> {
    templates
        .iter()
        .find(|(known, _)| known == address)
        .map(|(_, template)| template.as_str())
}

/// python `load_page_state` — состояние для страницы «Настройки DNS»: то же
/// плюс прошлая проверка серверов на этой линии.
#[must_use]
pub fn load_page_state(io: &DnsIo<'_>) -> DnsState {
    let mut state = load_state(io);
    state.line_check = (io.line_check)();
    state
}

static WARMED: Mutex<Option<DnsState>> = Mutex::new(None);

/// python `warm_state` — загружает состояние заранее (после запуска), чтобы
/// страница открылась сразу.
#[must_use]
pub fn warm_state(load: impl FnOnce() -> DnsState) -> DnsState {
    let state = load();
    *WARMED.lock().expect("warmed: блокировка жива") = Some(state.clone());
    state
}

/// python `consume_warmed_state` — отдаёт заранее загруженное состояние один
/// раз.
#[must_use]
pub fn consume_warmed_state() -> Option<DnsState> {
    WARMED.lock().expect("warmed: блокировка жива").take()
}

// ── действия ──────────────────────────────────────────────────────────────

/// python `apply_dns` — прописывает DNS отмеченным адаптерам; пустые списки —
/// вернуть автоматические.
///
/// Обе версии протокола пишутся всегда: если у сервера нет IPv6-адресов,
/// IPv6 возвращается в автоматический режим, чтобы на адаптере не осталось
/// IPv6-адресов прежнего сервера.
///
/// Пишем только адаптерам, которые сейчас есть на странице: Windows молча
/// принимает любой GUID и заводит под него ветку реестра, поэтому исчезнувший
/// адаптер надо отсечь до записи.
///
/// Сервер, который из сети пользователя не отвечает ни одним способом, не
/// ставится вовсе (dns.reachability): его мог заблокировать провайдер, и с
/// ним компьютер остался бы без DNS.
pub fn apply_dns(
    io: &DnsIo<'_>,
    check: &ReachFn<'_>,
    guids: &[String],
    ipv4: &[String],
    ipv6: &[String],
) -> DnsCommandResult {
    // Повторы и пустые GUID отбрасываются с сохранением порядка.
    let mut ordered: Vec<String> = Vec::new();
    for item in guids {
        let guid = item.trim();
        if !guid.is_empty() && !ordered.iter().any(|known| known == guid) {
            ordered.push(guid.to_string());
        }
    }
    let state = load_state(io);
    let templates = write_doh_templates(state.doh_supported, &state.custom_servers);
    let reach = check(ipv4, ipv6, templates.as_deref());
    if !reach.blocked.is_empty() {
        return DnsCommandResult {
            success: false,
            message: reach.blocked,
            total_count: ordered.len() as u32,
            ..DnsCommandResult::default()
        };
    }
    let mut errors: Vec<String> = Vec::new();
    for guid in &ordered {
        let Some(name) = state
            .adapters
            .iter()
            .find(|adapter| adapter.guid == *guid)
            .map(|adapter| adapter.name.clone())
        else {
            errors.push(format!("адаптер {guid} не найден — он отключён или удалён"));
            continue;
        };
        let write = |servers: &[String], is_v6: bool| {
            (io.write_dns)(guid, servers, is_v6, templates.as_deref())
        };
        if let Err(error) = write(ipv4, false).and_then(|()| write(ipv6, true)) {
            errors.push(format!("«{name}»: {error}"));
        }
    }
    // Кэш чистится, только если хоть одному адаптеру что-то записали.
    if errors.len() < ordered.len() {
        (io.flush_resolver_cache)();
    }
    let affected = (ordered.len() - errors.len()) as u32;
    DnsCommandResult {
        success: errors.is_empty(),
        message: errors.join("; "),
        affected_count: affected,
        total_count: ordered.len() as u32,
        doh_closed: reach.doh_closed && affected > 0,
        ..DnsCommandResult::default()
    }
}

/// python `reset_to_auto` — вернуть DNS отмеченных адаптеров в автоматические.
pub fn reset_to_auto(io: &DnsIo<'_>, check: &ReachFn<'_>, guids: &[String]) -> DnsCommandResult {
    apply_dns(io, check, guids, &[], &[])
}

/// python `flush_dns_cache` — очистить кэш DNS Windows.
#[must_use]
pub fn flush_dns_cache(io: &DnsIo<'_>) -> DnsCommandResult {
    if (io.flush_resolver_cache)() {
        return DnsCommandResult {
            success: true,
            ..DnsCommandResult::default()
        };
    }
    DnsCommandResult {
        success: false,
        message: "Windows не смогла очистить кэш DNS".to_string(),
        ..DnsCommandResult::default()
    }
}

// ── шифрованный DNS (встроенный dnscrypt-proxy) ───────────────────────────

/// python `_static_addresses` — все адреса DNS, прописанные вручную на
/// адаптерах страницы.
#[must_use]
pub fn static_addresses(adapters: &[DnsAdapter]) -> Vec<String> {
    adapters
        .iter()
        .flat_map(|adapter| adapter.static_ipv4.iter().chain(adapter.static_ipv6.iter()))
        .cloned()
        .collect()
}

/// python `start_local_proxy` — запускает шифрованный DNS; адаптеры не
/// трогает — их пишет [`apply_dns`] после успеха.
///
/// `upstreams` и `server_name` — серверы и название плитки для режима DoH.
pub fn start_local_proxy(
    system: &mut dyn LocalProxySystem,
    mode: &str,
    upstreams: &[Upstream],
    server_name: &str,
) -> DnsCommandResult {
    let result = local_proxy::start(mode, upstreams, server_name, system);
    DnsCommandResult {
        success: result.success,
        message: result.message,
        listen_ipv6: result.listen_ipv6,
        ..DnsCommandResult::default()
    }
}

/// python `stop_local_proxy_if_unused` — после смены DNS: движок убирается,
/// если на 127.0.0.1 больше никто не смотрит.
pub fn stop_local_proxy_if_unused(io: &DnsIo<'_>, system: &mut dyn LocalProxySystem) -> bool {
    let addresses = static_addresses(&load_state(io).adapters);
    local_proxy::stop_if_unused(addresses.iter().map(String::as_str), system)
}

/// python `repair_local_proxy` — проверка шифрованного DNS при запуске
/// программы (см. `local_proxy::repair`).
#[must_use]
pub fn repair_local_proxy(io: &DnsIo<'_>, system: &mut dyn LocalProxySystem) -> String {
    let addresses = static_addresses(&load_state(io).adapters);
    let summary = local_proxy::repair(addresses.iter().map(String::as_str), system);
    if !summary.is_empty() {
        (io.flush_resolver_cache)();
    }
    summary
}

/// python `adapters_with_static_dns` — адаптеры с ручными DNS.
#[must_use]
pub fn adapters_with_static_dns(adapters: &[DnsAdapter]) -> Vec<DnsAdapter> {
    adapters
        .iter()
        .filter(|adapter| !adapter.is_automatic())
        .cloned()
        .collect()
}

/// python `address_migration.migrate_outdated_dns_addresses` — меняет старые
/// адреса провайдеров на адаптерах страницы DNS.
///
/// Трогает только адреса, прописанные вручную; автоматические (DHCP) не
/// меняются. Возвращает список изменений в виде строк для лога.
///
/// `replacements` — пары «старый адрес → новый»; `None` — встроенный список
/// (`providers::outdated_dns_address_replacements`).
pub fn migrate_outdated_dns_addresses(
    replacements: Option<&HashMap<String, String>>,
    io: &DnsIo<'_>,
) -> Vec<String> {
    let state = load_state(io);
    let templates = write_doh_templates(state.doh_supported, &state.custom_servers);
    let replacements: HashMap<String, String> = match replacements {
        Some(map) => map.clone(),
        None => providers::outdated_dns_address_replacements()
            .iter()
            .map(|(old, new)| ((*old).to_string(), (*new).to_string()))
            .collect(),
    };
    let usable = address_migration::usable_replacements(&replacements, templates.is_some());
    let mut changes: Vec<String> = Vec::new();
    for adapter in adapters_with_static_dns(&state.adapters) {
        for (is_v6, current) in [
            (false, adapter.static_ipv4.clone()),
            (true, adapter.static_ipv6.clone()),
        ] {
            let Some(new_servers) = address_migration::plan_dns_server_migration(&current, &usable)
            else {
                continue;
            };
            let family = if is_v6 { "IPv6" } else { "IPv4" };
            let summary = format!(
                "{} ({family}): {} -> {}",
                adapter.name,
                current.join(", "),
                new_servers.join(", ")
            );
            if (io.write_dns)(&adapter.guid, &new_servers, is_v6, templates.as_deref()).is_err() {
                // python пишет в журнал и идёт к следующей семье адресов.
                continue;
            }
            changes.push(summary);
        }
    }
    if !changes.is_empty() {
        (io.flush_resolver_cache)();
    }
    changes
}

/// Живая проверка достижимости серверов (python `check_servers` из
/// dns.reachability с настоящими запросами).
#[must_use]
#[allow(clippy::double_must_use)] // замыкание-обёртка: must_use у ReachFn теряется в Box
pub fn live_check() -> Box<ReachFn<'static>> {
    Box::new(
        |ipv4: &[String], ipv6: &[String], templates: Option<&[(String, String)]>| {
            crate::reachability::check_servers(ipv4, ipv6, templates.unwrap_or(&[]))
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::Cell;
    use std::cell::RefCell;

    const ETH: &str = "{00000000-0000-0000-0000-000000000009}";
    const WIFI: &str = "{00000000-0000-0000-0000-000000000012}";
    const GHOST: &str = "{00000000-0000-0000-0000-000000000000}";

    type WriteRecord = (String, Vec<String>, bool, Option<Vec<(String, String)>>);

    /// python `_FakeWinApi` — Windows для тестов: записи и кэш — в памяти.
    struct FakeWinApi {
        doh: bool,
        fail: Vec<String>,
        writes: RefCell<Vec<WriteRecord>>,
        flushes: Cell<u32>,
    }

    impl FakeWinApi {
        fn new(doh: bool) -> Self {
            Self {
                doh,
                fail: Vec::new(),
                writes: RefCell::new(Vec::new()),
                flushes: Cell::new(0),
            }
        }
    }

    fn interface(guid: &str, name: &str, if_type: u32) -> RawInterface {
        RawInterface {
            guid: guid.to_string(),
            index: 1,
            ipv6_index: 1,
            name: name.to_string(),
            description: format!("описание {name}"),
            if_type,
            connected: true,
            hardware: true,
            filter: false,
            connector: true,
            dns_ipv4: Vec::new(),
            dns_ipv6: Vec::new(),
        }
    }

    /// python `KNOWN` — два известных адаптера: Ethernet (интернет) и Wi-Fi.
    fn known_io(fake: &FakeWinApi, custom: Vec<Value>) -> DnsIo<'_> {
        DnsIo {
            list_interfaces: Box::new(|| {
                vec![
                    interface(ETH, "Ethernet", adapters::IF_TYPE_ETHERNET_CSMACD),
                    interface(WIFI, "Беспроводная сеть", adapters::IF_TYPE_IEEE80211),
                ]
            }),
            internet_route: Box::new(|| InternetRoute {
                ipv4_index: 1,
                ipv6_index: 0,
            }),
            read_static_dns: Box::new(|_guid| Ok(StaticDns::default())),
            is_doh_supported: Box::new(move || fake.doh),
            write_dns: Box::new(move |guid, servers, is_v6, templates| {
                if fake.fail.iter().any(|item| item == guid) {
                    return Err(
                        "SetInterfaceDnsSettings: ошибка Windows 5 — Отказано в доступе."
                            .to_string(),
                    );
                }
                fake.writes.borrow_mut().push((
                    guid.to_string(),
                    servers.to_vec(),
                    is_v6,
                    templates.map(<[(String, String)]>::to_vec),
                ));
                Ok(())
            }),
            flush_resolver_cache: Box::new(|| {
                fake.flushes.set(fake.flushes.get() + 1);
                true
            }),
            custom_servers: Box::new(move || custom.clone()),
            local_proxy_mode: Box::new(String::new),
            local_proxy_server: Box::new(String::new),
            line_check: Box::new(|| None),
        }
    }

    /// python `self.reach` — сервер считается отвечающим, если тест не говорит
    /// иного.
    fn silent_check() -> Box<ReachFn<'static>> {
        Box::new(
            |_ipv4: &[String], _ipv6: &[String], _templates: Option<&[(String, String)]>| {
                ServerReach::default()
            },
        )
    }

    fn blocked_check(message: &str) -> Box<ReachFn<'static>> {
        let message = message.to_string();
        Box::new(move |_ipv4, _ipv6, _templates| ServerReach {
            blocked: message.clone(),
            ..ServerReach::default()
        })
    }

    fn doh_closed_check() -> Box<ReachFn<'static>> {
        Box::new(|_ipv4, _ipv6, _templates| ServerReach {
            blocked: String::new(),
            doh_closed: true,
        })
    }

    fn custom_server(id: &str, name: &str, ipv4: &[&str], ipv6: &[&str], doh: &str) -> Value {
        serde_json::json!({
            "id": id,
            "name": name,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "doh": doh,
        })
    }

    #[test]
    fn server_that_does_not_answer_is_not_applied() {
        // Заблокированный провайдером сервер не ставится: с ним не осталось бы DNS.
        let fake = FakeWinApi::new(false);
        let io = known_io(&fake, Vec::new());
        let check = blocked_check("Сервер 144.31.82.230 не отвечает из вашей сети");

        let result = apply_dns(
            &io,
            &check,
            &[ETH.to_string(), WIFI.to_string()],
            &["144.31.82.230".to_string()],
            &[],
        );

        assert!(!result.success);
        assert!(fake.writes.borrow().is_empty());
        assert_eq!(fake.flushes.get(), 0);
        assert_eq!((result.affected_count, result.total_count), (0, 2));
        assert!(result.message.contains("не отвечает из вашей сети"));
    }

    #[test]
    fn closed_doh_is_carried_to_the_result_only_when_dns_is_set() {
        let fake = FakeWinApi::new(true);
        let io = known_io(&fake, Vec::new());
        let check = doh_closed_check();

        let result = apply_dns(
            &io,
            &check,
            &[ETH.to_string()],
            &["9.9.9.9".to_string()],
            &[],
        );
        assert_eq!((result.success, result.doh_closed), (true, true));

        let nothing_set = apply_dns(
            &io,
            &check,
            &["{00000000-0000-0000-0000-00000000dead}".to_string()],
            &["9.9.9.9".to_string()],
            &[],
        );
        assert!(!nothing_set.doh_closed);
    }

    #[test]
    fn apply_writes_both_families_then_flushes_cache() {
        let fake = FakeWinApi::new(false);
        let io = known_io(&fake, Vec::new());

        let result = apply_dns(
            &io,
            &silent_check(),
            &[ETH.to_string(), WIFI.to_string(), ETH.to_string()],
            &["1.1.1.1".to_string(), "1.0.0.1".to_string()],
            &[],
        );

        assert_eq!(
            *fake.writes.borrow(),
            vec![
                (
                    ETH.to_string(),
                    vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
                    false,
                    None
                ),
                (ETH.to_string(), Vec::<String>::new(), true, None),
                (
                    WIFI.to_string(),
                    vec!["1.1.1.1".to_string(), "1.0.0.1".to_string()],
                    false,
                    None
                ),
                (WIFI.to_string(), Vec::<String>::new(), true, None),
            ]
        );
        assert_eq!(fake.flushes.get(), 1);
        assert!(result.success);
        assert_eq!((result.affected_count, result.total_count), (2, 2));
    }

    #[test]
    fn windows_11_gets_doh_templates_for_known_servers() {
        let fake = FakeWinApi::new(true);
        let io = known_io(&fake, Vec::new());

        reset_to_auto(&io, &silent_check(), &[ETH.to_string()]);

        let writes = fake.writes.borrow();
        assert_eq!(
            writes
                .iter()
                .map(|(_, servers, _, _)| servers.clone())
                .collect::<Vec<_>>(),
            vec![Vec::<String>::new(), Vec::<String>::new()]
        );
        assert_eq!(writes[0].3.as_ref(), Some(&providers::doh_templates()));
    }

    #[test]
    fn custom_server_addresses_get_their_own_doh_template() {
        let fake = FakeWinApi::new(true);
        let custom = vec![
            custom_server(
                "a",
                "Мой",
                &["203.0.113.5"],
                &["2001:db8::5"],
                "https://dns.example.com/dns-query",
            ),
            custom_server("b", "Без шифрования", &["203.0.113.9"], &[], ""),
            // Свой сервер с адресом сервера программы шаблон программы не перебивает.
            custom_server(
                "c",
                "Подмена",
                &["1.1.1.1"],
                &[],
                "https://other.example/dns-query",
            ),
        ];
        let io = known_io(&fake, custom);

        apply_dns(
            &io,
            &silent_check(),
            &[ETH.to_string()],
            &["203.0.113.5".to_string()],
            &["2001:db8::5".to_string()],
        );

        let writes = fake.writes.borrow();
        let templates = writes[0].3.as_ref().expect("шаблоны DoH переданы");
        assert_eq!(
            template_for(templates, "203.0.113.5"),
            Some("https://dns.example.com/dns-query")
        );
        assert_eq!(
            template_for(templates, "2001:db8::5"),
            Some("https://dns.example.com/dns-query")
        );
        assert_eq!(template_for(templates, "203.0.113.9"), None);
        // Свой сервер с адресом сервера программы: шаблон программы главнее.
        assert_eq!(
            template_for(templates, "1.1.1.1"),
            template_for(&providers::doh_templates(), "1.1.1.1")
        );
        assert_eq!(writes[1].3.as_ref(), Some(templates));
    }

    #[test]
    fn windows_without_doh_gets_no_templates_even_for_custom_servers() {
        let fake = FakeWinApi::new(false);
        let custom = vec![custom_server(
            "a",
            "Мой",
            &["203.0.113.5"],
            &[],
            "https://dns.example.com/dns-query",
        )];
        let io = known_io(&fake, custom);

        apply_dns(
            &io,
            &silent_check(),
            &[ETH.to_string()],
            &["203.0.113.5".to_string()],
            &[],
        );

        assert_eq!(fake.writes.borrow()[0].3, None);
    }

    #[test]
    fn state_carries_custom_servers_from_settings() {
        let custom = vec![custom_server("a", "Мой", &["203.0.113.5"], &[], "")];
        let fake = FakeWinApi::new(true);
        let io = known_io(&fake, custom.clone());

        let state = load_state(&io);

        assert_eq!(state.custom_servers, custom);
    }

    #[test]
    fn unreadable_settings_give_no_custom_servers() {
        assert!(load_custom_servers(|| Err("база занята".to_string())).is_empty());
    }

    #[test]
    fn failed_adapter_is_reported_by_name() {
        let mut fake = FakeWinApi::new(false);
        fake.fail = vec![WIFI.to_string()];
        let io = known_io(&fake, Vec::new());

        let result = apply_dns(
            &io,
            &silent_check(),
            &[ETH.to_string(), WIFI.to_string()],
            &["9.9.9.9".to_string()],
            &["2620:fe::fe".to_string()],
        );

        assert!(!result.success);
        assert_eq!((result.affected_count, result.total_count), (1, 2));
        assert!(result
            .message
            .contains("«Беспроводная сеть»: SetInterfaceDnsSettings: ошибка Windows 5"));
    }

    #[test]
    fn unknown_adapter_is_never_written() {
        // Windows молча принимает любой GUID и заводит под него ветку реестра.
        let fake = FakeWinApi::new(false);
        let io = known_io(&fake, Vec::new());

        let result = apply_dns(
            &io,
            &silent_check(),
            &[GHOST.to_string()],
            &["1.1.1.1".to_string()],
            &[],
        );

        assert!(fake.writes.borrow().is_empty());
        assert_eq!(fake.flushes.get(), 0);
        assert!(!result.success);
        assert!(result.message.contains("не найден"));
    }

    #[test]
    fn warmed_state_is_given_out_once() {
        let _ = warm_state(DnsState::default);

        assert!(consume_warmed_state().is_some());
        assert!(consume_warmed_state().is_none());
    }

    #[test]
    fn page_state_adds_the_last_server_check_on_this_line() {
        let line = LineCheck {
            time: "2026-10-12T21:05:00".to_string(),
            cards: vec![("Quad9".to_string(), "ok".to_string(), String::new())],
        };
        let fake = FakeWinApi::new(false);
        let mut io = known_io(&fake, Vec::new());
        io.line_check = Box::new(move || Some(line.clone()));

        let state = load_page_state(&io);

        assert_eq!(
            state.line_check.as_ref().map(|check| check.time.as_str()),
            Some("2026-10-12T21:05:00")
        );
        assert_eq!(
            state.line_check.and_then(|check| check.card("Quad9")),
            Some(("ok".to_string(), String::new()))
        );
    }

    fn migration_io<'a>(
        fake: &'a FakeWinApi,
        ethernet_ipv4: &[&str],
        ethernet_ipv6: &[&str],
    ) -> DnsIo<'a> {
        let mut io = known_io(fake, Vec::new());
        let ipv4: Vec<String> = ethernet_ipv4.iter().map(|item| item.to_string()).collect();
        let ipv6: Vec<String> = ethernet_ipv6.iter().map(|item| item.to_string()).collect();
        io.read_static_dns = Box::new(move |guid: &str| {
            if guid == ETH {
                return Ok(StaticDns {
                    ipv4: ipv4.clone(),
                    ipv6: ipv6.clone(),
                });
            }
            if guid == WIFI {
                return Ok(StaticDns {
                    ipv4: vec!["1.1.1.1".to_string()],
                    ipv6: Vec::new(),
                });
            }
            Ok(StaticDns::default())
        });
        io
    }

    #[test]
    fn migration_replaces_only_outdated_static_addresses() {
        let fake = FakeWinApi::new(true);
        let io = migration_io(
            &fake,
            &["176.99.11.77", "80.78.247.254"],
            &["2a00:ab00:1233:26::50"],
        );

        let changes = migrate_outdated_dns_addresses(None, &io);

        // Xbox DNS закрыл сервисы ИИ: его адреса переходят на DNS-AI, чужой
        // 1.1.1.1 не трогают.
        let writes = fake.writes.borrow();
        let plain: Vec<(String, Vec<String>, bool)> = writes
            .iter()
            .map(|(guid, servers, is_v6, _): &WriteRecord| (guid.clone(), servers.clone(), *is_v6))
            .collect();
        assert_eq!(
            plain,
            vec![
                (
                    ETH.to_string(),
                    vec!["192.144.59.14".to_string(), "186.246.49.127".to_string()],
                    false
                ),
                (
                    ETH.to_string(),
                    vec!["2a0d:8480:0:67c::14".to_string()],
                    true
                ),
            ]
        );
        // DNS-AI принимает только шифрованные запросы: адреса пишутся вместе
        // с его шаблоном DoH.
        for (_, _, _, templates) in writes.iter() {
            let templates = templates.as_ref().expect("шаблоны переданы");
            assert_eq!(
                template_for(templates, "192.144.59.14"),
                Some("https://dns.dns-ai.ru/dns-query")
            );
        }
        assert_eq!(changes.len(), 2);
        assert_eq!(fake.flushes.get(), 1);
    }

    #[test]
    fn migration_to_encrypted_only_server_is_skipped_without_doh() {
        // Без DoH система не сможет спросить DNS-AI: адаптер остался бы без DNS.
        let fake = FakeWinApi::new(false);
        let io = migration_io(&fake, &["111.88.96.54", "111.88.96.55"], &[]);

        let changes = migrate_outdated_dns_addresses(None, &io);

        assert!(fake.writes.borrow().is_empty());
        assert!(changes.is_empty());
        assert_eq!(fake.flushes.get(), 0);
    }

    #[test]
    fn every_provider_with_doh_has_templates_for_all_addresses() {
        let templates = providers::doh_templates();
        for (_group, name, data) in providers::iter_providers() {
            let strings = |items: Option<&Vec<Value>>| -> Vec<String> {
                items
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_string)
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let mut addresses: Vec<String> = strings(data.get("ipv4").and_then(Value::as_array));
            addresses.extend(strings(data.get("ipv6").and_then(Value::as_array)));
            for address in addresses {
                let doh = data.get("doh").and_then(Value::as_str).unwrap_or("");
                let found = template_for(&templates, &address);
                if !doh.is_empty() {
                    assert_eq!(found, Some(doh), "{name}: {address}");
                } else {
                    // У сервера без DoH шаблона нет: Windows не шифрует запросы к нему.
                    assert_eq!(found, None, "{name}: {address}");
                }
            }
        }
    }

    #[test]
    fn hosts_dns_services_are_available_as_dns_servers() {
        let ai = providers::dns_providers()
            .get("Для ИИ")
            .expect("группа есть");

        let astracat = ai.get("AstraCat").expect("плитка есть");
        assert_eq!(
            astracat.get("ipv4"),
            Some(&json!(["135.106.217.200", "135.106.197.22"])),
            "список"
        );
        let geohide = ai.get("GeoHide").expect("плитка есть");
        assert_eq!(
            geohide.get("ipv4"),
            Some(&json!(["193.233.112.67", "193.233.112.68"])),
            "список"
        );
        // Серверы, которые перестали отвечать, из списка убраны.
        assert!(ai.get("dns.malw.link").is_none());
        assert!(ai.get("Xbox DNS (old)").is_none());
        // Xbox DNS закрыл сервисы ИИ и отвечает на них пустым адресом.
        assert!(ai.get("Xbox DNS").is_none());
        assert!(ai.get("Xbox DNS v2").is_none());
    }

    #[test]
    fn adapters_with_static_dns_filters_automatic_ones() {
        let ethernet = DnsAdapter {
            guid: ETH.to_string(),
            static_ipv4: vec!["1.1.1.1".to_string()],
            ..DnsAdapter::default()
        };
        let wifi = DnsAdapter {
            guid: WIFI.to_string(),
            ..DnsAdapter::default()
        };

        let kept = adapters_with_static_dns(&[ethernet, wifi]);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].guid, ETH);
    }
}
