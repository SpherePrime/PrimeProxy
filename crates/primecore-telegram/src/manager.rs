//! Менеджер жизненного цикла прокси: запуск, остановка, статус.
//!
//! Порт чистой части `telegram_proxy/manager.py` (класс
//! `TelegramProxyManager`). Сам менеджер в python — QThread с сигналами
//! `status_changed(bool)` и `upstream_state_changed(object)`: в Rust сигналы
//! становятся замыканиями, а реальный runtime прокси (asyncio-сервер
//! `TelegramProxyRuntime` из `wss_proxy.py`) — трейтом [`ProxyRuntime`],
//! который передаётся фабрикой при запуске.
//!
//! Чистые решения, оставшиеся здесь: какое состояние считается «запущенным»,
//! когда рестарт меняется на остановку и запуск, какие значения отдаются
//! без запущенного runtime и что берётся из хранилища для автозапуска.

use crate::config::settings::{
    build_cloudflare_config, build_dc_endpoint_overrides, build_upstream_config,
    ensure_mtproxy_secret_for_mode, normalize_buffer_kb, normalize_pool_size, normalize_proxy_mode,
    TelegramSettingsReader, DEFAULT_HOST, DEFAULT_PORT,
};
use crate::config::upstream_catalog::UpstreamPresetResolver;
use crate::proxy::cloudflare::CloudflareFallbackConfig;
use crate::proxy::routing::UpstreamProxyConfig;
use crate::proxy::stats::ProxyStats;
use crate::proxy::upstream_controller::UpstreamRuntimeSnapshot;
use crate::runtime::TelegramProxyStore;

/// Работающий прокси с точки зрения менеджера
/// (python `TelegramProxyRuntime` в `manager.py`).
///
/// Реализация остаётся у вызывающего кода: в python это asyncio-сервер, в
/// крейте сетевых действий нет.
pub trait ProxyRuntime {
    /// Прокси принимает соединения.
    fn is_running(&self) -> bool;
    /// Живая статистика; `None` — статистики нет.
    fn stats(&self) -> Option<ProxyStats>;
    /// Порт локального прокси.
    fn port(&self) -> i64;
    /// Режим локального прокси (`socks5` или `mtproxy`).
    fn mode(&self) -> String;
    /// Хост локального прокси.
    fn host(&self) -> String;
    /// Снимок состояния внешнего SOCKS5; `None` — состояния нет.
    fn upstream_state(&self) -> Option<UpstreamRuntimeSnapshot>;
    /// Запуск сервера; `false` — запустить не удалось.
    fn start(&mut self) -> bool;
    /// Остановка сервера.
    fn stop(&mut self);
    /// Горячая замена upstream-конфига; `false` — заменить не удалось.
    fn apply_upstream_config(&mut self, config: Option<UpstreamProxyConfig>) -> bool;
}

/// Параметры запуска прокси (python `TelegramProxyStartConfig` из
/// `runtime/commands.py` и аргументы `manager.start_proxy`).
///
/// Значения по умолчанию совпадают с python: порт `1353`, режим `socks5`,
/// хост `127.0.0.1`, пул `4`, буфер `256` КБ.
#[derive(Debug, Clone, PartialEq)]
pub struct ProxyStartParams {
    /// Порт локального прокси.
    pub port: i64,
    /// Режим локального прокси (`socks5` или `mtproxy`).
    pub mode: String,
    /// Хост локального прокси.
    pub host: String,
    /// Конфиг внешнего SOCKS5 (`None` — не используется).
    pub upstream_config: Option<UpstreamProxyConfig>,
    /// Конфиг своего домена Cloudflare (`None` — не используется).
    pub cloudflare_config: Option<CloudflareFallbackConfig>,
    /// Секрет MTProxy (пустой для SOCKS5).
    pub mtproxy_secret: String,
    /// Переопределения адресов DC (`dc → host`).
    pub dc_endpoint_overrides: Vec<(i32, String)>,
    /// Размер пула запасных соединений.
    pub pool_size: i64,
    /// Размер буфера в КБ.
    pub buffer_kb: i64,
    /// Домен Fake TLS для MTProxy.
    pub fake_tls_domain: String,
    /// Отдавать ли PROXY-протокол перед данными Telegram.
    pub proxy_protocol: bool,
}

impl Default for ProxyStartParams {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            mode: "socks5".to_string(),
            host: DEFAULT_HOST.to_string(),
            upstream_config: None,
            cloudflare_config: None,
            mtproxy_secret: String::new(),
            dc_endpoint_overrides: Vec::new(),
            pool_size: 4,
            buffer_kb: 256,
            fake_tls_domain: String::new(),
            proxy_protocol: false,
        }
    }
}

/// Менеджер прокси (python `TelegramProxyManager` без QThread).
///
/// Сигналы python стали замыканиями: `on_log`, `on_status_changed`,
/// `on_upstream_state` (см. [`Self::new`]).
pub struct TelegramProxyManager<R: ProxyRuntime> {
    runtime: Option<R>,
    upstream_state: Option<UpstreamRuntimeSnapshot>,
    on_log: Box<dyn Fn(&str)>,
    on_status_changed: Box<dyn Fn(bool)>,
    on_upstream_state: Box<dyn Fn(&UpstreamRuntimeSnapshot)>,
}

impl<R: ProxyRuntime> TelegramProxyManager<R> {
    /// Новый менеджер без запущенного прокси.
    #[must_use]
    pub fn new(
        on_log: Box<dyn Fn(&str)>,
        on_status_changed: Box<dyn Fn(bool)>,
        on_upstream_state: Box<dyn Fn(&UpstreamRuntimeSnapshot)>,
    ) -> Self {
        Self {
            runtime: None,
            upstream_state: None,
            on_log,
            on_status_changed,
            on_upstream_state,
        }
    }

    /// Прокси запущен.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.runtime
            .as_ref()
            .is_some_and(|runtime| runtime.is_running())
    }

    /// Живая статистика запущенного прокси.
    #[must_use]
    pub fn stats(&self) -> Option<ProxyStats> {
        self.runtime.as_ref().and_then(|runtime| runtime.stats())
    }

    /// Снимок состояния внешнего SOCKS5: сначала runtime, затем последний
    /// полученный (python держит его после остановки прокси).
    #[must_use]
    pub fn upstream_state(&self) -> Option<UpstreamRuntimeSnapshot> {
        if let Some(runtime) = &self.runtime {
            if let Some(state) = runtime.upstream_state() {
                return Some(state);
            }
        }
        self.upstream_state.clone()
    }

    /// Порт: из runtime или `1353` без запущенного прокси.
    #[must_use]
    pub fn port(&self) -> i64 {
        self.runtime
            .as_ref()
            .map_or(DEFAULT_PORT, |runtime| runtime.port())
    }

    /// Режим: из runtime или `socks5` без запущенного прокси.
    #[must_use]
    pub fn mode(&self) -> String {
        self.runtime
            .as_ref()
            .map_or_else(|| "socks5".to_string(), |runtime| runtime.mode())
    }

    /// Хост: из runtime или `127.0.0.1` без запущенного прокси.
    #[must_use]
    pub fn host(&self) -> String {
        self.runtime
            .as_ref()
            .map_or_else(|| DEFAULT_HOST.to_string(), |runtime| runtime.host())
    }

    /// python `start_proxy`: запуск прокси. Запущенный прокси не
    /// перезапускается — возвращается `false`. Runtime создаёт `factory`;
    /// создание asyncio-сервера — платформа. При неудаче запуска runtime
    /// всё равно остаётся у менеджера (как python), но сигнал статуса не
    /// отправляется.
    pub fn start_proxy(
        &mut self,
        params: &ProxyStartParams,
        factory: &dyn Fn(&ProxyStartParams) -> R,
    ) -> bool {
        if self.is_running() {
            return false;
        }
        let mut runtime = factory(params);
        let ok = runtime.start();
        self.runtime = Some(runtime);
        if ok {
            (self.on_status_changed)(true);
        } else {
            (self.on_log)("Failed to start proxy");
        }
        ok
    }

    /// python `stop_proxy`: остановка прокси и сигнал статуса. Без runtime
    /// ничего не делает и сигнал не отправляет.
    pub fn stop_proxy(&mut self) {
        let Some(mut runtime) = self.runtime.take() else {
            return;
        };
        runtime.stop();
        (self.on_status_changed)(false);
    }

    /// python `_stop_runtime_only`: остановка только runtime, без сигнала
    /// статуса. Вызывается из любого потока; Qt-очистка (таймер, сигнал) в
    /// python выполняется отдельно на GUI-потоке.
    pub fn stop_runtime_only(&mut self) {
        if let Some(mut runtime) = self.runtime.take() {
            runtime.stop();
        }
        // python дополнительно проверяет `self._runtime is runtime` для
        // многопоточности: в Rust здесь нет повторного входа.
    }

    /// python `apply_upstream_config`: горячая замена upstream-конфига без
    /// рестарта. `false` — прокси не запущен.
    pub fn apply_upstream_config(&mut self, config: Option<UpstreamProxyConfig>) -> bool {
        match &mut self.runtime {
            Some(runtime) => runtime.apply_upstream_config(config),
            None => false,
        }
    }

    /// python `restart_proxy`: остановка, затем запуск с новым конфигом.
    pub fn restart_proxy(
        &mut self,
        params: &ProxyStartParams,
        factory: &dyn Fn(&ProxyStartParams) -> R,
    ) -> bool {
        self.stop_proxy();
        self.start_proxy(params, factory)
    }

    /// python `cleanup`: вызывается при выходе из программы. Сигнал статуса
    /// не отправляется.
    pub fn cleanup(&mut self) {
        if let Some(mut runtime) = self.runtime.take() {
            runtime.stop();
        }
    }

    /// python `_on_upstream_state`: снимок состояния апстримов запоминается
    /// и отправляется слушателям.
    pub fn receive_upstream_state(&mut self, state: UpstreamRuntimeSnapshot) {
        (self.on_upstream_state)(&state);
        self.upstream_state = Some(state);
    }
}

/// Конфиг внешнего SOCKS5 из хранилища (python
/// `build_upstream_proxy_config_from_settings`).
///
/// Сбой хранилища даёт `None` — прокси работает без внешнего SOCKS5.
#[must_use]
pub fn build_upstream_proxy_config_from_settings(
    store: &dyn TelegramSettingsReader,
    resolver: &UpstreamPresetResolver,
) -> Option<UpstreamProxyConfig> {
    build_upstream_config(store, resolver)
}

/// Конфиг своего домена Cloudflare из хранилища (python
/// `build_cloudflare_proxy_config_from_settings`); сбой даёт конфиг по
/// умолчанию (всё выключено).
#[must_use]
pub fn build_cloudflare_proxy_config_from_settings(
    store: &dyn TelegramSettingsReader,
) -> CloudflareFallbackConfig {
    build_cloudflare_config(store)
}

/// Переопределения адресов DC из хранилища (python
/// `build_dc_endpoint_overrides_from_settings`); сбой даёт пустой список.
#[must_use]
pub fn build_dc_endpoint_overrides_from_settings(
    store: &dyn TelegramSettingsReader,
) -> Vec<(i32, String)> {
    build_dc_endpoint_overrides(store)
}

/// python `start_proxy_if_enabled_async`: параметры автозапуска из хранилища.
///
/// `None` — автозапуск выключен. Нормализация режима, размера пула и буфера
/// в python обёрнута в `try/except` с запасными значениями; в Rust эти
/// функции тотальны, поэтому запасные значения совпадают с их собственными
/// значениями по умолчанию.
#[must_use]
pub fn autostart_params(
    store: &mut dyn TelegramProxyStore,
    resolver: &UpstreamPresetResolver,
) -> Option<ProxyStartParams> {
    if !store.get_tg_proxy_enabled() {
        return None;
    }
    let mode_value = store.get_tg_proxy_mode();
    let mode = normalize_proxy_mode(&mode_value);
    let mtproxy_secret =
        ensure_mtproxy_secret_for_mode(&mode_value, &store.get_tg_proxy_mtproxy_secret(), store);
    let host = store.get_tg_proxy_host();
    let port = store.get_tg_proxy_port();
    Some(ProxyStartParams {
        port: if port == 0 { DEFAULT_PORT } else { port },
        mode,
        host: if host.is_empty() {
            DEFAULT_HOST.to_string()
        } else {
            host
        },
        upstream_config: build_upstream_config(store, resolver),
        cloudflare_config: Some(build_cloudflare_config(store)),
        mtproxy_secret,
        dc_endpoint_overrides: build_dc_endpoint_overrides(store),
        pool_size: normalize_pool_size(&store.get_tg_proxy_pool_size()),
        buffer_kb: normalize_buffer_kb(&store.get_tg_proxy_buffer_kb()),
        fake_tls_domain: crate::proxy::fake_tls::normalize_fake_tls_domain(
            &store.get_tg_proxy_fake_tls_domain(),
        ),
        proxy_protocol: store.get_tg_proxy_proxy_protocol(),
    })
}

/// python `start_proxy_if_enabled_async`: автозапуск по настройкам.
///
/// В python старт уходит в фоновый поток, а функция возвращает `true` как
/// признак «старт запланирован». Здесь запуск синхронный: фон остаётся у
/// вызывающего кода, а результат — итог запуска. `false` — автозапуск
/// выключен или прокси уже работает.
pub fn start_proxy_if_enabled_async<R: ProxyRuntime>(
    manager: &mut TelegramProxyManager<R>,
    factory: &dyn Fn(&ProxyStartParams) -> R,
    store: &mut dyn TelegramProxyStore,
    resolver: &UpstreamPresetResolver,
) -> bool {
    if !store.get_tg_proxy_enabled() {
        return false;
    }
    if manager.is_running() {
        return false;
    }
    let Some(params) = autostart_params(store, resolver) else {
        return false;
    };
    manager.start_proxy(&params, factory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::settings::TelegramSettingsWriter;
    use crate::runtime::TelegramProxyStoreReader;
    use serde_json::{json, Value};
    use std::cell::RefCell;
    use std::rc::Rc;

    /// Подменный runtime: запоминает действия менеджера в журнал строк.
    struct FakeRuntime {
        running: bool,
        start_ok: bool,
        port: i64,
        mode: String,
        host: String,
        state: Option<UpstreamRuntimeSnapshot>,
        events: Rc<RefCell<Vec<String>>>,
    }

    impl FakeRuntime {
        fn new(port: i64, start_ok: bool, events: Rc<RefCell<Vec<String>>>) -> Self {
            Self {
                running: false,
                start_ok,
                port,
                mode: "mtproxy".to_string(),
                host: "10.1.2.3".to_string(),
                state: None,
                events,
            }
        }
    }

    impl ProxyRuntime for FakeRuntime {
        fn is_running(&self) -> bool {
            self.running
        }
        fn stats(&self) -> Option<ProxyStats> {
            None
        }
        fn port(&self) -> i64 {
            self.port
        }
        fn mode(&self) -> String {
            self.mode.clone()
        }
        fn host(&self) -> String {
            self.host.clone()
        }
        fn upstream_state(&self) -> Option<UpstreamRuntimeSnapshot> {
            self.state.clone()
        }
        fn start(&mut self) -> bool {
            self.events
                .borrow_mut()
                .push(format!("start:{}", self.port));
            self.running = self.start_ok;
            self.start_ok
        }
        fn stop(&mut self) {
            self.events.borrow_mut().push("stop".to_string());
            self.running = false;
        }
        fn apply_upstream_config(&mut self, config: Option<UpstreamProxyConfig>) -> bool {
            let port = config.as_ref().map_or(-1, |upstream| upstream.port);
            self.events.borrow_mut().push(format!("apply:{port}"));
            true
        }
    }

    /// Новый runtime для каждого запуска (python создаёт TelegramProxyRuntime).
    fn factory(
        events: &Rc<RefCell<Vec<String>>>,
        start_ok: bool,
    ) -> impl Fn(&ProxyStartParams) -> FakeRuntime + '_ {
        let events = events.clone();
        move |params| {
            events.borrow_mut().push(format!("create:{}", params.port));
            FakeRuntime::new(params.port, start_ok, events.clone())
        }
    }

    type ManagerLog = Rc<RefCell<Vec<String>>>;

    fn new_manager(log: &ManagerLog) -> TelegramProxyManager<FakeRuntime> {
        let log_lines: ManagerLog = log.clone();
        let status: ManagerLog = log.clone();
        let upstream: ManagerLog = log.clone();
        TelegramProxyManager::new(
            Box::new(move |line| log_lines.borrow_mut().push(format!("log:{line}"))),
            Box::new(move |running| status.borrow_mut().push(format!("status:{running}"))),
            Box::new(move |state| {
                upstream
                    .borrow_mut()
                    .push(format!("upstream:{}", state.generation))
            }),
        )
    }

    #[test]
    fn without_runtime_defaults_match_python() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let manager = new_manager(&log);
        assert!(!manager.is_running());
        assert!(manager.stats().is_none());
        assert_eq!(manager.port(), 1353);
        assert_eq!(manager.mode(), "socks5");
        assert_eq!(manager.host(), "127.0.0.1");
        assert!(manager.upstream_state().is_none());
        assert!(log.borrow().is_empty());
    }

    #[test]
    fn start_proxy_emits_status_and_reads_runtime_values() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        let ok = manager.start_proxy(&ProxyStartParams::default(), &factory(&log, true));
        assert!(ok);
        assert!(manager.is_running());
        assert_eq!(manager.port(), 1353);
        assert_eq!(manager.mode(), "mtproxy");
        assert_eq!(manager.host(), "10.1.2.3");
        assert_eq!(
            *log.borrow(),
            vec![
                "create:1353".to_string(),
                "start:1353".to_string(),
                "status:true".to_string()
            ]
        );
    }

    #[test]
    fn start_proxy_refuses_to_start_twice() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        assert!(manager.start_proxy(&ProxyStartParams::default(), &factory(&log, true)));
        let before = log.borrow().len();
        assert!(!manager.start_proxy(&ProxyStartParams::default(), &factory(&log, true)));
        assert_eq!(log.borrow().len(), before, "фабрика не вызывалась");
    }

    #[test]
    fn failed_start_logs_and_keeps_runtime_without_status() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        let ok = manager.start_proxy(
            &ProxyStartParams {
                port: 1354,
                ..ProxyStartParams::default()
            },
            &factory(&log, false),
        );
        assert!(!ok);
        assert!(!manager.is_running());
        assert_eq!(
            *log.borrow(),
            vec![
                "create:1354".to_string(),
                "start:1354".to_string(),
                "log:Failed to start proxy".to_string(),
            ]
        );
    }

    #[test]
    fn stop_proxy_stops_runtime_and_emits_status_once() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        assert!(manager.start_proxy(&ProxyStartParams::default(), &factory(&log, true)));
        manager.stop_proxy();
        assert!(!manager.is_running());
        assert!(log.borrow().iter().any(|line| line == "status:false"));
        let statuses = log
            .borrow()
            .iter()
            .filter(|line| line.starts_with("status:"))
            .count();
        assert_eq!(statuses, 2);

        // Повторная остановка без runtime ничего не делает.
        let before = log.borrow().len();
        manager.stop_proxy();
        assert_eq!(log.borrow().len(), before);
    }

    #[test]
    fn stop_runtime_only_stops_without_status_signal() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        assert!(manager.start_proxy(&ProxyStartParams::default(), &factory(&log, true)));
        manager.stop_runtime_only();
        assert!(!manager.is_running());
        assert!(!log.borrow().iter().any(|line| line == "status:false"));
    }

    #[test]
    fn restart_proxy_stops_then_starts() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        assert!(manager.start_proxy(
            &ProxyStartParams {
                port: 1353,
                ..ProxyStartParams::default()
            },
            &factory(&log, true)
        ));
        let ok = manager.restart_proxy(
            &ProxyStartParams {
                port: 1354,
                ..ProxyStartParams::default()
            },
            &factory(&log, true),
        );
        assert!(ok);
        // Порядок: создать 1353 и запустить, остановить, создать 1354.
        assert_eq!(
            *log.borrow(),
            vec![
                "create:1353".to_string(),
                "start:1353".to_string(),
                "status:true".to_string(),
                "stop".to_string(),
                "status:false".to_string(),
                "create:1354".to_string(),
                "start:1354".to_string(),
                "status:true".to_string(),
            ]
        );
    }

    #[test]
    fn apply_upstream_config_requires_runtime() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        assert!(!manager.apply_upstream_config(None));
        assert!(manager.start_proxy(&ProxyStartParams::default(), &factory(&log, true)));
        assert!(manager.apply_upstream_config(None));
        assert!(log.borrow().iter().any(|line| line == "apply:-1"));
    }

    #[test]
    fn upstream_state_prefers_runtime_then_kept_snapshot() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        let state = UpstreamRuntimeSnapshot {
            selected_preset_id: "uk".to_string(),
            selected_name: "Великобритания".to_string(),
            active_preset_id: String::new(),
            active_name: String::new(),
            state: crate::proxy::upstream_controller::UpstreamState::Fallback,
            reason: String::new(),
            generation: 3,
            queued_connections: 0,
            rejected_connections: 0,
        };

        // Снимок без запущенного прокси запоминается и отправляется.
        manager.receive_upstream_state(state.clone());
        assert_eq!(manager.upstream_state(), Some(state.clone()));
        assert!(log.borrow().iter().any(|line| line == "upstream:3"));

        // Запущенный runtime без снимка: менеджер отдаёт сохранённый снимок.
        assert!(manager.start_proxy(&ProxyStartParams::default(), &factory(&log, true)));
        assert_eq!(manager.upstream_state().map(|s| s.generation), Some(3));
        // Runtime со своим снимком имеет приоритет над сохранённым.
        let mut runtime_state = state.clone();
        runtime_state.generation = 7;
        manager.runtime.as_mut().expect("runtime запущен").state = Some(runtime_state.clone());
        assert_eq!(manager.upstream_state(), Some(runtime_state));
        manager.stop_proxy();
        // После остановки остаётся последний полученный снимок.
        assert_eq!(manager.upstream_state().map(|s| s.generation), Some(3));
    }

    #[test]
    fn cleanup_stops_runtime_without_status_signal() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        assert!(manager.start_proxy(&ProxyStartParams::default(), &factory(&log, true)));
        manager.cleanup();
        assert!(!manager.is_running());
        assert!(!log.borrow().iter().any(|line| line == "status:false"));
    }

    #[test]
    fn settings_builders_wrap_config_helpers() {
        let store = Store::default();
        let resolver = UpstreamPresetResolver::new(&[]);
        assert_eq!(
            build_upstream_proxy_config_from_settings(&store, &resolver),
            None,
            "upstream выключен"
        );
        let cloudflare = build_cloudflare_proxy_config_from_settings(&store);
        assert!(!cloudflare.enabled);
        assert!(build_dc_endpoint_overrides_from_settings(&store).is_empty());
    }

    #[test]
    fn autostart_disabled_or_running_does_not_start() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        let resolver = UpstreamPresetResolver::new(&[]);
        let mut store = Store::default();
        assert!(!start_proxy_if_enabled_async(
            &mut manager,
            &factory(&log, true),
            &mut store,
            &resolver
        ));

        store.tg_enabled = true;
        assert!(manager.start_proxy(&ProxyStartParams::default(), &factory(&log, true)));
        assert!(!start_proxy_if_enabled_async(
            &mut manager,
            &factory(&log, true),
            &mut store,
            &resolver
        ));
    }

    #[test]
    fn autostart_uses_normalized_store_values() {
        let log = Rc::new(RefCell::new(Vec::new()));
        let mut manager = new_manager(&log);
        let mut store = Store {
            tg_enabled: true,
            tg_host: "10.0.0.9".to_string(),
            tg_mode: json!("mtproxy"),
            tg_pool_size: json!(99),
            tg_buffer_kb: json!(1),
            ..Store::default()
        };
        let resolver = UpstreamPresetResolver::new(&[]);
        assert!(start_proxy_if_enabled_async(
            &mut manager,
            &factory(&log, true),
            &mut store,
            &resolver
        ));
        assert!(manager.is_running());
        assert_eq!(manager.mode(), "mtproxy");
        assert_eq!(
            manager.port(),
            1353,
            "порт 0 заменён на значение по умолчанию"
        );
    }

    #[test]
    fn autostart_params_generate_mtproxy_secret() {
        let mut store = Store {
            tg_enabled: true,
            tg_mode: json!("mtproxy"),
            ..Store::default()
        };
        let resolver = UpstreamPresetResolver::new(&[]);
        let params = autostart_params(&mut store, &resolver).expect("автозапуск включён");
        assert_eq!(params.mode, "mtproxy");
        assert!(!params.mtproxy_secret.is_empty());
        assert_eq!(params.pool_size, 4);
        assert_eq!(params.buffer_kb, 256);
        assert_eq!(params.host, "127.0.0.1");
        assert_eq!(params.port, 1353);
    }

    /// Тестовое хранилище: чтение из полей, запись без действия.
    #[derive(Default)]
    struct Store {
        tg_enabled: bool,
        tg_host: String,
        tg_port: i64,
        tg_mode: Value,
        tg_secret: String,
        tg_pool_size: Value,
        tg_buffer_kb: Value,
        tg_fake_tls: String,
        tg_proxy_protocol: bool,
    }

    impl TelegramSettingsReader for Store {
        fn read_settings(&self) -> Result<Value, String> {
            Ok(json!({}))
        }
        fn get_auto_deeplink(&self) -> bool {
            false
        }
        fn get_deeplink_done(&self) -> bool {
            false
        }
        fn get_upstream_enabled(&self) -> bool {
            false
        }
        fn get_upstream_host(&self) -> String {
            String::new()
        }
        fn get_upstream_port(&self) -> i64 {
            0
        }
        fn get_upstream_user(&self) -> String {
            String::new()
        }
        fn get_upstream_pass(&self) -> String {
            String::new()
        }
        fn get_upstream_preset_id(&self) -> String {
            String::new()
        }
        fn get_upstream_mode(&self) -> String {
            String::new()
        }
        fn get_upstream_udp_enabled(&self) -> bool {
            false
        }
        fn get_cloudflare_enabled(&self) -> bool {
            false
        }
        fn get_cloudflare_domains(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_cloudflare_worker_enabled(&self) -> bool {
            false
        }
        fn get_cloudflare_worker_domains(&self) -> Vec<String> {
            Vec::new()
        }
        fn get_dc_ip(&self) -> Vec<String> {
            Vec::new()
        }
    }

    impl TelegramProxyStoreReader for Store {
        fn get_tg_proxy_enabled(&self) -> bool {
            self.tg_enabled
        }
        fn get_tg_proxy_host(&self) -> String {
            self.tg_host.clone()
        }
        fn get_tg_proxy_port(&self) -> i64 {
            self.tg_port
        }
        fn get_tg_proxy_mode(&self) -> Value {
            self.tg_mode.clone()
        }
        fn get_tg_proxy_mtproxy_secret(&self) -> String {
            self.tg_secret.clone()
        }
        fn get_tg_proxy_pool_size(&self) -> Value {
            self.tg_pool_size.clone()
        }
        fn get_tg_proxy_buffer_kb(&self) -> Value {
            self.tg_buffer_kb.clone()
        }
        fn get_tg_proxy_fake_tls_domain(&self) -> String {
            self.tg_fake_tls.clone()
        }
        fn get_tg_proxy_proxy_protocol(&self) -> bool {
            self.tg_proxy_protocol
        }
    }

    impl TelegramSettingsWriter for Store {
        fn set_port(&mut self, _value: i64) -> Result<(), String> {
            Ok(())
        }
        fn set_host(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_enabled(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_mode(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_mtproxy_secret(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_dc_ip(&mut self, _value: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn set_pool_size(&mut self, _value: i64) -> Result<(), String> {
            Ok(())
        }
        fn set_buffer_kb(&mut self, _value: i64) -> Result<(), String> {
            Ok(())
        }
        fn set_fake_tls_domain(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_proxy_protocol(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_auto_deeplink(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_deeplink_done(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_enabled(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_mode(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_udp_enabled(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_preset_id(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_host(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_port(&mut self, _value: i64) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_user(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_upstream_pass(&mut self, _value: &str) -> Result<(), String> {
            Ok(())
        }
        fn set_cloudflare_enabled(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_cloudflare_domains(&mut self, _value: &[String]) -> Result<(), String> {
            Ok(())
        }
        fn set_cloudflare_worker_enabled(&mut self, _value: bool) -> Result<(), String> {
            Ok(())
        }
        fn set_cloudflare_worker_domains(&mut self, _value: &[String]) -> Result<(), String> {
            Ok(())
        }
    }
}
