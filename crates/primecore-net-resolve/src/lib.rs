//! Порт `src/utils/net_resolve.py` — разрешение имён с жёстким дедлайном.
//!
//! Зачем этот модуль: разрешение имени в ОС — синхронный вызов без
//! таймаута, который нельзя прервать; на неисправном или «чёрнодырном»
//! DNS (обычная ситуация у наших пользователей) такой вызов висит
//! десятки секунд, «Остановить» не работает. Решение: резолв уходит в
//! отдельный поток, вызывающая сторона ждёт его с дедлайном.
//! Просроченный резолв не удерживает никого — поток тихо доживёт своё
//! в фоне и запишет результат в кэш.
//!
//! Отличия от python: вместо `socket.getaddrinfo` — резолвер-замыкание
//! (по умолчанию `std::net::ToSocketAddrs`, в тестах — подставка, как
//! monkeypatch `socket.getaddrinfo` в python-тестах); адреса отдаются
//! строками IP, а не кортежами sockaddr. Поток-потомок в Rust нельзя
//! сделать «демоническим»: залипший резолв доживёт своё при выходе
//! процесса (как в python), но явно процесс не держит.
//!
//! Успешный ответ живёт недолго ([`SUCCESS_TTL`]): в пределах одного
//! прогона BlockCheck один и тот же домен резолвится 3–4 раза, и
//! переспрашивать ОС каждый раз незачем. Дольше держать нельзя —
//! диагностика должна видеть свежее состояние сети.

use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant};

/// python `DEFAULT_DNS_TIMEOUT`.
pub const DEFAULT_DNS_TIMEOUT: f64 = 5.0;
/// python `_SUCCESS_TTL` — сколько живёт успешный ответ в кэше.
pub const SUCCESS_TTL: f64 = 30.0;
/// python `_FAILURE_TTL` — отрицательный ответ кэшируется ещё короче:
/// DNS мог просто моргнуть.
pub const FAILURE_TTL: f64 = 5.0;
/// python `_CACHE_LIMIT` — простой предел сверху: кэш служебный, точность
/// вытеснения не важна, важно не течь по памяти в долгих сессиях.
pub const CACHE_LIMIT: usize = 512;

/// Ошибка разрешения — значение (python: `DNSTimeoutError` намеренно НЕ
/// наследует `socket.gaierror`: вызывающий код трактует gaierror как
/// «домена не существует», а это совсем другой диагноз).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// Имя не разрешилось за отведённое время (python `DNSTimeoutError`).
    Timeout(String),
    /// Ошибка разрешения, поднятая самой ОС (python `gaierror`/`OSError`).
    Lookup(String),
}

impl core::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Timeout(message) => write!(f, "{message}"),
            Self::Lookup(message) => write!(f, "{message}"),
        }
    }
}

/// Ключ кэша/залетевших запросов: (host, port, только IPv4).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Key {
    host: String,
    port: Option<u16>,
    ipv4_only: bool,
}

/// python `_Pending` — общий ожидание несколькими ждущими.
struct Pending {
    state: Mutex<PendingState>,
    done: Condvar,
}

struct PendingState {
    value: Option<Vec<String>>,
    error: Option<String>,
    finished: bool,
}

struct CacheEntry {
    stamp: Instant,
    value: Option<Vec<String>>,
    error: Option<String>,
}

static CACHE: LazyLock<Mutex<HashMap<Key, CacheEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
static INFLIGHT: LazyLock<Mutex<HashMap<Key, Arc<Pending>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// python `clear_cache` — сбрасывает кэш. Вызывать в начале длительной
/// диагностики.
pub fn clear_cache() {
    CACHE.lock().expect("замок кэша резолва").clear();
}

/// python `_store` — результат уходит в кэш (с вытеснением старейшего)
/// и снимается отметка «в процессе».
fn store(
    key: &Key,
    value: Option<Vec<String>>,
    error: Option<String>,
    clock: &dyn Fn() -> Instant,
) {
    let mut cache = CACHE.lock().expect("замок кэша резолва");
    if cache.len() >= CACHE_LIMIT {
        // Простое ограничение сверху: вытесняем самую старую запись.
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, entry)| entry.stamp)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(
        key.clone(),
        CacheEntry {
            stamp: clock(),
            value,
            error,
        },
    );
    INFLIGHT.lock().expect("замок залетевших").remove(key);
}

/// python `_cached` — живая запись кэша или `None` (устаревшая снимается).
fn cached(key: &Key, clock: &dyn Fn() -> Instant) -> Option<(Option<Vec<String>>, Option<String>)> {
    let mut cache = CACHE.lock().expect("замок кэша резолва");
    let entry = cache.get(key)?;
    let ttl = if entry.error.is_some() {
        FAILURE_TTL
    } else {
        SUCCESS_TTL
    };
    if clock().saturating_duration_since(entry.stamp).as_secs_f64() > ttl {
        cache.remove(key);
        return None;
    }
    Some((entry.value.clone(), entry.error.clone()))
}

/// Тип резолвера: (host, port, только IPv4) → список IP или текст ошибки.
pub trait ResolverSource: Fn(&str, Option<u16>, bool) -> Result<Vec<String>, String> {
    /// Копия для отдельного потока-воркера.
    fn clone_boxed(&self) -> Box<dyn ResolverSource + Send>;
}

impl<F> ResolverSource for F
where
    F: Fn(&str, Option<u16>, bool) -> Result<Vec<String>, String> + Clone + Send + 'static,
{
    fn clone_boxed(&self) -> Box<dyn ResolverSource + Send> {
        Box::new(self.clone())
    }
}

/// Источник «сейчас» для кэша (в тестах — подставные часы).
pub trait ClockSource: Fn() -> Instant {
    /// Копия для отдельного потока-воркера.
    fn clone_boxed(&self) -> Box<dyn ClockSource + Send>;
}

impl<F> ClockSource for F
where
    F: Fn() -> Instant + Clone + Send + 'static,
{
    fn clone_boxed(&self) -> Box<dyn ClockSource + Send> {
        Box::new(self.clone())
    }
}

/// python `resolve_addrinfo` — `socket.getaddrinfo` с гарантированным
/// дедлайном; возвращает список IP (python отдавал кортежи addrinfo —
/// здесь только адреса, в порядке ответа).
///
/// `resolver` — источник адресов (в проде — ОС, в тестах — подставка,
/// как monkeypatch `socket.getaddrinfo` в python-тестах); `clock` —
/// «сейчас» для кэша.
pub fn resolve_addrinfo_with(
    host: &str,
    port: Option<u16>,
    ipv4_only: bool,
    timeout: f64,
    resolver: &dyn ResolverSource,
    clock: &dyn ClockSource,
) -> Result<Vec<String>, ResolveError> {
    let host = host.trim();
    if host.is_empty() {
        // python: gaierror(EAI_NONAME, "empty host").
        return Err(ResolveError::Lookup("empty host".to_string()));
    }
    let key = Key {
        host: host.to_string(),
        port,
        ipv4_only,
    };

    if let Some((value, error)) = cached(&key, clock) {
        if let Some(error) = error {
            return Err(ResolveError::Lookup(error));
        }
        return Ok(value.unwrap_or_default());
    }

    let pending = {
        let mut inflight = INFLIGHT.lock().expect("замок залетевших");
        match inflight.get(&key) {
            Some(existing) => Arc::clone(existing),
            None => {
                let pending = Arc::new(Pending {
                    state: Mutex::new(PendingState {
                        value: None,
                        error: None,
                        finished: false,
                    }),
                    done: Condvar::new(),
                });
                inflight.insert(key.clone(), Arc::clone(&pending));
                // Резолв уходит в отдельный поток; просроченный доживёт
                // своё в фоне и запишет результат в кэш.
                let worker_pending = Arc::clone(&pending);
                // Резолв уходит в отдельный поток; просроченный доживёт
                // своё в фоне и запишет результат в кэш.
                let worker_key = key.clone();
                let worker_host = host.to_string();
                let worker_resolver = resolver.clone_boxed();
                let worker_clock = clock.clone_boxed();
                std::thread::spawn(move || {
                    let outcome = worker_resolver(&worker_host, port, ipv4_only);
                    let (value, error) = match outcome {
                        Ok(ips) => (Some(ips), None),
                        Err(error) => (None, Some(error)),
                    };
                    store(&worker_key, value.clone(), error.clone(), &worker_clock);
                    let mut state = worker_pending.state.lock().expect("замок ожидания");
                    state.value = value;
                    state.error = error;
                    state.finished = true;
                    worker_pending.done.notify_all();
                });
                pending
            }
        }
    };

    let deadline = Duration::from_secs_f64(timeout.max(0.0));
    let started = clock();
    let mut state = pending.state.lock().expect("замок ожидания");
    while !state.finished {
        let waited = clock().saturating_duration_since(started);
        if waited >= deadline {
            // python: DNSTimeoutError; залетевший поток продолжает жить.
            return Err(ResolveError::Timeout(format!(
                "DNS не ответил за {:.0}с: {host}",
                timeout.max(0.0)
            )));
        }
        let (guard, wait_result) = pending
            .done
            .wait_timeout(state, deadline - waited)
            .expect("замок ожидания");
        state = guard;
        if wait_result.timed_out() && !state.finished {
            return Err(ResolveError::Timeout(format!(
                "DNS не ответил за {:.0}с: {host}",
                timeout.max(0.0)
            )));
        }
    }
    if let Some(error) = &state.error {
        return Err(ResolveError::Lookup(error.clone()));
    }
    Ok(state.value.clone().unwrap_or_default())
}

/// Настоящий резолвер ОС: python `socket.getaddrinfo(host, port,
/// AF_UNSPEC/AF_INET, SOCK_STREAM)`; адреса — строками, без дублей
/// (порядок сохранён).
pub fn std_resolve(host: &str, port: Option<u16>, ipv4_only: bool) -> Result<Vec<String>, String> {
    let port = port.unwrap_or(0);
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .collect();
    let mut ips: Vec<String> = Vec::new();
    for address in addrs {
        let ip = address.ip().to_string();
        if ipv4_only && !address.is_ipv4() {
            continue;
        }
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    Ok(ips)
}

/// python `resolve_addrinfo` с настоящим резолвером ОС.
pub fn resolve_addrinfo(
    host: &str,
    port: Option<u16>,
    timeout: f64,
) -> Result<Vec<String>, ResolveError> {
    resolve_addrinfo_with(host, port, false, timeout, &std_resolve, &Instant::now)
}

/// python `resolve_ips` — возвращает `(ipv4, ipv6)`. Никогда не даёт
/// ошибки: любая проблема разрешения — пустые списки. Дубли внутри
/// каждого семейства убираются (порядок сохранён).
#[must_use]
pub fn resolve_ips_with(
    host: &str,
    timeout: f64,
    port: Option<u16>,
    resolver: &dyn ResolverSource,
    clock: &dyn ClockSource,
) -> (Vec<String>, Vec<String>) {
    let infos = match resolve_addrinfo_with(host, port, false, timeout, resolver, clock) {
        Ok(infos) => infos,
        Err(_) => return (Vec::new(), Vec::new()),
    };
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for ip in infos {
        if ip.contains(':') {
            if !ipv6.contains(&ip) {
                ipv6.push(ip);
            }
        } else if !ipv4.contains(&ip) {
            ipv4.push(ip);
        }
    }
    (ipv4, ipv6)
}

/// python `resolve_ips` с настоящим резолвером ОС.
#[must_use]
pub fn resolve_ips(host: &str, timeout: f64, port: Option<u16>) -> (Vec<String>, Vec<String>) {
    resolve_ips_with(host, timeout, port, &std_resolve, &Instant::now)
}

/// python `resolve_ipv4` — первый IPv4-адрес хоста или `None`. Никогда
/// не даёт ошибки.
#[must_use]
pub fn resolve_ipv4(host: &str, timeout: f64) -> Option<String> {
    // python: family=socket.AF_INET — кэш отдельный от безадресного.
    match resolve_addrinfo_with(host, None, true, timeout, &std_resolve, &Instant::now) {
        Ok(ips) => ips.into_iter().next(),
        Err(_) => None,
    }
}

/// python `connect_tcp` — TCP-соединение, у которого ограничены обе
/// фазы: резолв и коннект.
///
/// `socket.create_connection` так не умеет — его timeout относится
/// только к коннекту, а разрешение имени внутри висит без ограничения.
///
/// Возвращает подключённый поток и IP, к которому подключились.
pub fn connect_tcp(
    host: &str,
    port: u16,
    timeout: f64,
    dns_timeout: Option<f64>,
    resolved_ip: Option<&str>,
) -> Result<(TcpStream, String), ResolveError> {
    connect_tcp_with(
        host,
        port,
        timeout,
        dns_timeout,
        resolved_ip,
        &std_resolve,
        &Instant::now,
    )
}

/// python `connect_tcp` с подставным резолвером (для тестов).
pub fn connect_tcp_with(
    host: &str,
    port: u16,
    timeout: f64,
    dns_timeout: Option<f64>,
    resolved_ip: Option<&str>,
    resolver: &dyn ResolverSource,
    clock: &dyn ClockSource,
) -> Result<(TcpStream, String), ResolveError> {
    let candidates: Vec<String> = if let Some(ip) = resolved_ip.filter(|ip| !ip.is_empty()) {
        vec![ip.to_string()]
    } else {
        resolve_addrinfo_with(
            host,
            Some(port),
            false,
            dns_timeout.unwrap_or(timeout),
            resolver,
            clock,
        )?
    };

    if candidates.is_empty() {
        // python: gaierror(EAI_NONAME, f"нет адресов для {host}").
        return Err(ResolveError::Lookup(format!("нет адресов для {host}")));
    }

    let connect_timeout = Duration::from_secs_f64(timeout.max(0.0));
    let mut last_error: Option<String> = None;
    for ip in candidates {
        let address: SocketAddr = match format!("{ip}:{port}").parse() {
            Ok(address) => address,
            Err(error) => {
                last_error = Some(error.to_string());
                continue;
            }
        };
        match TcpStream::connect_timeout(&address, connect_timeout) {
            Ok(stream) => return Ok((stream, ip)),
            Err(error) => {
                last_error = Some(error.to_string());
            }
        }
    }
    // python поднимал последнюю ошибку; без неё — общий текст.
    Err(ResolveError::Lookup(last_error.unwrap_or_else(|| {
        format!("не удалось подключиться к {host}")
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// python `_BlackholeDNS` — резолвер, вечно висящий, как мёртвый DNS.
    fn blackhole(_host: &str, _port: Option<u16>, _ipv4_only: bool) -> Result<Vec<String>, String> {
        // Дольше дедлайна теста: как мёртвый DNS, ответ не успевает.
        std::thread::sleep(Duration::from_millis(2_500));
        Err("blackhole".to_string())
    }

    #[test]
    fn resolve_respects_deadline_on_dead_dns() {
        let started = Instant::now();
        let result = resolve_addrinfo_with(
            "blackhole.test",
            Some(443),
            false,
            1.0,
            &blackhole,
            &Instant::now,
        );
        let elapsed = started.elapsed().as_secs_f64();
        assert!(
            matches!(result, Err(ResolveError::Timeout(_))),
            "жило: {result:?}"
        );
        assert!(
            elapsed < 3.0,
            "резолв должен уложиться в дедлайн, а занял {elapsed:.1}с"
        );
    }

    #[test]
    fn empty_host_is_lookup_error_not_timeout() {
        let result = resolve_addrinfo_with("", Some(443), false, 1.0, &blackhole, &Instant::now);
        assert_eq!(result, Err(ResolveError::Lookup("empty host".to_string())));
    }

    #[test]
    fn successful_result_is_cached_and_reused() {
        clear_cache();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_in = std::sync::Arc::clone(&calls);
        let resolver = move |host: &str,
                             _port: Option<u16>,
                             _ipv4_only: bool|
              -> Result<Vec<String>, String> {
            calls_in.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            assert_eq!(host, "cache.test");
            Ok(vec!["1.2.3.4".to_string(), "5.6.7.8".to_string()])
        };
        let first = resolve_addrinfo_with(
            "cache.test",
            Some(443),
            false,
            1.0,
            &resolver,
            &Instant::now,
        )
        .unwrap();
        let second = resolve_addrinfo_with(
            "cache.test",
            Some(443),
            false,
            1.0,
            &resolver,
            &Instant::now,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        clear_cache();
    }

    #[test]
    fn failure_is_cached_for_short_ttl() {
        clear_cache();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_in = std::sync::Arc::clone(&calls);
        let resolver = move |_host: &str,
                             _port: Option<u16>,
                             _ipv4_only: bool|
              -> Result<Vec<String>, String> {
            calls_in.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err("нет такого домена".to_string())
        };
        let base = Instant::now();
        let clock_base = move || base;
        let first = resolve_addrinfo_with("fail.test", None, false, 1.0, &resolver, &clock_base)
            .unwrap_err();
        let second = resolve_addrinfo_with("fail.test", None, false, 1.0, &resolver, &clock_base)
            .unwrap_err();
        assert_eq!(first, second);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        // По прошествии FAILURE_TTL кэш отдаёт вопрос ОС заново.
        let later = base + Duration::from_secs_f64(FAILURE_TTL + 0.1);
        let clock_later = move || later;
        let _ = resolve_addrinfo_with("fail.test", None, false, 1.0, &resolver, &clock_later);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
        clear_cache();
    }

    #[test]
    fn resolve_ips_splits_and_dedups_families() {
        clear_cache();
        let resolver =
            |_host: &str, _port: Option<u16>, _ipv4_only: bool| -> Result<Vec<String>, String> {
                Ok(vec![
                    "1.2.3.4".to_string(),
                    "::1".to_string(),
                    "1.2.3.4".to_string(),
                ])
            };
        // addrinfo отдаёт адреса как пришло (python: список addrinfo).
        let raw = resolve_addrinfo_with("split.test", None, false, 1.0, &resolver, &Instant::now)
            .unwrap();
        assert_eq!(raw, vec!["1.2.3.4", "::1", "1.2.3.4"]);
        // resolve_ips дедуплицирует внутри семейств (python: ip not in).
        let (ipv4, ipv6) = resolve_ips_with("split.test", 1.0, None, &resolver, &Instant::now);
        assert_eq!(ipv4, vec!["1.2.3.4"]);
        assert_eq!(ipv6, vec!["::1"]);
        clear_cache();
    }

    #[test]
    fn parallel_callers_share_one_inflight_request() {
        clear_cache();
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let calls_in = std::sync::Arc::clone(&calls);
        let resolver = move |_host: &str,
                             _port: Option<u16>,
                             _ipv4_only: bool|
              -> Result<Vec<String>, String> {
            calls_in.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(100));
            Ok(vec!["9.9.9.9".to_string()])
        };
        let first = std::thread::scope(|scope| {
            let resolver_a = &resolver;
            let resolver_b = &resolver;
            let handle_a = scope.spawn(|| {
                resolve_addrinfo_with(
                    "shared.test",
                    Some(443),
                    false,
                    3.0,
                    resolver_a,
                    &Instant::now,
                )
            });
            let handle_b = scope.spawn(|| {
                resolve_addrinfo_with(
                    "shared.test",
                    Some(443),
                    false,
                    3.0,
                    resolver_b,
                    &Instant::now,
                )
            });
            (handle_a.join().unwrap(), handle_b.join().unwrap())
        });
        assert_eq!(first.0.unwrap(), vec!["9.9.9.9"]);
        assert_eq!(first.1.unwrap(), vec!["9.9.9.9"]);
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
        clear_cache();
    }

    #[test]
    fn connect_tcp_with_resolved_ip_connects_locally() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (stream, ip) =
            connect_tcp("unused.test", address.port(), 2.0, None, Some("127.0.0.1")).unwrap();
        assert_eq!(ip, "127.0.0.1");
        drop(stream);
        drop(listener);
    }

    #[test]
    fn connect_tcp_without_addresses_is_lookup_error() {
        clear_cache();
        let resolver = |_host: &str,
                        _port: Option<u16>,
                        _ipv4_only: bool|
         -> Result<Vec<String>, String> { Ok(Vec::new()) };
        let result = connect_tcp_with("empty.test", 443, 1.0, None, None, &resolver, &Instant::now);
        assert_eq!(
            result.unwrap_err(),
            ResolveError::Lookup("нет адресов для empty.test".to_string())
        );
        clear_cache();
    }
}
