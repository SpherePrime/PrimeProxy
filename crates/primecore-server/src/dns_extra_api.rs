//! DNS-инструменты: текущие системные DNS-серверы, живой запрос к серверу
//! и привилегированная установка серверов через демон `privd`.
//!
//! * `GET /api/dns/current` — разбор `/etc/resolv.conf` (и варианта
//!   NetworkManager, если он есть) плюс каталог известных DoH из
//!   [`primecore_dns::providers`];
//! * `POST /api/dns/query` — один UDP-запрос A-записи через готовый
//!   [`primecore_dnswire::net::query_udp`] (таймаут 3 с);
//! * `POST /api/dns/set` — смена DNS: привилегированная операция, уходит
//!   демону `privd` как `{"op":"dns_set",…}` и исполняется там
//!   `resolvectl dns <ifname> <серверы…>`. Демон не поднят — 409.
//!
//! Как в [`crate::ws_api`]: сервер сам не повышает права, сетевые и
//! привилегированные вызовы из async выносятся в `spawn_blocking`, а в
//! тестах руки подменяются фейками.

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::Json;
use primecore_dnswire::net::query_udp;
use primecore_dnswire::{TYPE_A, TYPE_AAAA};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::ws_api::{request_privd, ws_error, NO_PRIVILEGE_ERROR};
use crate::{bad_request, internal_error};

/// Таймаут DNS-запроса, с.
const QUERY_TIMEOUT_S: f64 = 3.0;
/// Предел списка DNS-серверов в одном запросе.
const MAX_SERVERS: usize = 8;

// ─────────────────────────── endpoints ─────────────────────────────────

/// Текущие DNS: `GET /api/dns/current`.
///
/// ```json
/// {"system":[{"server":"192.168.1.1","kind":"resolv.conf"}],
///  "doh":[{"server":"1.1.1.1","url":"https://cloudflare-dns.com/dns-query"}]}
/// ```
pub async fn current() -> Json<Value> {
    let mut system: Vec<Value> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    // Каждый источник в порядке достоверности; дубль сервера пропускается —
    // источник первого упоминания и остаётся его kind.
    let sources: [(&str, &str); 3] = [
        ("/etc/resolv.conf", "resolv.conf"),
        ("/run/systemd/resolve/resolv.conf", "resolv.conf"),
        ("/var/run/NetworkManager/resolv.conf", "nm"),
    ];
    for (path, kind) in sources {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for server in parse_resolv_conf(&text) {
            if seen.contains(&server) {
                continue;
            }
            seen.push(server.clone());
            system.push(json!({ "server": server, "kind": kind }));
        }
    }
    let doh: Vec<Value> = primecore_dns::providers::doh_templates()
        .into_iter()
        .map(|(server, template)| json!({ "server": server, "url": template }))
        .collect();
    Json(json!({ "system": system, "doh": doh }))
}

/// Разбор текста resolv.conf: адреса строк `nameserver <адрес>`. Комментарии
/// и прочие директивы пропускаются; адреса, не разобравшиеся как IP, — тоже
/// (localhost-литерал вида `localhost` не годится для UDP-запросов).
#[must_use]
pub fn parse_resolv_conf(text: &str) -> Vec<String> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let Some(server) = rest.split_whitespace().next() else {
            continue;
        };
        if server.parse::<IpAddr>().is_ok() && !servers.iter().any(|known| known == server) {
            servers.push(server.to_string());
        }
    }
    servers
}

/// Тело `POST /api/dns/query`.
#[derive(Deserialize)]
pub struct DnsQueryRequest {
    /// Домен для запроса.
    pub domain: String,
    /// Адрес DNS-сервера (пусто — `1.1.1.1`).
    #[serde(default)]
    pub server: Option<String>,
    /// Тип записи: `A` (по умолчанию) или `AAAA`.
    #[serde(default)]
    pub rtype: Option<String>,
}

/// Живой DNS-запрос: `POST /api/dns/query`.
///
/// ```json
/// {"domain":"example.com","server":"1.1.1.1"}
/// ```
///
/// Ответ: `200 {"ok":true,"addresses":["93.184.216.34"],"ms":42,"error":null}`;
/// у сбоя — `ok:false` и текст в `error` (отказ/таймаут — тоже значение,
/// а не 5xx).
pub async fn query(
    body: Result<Json<DnsQueryRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let Json(request) = body.map_err(bad_json)?;
    let domain = request.domain.trim().to_string();
    if domain.is_empty() {
        return Err(bad_request(
            "domain",
            "домен пуст — спрашивать нечего".to_string(),
        ));
    }
    let server = request
        .server
        .unwrap_or_else(|| "1.1.1.1".to_string())
        .trim()
        .to_string();
    let rtype = match request.rtype.as_deref().map(str::trim).unwrap_or("A") {
        "" | "A" | "a" => TYPE_A,
        "AAAA" | "aaaa" => TYPE_AAAA,
        other => {
            return Err(bad_request(
                "rtype",
                format!("неизвестный тип записи: {other} (A|AAAA)"),
            ))
        }
    };
    // UDP-запрос — блокирующий вызов: из async выносим в отдельный поток.
    let result = tokio::task::spawn_blocking(move || {
        query_udp(&server, &domain, rtype, QUERY_TIMEOUT_S, 53, None)
    })
    .await
    .map_err(|error| {
        internal_error(
            "dns_query",
            format!("фоновая задача не отработала: {error}"),
        )
    })?;
    Ok(Json(query_result_to_json(&result)))
}

/// Итог запроса в JSON ответа: адреса, время, текст сбоя.
#[must_use]
pub fn query_result_to_json(result: &primecore_dnswire::DnsQueryResult) -> Value {
    let answered = result.answered();
    let ms = result.elapsed_ms.map(|ms| ms.round() as u64);
    let error = if answered {
        Value::Null
    } else if result.detail.is_empty() {
        json!(result.failure)
    } else {
        json!(format!("{}: {}", result.failure, result.detail))
    };
    json!({
        "ok": answered,
        "addresses": result.values(TYPE_A),
        "ms": ms,
        "error": error,
        "rcode": result.rcode,
        "transport": result.transport,
    })
}

// ─────────────────────────── установка DNS ─────────────────────────────

/// Привилегированные руки смены DNS: ping демона и сама установка.
/// Реализация — демон `privd` по unix-сокету; в тестах — фейк.
pub trait DnsSetExecutor: Send + Sync {
    /// Демон `privd` отвечает? Ошибка — человеко-читаемый текст.
    fn ping(&self) -> Result<(), String>;
    /// Задать интерфейсу DNS-серверы (`resolvectl dns`).
    ///
    /// # Errors
    /// Сокет не отвечает или демон вернул ошибку — текст.
    fn dns_set(&self, ifname: &str, servers: &[String]) -> Result<(), String>;
}

/// Руки через демон `privd`: каждый вызов — один запрос по unix-сокету.
pub struct PrivdDnsExecutor {
    sock: String,
}

impl PrivdDnsExecutor {
    #[must_use]
    pub fn new(sock: String) -> Self {
        Self { sock }
    }
}

impl DnsSetExecutor for PrivdDnsExecutor {
    fn ping(&self) -> Result<(), String> {
        primecore_privilege::client::connect_and_ping(&self.sock)
    }

    fn dns_set(&self, ifname: &str, servers: &[String]) -> Result<(), String> {
        let reply = request_privd(
            &self.sock,
            json!({ "op": "dns_set", "ifname": ifname, "servers": servers }),
        )?;
        if reply["ok"] == json!(true) {
            Ok(())
        } else {
            Err(reply["error"]
                .as_str()
                .unwrap_or("resolvectl не задал серверы")
                .to_string())
        }
    }
}

/// Тело `POST /api/dns/set`.
#[derive(Deserialize)]
pub struct DnsSetRequest {
    /// Адреса DNS-серверов (1..=8).
    pub servers: Vec<String>,
    /// Сетевой интерфейс; без него берётся маршрут по умолчанию из
    /// `/proc/net/route`.
    #[serde(default)]
    pub ifname: Option<String>,
}

/// Состояние смены DNS: путь сокета `privd` и руки исполнения.
pub struct DnsExtraInner {
    executor: Arc<dyn DnsSetExecutor>,
}

/// Клоняемая ручка состояния для ручек axum.
#[derive(Clone)]
pub struct DnsExtraState {
    inner: Arc<DnsExtraInner>,
}

impl FromRef<crate::App> for DnsExtraState {
    fn from_ref(app: &crate::App) -> Self {
        app.dns_extra.clone()
    }
}

impl DnsExtraState {
    /// Состояние живого сервера: руки — демон `privd` на его сокете.
    #[must_use]
    pub fn production() -> Self {
        Self::new(Arc::new(PrivdDnsExecutor::new(
            crate::ws_api::privd_sock_path(),
        )))
    }

    /// Состояние с явными руками (тесты подставляют фейк).
    #[must_use]
    pub fn new(executor: Arc<dyn DnsSetExecutor>) -> Self {
        Self {
            inner: Arc::new(DnsExtraInner { executor }),
        }
    }
}

/// Имя интерфейса с маршрутом по умолчанию из текста `/proc/net/route`:
/// строка с адресом назначения `00000000`.
#[must_use]
pub fn default_ifname_from_proc_route(text: &str) -> Option<String> {
    for line in text.lines().skip(1) {
        let mut cells = line.split('\t');
        let ifname = cells.next()?;
        let destination = cells.next().unwrap_or("");
        if destination == "00000000" && !ifname.is_empty() {
            return Some(ifname.to_string());
        }
    }
    None
}

/// Смена DNS: `POST /api/dns/set`.
///
/// ```json
/// {"servers":["1.1.1.1","8.8.8.8"],"ifname":"eth0"}
/// ```
///
/// Ответ: `200 {"ok":true,"ifname":"eth0","servers":["1.1.1.1","8.8.8.8"]}`;
/// демон не поднят — `409 {"error":"нет прав: нажмите «Разрешить» —
/// запустится privd"}`; пустой список серверов или не-IP — `400`.
pub async fn set(
    State(state): State<DnsExtraState>,
    body: Result<Json<DnsSetRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let Json(request) = body.map_err(bad_json)?;
    let servers = normalize_servers(&request.servers).ok_or_else(|| {
        bad_request(
            "servers",
            format!("нужны 1..={MAX_SERVERS} DNS-серверов в виде IP-адресов"),
        )
    })?;
    let ifname = match request.ifname.as_deref().map(str::trim) {
        Some(ifname) if !ifname.is_empty() => ifname.to_string(),
        _ => std::fs::read_to_string("/proc/net/route")
            .ok()
            .and_then(|text| default_ifname_from_proc_route(&text))
            .ok_or_else(|| {
                bad_request(
                    "ifname",
                    "интерфейс не указан и маршрут по умолчанию не найден".to_string(),
                )
            })?,
    };
    // ping и resolvectl — блокирующие вызовы: из async выносим в поток.
    let ping_executor = Arc::clone(&state.inner.executor);
    let ping = tokio::task::spawn_blocking(move || ping_executor.ping())
        .await
        .map_err(|error| {
            internal_error("dns_set", format!("фоновая задача не отработала: {error}"))
        })?;
    // Демон не отвечает — править DNS нечем, приглашаем нажать «Разрешить».
    ping.map_err(|_error| ws_error(StatusCode::CONFLICT, NO_PRIVILEGE_ERROR.to_string()))?;
    let set_ifname = ifname.clone();
    let set_servers = servers.clone();
    let set_executor = Arc::clone(&state.inner.executor);
    let applied =
        tokio::task::spawn_blocking(move || set_executor.dns_set(&set_ifname, &set_servers))
            .await
            .map_err(|error| {
                internal_error("dns_set", format!("фоновая задача не отработала: {error}"))
            })?;
    applied.map_err(|error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": format!("resolvectl: {error}") })),
        )
    })?;
    Ok(Json(
        json!({ "ok": true, "ifname": ifname, "servers": servers }),
    ))
}

/// Нормализация списка DNS-серверов: трим, проверка IP, дубли — прочь.
/// Пустой или избыточный список — `None`.
#[must_use]
pub fn normalize_servers(servers: &[String]) -> Option<Vec<String>> {
    let mut cleaned: Vec<String> = Vec::with_capacity(servers.len());
    for server in servers {
        let server = server.trim();
        if server.parse::<IpAddr>().is_err() || cleaned.iter().any(|known| known == server) {
            continue;
        }
        if cleaned.len() == MAX_SERVERS {
            break;
        }
        cleaned.push(server.to_string());
    }
    (!cleaned.is_empty()).then_some(cleaned)
}

/// Единый разбор сломанного JSON-тела.
fn bad_json(rejection: axum::extract::rejection::JsonRejection) -> (StatusCode, Json<Value>) {
    bad_request("query", rejection.to_string())
}

// ─────────────────────────── тесты ─────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::net::UdpSocket;
    use std::sync::{Arc, Mutex};

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use primecore_dnswire::{build_query, encode_name, parse_response, DnsQueryResult, TYPE_A};
    use serde_json::Value;
    use tower::ServiceExt;

    use super::*;

    /// Фейковые руки смены DNS: вызовы запоминает, ping подменяем.
    struct FakeDnsExecutor {
        calls: Mutex<Vec<(String, Vec<String>)>>,
        ping_ok: bool,
    }

    impl FakeDnsExecutor {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                ping_ok: true,
            })
        }

        fn without_privd() -> Arc<Self> {
            Arc::new(Self {
                calls: Mutex::new(Vec::new()),
                ping_ok: false,
            })
        }
    }

    impl DnsSetExecutor for FakeDnsExecutor {
        fn ping(&self) -> Result<(), String> {
            if self.ping_ok {
                Ok(())
            } else {
                Err("демон не отвечает".to_string())
            }
        }

        fn dns_set(&self, ifname: &str, servers: &[String]) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push((ifname.to_string(), servers.to_vec()));
            Ok(())
        }
    }

    fn router(executor: Arc<dyn DnsSetExecutor>) -> axum::Router {
        crate::router(crate::App {
            dns_extra: DnsExtraState::new(executor),
            ..crate::App::test_defaults()
        })
    }

    async fn post_json(router: axum::Router, uri: &str, body: &str) -> (StatusCode, Value) {
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    #[test]
    fn resolv_conf_parser_takes_nameservers_only() {
        let text = "\
# комментарий
nameserver 192.168.1.1
search lan
nameserver   10.0.0.53 # хвост-комментарий
nameserver localhost
nameserver 2001:4860:4860::8888
nameserver 192.168.1.1
options edns0
";
        assert_eq!(
            parse_resolv_conf(text),
            vec![
                "192.168.1.1".to_string(),
                "10.0.0.53".to_string(),
                "2001:4860:4860::8888".to_string()
            ]
        );
        assert!(parse_resolv_conf("").is_empty());
        assert!(parse_resolv_conf("search lan\n").is_empty());
    }

    #[test]
    fn normalize_servers_keeps_valid_ips_and_dedupes() {
        let servers = normalize_servers(&[
            " 1.1.1.1 ".to_string(),
            "not-an-ip".to_string(),
            "1.1.1.1".to_string(),
            "8.8.8.8".to_string(),
        ])
        .expect("список не пуст");
        assert_eq!(servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert!(normalize_servers(&["localhost".to_string()]).is_none());
        assert!(normalize_servers(&[]).is_none());
    }

    #[test]
    fn default_ifname_reads_proc_route_text() {
        let text = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\n\
                    eth0\t00000000\tC0A80101\t0003\t0\t0\t100\t00000000\t0\n\
                    wlan0\t00C0A80A\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\n";
        assert_eq!(
            default_ifname_from_proc_route(text),
            Some("eth0".to_string())
        );
        assert_eq!(default_ifname_from_proc_route("Iface\tDestination\n"), None);
        assert_eq!(default_ifname_from_proc_route(""), None);
    }

    #[tokio::test]
    async fn dns_set_uses_detected_interface() {
        let executor = FakeDnsExecutor::new();
        let (status, answer) = post_json(
            router(Arc::clone(&executor) as Arc<dyn DnsSetExecutor>),
            "/api/dns/set",
            r#"{"servers":["1.1.1.1","8.8.8.8"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(answer["ok"], true);
        let calls = executor.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        // /proc/net/route этой среды может назвать интерфейс по-разному —
        // важно, что имя пришло непустым, а серверы дошли как есть.
        let (ifname, servers) = &calls[0];
        assert!(!ifname.is_empty(), "интерфейс определён из /proc/net/route");
        assert_eq!(servers, &vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()]);
    }

    #[tokio::test]
    async fn dns_set_answers_conflict_without_privd() {
        let executor = FakeDnsExecutor::without_privd();
        let (status, answer) = post_json(
            router(Arc::clone(&executor) as Arc<dyn DnsSetExecutor>),
            "/api/dns/set",
            r#"{"servers":["1.1.1.1"],"ifname":"eth0"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(answer["error"]
            .as_str()
            .is_some_and(|error| error.contains("нет прав")));
        assert!(executor.calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn dns_set_rejects_empty_server_list() {
        let executor = FakeDnsExecutor::new();
        let (status, _answer) = post_json(
            router(Arc::clone(&executor) as Arc<dyn DnsSetExecutor>),
            "/api/dns/set",
            r#"{"servers":["not-an-ip"]}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(executor.calls.lock().unwrap().is_empty());
    }

    /// UDP-заглушка DNS: отвечает A-записью на каждый пришедший запрос.
    fn dns_stub(socket: Arc<UdpSocket>, queue: Arc<Mutex<VecDeque<String>>>) {
        let mut buffer = [0u8; 512];
        while let Ok((len, source)) = socket.recv_from(&mut buffer) {
            let Ok(query) = parse_response(&buffer[..len]) else {
                continue;
            };
            queue.lock().unwrap().push_back(query.question.clone());
            // Ответ собирается заново: заголовок + вопрос + один A-ответ
            // (OPT из запроса EDNS0 в ответ не попадает).
            let Ok(encoded) = encode_name(&query.question) else {
                continue;
            };
            let mut packet = Vec::with_capacity(len + 16);
            packet.extend_from_slice(&query.query_id.to_be_bytes());
            packet.extend_from_slice(&0x8180u16.to_be_bytes()); // QR|RD|RA
            packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
            packet.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
            packet.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
            packet.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
            packet.extend_from_slice(&encoded);
            packet.extend_from_slice(&TYPE_A.to_be_bytes());
            packet.extend_from_slice(&1u16.to_be_bytes()); // класс IN
            packet.extend_from_slice(&[0xC0, 0x0C]); // указатель на имя вопроса
            packet.extend_from_slice(&TYPE_A.to_be_bytes()); // тип A
            packet.extend_from_slice(&1u16.to_be_bytes()); // класс IN
            packet.extend_from_slice(&60u32.to_be_bytes()); // TTL
            packet.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            packet.extend_from_slice(&[192, 0, 2, 7]); // 192.0.2.7
            let _ = socket.send_to(&packet, source);
        }
    }

    #[test]
    fn query_parses_answer_from_local_udp_stub() {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("порт взят");
        let port = socket.local_addr().expect("адрес известен").port();
        let socket = Arc::new(socket);
        let queue: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
        let stub_socket = Arc::clone(&socket);
        let stub_queue = Arc::clone(&queue);
        std::thread::spawn(move || dns_stub(stub_socket, stub_queue));

        // Заглушка сравнивает имя вопроса — сначала проверяем сборку запроса.
        let query = build_query(0x1234, "example.com", TYPE_A).expect("запрос собран");
        socket
            .send_to(&query, ("127.0.0.1", port))
            .expect("запрос ушёл");
        let result = query_udp("127.0.0.1", "example.com", TYPE_A, 3.0, port, None);
        assert!(result.answered(), "заглушка ответила: {result:?}");
        assert_eq!(result.values(TYPE_A), vec!["192.0.2.7".to_string()]);
        assert_eq!(
            queue.lock().unwrap().pop_front(),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn query_result_json_maps_answer_and_failure() {
        let result = primecore_dnswire::DnsQueryResult {
            status: primecore_dnswire::STATUS_OK.to_string(),
            rcode: Some(0),
            records: vec![primecore_dnswire::DnsRecord {
                name: "example.com".to_string(),
                rtype: TYPE_A,
                ttl: 60,
                value: "93.184.216.34".to_string(),
            }],
            elapsed_ms: Some(41.6),
            ..primecore_dnswire::DnsQueryResult::default()
        };
        let json = query_result_to_json(&result);
        assert_eq!(json["ok"], true);
        assert_eq!(json["addresses"], json!(["93.184.216.34"]));
        assert_eq!(json["ms"], 42);
        assert!(json["error"].is_null());

        let failed = primecore_dnswire::DnsQueryResult {
            status: primecore_dnswire::STATUS_ERROR.to_string(),
            failure: primecore_dnswire::FAILURE_TIMEOUT.to_string(),
            detail: "сервер молчит".to_string(),
            ..DnsQueryResult::default()
        };
        let json = query_result_to_json(&failed);
        assert_eq!(json["ok"], false);
        assert!(json["error"].as_str().is_some_and(|e| !e.is_empty()));
    }
}
