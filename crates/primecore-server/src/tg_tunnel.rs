//! Живой локальный прокси Telegram: SOCKS5 на входе, WSS-туннель на выходе.
//!
//! Принцип tg-ws-proxy (github.com/Flowseal/tg-ws-proxy) и ZaStoGram:
//! Telegram Desktop подключается к локальному SOCKS5, а поток уходит в
//! WebSocket к фронту Cloudflare, который дотягивает его до дата-центра
//! Telegram. Для DPI это обычный HTTPS к чужому домену, а не MTProto.
//!
//! Чистые решения (адреса фронтов, IP → DC, кадры WebSocket, запрос upgrade)
//! живут в `primecore-telegram`; здесь — сеть: слушатель, TLS, перекачка.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use primecore_telegram::proxy::dc_map::ip_to_dc;
use primecore_telegram::proxy::route_catalog::{CDN_FRONTS, WSS_PATH};
use primecore_telegram::proxy::ws::{
    accept_value, build_request, decode_frame, encode_frame, parse_response_head, WsTarget,
    MAX_HEADER, OP_BINARY, OP_CLOSE, OP_CONT, OP_PING, OP_PONG, OP_TEXT,
};

/// Таймаут на TCP, TLS и upgrade к фронту.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Сколько фронтов пробуем, прежде чем вернуть ошибку.
const FRONT_ATTEMPTS: usize = 6;
/// Размер буфера перекачки.
const COPY_BUFFER: usize = 32 * 1024;

/// Счётчики и последняя ошибка прокси: их показывает вкладка Telegram.
#[derive(Default)]
pub struct TunnelStats {
    /// Сколько соединений принято с момента запуска.
    pub connections: AtomicU64,
    /// Сколько соединений живёт прямо сейчас.
    pub active: AtomicU64,
    /// Байт ушло от Telegram к фронту.
    pub bytes_up: AtomicU64,
    /// Байт пришло от фронта к Telegram.
    pub bytes_down: AtomicU64,
    /// Последняя ошибка — простым текстом для интерфейса.
    pub last_error: Mutex<String>,
    /// Фронт, через который прошло последнее соединение.
    pub last_front: Mutex<String>,
    /// Фронт, который уже отвечал: его пробуем первым.
    pub front_cache: Mutex<Option<(String, String, String)>>,
}

/// Что вернул запуск: адрес, который нужно вписать в Telegram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartedInfo {
    pub host: String,
    pub port: u16,
    pub front: String,
}

struct Running {
    host: String,
    port: u16,
    front: String,
    started_at: i64,
    task: tokio::task::JoinHandle<()>,
}

/// Прокси Telegram целиком: состояние, счётчики и TLS-настройки.
pub struct Tunnel {
    running: Mutex<Option<Running>>,
    stats: Arc<TunnelStats>,
    tls: Arc<rustls::ClientConfig>,
}

impl Default for Tunnel {
    fn default() -> Self {
        Self::new()
    }
}

impl Tunnel {
    /// Прокси с корневыми сертификатами webpki: своего хранилища не нужно.
    ///
    /// Провайдер выбираем явно: в дереве зависимостей рядом живут ring (наш)
    /// и aws-lc-rs (из reqwest), и rustls не берётся угадывать сам.
    #[must_use]
    pub fn new() -> Self {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring даёт безопасные версии протокола")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            running: Mutex::new(None),
            stats: Arc::new(TunnelStats::default()),
            tls: Arc::new(tls),
        }
    }

    /// Счётчики для интерфейса.
    #[must_use]
    pub fn stats(&self) -> Arc<TunnelStats> {
        self.stats.clone()
    }

    /// Запущенный прокси: адрес, фронт и время старта.
    pub async fn running(&self) -> Option<(String, u16, String, i64)> {
        let guard = self.running.lock().await;
        guard
            .as_ref()
            .map(|item| (item.host.clone(), item.port, item.front.clone(), item.started_at))
    }

    /// Поднять слушатель SOCKS5.
    ///
    /// `domain` — свой домен Cloudflare с воркером; пусто — берём встроенные
    /// фронты из каталога.
    ///
    /// # Errors
    /// Адрес занят, порт недоступен или домен не разбирается.
    pub async fn start(
        &self,
        host: &str,
        port: u16,
        domain: Option<String>,
    ) -> Result<StartedInfo, String> {
        let mut guard = self.running.lock().await;
        if guard.is_some() {
            return Err("прокси уже запущен".to_string());
        }
        let listener = TcpListener::bind((host, port))
            .await
            .map_err(|error| format!("не удалось занять {host}:{port}: {error}"))?;
        let stats = self.stats.clone();
        let tls = self.tls.clone();
        let front_label = match domain.as_deref() {
            Some(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => format!("встроенные фронты ({})", CDN_FRONTS.len()),
        };
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let stats = stats.clone();
                let tls = tls.clone();
                let domain = domain.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    if let Err(error) = serve_client(stream, tls, domain, stats.clone()).await {
                        *stats.last_error.lock().await = error;
                    }
                });
            }
        });
        let info = StartedInfo {
            host: host.to_string(),
            port,
            front: front_label.clone(),
        };
        *guard = Some(Running {
            host: host.to_string(),
            port,
            front: front_label,
            started_at: now_epoch_s(),
            task,
        });
        Ok(info)
    }

    /// Остановить прокси: слушатель закрывается, живые соединения доживают.
    pub async fn stop(&self) -> bool {
        let mut guard = self.running.lock().await;
        match guard.take() {
            Some(running) => {
                running.task.abort();
                true
            }
            None => false,
        }
    }
}

/// Текущее время в секундах (как в остальных ручках ядра).
fn now_epoch_s() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs() as i64)
        .unwrap_or(0)
}

/// Одно соединение: SOCKS5-рукопожатие, затем туннель до фронта.
async fn serve_client(
    mut client: TcpStream,
    tls: Arc<rustls::ClientConfig>,
    domain: Option<String>,
    stats: Arc<TunnelStats>,
) -> Result<(), String> {
    let target = socks5_handshake(&mut client).await?;
    stats.connections.fetch_add(1, Ordering::Relaxed);
    stats.active.fetch_add(1, Ordering::Relaxed);
    let result = tunnel(client, &target, tls, domain, stats.clone()).await;
    stats.active.fetch_sub(1, Ordering::Relaxed);
    result
}

/// SOCKS5 без пароля: приветствие, запрос CONNECT, ответ об успехе.
///
/// Возвращает адрес назначения — его и просит Telegram (адрес дата-центра).
async fn socks5_handshake(client: &mut TcpStream) -> Result<String, String> {
    let mut head = [0_u8; 2];
    client
        .read_exact(&mut head)
        .await
        .map_err(|error| format!("socks5: нет приветствия: {error}"))?;
    if head[0] != 5 {
        return Err(format!("socks5: чужая версия {}", head[0]));
    }
    let mut methods = vec![0_u8; head[1] as usize];
    client
        .read_exact(&mut methods)
        .await
        .map_err(|error| format!("socks5: нет списка методов: {error}"))?;
    // Выбираем «без аутентификации»; другого варианта у локального прокси нет.
    client
        .write_all(&[5, 0])
        .await
        .map_err(|error| format!("socks5: ответ не ушёл: {error}"))?;

    let mut request = [0_u8; 4];
    client
        .read_exact(&mut request)
        .await
        .map_err(|error| format!("socks5: нет запроса: {error}"))?;
    if request[1] != 1 {
        // Поддерживаем только CONNECT — остальное Telegram не просит.
        let _ = client.write_all(&[5, 7, 0, 1, 0, 0, 0, 0, 0, 0]).await;
        return Err(format!("socks5: команда {} не поддержана", request[1]));
    }
    let address = match request[3] {
        1 => {
            let mut raw = [0_u8; 4];
            client
                .read_exact(&mut raw)
                .await
                .map_err(|error| format!("socks5: нет адреса: {error}"))?;
            format!("{}.{}.{}.{}", raw[0], raw[1], raw[2], raw[3])
        }
        4 => {
            let mut raw = [0_u8; 16];
            client
                .read_exact(&mut raw)
                .await
                .map_err(|error| format!("socks5: нет адреса: {error}"))?;
            let parts: Vec<String> = raw.chunks(2).map(|pair| format!("{:x}", u16::from_be_bytes([pair[0], pair[1]]))).collect();
            parts.join(":")
        }
        3 => {
            let mut length = [0_u8; 1];
            client
                .read_exact(&mut length)
                .await
                .map_err(|error| format!("socks5: нет длины имени: {error}"))?;
            let mut raw = vec![0_u8; length[0] as usize];
            client
                .read_exact(&mut raw)
                .await
                .map_err(|error| format!("socks5: нет имени: {error}"))?;
            String::from_utf8_lossy(&raw).into_owned()
        }
        other => return Err(format!("socks5: тип адреса {other} не поддержан")),
    };
    let mut port = [0_u8; 2];
    client
        .read_exact(&mut port)
        .await
        .map_err(|error| format!("socks5: нет порта: {error}"))?;
    let _port = u16::from_be_bytes(port);
    // Отвечаем «получилось»: адрес в ответе не важен, клиент его не смотрит.
    client
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|error| format!("socks5: ответ не ушёл: {error}"))?;
    Ok(address)
}

/// Туннель: выбираем фронт, поднимаем WebSocket и перекачиваем байты.
async fn tunnel(
    client: TcpStream,
    target: &str,
    tls: Arc<rustls::ClientConfig>,
    domain: Option<String>,
    stats: Arc<TunnelStats>,
) -> Result<(), String> {
    let dc = ip_to_dc(target);
    let path = format!("{WSS_PATH}?dst={target}&dc={dc}");
    let mut candidates = front_candidates(&domain, dc);
    // Уже проверенный фронт — первым: остальные нужны только на случай,
    // если он перестал отвечать.
    if let Some(known) = stats.front_cache.lock().await.clone() {
        candidates.retain(|item| item.2 != known.2);
        candidates.insert(0, known);
    }
    let (stream, front) = race_fronts(candidates, &path, tls).await?;
    *stats.last_front.lock().await = front.2.clone();
    *stats.front_cache.lock().await = Some(front);
    pipe(client, stream, stats).await
}

/// Гонка фронтов: побеждает тот, кто первым подтвердил upgrade.
///
/// Последовательный перебор занимал бы минуты (фронты отвечают медленно),
/// а пользователю нужен ответ сразу — поэтому пробуем параллельно.
async fn race_fronts(
    candidates: Vec<(String, String, String)>,
    path: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<(tokio_rustls::client::TlsStream<TcpStream>, (String, String, String)), String> {
    if candidates.is_empty() {
        return Err("нет фронтов для подключения".to_string());
    }
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    let mut handles = Vec::with_capacity(candidates.len());
    for (connect_host, sni, label) in candidates {
        let sender = sender.clone();
        let path = path.to_string();
        let tls = tls.clone();
        // Победитель возвращается целиком: его адрес кладём в кэш.
        let entry = (connect_host.clone(), sni.clone(), label);
        handles.push(tokio::spawn(async move {
            if let Ok(stream) = connect_ws(&connect_host, &sni, &path, tls).await {
                let _ = sender.send((stream, entry)).await;
            }
        }));
    }
    drop(sender);
    match receiver.recv().await {
        Some((stream, front)) => {
            for handle in handles {
                handle.abort();
            }
            Ok((stream, front))
        }
        None => Err("ни один фронт не подтвердил WebSocket — нужен свой воркер".to_string()),
    }
}

/// Кандидаты подключения: свой домен, иначе встроенные фронты.
fn front_candidates(domain: &Option<String>, dc: i32) -> Vec<(String, String, String)> {
    if let Some(value) = domain.as_deref().map(str::trim).filter(|it| !it.is_empty()) {
        let host = format!("kws{dc}.{value}");
        return vec![(host.clone(), host.clone(), host)];
    }
    CDN_FRONTS
        .iter()
        .take(FRONT_ATTEMPTS)
        .flat_map(|front| {
            let host = front.host_for(dc);
            front.addresses.iter().map(move |address| {
                (
                    (*address).to_string(),
                    host.clone(),
                    format!("{host} · {address}"),
                )
            })
        })
        .collect()
}

/// TCP + TLS + WebSocket-upgrade к фронту.
async fn connect_ws(
    connect_host: &str,
    sni: &str,
    path: &str,
    tls: Arc<rustls::ClientConfig>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>, String> {
    let socket = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect((connect_host, 443)))
        .await
        .map_err(|_| "таймаут подключения".to_string())?
        .map_err(|error| format!("соединение не открылось: {error}"))?;
    let _ = socket.set_nodelay(true);
    let name = rustls::pki_types::ServerName::try_from(sni.to_string())
        .map_err(|error| format!("имя фронта не разобралось: {error}"))?;
    let connector = tokio_rustls::TlsConnector::from(tls);
    let mut stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, socket))
        .await
        .map_err(|_| "таймаут TLS".to_string())?
        .map_err(|error| format!("TLS не поднялся: {error}"))?;

    let key = ws_key();
    let target = WsTarget {
        connect_host: connect_host.to_string(),
        sni: sni.to_string(),
        path: path.to_string(),
        port: 443,
    };
    stream
        .write_all(&build_request(&target, &key))
        .await
        .map_err(|error| format!("запрос upgrade не ушёл: {error}"))?;
    let head = read_head(&mut stream).await?;
    let parsed = parse_response_head(&head).map_err(|error| error.to_string())?;
    if parsed.status != 101 {
        return Err(format!("фронт ответил {}", parsed.status));
    }
    match parsed.header("sec-websocket-accept") {
        Some(value) if value == accept_value(&key) => Ok(stream),
        Some(_) => Err("фронт вернул чужой Sec-WebSocket-Accept".to_string()),
        None => Err("фронт не подтвердил upgrade".to_string()),
    }
}

/// Случайный ключ upgrade (16 байт в base64).
fn ws_key() -> String {
    use base64::Engine;
    let mut raw = [0_u8; 16];
    fastrand::fill(&mut raw);
    base64::engine::general_purpose::STANDARD.encode(raw)
}

/// Читает голову ответа до пустой строки.
async fn read_head(stream: &mut tokio_rustls::client::TlsStream<TcpStream>) -> Result<Vec<u8>, String> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    while head.len() < MAX_HEADER {
        let read = stream
            .read(&mut byte)
            .await
            .map_err(|error| format!("ответ upgrade не читается: {error}"))?;
        if read == 0 {
            break;
        }
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    Err("ответ upgrade оборвался".to_string())
}

/// Перекачка в обе стороны: кадры WebSocket против потока Telegram.
async fn pipe(
    client: TcpStream,
    stream: tokio_rustls::client::TlsStream<TcpStream>,
    stats: Arc<TunnelStats>,
) -> Result<(), String> {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut ws_read, mut ws_write) = tokio::io::split(stream);
    let mut client_buffer = vec![0_u8; COPY_BUFFER];
    let mut ws_buffer = vec![0_u8; COPY_BUFFER];
    let mut pending: Vec<u8> = Vec::new();

    loop {
        tokio::select! {
            read = client_read.read(&mut client_buffer) => {
                let read = read.map_err(|error| format!("чтение от Telegram: {error}"))?;
                if read == 0 {
                    let _ = ws_write.write_all(&encode_frame(OP_CLOSE, &[])).await;
                    return Ok(());
                }
                stats.bytes_up.fetch_add(read as u64, Ordering::Relaxed);
                ws_write
                    .write_all(&encode_frame(OP_BINARY, &client_buffer[..read]))
                    .await
                    .map_err(|error| format!("запись в WebSocket: {error}"))?;
            }
            read = ws_read.read(&mut ws_buffer) => {
                let read = read.map_err(|error| format!("чтение от фронта: {error}"))?;
                if read == 0 {
                    return Ok(());
                }
                pending.extend_from_slice(&ws_buffer[..read]);
                loop {
                    let frame = decode_frame(&pending).map_err(|error| error.to_string())?;
                    let Some(frame) = frame else { break };
                    pending.drain(..frame.consumed);
                    match frame.opcode {
                        OP_BINARY | OP_CONT | OP_TEXT => {
                            if !frame.payload.is_empty() {
                                stats.bytes_down.fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
                                client_write
                                    .write_all(&frame.payload)
                                    .await
                                    .map_err(|error| format!("запись в Telegram: {error}"))?;
                            }
                        }
                        OP_PING => {
                            ws_write
                                .write_all(&encode_frame(OP_PONG, &frame.payload))
                                .await
                                .map_err(|error| format!("ответ на ping: {error}"))?;
                        }
                        OP_CLOSE => return Ok(()),
                        _ => {}
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn front_candidates_use_own_domain_first() {
        let list = front_candidates(&Some("example.com".to_string()), 2);
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "kws2.example.com");
        assert_eq!(list[0].1, "kws2.example.com");
    }

    #[test]
    fn front_candidates_fall_back_to_builtin_fronts() {
        let list = front_candidates(&None, 2);
        assert!(!list.is_empty());
        // Два адреса на фронт, не больше FRONT_ATTEMPTS фронтов.
        assert!(list.len() <= FRONT_ATTEMPTS * 2);
        assert!(list.iter().all(|(host, sni, _)| host != sni || !sni.is_empty()));
        assert!(list[0].1.starts_with("kws2."));
    }

    #[test]
    fn ws_key_is_base64_of_sixteen_bytes() {
        use base64::Engine;
        let key = ws_key();
        let raw = base64::engine::general_purpose::STANDARD
            .decode(key.as_bytes())
            .expect("ключ в base64");
        assert_eq!(raw.len(), 16);
    }
}
