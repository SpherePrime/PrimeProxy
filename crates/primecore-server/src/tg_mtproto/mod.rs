mod bridge;
mod handshake;
mod routes;
mod splitter;
mod ws_conn;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use handshake::{build_crypto, build_relay_init, parse_client_hello, HANDSHAKE_LEN};
use routes::{fallback_ip, redirect_ip, ws_domains, Balancer, CF_DOMAINS_URL, FRONTING_SNI, WS_PATH, WS_PATH_TEST};
use splitter::MsgSplitter;
use ws_conn::{connect, TlsConfigs, WsReader, WsTarget, WsWriter};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const DIRECT_TIMEOUT: Duration = Duration::from_secs(6);
const CF_TIMEOUT: Duration = Duration::from_secs(8);
const TCP_TIMEOUT: Duration = Duration::from_secs(8);
const CF_ATTEMPTS: usize = 6;
const DIRECT_BACKOFF: Duration = Duration::from_secs(60);
const DOMAIN_REFRESH: Duration = Duration::from_secs(3600);
const BAD_HANDSHAKE_DRAIN: usize = 64 * 1024;

#[derive(Default)]
pub struct TunnelStats {
    pub connections: AtomicU64,
    pub active: AtomicU64,
    pub bytes_up: AtomicU64,
    pub bytes_down: AtomicU64,
    pub last_error: Mutex<String>,
    pub last_front: Mutex<String>,
}

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
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

struct Shared {
    secret: [u8; 16],
    worker: Option<String>,
    tls: TlsConfigs,
    balancer: Arc<std::sync::Mutex<Balancer>>,
    stats: Arc<TunnelStats>,
    direct_blocked_until: std::sync::Mutex<HashMap<(i32, bool), Instant>>,
    fronting_first: AtomicBool,
    rng: SystemRandom,
}

pub struct Tunnel {
    running: Mutex<Option<Running>>,
    stats: Arc<TunnelStats>,
    tls: TlsConfigs,
    balancer: Arc<std::sync::Mutex<Balancer>>,
}

impl Default for Tunnel {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use]
pub fn generate_secret() -> String {
    let mut raw = [0_u8; 16];
    if SystemRandom::new().fill(&mut raw).is_err() {
        fastrand::fill(&mut raw);
    }
    raw.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[must_use]
pub fn parse_secret(hex: &str) -> Option<[u8; 16]> {
    let hex = hex.trim();
    if hex.len() != 32 {
        return None;
    }
    let mut secret = [0_u8; 16];
    for (index, slot) in secret.iter_mut().enumerate() {
        *slot = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(secret)
}

#[must_use]
pub fn proxy_link(host: &str, port: u16, secret: &str) -> String {
    format!("tg://proxy?server={host}&port={port}&secret=dd{secret}")
}

impl Tunnel {
    #[must_use]
    pub fn new() -> Self {
        Self {
            running: Mutex::new(None),
            stats: Arc::new(TunnelStats::default()),
            tls: TlsConfigs::new(),
            balancer: Arc::new(std::sync::Mutex::new(Balancer::with_defaults())),
        }
    }

    #[must_use]
    pub fn stats(&self) -> Arc<TunnelStats> {
        self.stats.clone()
    }

    pub async fn running(&self) -> Option<(String, u16, String, i64)> {
        let guard = self.running.lock().await;
        guard
            .as_ref()
            .map(|item| (item.host.clone(), item.port, item.front.clone(), item.started_at))
    }

    pub async fn start(&self, host: &str, port: u16, secret: &str, worker: Option<String>) -> Result<StartedInfo, String> {
        let mut guard = self.running.lock().await;
        if guard.is_some() {
            return Err("прокси уже запущен".to_string());
        }
        let secret = parse_secret(secret).ok_or_else(|| "секрет прокси должен быть из 32 hex-символов".to_string())?;
        let listener = TcpListener::bind((host, port))
            .await
            .map_err(|error| format!("не удалось занять {host}:{port}: {error}"))?;
        let port = listener.local_addr().map_or(port, |address| address.port());

        let front = match worker.as_deref() {
            Some(domain) => format!("воркер {domain} + CF-прокси"),
            None => {
                let count = self.balancer.lock().map(|item| item.count()).unwrap_or(0);
                format!("прямой WS + CF-прокси ({count})")
            }
        };
        let shared = Arc::new(Shared {
            secret,
            worker,
            tls: self.tls.clone(),
            balancer: self.balancer.clone(),
            stats: self.stats.clone(),
            direct_blocked_until: std::sync::Mutex::new(HashMap::new()),
            fronting_first: AtomicBool::new(false),
            rng: SystemRandom::new(),
        });

        let accept_shared = shared.clone();
        let accept = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let shared = accept_shared.clone();
                tokio::spawn(async move {
                    let _ = stream.set_nodelay(true);
                    shared.stats.connections.fetch_add(1, Ordering::Relaxed);
                    shared.stats.active.fetch_add(1, Ordering::Relaxed);
                    if let Err(error) = serve_client(stream, shared.clone()).await {
                        *shared.stats.last_error.lock().await = error;
                    }
                    shared.stats.active.fetch_sub(1, Ordering::Relaxed);
                });
            }
        });
        let refresh = tokio::spawn(refresh_domains(self.balancer.clone()));

        let info = StartedInfo {
            host: host.to_string(),
            port,
            front: front.clone(),
        };
        *guard = Some(Running {
            host: host.to_string(),
            port,
            front,
            started_at: crate::ws_api::now_epoch_s(),
            tasks: vec![accept, refresh],
        });
        Ok(info)
    }

    pub async fn stop(&self) -> bool {
        let mut guard = self.running.lock().await;
        match guard.take() {
            Some(running) => {
                for task in running.tasks {
                    task.abort();
                }
                true
            }
            None => false,
        }
    }
}

async fn refresh_domains(balancer: Arc<std::sync::Mutex<Balancer>>) {
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("tg-ws-proxy")
        .build()
    else {
        return;
    };
    loop {
        let url = format!("{CF_DOMAINS_URL}?{}", fastrand::u32(..));
        if let Ok(response) = client.get(&url).send().await {
            if let Ok(text) = response.text().await {
                if let Some(domains) = routes::parse_domain_list(&text) {
                    if let Ok(mut guard) = balancer.lock() {
                        guard.update(domains);
                    }
                }
            }
        }
        tokio::time::sleep(DOMAIN_REFRESH).await;
    }
}

enum Upstream {
    Ws {
        reader: WsReader,
        writer: WsWriter,
        label: String,
        split: bool,
    },
    Tcp {
        stream: TcpStream,
        label: String,
    },
}

async fn serve_client(mut client: TcpStream, shared: Arc<Shared>) -> Result<(), String> {
    let mut init = [0_u8; HANDSHAKE_LEN];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, client.read_exact(&mut init))
        .await
        .map_err(|_| "Telegram не прислал рукопожатие".to_string())?
        .map_err(|_| "Telegram закрыл соединение до рукопожатия".to_string())?;

    let Some(hello) = parse_client_hello(&init, &shared.secret) else {
        let mut sink = vec![0_u8; 4096];
        let mut drained = 0;
        while drained < BAD_HANDSHAKE_DRAIN {
            match tokio::time::timeout(HANDSHAKE_TIMEOUT, client.read(&mut sink)).await {
                Ok(Ok(read)) if read > 0 => drained += read,
                _ => break,
            }
        }
        return Err("неверный секрет: обновите ссылку прокси в Telegram".to_string());
    };

    let is_test = hello.dc >= 10000;
    let dc = if is_test { hello.dc - 10000 } else { hello.dc };
    let dc_idx = i16::try_from(if hello.is_media { -dc } else { dc }).unwrap_or(2);
    let rng = &shared.rng;
    let relay_init = build_relay_init(hello.proto_tag, dc_idx, &mut |buffer: &mut [u8]| {
        if rng.fill(buffer).is_err() {
            fastrand::fill(buffer);
        }
    });
    let ctx = build_crypto(&hello, &shared.secret, &relay_init);

    let upstream = open_upstream(&shared, dc, hello.is_media, is_test).await?;
    match upstream {
        Upstream::Ws {
            reader,
            writer,
            label,
            split,
        } => {
            *shared.stats.last_front.lock().await = label;
            writer
                .send(&relay_init)
                .await
                .map_err(|error| format!("заголовок к Telegram не ушёл: {error}"))?;
            let splitter = split.then(|| MsgSplitter::new(hello.proto));
            bridge::bridge_ws(client, reader, writer, ctx, splitter, shared.stats.clone()).await;
        }
        Upstream::Tcp { mut stream, label } => {
            *shared.stats.last_front.lock().await = label;
            tokio::io::AsyncWriteExt::write_all(&mut stream, &relay_init)
                .await
                .map_err(|error| format!("заголовок к Telegram не ушёл: {error}"))?;
            bridge::bridge_tcp(client, stream, ctx, shared.stats.clone()).await;
        }
    }
    Ok(())
}

async fn open_upstream(shared: &Shared, dc: i32, is_media: bool, is_test: bool) -> Result<Upstream, String> {
    let mut errors: Vec<String> = Vec::new();
    let media = if is_media { " media" } else { "" };

    if let Some(upstream) = try_direct(shared, dc, is_media, is_test, &mut errors).await {
        return Ok(upstream);
    }

    if let (Some(worker), Some(dst)) = (shared.worker.as_deref(), fallback_ip(dc, is_test)) {
        let path = format!("{WS_PATH}?dst={dst}&dc={dc}");
        let target = WsTarget {
            connect_host: worker,
            host_header: worker,
            sni: worker,
            path: &path,
            fronting: false,
        };
        match connect(&target, &shared.tls, CF_TIMEOUT).await {
            Ok((reader, writer)) => {
                return Ok(Upstream::Ws {
                    reader,
                    writer,
                    label: format!("DC{dc}{media} · воркер {worker}"),
                    split: false,
                })
            }
            Err(error) => errors.push(error),
        }
    }

    if !is_test {
        let candidates = shared
            .balancer
            .lock()
            .map(|balancer| balancer.domains_for_dc(dc))
            .unwrap_or_default();
        for base in candidates.into_iter().take(CF_ATTEMPTS) {
            let host = format!("kws{dc}.{base}");
            let target = WsTarget {
                connect_host: &host,
                host_header: &host,
                sni: &host,
                path: WS_PATH,
                fronting: false,
            };
            match connect(&target, &shared.tls, CF_TIMEOUT).await {
                Ok((reader, writer)) => {
                    if let Ok(mut balancer) = shared.balancer.lock() {
                        balancer.remember(dc, &base);
                    }
                    return Ok(Upstream::Ws {
                        reader,
                        writer,
                        label: format!("DC{dc}{media} · CF {host}"),
                        split: true,
                    });
                }
                Err(error) => errors.push(error),
            }
        }
    }

    if let Some(dst) = fallback_ip(dc, is_test) {
        match tokio::time::timeout(TCP_TIMEOUT, TcpStream::connect((dst, 443))).await {
            Ok(Ok(stream)) => {
                let _ = stream.set_nodelay(true);
                return Ok(Upstream::Tcp {
                    stream,
                    label: format!("DC{dc}{media} · TCP {dst}"),
                });
            }
            Ok(Err(error)) => errors.push(format!("TCP {dst}: {error}")),
            Err(_) => errors.push(format!("TCP {dst}: таймаут")),
        }
    }

    Err(format!(
        "DC{dc}{media}: ни один маршрут не ответил ({})",
        errors.last().cloned().unwrap_or_else(|| "нет маршрутов".to_string())
    ))
}

async fn try_direct(shared: &Shared, dc: i32, is_media: bool, is_test: bool, errors: &mut Vec<String>) -> Option<Upstream> {
    let ip = redirect_ip(dc)?;
    let key = (dc, is_media);
    let now = Instant::now();
    if shared
        .direct_blocked_until
        .lock()
        .ok()
        .and_then(|map| map.get(&key).copied())
        .is_some_and(|until| until > now)
    {
        return None;
    }
    let path = if is_test { WS_PATH_TEST } else { WS_PATH };
    let fronting_first = shared.fronting_first.load(Ordering::Relaxed);
    let media = if is_media { " media" } else { "" };
    for domain in ws_domains(dc, is_media) {
        for fronting in [fronting_first, !fronting_first] {
            let target = WsTarget {
                connect_host: ip,
                host_header: &domain,
                sni: if fronting { FRONTING_SNI } else { &domain },
                path,
                fronting,
            };
            match connect(&target, &shared.tls, DIRECT_TIMEOUT).await {
                Ok((reader, writer)) => {
                    shared.fronting_first.store(fronting, Ordering::Relaxed);
                    let mode = if fronting { "прямой WS, фронтинг" } else { "прямой WS" };
                    return Some(Upstream::Ws {
                        reader,
                        writer,
                        label: format!("DC{dc}{media} · {mode} {domain}"),
                        split: true,
                    });
                }
                Err(error) => errors.push(error),
            }
        }
    }
    if let Ok(mut map) = shared.direct_blocked_until.lock() {
        map.insert(key, now + DIRECT_BACKOFF);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_roundtrip_and_link() {
        let secret = generate_secret();
        assert_eq!(secret.len(), 32);
        assert!(parse_secret(&secret).is_some());
        assert!(parse_secret("zz").is_none());
        assert_eq!(
            proxy_link("127.0.0.1", 1443, "00112233445566778899aabbccddeeff"),
            "tg://proxy?server=127.0.0.1&port=1443&secret=dd00112233445566778899aabbccddeeff"
        );
    }
}
