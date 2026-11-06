use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use primecore_telegram::proxy::ws::{
    accept_value, decode_frame, encode_frame, parse_response_head, MAX_HEADER, OP_BINARY, OP_CLOSE,
    OP_CONT, OP_PING, OP_PONG, OP_TEXT,
};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

type Stream = TlsStream<TcpStream>;

#[derive(Clone)]
pub struct TlsConfigs {
    pub verified: Arc<rustls::ClientConfig>,
    pub fronting: Arc<rustls::ClientConfig>,
}

impl TlsConfigs {
    #[must_use]
    pub fn new() -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let verified = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("ring даёт безопасные версии протокола")
            .with_root_certificates(roots)
            .with_no_client_auth();
        let fronting = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_safe_default_protocol_versions()
            .expect("ring даёт безопасные версии протокола")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertificate(provider)))
            .with_no_client_auth();
        Self {
            verified: Arc::new(verified),
            fronting: Arc::new(fronting),
        }
    }
}

impl Default for TlsConfigs {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
struct AnyCertificate(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AnyCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

pub struct WsTarget<'a> {
    pub connect_host: &'a str,
    pub host_header: &'a str,
    pub sni: &'a str,
    pub path: &'a str,
    pub fronting: bool,
}

fn ws_key() -> String {
    let mut raw = [0_u8; 16];
    fastrand::fill(&mut raw);
    base64::engine::general_purpose::STANDARD.encode(raw)
}

async fn read_head(stream: &mut Stream) -> Result<Vec<u8>, String> {
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

pub async fn connect(target: &WsTarget<'_>, tls: &TlsConfigs, timeout: Duration) -> Result<(WsReader, WsWriter), String> {
    tokio::time::timeout(timeout, connect_inner(target, tls))
        .await
        .map_err(|_| format!("{}: таймаут", target.host_header))?
}

async fn connect_inner(target: &WsTarget<'_>, tls: &TlsConfigs) -> Result<(WsReader, WsWriter), String> {
    let socket = TcpStream::connect((target.connect_host, 443))
        .await
        .map_err(|error| format!("{}: соединение не открылось: {error}", target.host_header))?;
    let _ = socket.set_nodelay(true);
    let name = ServerName::try_from(target.sni.to_string())
        .map_err(|error| format!("имя {} не разобралось: {error}", target.sni))?;
    let config = if target.fronting { tls.fronting.clone() } else { tls.verified.clone() };
    let mut stream = tokio_rustls::TlsConnector::from(config)
        .connect(name, socket)
        .await
        .map_err(|error| format!("{}: TLS не поднялся: {error}", target.host_header))?;

    let key = ws_key();
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: binary\r\n\r\n",
        target.path, target.host_header
    );
    stream
        .write_all(request.as_bytes())
        .await
        .map_err(|error| format!("{}: запрос upgrade не ушёл: {error}", target.host_header))?;
    let head = read_head(&mut stream).await?;
    let parsed = parse_response_head(&head).map_err(|error| error.to_string())?;
    if parsed.status != 101 {
        return Err(format!("{} ответил {}", target.host_header, parsed.status));
    }
    if parsed.header("sec-websocket-accept") != Some(accept_value(&key).as_str()) {
        return Err(format!("{} не подтвердил upgrade", target.host_header));
    }
    let (reader, writer) = tokio::io::split(stream);
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    Ok((
        WsReader {
            inner: reader,
            buffer: Vec::with_capacity(64 * 1024),
            fragments: Vec::new(),
            writer: writer.clone(),
        },
        WsWriter { inner: writer },
    ))
}

#[derive(Clone)]
pub struct WsWriter {
    inner: Arc<tokio::sync::Mutex<WriteHalf<Stream>>>,
}

impl WsWriter {
    pub async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        let frame = encode_frame(OP_BINARY, payload);
        let mut writer = self.inner.lock().await;
        writer.write_all(&frame).await?;
        writer.flush().await
    }

    pub async fn send_many(&self, payloads: &[Vec<u8>]) -> std::io::Result<()> {
        let mut batch = Vec::new();
        for payload in payloads {
            batch.extend(encode_frame(OP_BINARY, payload));
        }
        let mut writer = self.inner.lock().await;
        writer.write_all(&batch).await?;
        writer.flush().await
    }

    pub async fn close(&self) {
        let frame = encode_frame(OP_CLOSE, &[]);
        let mut writer = self.inner.lock().await;
        let _ = writer.write_all(&frame).await;
        let _ = writer.shutdown().await;
    }
}

pub struct WsReader {
    inner: ReadHalf<Stream>,
    buffer: Vec<u8>,
    fragments: Vec<u8>,
    writer: Arc<tokio::sync::Mutex<WriteHalf<Stream>>>,
}

impl WsReader {
    pub async fn recv(&mut self) -> Result<Option<Vec<u8>>, String> {
        loop {
            match decode_frame(&self.buffer).map_err(|error| error.0)? {
                Some(frame) => {
                    self.buffer.drain(..frame.consumed);
                    match frame.opcode {
                        OP_BINARY | OP_TEXT => {
                            if self.fragments.is_empty() {
                                return Ok(Some(frame.payload));
                            }
                            self.fragments.extend(frame.payload);
                            return Ok(Some(std::mem::take(&mut self.fragments)));
                        }
                        OP_CONT => {
                            self.fragments.extend(frame.payload);
                        }
                        OP_PING => {
                            let pong = encode_frame(OP_PONG, &frame.payload);
                            let mut writer = self.writer.lock().await;
                            writer
                                .write_all(&pong)
                                .await
                                .map_err(|error| format!("pong не ушёл: {error}"))?;
                        }
                        OP_CLOSE => return Ok(None),
                        _ => {}
                    }
                }
                None => {
                    let mut chunk = [0_u8; 64 * 1024];
                    let read = self
                        .inner
                        .read(&mut chunk)
                        .await
                        .map_err(|error| format!("релей оборвал соединение: {error}"))?;
                    if read == 0 {
                        return Ok(None);
                    }
                    self.buffer.extend_from_slice(&chunk[..read]);
                }
            }
        }
    }
}
