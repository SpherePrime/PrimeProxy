use std::sync::atomic::Ordering;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::handshake::CryptoCtx;
use super::splitter::MsgSplitter;
use super::ws_conn::{WsReader, WsWriter};
use super::TunnelStats;

const READ_CHUNK: usize = 64 * 1024;

pub async fn bridge_ws(
    client: TcpStream,
    mut reader: WsReader,
    writer: WsWriter,
    ctx: CryptoCtx,
    mut splitter: Option<MsgSplitter>,
    stats: Arc<TunnelStats>,
) {
    let (mut client_read, mut client_write) = client.into_split();
    let CryptoCtx {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ctx;
    let up_stats = stats.clone();
    let up_writer = writer.clone();

    let upstream = async move {
        let mut buffer = vec![0_u8; READ_CHUNK];
        loop {
            let read = match client_read.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    if let Some(tail) = splitter.as_mut().and_then(MsgSplitter::flush) {
                        let _ = up_writer.send(&tail).await;
                    }
                    break;
                }
                Ok(read) => read,
            };
            up_stats.bytes_up.fetch_add(read as u64, Ordering::Relaxed);
            let plain = clt_dec.update(&buffer[..read]);
            let cipher = tg_enc.update(&plain);
            let sent = match splitter.as_mut() {
                Some(splitter) => {
                    let parts = splitter.split(&cipher, &plain);
                    match parts.len() {
                        0 => Ok(()),
                        1 => up_writer.send(&parts[0]).await,
                        _ => up_writer.send_many(&parts).await,
                    }
                }
                None => up_writer.send(&cipher).await,
            };
            if sent.is_err() {
                break;
            }
        }
    };

    let downstream = async move {
        while let Ok(Some(data)) = reader.recv().await {
            stats.bytes_down.fetch_add(data.len() as u64, Ordering::Relaxed);
            let plain = tg_dec.update(&data);
            let cipher = clt_enc.update(&plain);
            if client_write.write_all(&cipher).await.is_err() {
                break;
            }
        }
        let _ = client_write.shutdown().await;
    };

    tokio::select! {
        () = upstream => {}
        () = downstream => {}
    }
    writer.close().await;
}

pub async fn bridge_tcp(client: TcpStream, remote: TcpStream, ctx: CryptoCtx, stats: Arc<TunnelStats>) {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut remote_read, mut remote_write) = remote.into_split();
    let CryptoCtx {
        mut clt_dec,
        mut clt_enc,
        mut tg_enc,
        mut tg_dec,
    } = ctx;
    let up_stats = stats.clone();

    let upstream = async move {
        let mut buffer = vec![0_u8; READ_CHUNK];
        while let Ok(read) = client_read.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            up_stats.bytes_up.fetch_add(read as u64, Ordering::Relaxed);
            let cipher = tg_enc.update(&clt_dec.update(&buffer[..read]));
            if remote_write.write_all(&cipher).await.is_err() {
                break;
            }
        }
        let _ = remote_write.shutdown().await;
    };

    let downstream = async move {
        let mut buffer = vec![0_u8; READ_CHUNK];
        while let Ok(read) = remote_read.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            stats.bytes_down.fetch_add(read as u64, Ordering::Relaxed);
            let cipher = clt_enc.update(&tg_dec.update(&buffer[..read]));
            if client_write.write_all(&cipher).await.is_err() {
                break;
            }
        }
        let _ = client_write.shutdown().await;
    };

    tokio::select! {
        () = upstream => {}
        () = downstream => {}
    }
}
