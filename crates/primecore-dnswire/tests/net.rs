//! Тесты UDP/TCP-транспорта против локального MOCK-сервера (127.0.0.1).
//!
//! Пакеты-заглушки берутся из golden.json (simple_a, truncated) с заменой
//! query id на id живого запроса — как reply реального сервера.

use std::io::{Read, Write};
use std::net::{TcpListener, UdpSocket};
use std::thread;

use primecore_socketcancel::SocketCancel;

use primecore_dnswire::net::{query_server, query_tcp, query_udp};
use primecore_dnswire::{STATUS_EMPTY, STATUS_ERROR, STATUS_OK, STATUS_TIMEOUT, TYPE_A};


/// Учитывает query id и признак ответа в заглушке (сервер копирует id).
fn reply_as(packet: Vec<u8>, query_id: u16) -> Vec<u8> {
    let mut reply = packet;
    reply[0] = (query_id >> 8) as u8;
    reply[1] = (query_id & 0xFF) as u8;
    reply
}

fn udp_server(packet_name: &'static str, hold: bool) -> (u16, thread::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("локальный UDP");
    let port = socket.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        let (size, source) = socket.recv_from(&mut buffer).expect("запрос пришёл");
        let query_id = u16::from_be_bytes([buffer[0], buffer[1]]);
        let _ = size;
        if hold {
            thread::sleep(std::time::Duration::from_millis(600));
        }
        let _ = socket.send_to(&reply_as(golden_packet_vec(packet_name), query_id), source);
    });
    (port, handle)
}

fn golden_packet_vec(name: &str) -> Vec<u8> {
    decode_packet(name)
}

fn decode_packet(name: &str) -> Vec<u8> {
    let golden: serde_json::Value =
        serde_json::from_slice(include_bytes!("../tests/golden.json")).unwrap();
    let hex = golden["parse_response"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"].as_str().unwrap() == name)
        .unwrap()["packet"]
        .as_str()
        .unwrap()
        .to_string();
    (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
        .collect()
}

#[test]
fn udp_simple_answer() {
    let (port, server) = udp_server("simple_a", false);
    let result = query_udp("127.0.0.1", "example.com", TYPE_A, 2.0, port, None);
    assert_eq!(result.status, STATUS_OK);
    assert!(!result.truncated);
    assert_eq!(result.values(TYPE_A), vec!["93.184.216.34".to_string()]);
    server.join().expect("сервер не падает");
}

#[test]
fn udp_truncated_reports_flag() {
    let (port, server) = udp_server("truncated", false);
    let result = query_udp("127.0.0.1", "example.com", TYPE_A, 2.0, port, None);
    // В золоте TC-пакет пустой: статус empty, флаг TC доведён до truncated.
    assert_eq!(result.status, STATUS_EMPTY);
    assert!(result.truncated);
    server.join().expect("сервер не падает");
}

#[test]
fn udp_timeout_to_silent_server() {
    let (port, server) = udp_server("simple_a", true);
    let result = query_udp("127.0.0.1", "example.com", TYPE_A, 0.4, port, None);
    assert_eq!(result.status, STATUS_TIMEOUT);
    assert_eq!(result.failure, "timeout");
    drop(server);
}

#[test]
fn udp_timeout_when_port_closed() {
    // Порт никто не слушает. Несвязанный (unconnected) UDP-сокет не получает
    // ICMP-отказ — и у python на Linux тоже: молчание. (refused-случай
    // приходит в recvfrom на Windows как ConnectionResetError — ветка есть,
    // проверяется вручную, в golden-фикстуре failure_text.)
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let result = query_udp("127.0.0.1", "example.com", TYPE_A, 0.5, port, None);
    assert_eq!(result.status, STATUS_TIMEOUT);
    assert_eq!(result.failure, "timeout");
}

#[test]
fn udp_cancel_stops_wait() {
    // Как у python: «Стоп» из другого потока обрывает ожидание —
    // result.failure = cancelled, detail пустой.
    let (port, server) = udp_server("simple_a", true);
    let cancel = std::sync::Arc::new(SocketCancel::new());
    let stopper = {
        let cancel = std::sync::Arc::clone(&cancel);
        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(120));
            cancel.cancel();
        })
    };
    let result = query_udp("127.0.0.1", "example.com", TYPE_A, 2.0, port, Some(&cancel));
    stopper.join().expect("отмена нажалась");
    assert_eq!(result.status, STATUS_ERROR);
    assert_eq!(result.failure, "cancelled");
    assert_eq!(result.detail, "");
    drop(server);
}

#[test]
fn tcp_simple_answer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("TCP-подключение");
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).expect("длина запроса");
        let size = u16::from_be_bytes(header) as usize;
        let mut query = vec![0u8; size];
        stream.read_exact(&mut query).expect("запрос");
        let query_id = u16::from_be_bytes([query[0], query[1]]);
        let reply = reply_as(decode_packet("simple_a"), query_id);
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).expect("ответ");
    });
    let result = query_tcp("127.0.0.1", "example.com", TYPE_A, 2.0, port, None);
    assert_eq!(result.status, STATUS_OK);
    assert_eq!(result.values(TYPE_A), vec!["93.184.216.34".to_string()]);
    assert_eq!(result.records[0].name, "example.com");
    handle.join().expect("сервер TCP не падает");
}

#[test]
fn tcp_server_closes_without_answer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("TCP-подключение");
        // python-сервер, читающий запрос и закрывающий соединение без ответа:
        // клиент увидит FIN → «сервер закрыл соединение».
        let mut header = [0u8; 2];
        let _ = stream.read_exact(&mut header);
        let size = u16::from_be_bytes(header) as usize;
        let mut query = vec![0u8; size];
        let _ = stream.read_exact(&mut query);
        drop(stream);
    });
    let result = query_tcp("127.0.0.1", "example.com", TYPE_A, 2.0, port, None);
    assert_eq!(result.status, STATUS_ERROR);
    assert_eq!(result.failure, "closed");
    handle.join().expect("сервер TCP не падает");
}

#[test]
fn tcp_refused_on_closed_port() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = socket.local_addr().unwrap().port();
    drop(socket);
    let result = query_tcp("127.0.0.1", "example.com", TYPE_A, 0.8, port, None);
    assert_eq!(result.status, STATUS_ERROR);
    assert_eq!(result.failure, "refused");
}

#[test]
fn tcp_wrong_id_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("TCP-подключение");
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).expect("длина запроса");
        let size = u16::from_be_bytes(header) as usize;
        let mut query = vec![0u8; size];
        stream.read_exact(&mut query).expect("запрос");
        // Чужой id ответа — python-сервер поведёт себя так же: сбоит разбор.
        let reply = reply_as(decode_packet("simple_a"), 0);
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        let _ = stream.write_all(&framed);
    });
    let result = query_tcp("127.0.0.1", "example.com", TYPE_A, 2.0, port, None);
    assert_eq!(result.status, STATUS_ERROR);
    assert_eq!(result.failure, "malformed");
    handle.join().expect("сервер TCP не падает");
}

#[test]
fn query_server_falls_back_to_tcp_on_truncated() {
    // UDP отдаёт TC-ответ; TCP-сервер слушает на том же номере порта
    // (python query_server мержит и UDP и TCP на том же порту).
    let (udp_port, udp_thread) = udp_server("truncated", false);
    let listener = TcpListener::bind(("127.0.0.1", udp_port))
        .expect("TCP на том же номере порта, что и UDP");
    let handle = thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("TCP-подключение");
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).expect("длина запроса");
        let size = u16::from_be_bytes(header) as usize;
        let mut query = vec![0u8; size];
        stream.read_exact(&mut query).expect("запрос");
        let query_id = u16::from_be_bytes([query[0], query[1]]);
        let reply = reply_as(decode_packet("simple_a"), query_id);
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).expect("ответ");
    });
    let result = query_server("127.0.0.1", "example.com", TYPE_A, 2.0, 2, udp_port, None);
    assert_eq!(result.status, STATUS_OK);
    assert_eq!(result.values(TYPE_A), vec!["93.184.216.34".to_string()]);
    assert!(!result.truncated);
    udp_thread.join().expect("UDP mock не падает");
    handle.join().expect("TCP mock не падает");
}
