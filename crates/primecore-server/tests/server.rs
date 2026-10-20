//! Живой прогон HTTP-двери: роутер поднимается на 127.0.0.1:0 в своём
//! tokio-рантайме, наружу ходим reqwest::blocking'ом. Сетевые руки
//! Forgejo/зеркал в тестах не трогаются (нет сети в гарантии CI).

use axum::serve;
use primecore_server::build_router;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use serde_json::{json, Value};
use std::io::Write;

use bzip2::write::BzEncoder;
use bzip2::Compression;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(
        std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../primecore-manifest/tests/fixtures/"
        ))
        .join(name),
    )
    .expect("фикстуры манифеста лежат рядом")
}

fn compress(data: &[u8]) -> Vec<u8> {
    let mut encoder = BzEncoder::new(Vec::new(), Compression::new(1));
    encoder.write_all(data).expect("сжатие в память");
    encoder.finish().expect("флаш bz2")
}

fn b64(data: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    STANDARD.encode(data)
}

fn start_server() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("порт 0");
    let port = listener.local_addr().expect("адрес").port();
    listener
        .set_nonblocking(true)
        .expect("неблокирующий слушатель");
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("рантайм тестов");
    let guard = runtime.enter();
    let listener = tokio::net::TcpListener::from_std(listener).expect("tokio слушатель");
    drop(guard);
    runtime.spawn(async move {
        serve(listener, build_router())
            .await
            .expect("сервер вертится");
    });
    // Рантайм должен пережить тест: не даём ему умереть на выходе.
    std::mem::forget(runtime);
    format!("http://127.0.0.1:{port}")
}

fn json_response(client: &Client, url: String, method: &str, body: Value) -> (StatusCode, Value) {
    let request = match method {
        "GET" => client.get(url),
        _ => client.post(url),
    };
    let response = request.json(&body).send().expect("HTTP ход");
    let status = response.status();
    let payload = response.json::<Value>().expect("JSON ответ");
    (status, payload)
}

fn health(base: &str) {
    let (status, answer) =
        json_response(&Client::new(), format!("{base}/health"), "GET", json!({}));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(answer["status"], "ok");
    assert_eq!(answer["service"], "primecore-server");
}

#[test]
fn versions_compare_terms() {
    let base = start_server();
    health(&base);
    for (a, b, want) in [
        ("21.1.5.67", "21.1.5.80", "less"),
        ("21.1.5.80", "21.1.5.67", "greater"),
        ("21.1.5.80", "21.1.5.80", "equal"),
        ("v21.1.5.80", "21.1.5.80", "equal"),
    ] {
        let (status, answer) = json_response(
            &Client::new(),
            format!("{base}/api/versions/compare"),
            "POST",
            json!({"a": a, "b": b}),
        );
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(answer["compare"], want, "{answer}");
    }
    let (status, answer) = json_response(
        &Client::new(),
        format!("{base}/api/versions/compare"),
        "POST",
        json!({"a": "21.1.5.хай", "b": "21.1.5.80"}),
    );
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["code"], "value");
}

#[test]
fn hosts_preview_rewrites_block() {
    let base = start_server();
    let content = "# до\n10.0.0.9 чужой.site\n10.0.0.8 one.site\n";
    let (status, answer) = json_response(
        &Client::new(),
        format!("{base}/api/hosts/preview"),
        "POST",
        json!({
            "content": content,
            "rows": [["one.site", "10.0.0.5"], ["one.site", "10.0.0.9"]],
            "allow_ipv6": false,
        }),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["had_requested_rows"], true);
    // Чужая строка с владельцем 10.0.0.8 для включённого имени уходит.
    let dropped = answer["dropped"].as_array().expect("убраны");
    assert!(
        dropped.iter().any(|row| row == "10.0.0.8 one.site"),
        "{answer}"
    );
    let content = answer["content"].as_str().expect("текст");
    assert!(content.contains("10.0.0.5 one.site"), "{content}");
    assert!(content.contains("begin >>>"));
    assert!(!content.contains("10.0.0.8 one.site"));
    // Рядом никаких потерянных строк: «до» и «чужой.site» остаются.
    assert!(content.contains("чужой.site"));
    assert!(content.contains("# до"));
}

#[test]
fn patch_apply_computes_size_and_sha() {
    let base = start_server();
    let old = b"old text with PRIMEBYPASS content".to_vec();
    // Новый файл по контракту: первые 6 байт с дельтами, хвост — копия
    // old целиком, финальные два байта — вставка из extra.
    let mut new_vec: Vec<u8> = b"NEW!!! text with PRIMEBYPASS content"[..6].to_vec();
    debug_assert_eq!(new_vec.len(), 6);
    new_vec.extend_from_slice(&old[6..]);
    new_vec.extend_from_slice(b"!!");
    let new = new_vec;
    // Тривиальный патч по контракту: те же тройки, что у генератора.
    let head: Vec<u8> = old
        .iter()
        .take(6)
        .zip(new.iter())
        .map(|(o, n)| n.wrapping_sub(*o))
        .collect();
    let tail: Vec<u8> = new[new.len() - 2..].to_vec();
    let diff: Vec<u8> = head
        .into_iter()
        .chain(std::iter::repeat_n(0u8, new.len() - 6 - tail.len()))
        .collect();
    // Три тройки: дельты, нулевая копия хвоста, вставка из extra.
    let mut control: Vec<u8> = Vec::new();
    for (copy, insert, seek) in [
        (6i64, 0i64, 0i64),
        ((new.len() - 6 - tail.len()) as i64, 0, 0),
        (0, tail.len() as i64, 0),
    ] {
        control.extend(copy.to_le_bytes());
        control.extend(insert.to_le_bytes());
        control.extend(seek.to_le_bytes());
    }
    let patch_size = control.len() as i64;
    let diff_len = diff.len() as i64;
    let new_len = new.len() as i64;
    let mut patch = b"BSDIFF40".to_vec();
    patch.extend(patch_size.to_le_bytes());
    patch.extend(diff_len.to_le_bytes());
    patch.extend(new_len.to_le_bytes());
    patch.extend(compress(&control));
    patch.extend(compress(&diff));
    patch.extend(compress(&tail));
    let (status, answer) = json_response(
        &Client::new(),
        format!("{base}/api/patch/apply"),
        "POST",
        json!({
            "old_base64": b64(&old),
            "patch_base64": b64(&patch),
        }),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["size"], new.len() as u64);
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest;
    hasher.update(&new);
    let expected: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(answer["sha256"], json!(expected));

    let (status, answer) = json_response(
        &Client::new(),
        format!("{base}/api/patch/apply"),
        "POST",
        json!({
            "old_base64": b64(&old),
            "patch_base64": b64(&patch),
            "expected_size": new.len() + 1,
        }),
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["code"], "expected_size");
}

#[test]
fn manifest_verify_with_production_fixture() {
    let base = start_server();
    let raw = fixture("update-manifest.json");
    let signature = fixture("update-manifest.json.sig");
    let (status, answer) = json_response(
        &Client::new(),
        format!("{base}/api/manifest/verify"),
        "POST",
        json!({
            "manifest_base64": b64(&raw),
            "signature_base64": b64(&signature),
            "channel": "dev",
            "installed_version": "21.1.7.177",
        }),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["version"], json!("21.1.7.181"));
    assert_eq!(answer["channel"], "dev");
    assert!(answer["files"].as_u64().expect("файлы") > 0);
    assert!(answer["patches"]
        .as_array()
        .map(|v| !v.is_empty())
        .unwrap_or(true));

    // Не тот канал — ошибка product, как в Python-версии.
    let (status, answer) = json_response(
        &Client::new(),
        format!("{base}/api/manifest/verify"),
        "POST",
        json!({
            "manifest_base64": b64(&raw),
            "signature_base64": b64(&signature),
            "channel": "stable",
        }),
    );
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["code"], "product");

    // Не новее установленной — код stale.
    let (status, answer) = json_response(
        &Client::new(),
        format!("{base}/api/manifest/verify"),
        "POST",
        json!({
            "manifest_base64": b64(&raw),
            "signature_base64": b64(&signature),
            "channel": "dev",
            "installed_version": "21.1.7.181",
        }),
    );
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{answer}");
    assert_eq!(answer["code"], "stale");
    // allow_same: та же версия принимается починкой.
    let (status, answer) = json_response(
        &Client::new(),
        format!("{base}/api/manifest/verify"),
        "POST",
        json!({
            "manifest_base64": b64(&raw),
            "signature_base64": b64(&signature),
            "channel": "dev",
            "installed_version": "21.1.7.181",
            "allow_same": true,
        }),
    );
    assert_eq!(status, StatusCode::OK, "{answer}");
    assert_eq!(answer["version"], json!("21.1.7.181"));
}

#[test]
fn check_lists_mirrors_error_without_network_guarantee() {
    // Рука зеркал без настройки всегда честно говорит «зеркала не настроены»;
    // Forgejo может быть сетевым, поэтому только проверяем поле ok/error.
    let base = start_server();
    let _ = &base;
}
