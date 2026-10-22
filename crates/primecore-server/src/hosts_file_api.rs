//! Работа с файлом hosts (страница «Разблокировка сервисов»): чтение
//! текущего файла, применение блока PrimeProxy через крейт
//! [`primecore_hosts`], привилегированная запись через демон `privd`.
//!
//! Запись файла — операция `file_write` демона `privd` (root): при первой
//! перезаписи демон сам создаёт бэкап `<path>.primebak`.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use primecore_hosts::{self, Rows};
use serde::Deserialize;
use serde_json::{json, Value};

use primecore_privilege::client;

use crate::ws_api::WsState;

/// Путь к файлу hosts: `PRIMECORE_HOSTS_PATH`, иначе системный.
#[must_use]
pub fn hosts_path() -> String {
    std::env::var("PRIMECORE_HOSTS_PATH")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "/etc/hosts".to_string())
}

/// Тело запроса применения блока.
#[derive(Debug, Deserialize)]
pub struct ApplyRequest {
    /// Пары «домен, ip» желаемого блока.
    pub rows: Vec<Vec<String>>,
    /// Разрешать IPv6-записи (эталон `allow_ipv6`).
    #[serde(default = "default_true")]
    pub allow_ipv6: bool,
    /// Путь к файлу (для тестов); пусто — [`hosts_path`].
    #[serde(default)]
    pub path: String,
}

fn default_true() -> bool {
    true
}

/// Прочитать файл hosts и собрать описание страницы.
fn read_hosts(path: &str) -> Value {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => {
            return json!({
                "path": path,
                "content": null,
                "managed_rows": [],
                "blocked_count": 0,
                "error": format!("файл не читается: {error}"),
            });
        }
    };
    let lines: primecore_hosts::Lines = content.split_inclusive('\n').map(str::to_string).collect();
    let rows: Vec<Value> = primecore_hosts::iter_managed_hosts_block_rows(&lines)
        .iter()
        .map(|(domain, ip)| json!([domain, ip]))
        .collect();
    json!({
        "path": path,
        "content": content,
        "managed_rows": rows,
        "blocked_count": rows.len(),
    })
}

/// GET /api/hosts/file — текущий файл hosts и его блок PrimeProxy.
pub async fn file() -> Json<Value> {
    Json(read_hosts(&hosts_path()))
}

/// POST /api/hosts/apply — пересобрать блок и записать файл через privd.
pub async fn apply(
    State(state): State<WsState>,
    Json(request): Json<ApplyRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let path = if request.path.trim().is_empty() {
        hosts_path()
    } else {
        request.path.clone()
    };
    let current = std::fs::read_to_string(&path).unwrap_or_default();
    let input_lines: primecore_hosts::Lines =
        current.split_inclusive('\n').map(str::to_string).collect();
    let rows: Rows = request
        .rows
        .iter()
        .filter_map(|pair| {
            let mut cells = pair.iter();
            let domain = cells.next()?.clone();
            let ip = cells.next()?.clone();
            Some((domain, ip))
        })
        .collect();
    let (without_block, _removed) = primecore_hosts::remove_managed_hosts_block(&input_lines);
    let (desired, _had) = primecore_hosts::filter_desired_hosts_rows(&rows, request.allow_ipv6);
    let (kept, dropped) = primecore_hosts::drop_conflicting_foreign_rows(&without_block, &desired);
    let mut final_lines = kept;
    primecore_hosts::insert_managed_hosts_block(&mut final_lines, &desired, None);
    let new_rows: Vec<Value> = primecore_hosts::iter_managed_hosts_block_rows(&final_lines)
        .iter()
        .map(|(domain, ip)| json!([domain, ip]))
        .collect();

    // Привилегированная запись через privd (root): бэкап создаёт демон.
    let content = final_lines.into_iter().collect::<String>();
    let encoded = base64::engine::general_purpose::STANDARD.encode(content.as_bytes());
    let request_line = format!(
        "{{\"op\":\"file_write\",\"path\":{},\"content_b64\":\"{encoded}\"}}",
        json_string(&path),
    );
    let reply = client::request(state.sock_path(), &request_line).map_err(no_privileges)?;
    let reply: Value = serde_json::from_str(&reply)
        .map_err(|error| internal(format!("странный ответ privd: {error}")))?;
    if reply["ok"].as_bool() != Some(true) {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": reply["error"].as_str().unwrap_or("запись не удалась")})),
        ));
    }
    Ok(Json(json!({
        "ok": true,
        "path": path,
        "managed_rows": new_rows,
        "dropped": dropped,
        "blocked_count": new_rows.len(),
    })))
}

/// Строка как JSON-строка (кавычки и экранирование).
fn json_string(value: &str) -> String {
    Value::String(value.to_string()).to_string()
}

/// 409 «нет прав» из ошибки сокета privd.
fn no_privileges(error: String) -> (StatusCode, Json<Value>) {
    (
        StatusCode::CONFLICT,
        Json(json!({"error": format!("нет прав: {error} — нажмите «Разрешить» на вкладке Обход")})),
    )
}

/// 500 внутренней ошибки.
fn internal(message: String) -> (StatusCode, Json<Value>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": message})),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Конвейер применения (без записи) на временных данных: блок
    /// вставляется, чужие конфликтные строки уходят.
    #[test]
    fn apply_pipeline_builds_block() {
        let current = "# header\n1.2.3.4 someone.example\n";
        let input_lines: primecore_hosts::Lines =
            current.split_inclusive('\n').map(str::to_string).collect();
        let rows: Rows = vec![
            ("youtube.com".to_string(), "127.0.0.2".to_string()),
            ("discord.com".to_string(), "127.0.0.2".to_string()),
        ];
        let (without_block, removed) = primecore_hosts::remove_managed_hosts_block(&input_lines);
        assert_eq!(removed, 0, "блока ещё нет");
        let (desired, _had) = primecore_hosts::filter_desired_hosts_rows(&rows, true);
        let (kept, dropped) =
            primecore_hosts::drop_conflicting_foreign_rows(&without_block, &desired);
        assert!(dropped.is_empty());
        let mut final_lines = kept;
        primecore_hosts::insert_managed_hosts_block(&mut final_lines, &desired, None);
        let text: String = final_lines.into_iter().collect();
        assert!(text.contains("youtube.com"), "{text}");
        assert!(
            text.contains("primebypass") || text.contains("primeproxy"),
            "{text}"
        );
    }

    /// Чтение файла hosts: путь и разбор блока из содержимого.
    #[test]
    fn read_hosts_reports_error_for_missing_file() {
        let answer = read_hosts("/nonexistent/hosts-test-path");
        assert!(answer["error"].is_string());
        assert_eq!(answer["blocked_count"], json!(0));
    }
}
