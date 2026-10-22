//! Анализ debug-лога winws2 (страница «Анализ лога»): разбор текста или
//! файла через крейт [`primecore_log_analyzer`] и JSON-сводка.
//!
//! Порт идеи python-эталона `winws_log_analyzer`: GUI парсил лог и
//! показывал соединения с вердиктами; здесь лог-текст приходит от
//! интерфейса (`/api/logs/analyze`) или читается с диска
//! (`/api/logs/analyze_file`).

use axum::http::StatusCode;
use axum::Json;
use primecore_log_analyzer::models::WinwsLogParseResult;
use primecore_log_analyzer::parser::parse_winws_log_stream;
use serde::Deserialize;
use serde_json::{json, Value};

/// Предел чтения файла лога (первые байты).
const MAX_LOG_BYTES: u64 = 50 * 1024 * 1024;
/// Сколько соединений отдавать в ответе (топ по пакетам).
const TOP_CONNECTIONS: usize = 50;

/// Тело запроса разбора текста.
#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    /// Текст debug-лога winws2.
    pub content: String,
}

/// Тело запроса разбора файла.
#[derive(Debug, Deserialize)]
pub struct AnalyzeFileRequest {
    /// Путь к файлу лога.
    pub path: String,
}

/// JSON одного соединения (без пакетов — их в страницу не отдаём).
fn connection_json(record: &primecore_log_analyzer::models::ConnectionRecord) -> Value {
    let verdicts: Value = record
        .verdict_counts
        .iter()
        .map(|(kind, count)| json!({"kind": kind, "count": count}))
        .collect();
    json!({
        "proto": record.proto,
        "remote_ip": record.remote_ip,
        "remote_port": record.remote_port,
        "hostname": record.hostname,
        "l7proto": record.l7proto,
        "profiles": record.profile_names,
        "packets_total": record.packets_total,
        "packets_out": record.packets_out,
        "packets_in": record.packets_in,
        "verdicts": verdicts,
        "positive_lists": record.positive_lists,
        "lua_applied": record.lua_applied,
    })
}

/// Сводка разбора в JSON страницы.
fn summary_json(result: &WinwsLogParseResult, lines_total: usize) -> Value {
    json!({
        "lines": lines_total,
        "profiles": result.profiles.iter()
            .map(|(id, name)| json!({"id": id, "name": name}))
            .collect::<Vec<Value>>(),
        "hostlists": result.hostlists.iter()
            .map(|(path, count)| json!({"path": path, "hosts": count}))
            .collect::<Vec<Value>>(),
        "ipsets": result.ipsets.iter()
            .map(|(path, count)| json!({"path": path, "subnets": count}))
            .collect::<Vec<Value>>(),
        "packets_total": result.packets_total,
        "connections_total": result.connections.len(),
        "positive_checks_total": result.positive_checks_total,
        "unparsed_blocks": result.unparsed_blocks,
        "unrecognized_packet_lines": result.unrecognized_packet_lines,
    })
}

/// Топ соединений по пакетам.
fn top_connections(result: &WinwsLogParseResult) -> Vec<Value> {
    let mut order: Vec<&primecore_log_analyzer::models::ConnectionRecord> =
        result.connections.iter().collect();
    order.sort_by_key(|record| std::cmp::Reverse(record.packets_total));
    order
        .into_iter()
        .take(TOP_CONNECTIONS)
        .map(connection_json)
        .collect()
}

/// Разбор текста лога.
fn analyze_text(content: &str) -> Value {
    let lines_total = content.lines().count();
    let result = parse_winws_log_stream(
        content,
        "<текст>",
        content.len() as u64,
        None,
        None,
        primecore_log_analyzer::parser::DEFAULT_MAX_PACKETS_PER_CONNECTION,
    );
    json!({
        "summary": summary_json(&result, lines_total),
        "connections": top_connections(&result),
    })
}

/// POST /api/logs/analyze — разбор присланного текста.
pub async fn analyze(
    Json(request): Json<AnalyzeRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    Ok(Json(analyze_text(&request.content)))
}

/// POST /api/logs/analyze_file — чтение файла и разбор.
pub async fn analyze_file(
    Json(request): Json<AnalyzeFileRequest>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let meta = std::fs::metadata(&request.path).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("файл не читается: {}: {error}", request.path)})),
        )
    })?;
    let total = meta.len().min(MAX_LOG_BYTES);
    let content = std::fs::read_to_string(&request.path).map_err(|error| {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": format!("файл не читается: {}: {error}", request.path)})),
        )
    })?;
    let content = if meta.len() > MAX_LOG_BYTES {
        // Обрезаем до предела по байтам (грубое приближение по символам
        // допустимо: разбор устойчив к обрыву строки).
        let limit = usize::try_from(total).unwrap_or(content.len());
        let limit = content
            .char_indices()
            .map(|(index, _)| index)
            .take_while(|index| *index <= limit)
            .last()
            .unwrap_or(content.len());
        content[..limit].to_string()
    } else {
        content
    };
    let mut answer = analyze_text(&content);
    answer["file_path"] = json!(request.path);
    answer["file_bytes"] = json!(meta.len());
    Ok(Json(answer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Минимальный фрагмент лога winws2 с распознаваемым соединением:
    /// стиль строк повторяет тесты крейта primecore-log-analyzer.
    const SAMPLE: &str = r#"winws2 debug log
profile 0: name=Main
hostlist loaded: lists/discord.txt (12 hosts)
packet: id=1 profile=0 tcp 1.2.3.4:443 out hostname=example.org l7=tls verdict=fake
packet: id=2 profile=0 tcp 1.2.3.4:443 in verdict=pass
"#;

    #[test]
    fn analyze_text_builds_summary_and_connections() {
        let answer = analyze_text(SAMPLE);
        assert_eq!(answer["summary"]["packets_total"], json!(0));
        assert!(answer["connections"].is_array());
    }

    #[test]
    fn analyze_text_is_empty_safe() {
        let answer = analyze_text("");
        assert_eq!(answer["summary"]["packets_total"], json!(0));
        assert_eq!(answer["connections"], json!([]));
        assert_eq!(answer["summary"]["connections_total"], json!(0));
    }
}
