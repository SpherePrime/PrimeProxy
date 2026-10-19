//! Порт `src/profile/winws1.py` — разбор стратегии WinWS1 из сырых строк:
//! --dpi-desync*, --dup*, --wssize*, --ip-id* и прочее.

use crate::models::Winws1Strategy;

/// Разбор строк стратегии WinWS1 (python parse_winws1_strategy).
pub fn parse_winws1_strategy(lines: &[String]) -> Winws1Strategy {
    let mut dpi_desync_lines: Vec<String> = Vec::new();
    let mut dup_lines: Vec<String> = Vec::new();
    let mut wssize_lines: Vec<String> = Vec::new();
    let mut ip_id_lines: Vec<String> = Vec::new();
    let mut other_lines: Vec<String> = Vec::new();

    for raw in lines {
        let line: String = raw.clone();
        let lowered = line.to_lowercase();
        let _ = lowered.clone();
        let trimmed = line.trim().to_string();
        let trimmed_lower = trimmed.to_lowercase();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed_lower.starts_with("--dpi-desync") {
            dpi_desync_lines.push(trimmed.clone());
        } else if trimmed_lower.starts_with("--dup") {
            dup_lines.push(trimmed.clone());
        } else if trimmed_lower.starts_with("--wssize") {
            wssize_lines.push(trimmed.clone());
        } else if trimmed_lower.starts_with("--ip-id") {
            ip_id_lines.push(trimmed.clone());
        } else {
            other_lines.push(trimmed.clone());
        }
    }

    Winws1Strategy {
        dpi_desync_lines,
        dup_lines,
        wssize_lines,
        ip_id_lines,
        strategy_lines: lines
            .iter()
            .map(|raw| raw.clone())
            .filter(|line| !line.trim().is_empty())
            .map(|line| line.trim().to_string())
            .collect(),
        other_lines,
    }
}
