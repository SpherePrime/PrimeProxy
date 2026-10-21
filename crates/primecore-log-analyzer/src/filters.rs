//! Порт `src/winws_log_analyzer/filters.py` — фильтрация списка
//! соединений для таблицы (чистые функции).

use crate::models::{ConnectionRecord, VERDICT_DROP, VERDICT_MODIFIED};

/// python `filter_connections` — отбирает соединения по подстроке
/// (hostname/IP) и флагам.
///
/// `only_affected` — оставить только соединения, где были modified/drop.
/// Возвращает ссылки на записи входного списка, сохраняя их порядок.
#[must_use]
pub fn filter_connections<'a>(
    connections: &'a [ConnectionRecord],
    text: &str,
    only_with_hostname: bool,
    only_affected: bool,
) -> Vec<&'a ConnectionRecord> {
    let needle = text.trim().to_lowercase();
    connections
        .iter()
        .filter(|conn| {
            if only_with_hostname && conn.hostname.is_empty() {
                return false;
            }
            if only_affected
                && conn
                    .verdict_counts
                    .get(VERDICT_MODIFIED)
                    .copied()
                    .unwrap_or(0)
                    == 0
                && conn.verdict_counts.get(VERDICT_DROP).copied().unwrap_or(0) == 0
            {
                return false;
            }
            if !needle.is_empty()
                && !conn.hostname.to_lowercase().contains(&needle)
                && !conn.remote_ip.to_lowercase().contains(&needle)
            {
                return false;
            }
            true
        })
        .collect()
}
