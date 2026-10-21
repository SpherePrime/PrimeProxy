//! Порт `src/log/crash_handler.py` (чистая часть) — отчёты о падении:
//! формат отчёта и имя файла сохранения.
//!
//! Хуки исключений python (sys/threading/Qt), сбор системных сведений и
//! потоков — платформенные: их место занимают строки, переданные
//! вызывающим кодом. Формат отчёта сохранён 1:1 — тесты сверяются с
//! python-эталоном.

/// python `_get_system_info`-строка приходит снаружи; здесь — формат
/// заголовка отчёта.
///
/// python `_format_crash_report`: разделители 80/40 символов, отметка
/// времени с миллисекундами (обрезанной до 3 знаков), контекст, поток,
/// тип и сообщение исключения, traceback, сведения о системе и потоках.
// Восемь частей — ровно как в python-подписи; сворачивать в структуру
// не стали, чтобы соответствие эталону оставалось очевидным.
#[allow(clippy::too_many_arguments)]
#[must_use]
pub fn format_crash_report(
    timestamp: &str,
    context: &str,
    thread_name: &str,
    exception_type: &str,
    message: &str,
    traceback_text: &str,
    system_info: &str,
    thread_info: &str,
) -> String {
    let eq = "=".repeat(80);
    let dash = "─".repeat(40);
    format!(
        "\n{eq}\n🔴 CRASH REPORT - {timestamp}\n{eq}\n\n\
         Context: {context}\nThread: {thread_name}\n\n\
         {dash}\nEXCEPTION\n{dash}\n\
         Type: {exception_type}\n\
         Message: {message}\n\n\
         {dash}\nTRACEBACK\n{dash}\n\
         {traceback_text}\n\n\
         {dash}\nSYSTEM INFO\n{dash}\n\
         {system_info}\n\n\
         {dash}\nTHREADS\n{dash}\n\
         {thread_info}\n\n\
         {eq}\n"
    )
}

/// python `_save_crash_report` — имя файла отчёта:
/// `crash_<контекст>_ГГГГММДД_ЧЧММСС.log`. Время передаёт вызывающий.
#[must_use]
pub fn crash_report_filename(context: &str, now: (i64, u32, u32, u32, u32, u32)) -> String {
    let (year, month, day, hour, minute, second) = now;
    format!("crash_{context}_{year:04}{month:02}{day:02}_{hour:02}{minute:02}{second:02}.log")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// python-эталон: формат отчёта от _format_crash_report с теми же
    /// частями.
    #[test]
    fn report_format_matches_python() {
        let report = format_crash_report(
            "2026-10-21 12:00:00.123",
            "startup",
            "MainThread",
            "ValueError",
            "плохое значение",
            "Traceback (most recent call last):\n  ...\nValueError: плохое значение\n",
            "Windows 11, Python 3.14",
            "3 потока живы",
        );
        assert!(report.contains("🔴 CRASH REPORT - 2026-10-21 12:00:00.123"));
        assert!(report.contains("Context: startup"));
        assert!(report.contains("Thread: MainThread"));
        assert!(report.contains("Type: ValueError"));
        assert!(report.contains("Message: плохое значение"));
        assert!(report.contains("EXCEPTION"));
        assert!(report.contains("TRACEBACK"));
        assert!(report.contains("SYSTEM INFO"));
        assert!(report.contains("THREADS"));
        // Разделители ровно те же: '='*80 и '─'*40.
        assert!(report.contains(&"=".repeat(80)));
        assert!(report.contains(&"─".repeat(40)));
        // Первая строка пустая (python f""" начинается с \n).
        assert!(report.starts_with('\n'));
    }

    #[test]
    fn crash_filename_matches_strftime() {
        // python strftime("%Y%m%d_%H%M%S"); 1760000000 с — 2025-10-09 08:53:20.
        assert_eq!(
            crash_report_filename("crash", (2025, 10, 9, 8, 53, 20)),
            "crash_crash_20251009_085320.log"
        );
        assert_eq!(
            crash_report_filename("qt", (2026, 1, 2, 3, 4, 5)),
            "crash_qt_20260102_030405.log"
        );
    }
}
