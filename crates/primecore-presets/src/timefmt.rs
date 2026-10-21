//! Время для метаданных пресетов без внешних крейтов.
//!
//! Python-происхождение: `presets/file_store.py` (`_now_iso`,
//! `_file_time_to_iso`) и `presets/list_metadata.py`
//! (`_format_file_modified_display`).
//!
//! Отклонение от python: python форматирует `modified_display` по локальному
//! времени машины (`datetime.fromtimestamp`), ядро считает по UTC — часовой
//! пояс применяет слой отображения (как в `primecore-diagnostics`).

/// python `datetime.now(timezone.utc).replace(microsecond=0).isoformat()`
/// с `+00:00` → `Z`: «2026-10-21T12:34:56Z».
#[must_use]
pub fn now_iso_utc(unix_s: i64) -> String {
    iso_z(unix_s)
}

/// python `datetime.fromtimestamp(value, tz=timezone.utc).replace(...)`:
/// время изменения файла в ISO; `value <= 0` — пустая строка.
#[must_use]
pub fn file_time_to_iso(unix_s: f64) -> String {
    if unix_s <= 0.0 {
        return String::new();
    }
    iso_z(unix_s.floor() as i64)
}

/// python `datetime.fromtimestamp(value).strftime("%d.%m.%Y %H:%M")`;
/// ошибка/нулевое время — пустая строка.
#[must_use]
pub fn format_file_modified_display(unix_s: f64) -> String {
    if unix_s <= 0.0 {
        return String::new();
    }
    let total = unix_s.floor() as i64;
    let days = total.div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let second_of_day = total.rem_euclid(86_400);
    format!(
        "{day:02}.{month:02}.{year:04} {:02}:{:02}",
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60
    )
}

fn iso_z(unix_s: i64) -> String {
    let days = unix_s.div_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let second_of_day = unix_s.rem_euclid(86_400);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / 3_600,
        (second_of_day % 3_600) / 60,
        second_of_day % 60
    )
}

/// python `datetime.date.fromordinal(719_468 + days)` — год/месяц/день.
#[must_use]
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let shifted = days + 719_468;
    let era = if shifted >= 0 {
        shifted
    } else {
        shifted - 146_096
    } / 146_097;
    let day_of_era = (shifted - era * 146_097) as u64;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era as i64 + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let mp = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if month <= 2 { year + 1 } else { year },
        month as u32,
        day as u32,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_matches_python_utc() {
        // python: datetime.fromtimestamp(1750000000, tz=timezone.utc)
        //         .replace(microsecond=0).isoformat().replace("+00:00", "Z")
        assert_eq!(now_iso_utc(1_750_000_000), "2025-06-15T15:06:40Z");
        assert_eq!(now_iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(now_iso_utc(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn file_time_iso_matches_python() {
        // python: то же, но от `float(path.stat().st_mtime)` — доли секунды
        // отбрасываются (replace(microsecond=0)).
        assert_eq!(file_time_to_iso(1_750_000_000.75), "2025-06-15T15:06:40Z");
        assert_eq!(file_time_to_iso(0.0), "");
        assert_eq!(file_time_to_iso(-5.0), "");
    }

    #[test]
    fn modified_display_matches_python() {
        // python: datetime.fromtimestamp(value).strftime("%d.%m.%Y %H:%M");
        // ядро считает по UTC (часовой пояс применяет слой отображения).
        assert_eq!(
            format_file_modified_display(1_750_000_000.0),
            "15.06.2025 15:06"
        );
        assert_eq!(format_file_modified_display(0.0), "");
        assert_eq!(format_file_modified_display(-1.0), "");
    }

    #[test]
    fn civil_from_days_matches_python_date() {
        // python: date.fromordinal(719468 + days)
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
        // Отрицательные дни ниже 0001-01-01 недостижимы: вызывающие коды
        // отбрасывают время <= 0 (`file_time_to_iso`, `format_file_modified_display`).
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }
}
