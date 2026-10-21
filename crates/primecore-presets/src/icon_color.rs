//! Порт `presets/icon_color.py` — цвет иконки пресета в шапке `# IconColor:`.

/// Цвет по умолчанию, если в шапке пресета цвета нет или он не узнаваем.
pub const DEFAULT_PRESET_ICON_COLOR: &str = "#5caee8";

/// python `normalize_preset_icon_color(value)`:
/// `#RRGGBB` — как есть (в нижнем регистре), `#RRGGBBAA` — первые шесть
/// знаков (альфа отбрасывается), всё остальное — цвет по умолчанию.
#[must_use]
pub fn normalize_preset_icon_color(value: Option<&str>) -> String {
    let raw = value.unwrap_or("").trim();
    if is_hex_rgb(raw) {
        return raw.to_lowercase();
    }
    if is_hex_rgba(raw) {
        return raw[..7].to_lowercase();
    }
    DEFAULT_PRESET_ICON_COLOR.to_string()
}

fn is_hex_rgb(value: &str) -> bool {
    value.len() == 7 && value.starts_with('#') && value[1..].chars().all(|c| c.is_ascii_hexdigit())
}

fn is_hex_rgba(value: &str) -> bool {
    value.len() == 9 && value.starts_with('#') && value[1..].chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_like_python() {
        assert_eq!(normalize_preset_icon_color(Some("#5CAEE8")), "#5caee8");
        assert_eq!(normalize_preset_icon_color(Some("#5caee8")), "#5caee8");
        assert_eq!(normalize_preset_icon_color(Some("#5caee8ff")), "#5caee8");
        assert_eq!(
            normalize_preset_icon_color(Some("red")),
            DEFAULT_PRESET_ICON_COLOR
        );
        assert_eq!(normalize_preset_icon_color(None), DEFAULT_PRESET_ICON_COLOR);
        assert_eq!(
            normalize_preset_icon_color(Some("#12345")),
            DEFAULT_PRESET_ICON_COLOR
        );
    }
}
