//! Порт pathlib.PureWindowsPath (имя/родитель/суффиксы) — ровно на те части,
//! которые нужны спискам и правкам фильтров.

/// Контекст Windows-пути (python pathlib.PureWindowsPath).
///
/// Только чистый разбор строки: разделители «\\» и «/», диск, UNC,
/// компоненты пути (без «/../..» — pathlib не разрешает «..»).
pub struct PureWinPath {
    drive: String,
    root: String,
    tail: Vec<String>,
}

fn splitroot(value: &str) -> (String, String, String) {
    let normalized: String = value.replace('/', "\\");
    if normalized.starts_with('\\') {
        if normalized.starts_with("\\\\") {
            // UNC-диск \\server\share или устройство \\?\device.
            let start = if normalized
                .get(..8)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("\\\\?\\UNC\\"))
            {
                8
            } else {
                2
            };
            let Some(index) = normalized[start..].find('\\').map(|p| p + start) else {
                return (normalized, String::new(), String::new());
            };
            let Some(index2) = normalized[index + 1..].find('\\').map(|p| p + index + 1) else {
                return (normalized, String::new(), String::new());
            };
            (
                normalized[..index2].to_string(),
                normalized[index2..index2 + 1].to_string(),
                normalized[index2 + 1..].to_string(),
            )
        } else {
            // Относительный путь с корнем, например \Windows.
            (
                String::new(),
                "\\".to_string(),
                normalized.trim_start_matches("\\").to_string(),
            )
        }
    } else if normalized.as_bytes().get(1) == Some(&b':') {
        if normalized.as_bytes().get(2) == Some(&b'\\') {
            // Абсолютный путь с диском, например X:\Windows.
            (
                normalized[..2].to_string(),
                "\\".to_string(),
                normalized[3..].to_string(),
            )
        } else {
            // Относительный путь с диском, например X:Windows.
            (
                normalized[..2].to_string(),
                String::new(),
                normalized[2..].to_string(),
            )
        }
    } else {
        // Относительный путь, например Windows.
        (String::new(), String::new(), normalized)
    }
}

fn unc_needs_root(drive: &str) -> bool {
    if !drive.starts_with('\\') || drive.ends_with('\\') {
        return false;
    }
    let parts: Vec<&str> = drive.split('\\').collect();
    (parts.len() == 4 && !matches!(parts[2], "?" | ".")) || parts.len() == 6
}

fn tail_from(rel: &str) -> Vec<String> {
    rel.split('\\')
        .filter(|part| !part.is_empty() && *part != ".")
        .map(str::to_string)
        .collect()
}

impl PureWinPath {
    /// python PureWindowsPath(значение).
    pub fn new(value: &str) -> Self {
        if value.is_empty() {
            return Self {
                drive: String::new(),
                root: String::new(),
                tail: Vec::new(),
            };
        }
        let (drive, mut root, rel) = splitroot(value);
        let mut tail = tail_from(&rel);
        if root.is_empty() && unc_needs_root(&drive) {
            // python _parse_path: у UNC без корня корень появляется дальше
            // (//server/share), при этом хвост — уже за диском.
            let normalized: String = value.replace('/', "\\");
            tail = tail_from(&normalized[drive.len()..]);
            root = "\\".to_string();
        }
        Self { drive, root, tail }
    }

    /// Финальный компонент пути (python name).
    pub fn name(&self) -> &str {
        self.tail.last().map(String::as_str).unwrap_or("")
    }

    /// Полное имя родителя (python str(path.parent)); у корня — сам путь.
    pub fn parent_string(&self) -> String {
        if self.tail.is_empty() {
            return self.to_string();
        }
        self.format(&self.tail[..self.tail.len() - 1])
    }

    /// Все суффиксы имени (python suffixes), включая точки.
    pub fn suffixes(&self) -> Vec<String> {
        self.name()
            .trim_start_matches('.')
            .split('.')
            .skip(1)
            .map(|ext| format!(".{ext}"))
            .collect()
    }

    /// Имя без последнего суффикса (python stem).
    pub fn stem(&self) -> String {
        let name = self.name();
        match name.rfind('.') {
            Some(index) if !name[..index].trim_start_matches('.').is_empty() => {
                name[..index].to_string()
            }
            _ => name.to_string(),
        }
    }

    /// Строковое представление (python str(path)): пустое — «.».
    fn format(&self, tail: &[String]) -> String {
        let text = self.format_path(tail);
        if text.is_empty() {
            return ".".to_string();
        }
        text
    }

    fn format_path(&self, tail: &[String]) -> String {
        if !self.drive.is_empty() || !self.root.is_empty() {
            return format!("{}{}{}", self.drive, self.root, tail.join("\\"));
        }
        let mut parts: Vec<&str> = Vec::new();
        if let Some(first) = tail.first() {
            if has_drive(first) {
                parts.push(".");
            }
        }
        parts.extend(tail.iter().map(String::as_str));
        parts.join("\\")
    }
}

fn has_drive(value: &str) -> bool {
    // python ntpath.splitdrive(tail[0])[0] непуст для «X:…» внутри хвоста.
    let normalized: String = value.replace('/', "\\");
    normalized.as_bytes().get(1) == Some(&b':')
}

impl std::fmt::Display for PureWinPath {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = self.format(&self.tail);
        if text.is_empty() {
            return formatter.write_str(".");
        }
        formatter.write_str(&text)
    }
}
