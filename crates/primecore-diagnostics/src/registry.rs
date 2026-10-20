//! Порт `src/diagnostics/registry.py` — отметка «в реестре РКН»: значится ли
//! сайт или его адрес в реестре блокировок.
//!
//! Откуда данные. Открытый список `bol-van/rulist` на GitHub: выгрузка реестра
//! Роскомнадзора, разобранная на имена сайтов (около 1,7 млн) и на адреса,
//! заблокированные целиком. Список скачивается не чаще раза в сутки и хранится
//! на компьютере: проверяемые сайты никуда не отправляются, поиск идёт локально.
//!
//! Как хранится. Полтора миллиона строк в памяти заняли бы сотни мегабайт,
//! поэтому от каждого имени остаётся 8 байт отпечатка; отпечатки отсортированы
//! и лежат одним файлом (~14 МБ), поиск — делением пополам. Совпадение двух
//! разных имён по отпечатку практически невозможно (один шанс на миллиарды).
//!
//! Что значит отметка. «В реестре» — имя или адрес названы в реестре: сайт
//! заблокирован официально. «Не значится» — НЕ значит «не блокируют»: YouTube,
//! X и многое другое режут без записи в реестре. Поэтому отметка — справка
//! рядом с результатом проверки, а не её вывод.
//!
//! Здесь нет сети: скачивание передаётся снаружи ([`refresh`]-функции `fetch`).

use std::path::{Path, PathBuf};

use serde_json::Map;
use serde_json::{json, Value};

pub const HOSTS_URL: &str =
    "https://raw.githubusercontent.com/bol-van/rulist/main/reestr_hostname.txt";
pub const IPS_URL: &str = "https://raw.githubusercontent.com/bol-van/rulist/main/reestr_ipban4.txt";

pub const MAX_AGE_S: f64 = 24.0 * 3600.0;
/// Список старше недели всё ещё полезен, но об этом надо сказать.
pub const STALE_AFTER_S: f64 = 7.0 * 24.0 * 3600.0;

pub const STATE_FRESH: &str = "fresh";
pub const STATE_STALE: &str = "stale";
pub const STATE_MISSING: &str = "missing";

const KEY_BYTES: usize = 8;
const HOSTS_FILE: &str = "hosts.idx";
const IPS_FILE: &str = "networks.txt";
const META_FILE: &str = "meta.json";
/// Меньше этого — скачалось что-то не то (страница ошибки, обрезанный файл):
/// старый список не трогаем.
const MIN_HOSTS: usize = 100_000;

/// Ответ на скачивание; python `Fetched`. `body=None` при `unchanged` —
/// на сервере та же версия.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Fetched {
    pub body: Option<Vec<u8>>,
    pub etag: String,
    pub unchanged: bool,
}

/// Совпадения по реестру (python `Match`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Match {
    /// Имя из реестра, под которое попал сайт: он сам или домен выше.
    /// Пусто — не значится.
    pub name: String,
    /// Сеть из списка заблокированных адресов, в которую попал адрес сервера.
    /// Пусто — не значится.
    pub network: String,
}

impl Match {
    #[must_use]
    pub fn listed(&self) -> bool {
        !self.name.is_empty() || !self.network.is_empty()
    }
}

/// Текущее время как в python `time.time()`.
#[must_use]
pub fn unix_now() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|step| step.as_secs_f64())
        .unwrap_or(0.0)
}

/// python `_clean`.
fn clean(host: &str) -> String {
    host.trim()
        .trim_matches(|c| c == '"' || c == '.')
        .to_lowercase()
}

/// python `_key`: blake2b(digest_size=8) от UTF-8 имени.
#[must_use]
pub fn key(host: &str) -> [u8; KEY_BYTES] {
    let digest = blake2b_simd::Params::new()
        .hash_length(KEY_BYTES)
        .to_state()
        .update(host.as_bytes())
        .finalize();
    let bytes = digest.as_bytes().to_vec();
    let mut key = [0_u8; KEY_BYTES];
    key.copy_from_slice(&bytes[..KEY_BYTES]);
    key
}

/// Заблокированные адреса и сети: (первый адрес, последний, запись), по возрастанию.
/// python `build_networks`; строки приходят итератором.
#[must_use]
pub fn build_networks(lines: impl Iterator<Item = String>) -> Vec<(u32, u32, String)> {
    let mut found: Vec<(u32, u32, String)> = Vec::new();
    for line in lines {
        let text = line.trim().to_string();
        if text.is_empty() || text.starts_with('#') {
            continue;
        }
        if let Some((first, last)) = ipv4_network_range(&text) {
            found.push((first, last, text));
        }
    }
    found.sort_unstable();
    found
}

/// python `ipaddress.ip_network(text, strict=False)` для IPv4:
/// первый адрес (адресхостмаску значения) и Broadcast.
#[must_use]
fn ipv4_network_range(text: &str) -> Option<(u32, u32)> {
    let (address, prefix) = match text.split_once('/') {
        Some((address, prefix)) => (address, prefix.parse::<u8>().ok()?),
        None => (text, 32_u8),
    };
    if prefix > 32 {
        return None;
    }
    let value = ipv4_to_u32(address)?;
    let mask = match prefix {
        0 => 0,
        32 => u32::MAX,
        _ => !(u32::MAX >> u32::from(prefix)),
    };
    Some((value & mask, value | !mask))
}

/// python `int(ipaddress.IPv4Address(ip))`.
#[must_use]
pub fn ipv4_to_u32(address: &str) -> Option<u32> {
    let mut value: u32 = 0;
    let mut labels = 0;
    for label in address.split('.') {
        if label.is_empty() || !label.bytes().all(|byte| byte.is_ascii_digit()) || label.len() > 3 {
            return None;
        }
        let parsed: u16 = label.parse().ok()?;
        if parsed > 255 {
            return None;
        }
        value = value << 8 | u32::from(parsed);
        labels += 1;
    }
    (labels == 4).then_some(value)
}

/// python `Index`: индекс реестра на память.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Index {
    pub hosts: Vec<u8>,
    pub networks: Vec<(u32, u32, String)>,
    /// Когда список скачан (время компьютера). 0 — списка нет.
    pub updated: f64,
    /// Когда список последний раз сверяли с сервером.
    pub checked: f64,
    pub etags: Vec<(String, String)>,
}

impl Index {
    #[must_use]
    pub fn count(&self) -> usize {
        self.hosts.len() / KEY_BYTES
    }

    /// python `Index.state`.
    #[must_use]
    pub fn state(&self, now: Option<f64>) -> &'static str {
        if self.hosts.is_empty() {
            return STATE_MISSING;
        }
        let age = now.unwrap_or_else(unix_now) - self.updated;
        if age > STALE_AFTER_S {
            STATE_STALE
        } else {
            STATE_FRESH
        }
    }

    fn has(&self, name: &str) -> bool {
        let key = key(name);
        let mut low = 0;
        let mut high = self.count();
        while low < high {
            let middle = (low + high) / 2;
            let start = middle * KEY_BYTES;
            let item = &self.hosts[start..start + KEY_BYTES];
            if item == key.as_slice() {
                return true;
            }
            if item < key.as_slice() {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        false
    }

    /// Имя из реестра, под которое попадает сайт: он сам, без `www.` или домен
    /// выше.
    #[must_use]
    pub fn find_host(&self, host: &str) -> String {
        let name = clean(host);
        if name.is_empty() || self.hosts.is_empty() {
            return String::new();
        }
        let labels: Vec<&str> = name.split('.').collect();
        // До домена второго уровня: «com» и «ru» в реестре не ищем.
        for start in 0..labels.len().saturating_sub(1).max(1) {
            let candidate = labels[start..].join(".");
            if self.has(&candidate) {
                return candidate;
            }
        }
        String::new()
    }

    /// Запись списка заблокированных адресов, в которую попадает `ip`.
    #[must_use]
    pub fn find_ip(&self, ip: &str) -> String {
        if self.networks.is_empty() || ip.is_empty() || ip.contains(':') {
            return String::new();
        }
        let Some(value) = ipv4_to_u32(ip) else {
            return String::new();
        };
        // Сети отсортированы по началу; нужная могла начаться раньше — смотрим несколько назад.
        let position = self
            .networks
            .partition_point(|(start, _end, _text)| *start <= value);
        for (start, end, text) in self.networks[position.saturating_sub(8)..position]
            .iter()
            .rev()
        {
            if *start <= value && value <= *end {
                return text.clone();
            }
        }
        String::new()
    }

    /// python `Index.match`.
    #[must_use]
    pub fn match_registry(&self, host: &str, ip: &str) -> Match {
        Match {
            name: self.find_host(host),
            network: self.find_ip(ip),
        }
    }
}

/// python `default_folder` — папка списка рядом с программой; путь выдаёт слой
/// запуска (rust `config.runtime_layout`), сюда он приходит открытым параметром.
///
/// python `load` — список с диска. Нет файлов или они испорчены — пустой
/// список, без ошибки.
#[must_use]
pub fn load(folder: &Path) -> Index {
    let meta_bytes = match std::fs::read(folder.join(META_FILE)) {
        Ok(bytes) => bytes,
        Err(_) => return Index::default(),
    };
    let hosts = match std::fs::read(folder.join(HOSTS_FILE)) {
        Ok(bytes) => bytes,
        Err(_) => return Index::default(),
    };
    let Ok(meta) = serde_json::from_slice::<Value>(&meta_bytes) else {
        return Index::default();
    };
    if !meta.is_object() || hosts.len() % KEY_BYTES != 0 {
        return Index::default();
    }
    let networks = std::fs::read_to_string(folder.join(IPS_FILE))
        .map(|text| build_networks(text.lines().map(ToOwned::to_owned)))
        .unwrap_or_default();
    let etags_raw = meta.get("etags").cloned().unwrap_or_default();
    let etags_pairs: Vec<(String, String)> = if etags_raw.is_object() {
        let mut pairs: Vec<(String, String)> = match etags_raw.as_object() {
            Some(entries) => entries
                .iter()
                .map(|(key, value)| (key.clone(), value.as_str().unwrap_or_default().to_string()))
                .collect(),
            None => Vec::new(),
        };
        pairs.sort();
        pairs
    } else {
        Vec::new()
    };
    Index {
        hosts,
        networks,
        updated: meta.get("updated").and_then(Value::as_f64).unwrap_or(0.0),
        checked: meta.get("checked").and_then(Value::as_f64).unwrap_or(0.0),
        etags: etags_pairs,
    }
}

/// python `_write` — запись через временный файл: прерванная запись не
/// испортит прежний список.
fn write_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let name = path.to_string_lossy().to_string();
    let temp = PathBuf::from(format!("{name}.new"));
    std::fs::write(&temp, data)?;
    std::fs::rename(temp, path)
}

/// python `refresh`. Обновляет список, если с последней сверки прошло больше
/// суток. Возвращает то, что есть.
///
/// `fetch(адрес, прежняя метка версии)` скачивает файл или сообщает, что он не
/// менялся. Любая неудача (нет сети, GitHub недоступен, скачалось не то)
/// оставляет прежний список: устаревшая справка лучше никакой.
#[must_use]
pub fn refresh(
    folder: &Path,
    mut fetch: impl FnMut(&str, &str) -> Option<Fetched>,
    now: Option<f64>,
    max_age: f64,
) -> Index {
    let moment = now.unwrap_or_else(unix_now);
    let current = load(folder);
    if !current.hosts.is_empty() && moment - current.checked < max_age {
        return current;
    }
    let mut etags: Vec<(String, String)> = current.etags.clone();
    let etag_of = |etags: &[(String, String)], url: &str| -> String {
        etags
            .iter()
            .find(|(key, _value)| key == url)
            .map(|(_key, value)| value.clone())
            .unwrap_or_default()
    };
    if let Err(_error) = std::fs::create_dir_all(folder) {
        return current;
    }
    let mut changed = false;
    let old_hosts = !current.hosts.is_empty();
    let result: std::io::Result<()> = (|| {
        let Some(hosts) = fetch(
            HOSTS_URL,
            &if old_hosts {
                etag_of(&etags, HOSTS_URL)
            } else {
                String::new()
            },
        ) else {
            return Err(std::io::Error::other("fetch"));
        };
        if !hosts.unchanged {
            let body = hosts.body.clone().unwrap_or_default();
            let names: Vec<String> = body
                .split(|byte| *byte == b'\n')
                .map(|line| String::from_utf8_lossy(line).into_owned())
                .collect();
            let (index, count) = build_hosts(names.into_iter());
            if count < MIN_HOSTS {
                return Err(std::io::Error::other("small"));
            }
            write_file(&folder.join(HOSTS_FILE), &index)?;
            set_etag(&mut etags, HOSTS_URL, &hosts.etag);
            changed = true;
        }
        let old_ips = !current.networks.is_empty();
        if let Some(ips) = fetch(
            IPS_URL,
            &if old_ips {
                etag_of(&etags, IPS_URL)
            } else {
                String::new()
            },
        ) {
            if !ips.unchanged {
                let body = ips.body.clone().unwrap_or_default();
                let rows: Vec<String> = body
                    .split(|byte| *byte == b'\n')
                    .map(|line| String::from_utf8_lossy(line).to_string())
                    .collect();
                let networks = build_networks(rows.into_iter());
                if !networks.is_empty() {
                    write_file(&folder.join(IPS_FILE), &body)?;
                    set_etag(&mut etags, IPS_URL, &ips.etag);
                    changed = true;
                }
            }
        }
        let updated = if changed || current.updated == 0.0 {
            moment
        } else {
            current.updated
        };
        let mut meta = Map::new();
        meta.insert("updated".into(), json!(updated));
        meta.insert("checked".into(), json!(moment));
        let mut etag_map = Map::new();
        for (key, value) in &etags {
            etag_map.insert(key.clone(), json!(value));
        }
        meta.insert("etags".into(), Value::Object(etag_map));
        write_file(
            &folder.join(META_FILE),
            serde_json::to_string(&Value::Object(meta))
                .unwrap_or_default()
                .as_bytes(),
        )?;
        Ok(())
    })();
    if result.is_err() {
        return current;
    }
    load(folder)
}

/// python `etags[url] = etag`.
fn set_etag(etags: &mut Vec<(String, String)>, url: &str, etag: &str) {
    if let Some(slot) = etags.iter_mut().find(|(key, _value)| key == url) {
        slot.1 = etag.to_string();
    } else {
        etags.push((url.to_string(), etag.to_string()));
        etags.sort();
    }
}

/// python `_lines` + `build_hosts`: отпечатки имён одним куском и их число.
/// python раскладывает отпечатки по первому байту на 256 кучек, чтобы длинная
/// сортировка не замирала FTC/UI-потоком; в rust сортировка 256 коротких
/// отрезков ломится по месту.
#[must_use]
pub fn build_hosts(lines: impl Iterator<Item = String>) -> (Vec<u8>, usize) {
    let mut keys: Vec<[u8; KEY_BYTES]> = Vec::new();
    for name in lines {
        let name = clean(&name);
        if name.contains('.') && !name.is_empty() {
            keys.push(key(&name));
        }
    }
    keys.sort_unstable();
    keys.dedup();
    let mut index = Vec::with_capacity(keys.len() * KEY_BYTES);
    for item in &keys {
        index.extend_from_slice(item);
    }
    (index, keys.len())
}

/// python `time.strftime("%d.%m.%Y", time.localtime(updated))` — UTC-дата
/// из времени компьютера.
#[must_use]
pub fn format_date(seconds: f64) -> String {
    let days = seconds.floor() as i64 / 86_400;
    let civil = civil_from_days(days);
    format!("{:02}.{:02}.{}", civil.2, civil.1, civil.0)
}

/// python `datetime.date.fromordinal(719_468 + days).timetuple()`.
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

/// python `summary` — состояние списка для отчёта: есть ли он, когда скачан и
/// сколько в нём имён.
#[must_use]
pub fn summary(index: &Index, now: Option<f64>) -> Value {
    json!({
        "state": index.state(now),
        "updated": index.updated,
        "hosts": index.count(),
        "networks": index.networks.len(),
    })
}

/// python `lines` — раздел «Реестр РКН» для текстового отчёта.
#[must_use]
pub fn lines(services: &[Value], index: &Index, now: Option<f64>) -> Vec<String> {
    let mut out = vec![String::new(), "━━━━━━━━ Реестр РКН ━━━━━━━━".to_string()];
    if index.hosts.is_empty() {
        out.push(
            "❔ Список реестра скачать не удалось — отметок «в реестре» в этот раз нет".to_string(),
        );
        return out;
    }
    let when = format_date(index.updated);
    let stale = if index.state(now) == STATE_STALE {
        " (давно не обновлялся: свежий скачать не удалось)"
    } else {
        ""
    };
    out.push(format!(
        "ℹ️ Список от {when}{stale}: {} имён сайтов и {} заблокированных адресов и сетей",
        index.count(),
        index.networks.len(),
    ));
    let mut found = 0;
    for service in services {
        for target in service
            .get("targets")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let mark = target.get("registry").cloned().unwrap_or_default();
            if !mark.get("listed").and_then(Value::as_bool).unwrap_or(false) {
                continue;
            }
            found += 1;
            let mut parts: Vec<String> = Vec::new();
            let name = mark.get("name").and_then(Value::as_str).unwrap_or("");
            if !name.is_empty() {
                if name == target.get("host").and_then(Value::as_str).unwrap_or("") {
                    parts.push("имя в реестре".to_string());
                } else {
                    parts.push(format!("в реестре есть {name}"));
                }
            }
            if let Some(network) = mark.get("network").and_then(Value::as_str) {
                if !network.is_empty() {
                    parts.push(format!(
                        "адрес {} в списке заблокированных ({network})",
                        target.get("address").and_then(Value::as_str).unwrap_or(""),
                    ));
                }
            }
            out.push(format!(
                "📕 {}: {}",
                target.get("host").and_then(Value::as_str).unwrap_or(""),
                parts.join("; "),
            ));
        }
    }
    if found == 0 {
        out.push("ℹ️ Ни один из проверенных сайтов в реестре не значится".to_string());
    }
    out.push(
        "   Сайт могут блокировать и без записи в реестре — так режут, например, YouTube."
            .to_string(),
    );
    out
}

/// python `TAG_REGISTRY` — метка сайта, который значится в списке.
pub fn tag_registry() -> Value {
    json!({"key": "registry", "text": "в реестре РКН", "state": "info"})
}

/// python `annotate` — отчёт по сайтам с отметкой реестра. Пустой список —
/// отчёт как был.
///
/// Переданный список не меняется: его уже мог получить экран и читать из
/// другого потока. Отметка ложится в новые записи сайтов и их адресов.
#[must_use]
pub fn annotate(services: &[Value], index: &Index) -> Vec<Value> {
    if index.hosts.is_empty() {
        return services.to_vec();
    }
    let mut marked: Vec<Value> = Vec::new();
    for service in services {
        let mut targets: Vec<Value> = Vec::new();
        for target in service
            .get("targets")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            let found = index.match_registry(
                target.get("host").and_then(Value::as_str).unwrap_or(""),
                target.get("address").and_then(Value::as_str).unwrap_or(""),
            );
            let mut entry = target.clone();
            if let Some(object) = entry.as_object_mut() {
                object.insert(
                    "registry".into(),
                    json!({"listed": found.listed(), "name": found.name, "network": found.network}),
                );
            }
            targets.push(entry);
        }
        let mut tags: Vec<Value> = service
            .get("tags")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if targets.iter().any(|target| {
            target
                .get("registry")
                .and_then(|registry| registry.get("listed"))
                .and_then(Value::as_bool)
                .unwrap_or(false)
        }) && !tags.contains(&tag_registry())
        {
            tags.push(tag_registry());
        }
        let mut entry = service.clone();
        if let Some(object) = entry.as_object_mut() {
            object.insert("targets".into(), Value::Array(targets));
            object.insert("tags".into(), Value::Array(tags));
        }
        marked.push(entry);
    }
    marked
}

#[cfg(test)]
mod tests {
    use super::*;

    /// python `_clean` — кавычки, точки и пробелы по краям, затем нижний регистр.
    #[test]
    fn clean_python() {
        assert_eq!(clean("  \"www.site.org\"  "), "www.site.org");
        assert_eq!(clean("Site.ORG."), "site.org");
        assert_eq!(clean(""), "");
    }

    /// python `hashlib.blake2b(digest_size=8)` — значения посчитаны python-эталоном.
    #[test]
    fn key_python() {
        assert_eq!(key(""), [228, 166, 160, 87, 116, 121, 178, 180]);
        assert_eq!(key("site.org"), [179, 221, 85, 213, 82, 234, 199, 83]);
        assert_eq!(key("www.youtube.com"), [178, 162, 24, 48, 239, 7, 206, 196]);
    }

    /// python `build_networks` — сети по возрастанию, мусор пропущен.
    #[test]
    fn networks_python() {
        let rows: Vec<String> = [
            "# comment",
            "10.0.0.0/8",
            "192.168.5.3/32",
            "212.192.85.0/24",
            "10.2.0.0/15",
            "",
            "bolvan.invalid",
        ]
        .iter()
        .map(|row| row.to_string())
        .collect();
        let networks = build_networks(rows.into_iter());
        assert_eq!(
            networks,
            vec![
                (167_772_160, 184_549_375, "10.0.0.0/8".to_string()),
                (167_903_232, 168_034_303, "10.2.0.0/15".to_string()),
                (3_232_236_803, 3_232_236_803, "192.168.5.3/32".to_string()),
                (3_569_374_464, 3_569_374_719, "212.192.85.0/24".to_string()),
            ]
        );
        // /33 — мусор.
        assert_eq!(ipv4_network_range("10.0.0.0/33"), None);
        assert_eq!(ipv4_network_range("10.0.0.0/0"), Some((0, u32::MAX)));
        assert_eq!(
            ipv4_network_range("192.168.5.3"),
            Some((3_232_236_803, 3_232_236_803))
        );
        assert_eq!(ipv4_network_range("2001:db8::/32"), None);
    }

    /// python `Index` — отпечатки, поиск имени и адреса; значения сверены
    /// с python-эталоном на том же наборе.
    #[test]
    fn index_find_python() {
        let rows: Vec<String> = [
            "site.org",
            "  \"www.site.org\"  ",
            "uni.ru",
            "",
            "10.0.0.1",
            "plain",
        ]
        .iter()
        .map(|row| row.to_string())
        .collect();
        let (hosts, count) = build_hosts(rows.into_iter());
        assert_eq!(count, 4);
        // python: первый байт отпечатка первого имени.
        assert_eq!(hosts[0], 73);
        let index = index_for_test(hosts);
        assert_eq!(index.find_host("site.org"), "site.org");
        assert_eq!(index.find_host("example.org"), "");
        assert_eq!(index.find_host("www.site.org"), "www.site.org");
        assert_eq!(index.find_host("deep.site.org"), "site.org");
        assert_eq!(index.find_ip("212.192.85.14"), "212.192.85.0/24");
        assert_eq!(index.find_ip("10.1.2.3"), "10.0.0.0/8");
        assert_eq!(index.find_ip("::1"), "");
        assert_eq!(index.find_ip("192.168.5.3"), "192.168.5.3/32");
        let whole = index.match_registry("www.site.org", "212.192.85.14");
        assert_eq!(whole.name, "www.site.org");
        assert_eq!(whole.network, "212.192.85.0/24");
        assert!(whole.listed());
        assert!(!index.match_registry("example.org", "").listed());
    }

    /// python `load` — испорченные файлы дают пустой список.
    #[test]
    fn load_broken_python() {
        let folder = std::env::temp_dir().join(format!("rkn-broken-{}", std::process::id()));
        let _ignored = std::fs::remove_dir_all(&folder);
        let _ignored = std::fs::create_dir_all(&folder);
        std::fs::write(folder.join(META_FILE), b"{oops").unwrap();
        std::fs::write(folder.join(HOSTS_FILE), b"1").unwrap();
        assert_eq!(load(&folder), Index::default());
        let _ignored = std::fs::remove_dir_all(&folder);
    }

    /// python `refresh` — пустая папка, «скачалось не то», удачная загрузка,
    /// затем «не старше суток».
    #[test]
    fn refresh_python() {
        let folder = std::env::temp_dir().join(format!("rkn-fresh-{}", std::process::id()));
        let _ignored = std::fs::remove_dir_all(&folder);
        // 1. Пустая папка, fetch вернул None — индекс остался пустым.
        let listed = refresh(&folder, |_url, _etag| None, Some(100.0), MAX_AGE_S);
        assert!(listed.hosts.is_empty());
        // 2. Скачалось что-то не то (меньше 100000 имён) — прежний список не трогаем.
        let mut small_calls = 0;
        let listed = refresh(
            &folder,
            |url, _etag| {
                small_calls += 1;
                Some(Fetched {
                    body: Some(match url {
                        HOSTS_URL => b"few.items\n".to_vec(),
                        _ => b"10.0.0.0/8\n".to_vec(),
                    }),
                    etag: "e1".into(),
                    unchanged: false,
                })
            },
            Some(100.0),
            MAX_AGE_S,
        );
        assert_eq!(small_calls, 1);
        assert!(listed.hosts.is_empty());
        // 3. Полный список (список имён на грани и выше минимума).
        let mut names = String::new();
        for number in 0..MIN_HOSTS {
            names.push_str(&format!("name{number}.example\n"));
        }
        let mut big_calls = 0;
        let named = refresh(
            &folder,
            |url, _etag| {
                big_calls += 1;
                Some(Fetched {
                    body: Some(match url {
                        HOSTS_URL => names.as_bytes().to_vec(),
                        _ => b"10.0.0.0/8\n".to_vec(),
                    }),
                    etag: if url == HOSTS_URL { "h2" } else { "i2" }.into(),
                    unchanged: false,
                })
            },
            Some(100.0),
            MAX_AGE_S,
        );
        assert_eq!(big_calls, 2);
        assert_eq!(named.count(), MIN_HOSTS);
        assert_eq!(
            named.etags,
            vec![
                (HOSTS_URL.to_string(), "h2".to_string()),
                (IPS_URL.to_string(), "i2".to_string())
            ]
        );
        assert_eq!(
            summary(&named, Some(100.0)).get("state"),
            Some(&json!(STATE_FRESH))
        );
        // 4. Свежий список не перекачивается.
        let mut questions = 0;
        let listed = refresh(
            &folder,
            |_url, _etag| {
                questions += 1;
                None
            },
            Some(100.0),
            MAX_AGE_S,
        );
        assert_eq!(questions, 0);
        assert_eq!(
            summary(&listed, Some(100.0)).get("state"),
            Some(&json!(STATE_FRESH))
        );
        let _ignored = std::fs::remove_dir_all(&folder);
    }

    /// python `lines` и `annotate` — отметки в отчёте и списках сайтов;
    /// вывод сверён с python-эталоном на том же наборе.
    #[test]
    fn lines_annotate_python() {
        let empty_report = lines(&[], &Index::default(), Some(100.0));
        assert_eq!(
            empty_report.get(2).map(String::as_str),
            Some("❔ Список реестра скачать не удалось — отметок «в реестре» в этот раз нет")
        );
        let names: Vec<String> = ["site.org", "tube.example"]
            .iter()
            .map(|name| name.to_string())
            .collect();
        let (hosts, _count) = build_hosts(names.into_iter());
        let index = index_for_test(hosts);
        let service = json!({
            "host": "www.site.org",
            "targets": [
                {"host": "www.site.org", "address": "212.192.85.14"},
                {"host": "Mirror.site.org", "address": "10.1.2.3"},
                {"host": "other.example", "address": "192.168.5.3"},
            ],
            "tags": [{"key": "broken", "text": "не открывается", "state": "bad"}],
        });
        let marked = annotate(std::slice::from_ref(&service), &index);
        let targets = marked[0]
            .get("targets")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert_eq!(
            targets[0].get("registry").unwrap(),
            &json!({"listed": true, "name": "site.org", "network": "212.192.85.0/24"})
        );
        assert_eq!(
            targets[1].get("registry").unwrap(),
            &json!({"listed": true, "name": "site.org", "network": "10.0.0.0/8"})
        );
        assert_eq!(
            targets[2].get("registry").unwrap(),
            &json!({"listed": true, "name": "", "network": "192.168.5.3/32"})
        );
        let tags = marked[0]
            .get("tags")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        assert!(tags.contains(&tag_registry()));
        assert_eq!(tags.len(), 2);
        // Отчёт без отметок: «ни один не значится».
        let raw = lines(std::slice::from_ref(&service), &index, Some(100.0));
        assert_eq!(raw.len(), 5);
        assert_eq!(
            raw[3],
            "ℹ️ Ни один из проверенных сайтов в реестре не значится"
        );
        // Отчёт с отметками: три строки 📕.
        let marked_slice = annotate(std::slice::from_ref(&service), &index);
        let report = lines(&marked_slice, &index, Some(100.0));
        assert_eq!(report.len(), 7);
        assert!(report[2].starts_with("ℹ️ Список от 01.01.1970: 2 имён сайтов и 4 заблокированных"));
        assert_eq!(
            report[3],
            "📕 www.site.org: в реестре есть site.org; адрес 212.192.85.14 в списке заблокированных (212.192.85.0/24)"
        );
        assert_eq!(
            report[4],
            "📕 Mirror.site.org: в реестре есть site.org; адрес 10.1.2.3 в списке заблокированных (10.0.0.0/8)"
        );
        assert_eq!(
            report[5],
            "📕 other.example: адрес 192.168.5.3 в списке заблокированных (192.168.5.3/32)"
        );
        assert!(report[6].starts_with("   Сайт могут блокировать и без записи в реестре"));
    }

    /// python: набор сетей, как в index_find_python.
    fn index_for_test(hosts: Vec<u8>) -> Index {
        Index {
            hosts,
            networks: build_networks(
                [
                    "10.0.0.0/8",
                    "192.168.5.3/32",
                    "212.192.85.0/24",
                    "10.2.0.0/15",
                ]
                .iter()
                .map(|row| row.to_string())
                .collect::<Vec<_>>()
                .into_iter(),
            ),
            updated: 0.0,
            checked: 0.0,
            etags: Vec::new(),
        }
    }
}
