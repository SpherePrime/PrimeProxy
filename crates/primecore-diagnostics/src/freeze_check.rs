//! Порт `src/diagnostics/freeze_check.py` — обрыв на 16–20 КБ: режет ли
//! провайдер загрузку с зарубежных серверов.
//!
//! ТСПУ пропускает начало ответа, а после ~16 КБ соединение замирает или
//! рвётся. Проверка качает по ~32 КБ с нескольких хостингов разных провайдеров:
//! если у одних файл приходит целиком, а у других обрывается на 12–36 КБ — это
//! и есть такой обрыв.
//!
//! Что было неверно раньше:
//!
//! * обрыв засчитывался, только если в тексте ошибки было слово «reset», а
//!   самый частый случай — соединение просто замирает (таймаут чтения) — уходил
//!   в «ошибку» и в итоге превращался в «доступ есть»;
//! * сервер, который сразу сбросил соединение (0 байт), тоже давал «доступ
//!   есть». На деле это «не удалось проверить»: сброс сразу — другой вид
//!   блокировки или недоступный хостинг, про 16 КБ он ничего не говорит;
//! * у каждого провайдера бралось по одному адресу: если он умер или не
//!   ответил, провайдер выпадал из проверки, а итог всё равно был «обрыва
//!   нет», хотя проверилась половина серверов. Теперь при неудаче берётся
//!   запасной адрес того же провайдера, а итог честно говорит, сколько
//!   серверов проверено.
//!
//! Сетевая загрузка приходит cнаружи ([`check_freeze`]); всё остальное — чистое.

use std::sync::Mutex;

use serde_json::Value;

use crate::limits::{FREEZE_MAX_BYTES, FREEZE_MIN_BYTES};
use crate::probe_result::ProbeResult;
use crate::upload_probe::{UploadVerdict, UPLOAD_BULK_STALLS, UPLOAD_OK, UPLOAD_PACKET_LIMIT};
use crate::verdict::Level;

pub const READ_LIMIT: u64 = 64 * 1024;
pub const TARGETS_COUNT: usize = 6;
/// Сколько серверов полной проверки опрашивать одновременно.
pub const EVERY_AT_ONCE: usize = 12;
/// Один обрыв при стольких серверах без обрыва — единичный случай, а не вывод о сети.
pub const SINGLE_CUT_NEEDS_FINE: usize = 4;
/// «Обрывает» всерьёз: не меньше стольких серверов и не меньше трети проверенных.
pub const WIDESPREAD_CUTS: usize = 3;
/// Сколько адресов одного провайдера пробовать, если первый не дал ответа.
pub const CANDIDATES_PER_PROVIDER: usize = 3;
/// Запасной адрес берётся, только пока с начала проверки прошло меньше этого:
/// иначе запасные попытки не уложатся в общий лимит BlockCheck и оборвут
/// проверку сайтов.
pub const FALLBACK_BUDGET: f64 = 14.0;
/// Провайдеры в порядке предпочтения: крупные хостинги, у которых ТСПУ
/// обрывает загрузку чаще всего.
const PREFERRED_PROVIDERS: [&str; 8] = [
    "Akamai",
    "AWS",
    "Cloudflare",
    "CDN77",
    "Hetzner",
    "OVH",
    "DigitalOcean",
    "Fastly",
];

const UNREACHED: [(&str, &str); 6] = [
    ("connect", "нет соединения с сервером"),
    ("timeout", "сервер не ответил"),
    ("reset", "соединение сброшено"),
    ("tls", "шифрование не установилось"),
    ("cert", "у сервера другой сертификат (он мог переехать)"),
    ("cancelled", "проверку прервали"),
];

/// python `FreezeState`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreezeState {
    Ok,
    Freeze,
    Unknown,
}

impl FreezeState {
    /// python `FreezeState.value`.
    pub fn value(self) -> &'static str {
        match self {
            FreezeState::Ok => "ok",
            FreezeState::Freeze => "freeze",
            FreezeState::Unknown => "unknown",
        }
    }
}

pub const DIRECTION_DOWNLOAD: &str = "download";
pub const DIRECTION_UPLOAD: &str = "upload";

/// Один проверенный сервер (python `FreezeServer`).
#[derive(Debug, Clone, PartialEq)]
pub struct FreezeServer {
    pub name: String,
    pub state: FreezeState,
    pub text: String,
    /// В какую сторону шли данные, когда соединение замерло.
    pub direction: String,
    pub provider: String,
    pub host: String,
    /// Метка сервера в списке: страна и номер («DE.AWS-01»).
    pub ident: String,
    pub seconds: f64,
}

impl FreezeServer {
    /// Заглушка без полей — для тестов сводки.
    #[cfg(test)]
    fn bare(provider: &str, text: &str) -> Self {
        Self {
            name: provider.to_string(),
            state: FreezeState::Unknown,
            text: text.to_string(),
            direction: DIRECTION_DOWNLOAD.to_string(),
            provider: provider.to_string(),
            host: String::new(),
            ident: String::new(),
            seconds: 0.0,
        }
    }
}

/// Итог раздела обрыва (python `FreezeReport`).
#[derive(Debug, Clone, PartialEq)]
pub struct FreezeReport {
    pub level: Level,
    pub headline: String,
    pub servers: Vec<FreezeServer>,
    pub advice: Vec<String>,
}

/// python `_split_url`: хост и путь с запросом.
#[must_use]
pub fn split_url(url: &str) -> (String, String) {
    // urllib.parse.urlsplit: "https://host/path?query".
    let after_scheme = url.split_once("://").map(|(_, tail)| tail).unwrap_or(url);
    let (authority, rest) = match after_scheme.find('/') {
        Some(index) => (&after_scheme[..index], &after_scheme[index..]),
        None => (after_scheme, ""),
    };
    let host = authority.split('@').next_back().unwrap_or(authority);
    // Порт отбрасываем: python parts.hostname не отдаёт его.
    let host = host.split(':').next().unwrap_or(host);
    let (path, query) = match rest.split_once('?') {
        Some((path, query)) => (path, query),
        None => (rest, ""),
    };
    let path = if path.is_empty() { "/" } else { path };
    let path = if query.is_empty() {
        path.to_string()
    } else {
        format!("{path}?{query}")
    };
    (host.to_string(), path)
}

/// Запись списка целей (python: dict со строками).
fn item_url(item: &Value) -> String {
    item.get("url")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn item_provider(item: &Value) -> String {
    item.get("provider")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn item_ident(item: &Value) -> String {
    item.get("id")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// Провайдеры для проверки и до `per_provider` HTTPS-адресов у каждого.
///
/// Первый адрес — основной, остальные — запасные на случай, если он не
/// ответит. Порядок постоянный: сначала крупные хостинги из
/// `PREFERRED_PROVIDERS`.
#[must_use]
pub fn pick_freeze_targets(
    targets: &[Value],
    count: usize,
    per_provider: usize,
) -> Vec<(String, Vec<Value>)> {
    let mut by_provider: Vec<(String, Vec<Value>)> = Vec::new();
    for item in targets {
        if !item_url(item).starts_with("https://") {
            continue;
        }
        let provider = item_provider(item);
        match by_provider.iter_mut().find(|(name, _)| *name == provider) {
            Some((_, candidates)) => {
                if candidates.len() < per_provider.max(1) {
                    candidates.push(item.clone());
                }
            }
            None => by_provider.push((provider, vec![item.clone()])),
        }
    }
    let mut names: Vec<String> = PREFERRED_PROVIDERS
        .iter()
        .filter(|name| by_provider.iter().any(|(provider, _)| provider == **name))
        .map(|name| (*name).to_string())
        .collect();
    names.extend(
        by_provider
            .iter()
            .filter(|(provider, _)| !PREFERRED_PROVIDERS.contains(&provider.as_str()))
            .map(|(provider, _)| provider.clone()),
    );
    names
        .into_iter()
        .take(count)
        .filter_map(|name| {
            by_provider
                .iter()
                .find(|(provider, _)| *provider == name)
                .map(|(provider, candidates)| (provider.clone(), candidates.clone()))
        })
        .collect()
}

/// Все HTTPS-адреса списка, каждый отдельной проверкой: так идёт полная проверка.
#[must_use]
pub fn every_freeze_target(targets: &[Value]) -> Vec<(String, Vec<Value>)> {
    targets
        .iter()
        .filter(|item| item_url(item).starts_with("https://"))
        .map(|item| (item_provider(item), vec![item.clone()]))
        .collect()
}

/// Что значит результат загрузки для проверки обрыва (python `classify_download`).
#[must_use]
pub fn classify_download(result: Option<&ProbeResult>) -> (FreezeState, String) {
    let Some(result) = result else {
        return (
            FreezeState::Unknown,
            "не удалось узнать адрес сервера".to_string(),
        );
    };
    if result.kind != "ok" {
        // Причины здесь не называются: мёртвый или переехавший сервер из списка
        // отвечал бы «чужой сертификат» — и это выглядело бы как перехват трафика.
        let reason = UNREACHED
            .iter()
            .find(|(code, _)| *code == result.kind)
            .map(|(_, text)| (*text).to_string())
            .unwrap_or_else(|| "сервер не ответил как ожидалось".to_string());
        return (
            FreezeState::Unknown,
            format!("не удалось проверить: {reason}"),
        );
    }
    let size = result.body_size;
    let kb = size / 1024;
    if result.body_cut && (FREEZE_MIN_BYTES..=FREEZE_MAX_BYTES).contains(&size) {
        return (
            FreezeState::Freeze,
            format!("загрузка оборвалась на {kb} КБ"),
        );
    }
    if size >= FREEZE_MAX_BYTES {
        return (FreezeState::Ok, format!("получено {kb} КБ без обрыва"));
    }
    if result.body_cut {
        return (
            FreezeState::Unknown,
            format!("загрузка оборвалась на {kb} КБ — вне окна 12–36 КБ, на этот обрыв не похоже"),
        );
    }
    let status = result.status.unwrap_or(0);
    if status >= 300 {
        return (
            FreezeState::Unknown,
            format!("сервер не отдал файл (код {status})"),
        );
    }
    (
        FreezeState::Unknown,
        format!("файл слишком маленький ({kb} КБ) — не показательно"),
    )
}

/// Обрыв считается обрывом, только если повторился: фильтр режет каждый раз,
/// сбой сети — нет (python `_confirm_cut`).
#[must_use]
pub fn confirm_cut(first_text: &str, again: (FreezeState, String)) -> (FreezeState, String) {
    let (state, text) = again;
    match state {
        FreezeState::Freeze => (FreezeState::Freeze, format!("{text} — дважды подряд")),
        FreezeState::Ok => (
            FreezeState::Ok,
            format!("{text} со второго раза: первый обрыв был случайным сбоем"),
        ),
        FreezeState::Unknown => (
            FreezeState::Unknown,
            format!("{first_text}, но при повторе обрыв не подтвердился ({text})"),
        ),
    }
}

/// Пробует адреса провайдера по очереди, пока один не даст ясный ответ.
///
/// Если загрузка прошла без обрыва, на том же сервере проверяется отправка:
/// ограничение работает в обе стороны.
pub type UploadCheck<'u> = dyn Fn(&str, &str) -> Option<UploadVerdict> + 'static;

pub fn check_provider(
    provider: &str,
    candidates: &[Value],
    mut download: impl FnMut(&str, &str) -> Option<ProbeResult>,
    mut fallback_allowed: impl FnMut() -> bool,
    upload: Option<&UploadCheck<'_>>,
) -> FreezeServer {
    let started = std::time::Instant::now();
    let mut host = String::new();
    let mut last_path = String::new();
    let mut ident = String::new();
    let mut state = FreezeState::Unknown;
    let mut text = "нет адресов для проверки".to_string();
    let mut tried = 0;
    for item in candidates {
        if tried > 0 && !fallback_allowed() {
            break;
        }
        let (next_host, path) = split_url(&item_url(item));
        host = next_host;
        last_path = path;
        ident = item_ident(item);
        tried += 1;
        (state, text) = classify_download(download(&host, &last_path).as_ref());
        if state == FreezeState::Freeze {
            (state, text) = confirm_cut(
                &text,
                classify_download(download(&host, &last_path).as_ref()),
            );
        }
        if state != FreezeState::Unknown {
            break;
        }
    }
    if state == FreezeState::Unknown && tried > 1 {
        text = format!("{text} (запасные адреса тоже не помогли, всего адресов: {tried})");
    }
    let name = if host.is_empty() {
        provider.to_string()
    } else {
        format!("{provider} ({host})")
    };
    let mut direction = DIRECTION_DOWNLOAD.to_string();
    if state == FreezeState::Ok {
        if let Some(upload) = upload {
            match upload(&host, &last_path) {
                Some(verdict)
                    if verdict.code == UPLOAD_BULK_STALLS
                        || verdict.code == UPLOAD_PACKET_LIMIT =>
                {
                    state = FreezeState::Freeze;
                    text = format!("загрузка проходит, но {}", verdict.text);
                    direction = DIRECTION_UPLOAD.to_string();
                }
                Some(verdict) if verdict.code == UPLOAD_OK => {
                    text = format!("{text}; отправка тоже проходит");
                }
                _ => {}
            }
        }
    }
    FreezeServer {
        name,
        state,
        text: text.to_string(),
        direction,
        provider: provider.to_string(),
        host,
        ident,
        seconds: started.elapsed().as_secs_f64(),
    }
}

/// Провайдеры проверяются параллельно, адреса одного провайдера — по очереди.
///
/// `every` — полная проверка: каждый адрес списка проверяется сам по себе, без
/// запасных. Сколько серверов идёт одновременно, решает движок ( submits по
/// очереди в `EVERY_AT_ONCE`). `on_server(сервер, готово, всего)` зовётся по
/// мере готовности — для хода проверки на экране. `when` — время от старта.
pub type OnServer<'s> = dyn Fn(&FreezeServer, usize, usize) + 's;
#[must_use]
pub fn check_freeze(
    targets: &[Value],
    every: bool,
    mut download: impl FnMut(&str, &str) -> Option<ProbeResult>,
    upload: Option<&UploadCheck<'_>>,
    on_server: Option<&OnServer<'_>>,
    mut when: impl FnMut() -> f64,
) -> Vec<FreezeServer> {
    let started = when();
    let mut fallback_allowed = move || when() - started < FALLBACK_BUDGET;
    let picked: Vec<(String, Vec<Value>)> = if every {
        every_freeze_target(targets)
    } else {
        pick_freeze_targets(targets, TARGETS_COUNT, CANDIDATES_PER_PROVIDER)
    };
    let total = picked.len();
    let done = Mutex::new(0);
    let servers: Vec<FreezeServer> = {
        // Python не гоняет треды в этой чистой части; здесь то же самое — по очереди.
        let mut list: Vec<FreezeServer> = Vec::new();
        for (provider, candidates) in &picked {
            let server = check_provider(
                provider,
                candidates,
                |host, path| download(host, path),
                &mut fallback_allowed,
                upload,
            );
            if let Some(on_server) = on_server {
                let mut done = done.lock().expect("lock");
                *done += 1;
                let ready = *done;
                drop(done);
                on_server(&server, ready, total);
            }
            list.push(server);
        }
        list
    };
    servers
}

/// Итог раздела обрыва (python `summarize_freeze`).
#[must_use]
pub fn summarize_freeze(servers: &[FreezeServer], zapret_running: Option<bool>) -> FreezeReport {
    let frozen: Vec<&FreezeServer> = servers
        .iter()
        .filter(|item| item.state == FreezeState::Freeze)
        .collect();
    let fine: Vec<&FreezeServer> = servers
        .iter()
        .filter(|item| item.state == FreezeState::Ok)
        .collect();
    if !frozen.is_empty() {
        let advice: Vec<String> = if zapret_running != Some(false) {
            vec![
                    "Подберите стратегию для любого сайта, который у вас грузится не до конца: впишите его адрес в \
                     «Подборе стратегии»."
                        .to_string(),
                ]
        } else {
            vec![
                    "Запустите Zapret на странице «Управление Zapret 2» — стратегии обходят этот обрыв."
                        .to_string(),
                ]
        };
        let mut directions: Vec<&str> = frozen.iter().map(|item| item.direction.as_str()).collect();
        directions.dedup();
        let all_upload = directions.len() == 1 && directions[0] == DIRECTION_UPLOAD;
        let all_download = directions.len() == 1 && directions[0] == DIRECTION_DOWNLOAD;
        let what = if all_upload {
            "отправка данных на зарубежные серверы"
        } else if all_download {
            "загрузка с зарубежных серверов на 16–20 КБ"
        } else {
            "загрузка с зарубежных серверов на 16–20 КБ и отправка данных на них"
        };
        let decided = frozen.len() + fine.len();
        if frozen.len() == 1 && fine.len() >= SINGLE_CUT_NEEDS_FINE {
            // Один сервер из многих — не картина сети: так бывает из-за самого сервера.
            return FreezeReport {
                level: Level::Ok,
                headline: format!(
                    "Обрыва на 16–20 КБ нет: без обрыва {} из {} серверов, один оборвался — единичный случай",
                    fine.len(),
                    decided
                ),
                servers: servers.to_vec(),
                advice: Vec::new(),
            };
        }
        // «Обрывает» — когда это видно у нескольких серверов и у заметной их доли.
        let widespread = frozen.len() >= WIDESPREAD_CUTS && frozen.len() * 3 >= decided;
        return FreezeReport {
            level: if widespread { Level::Fail } else { Level::Warn },
            headline: format!(
                "Обрывается {what}: {} из {} проверенных серверов",
                frozen.len(),
                decided
            ),
            servers: servers.to_vec(),
            advice,
        };
    }
    let unknown = servers.len() - fine.len();
    if !fine.is_empty() && unknown == 0 {
        return FreezeReport {
            level: Level::Ok,
            headline: "Обрыва загрузки на 16–20 КБ нет".to_string(),
            servers: servers.to_vec(),
            advice: Vec::new(),
        };
    }
    if !fine.is_empty() && fine.len() >= unknown {
        return FreezeReport {
            level: Level::Ok,
            headline: format!(
                "Обрыва на 16–20 КБ нет: проверено {} из {} серверов, остальные проверить не удалось",
                fine.len(),
                servers.len()
            ),
            servers: servers.to_vec(),
            advice: Vec::new(),
        };
    }
    if !fine.is_empty() {
        return FreezeReport {
            level: Level::Unknown,
            headline: format!(
                "Обрыв на 16–20 КБ проверен не до конца: без обрыва {} из {} серверов, остальные не ответили",
                fine.len(),
                servers.len()
            ),
            servers: servers.to_vec(),
            advice: Vec::new(),
        };
    }
    FreezeReport {
        level: Level::Unknown,
        headline: "Обрыв на 16–20 КБ проверить не удалось: тестовые серверы не ответили"
            .to_string(),
        servers: servers.to_vec(),
        advice: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe(ok_kind: &str, size: u64, cut: bool, status: Option<i64>) -> ProbeResult {
        ProbeResult {
            kind: ok_kind.to_string(),
            body_size: size,
            body_cut: cut,
            status,
            ..Default::default()
        }
    }

    #[test]
    fn split_url_python() {
        assert_eq!(
            split_url("https://cdn.example/files/a.png"),
            ("cdn.example".to_string(), "/files/a.png".to_string())
        );
        assert_eq!(
            split_url("https://host:8443/"),
            ("host".to_string(), "/".to_string())
        );
        assert_eq!(
            split_url("https://host/a.js?version=1.5"),
            ("host".to_string(), "/a.js?version=1.5".to_string())
        );
        assert_eq!(
            split_url("https://dot.com"),
            ("dot.com".to_string(), "/".to_string())
        );
    }

    #[test]
    fn classify_python_branches() {
        assert_eq!(classify_download(None).0, FreezeState::Unknown);
        assert_eq!(classify_download(None).1, "не удалось узнать адрес сервера");
        assert_eq!(
            classify_download(Some(&probe("connect", 0, false, None))),
            (
                FreezeState::Unknown,
                "не удалось проверить: нет соединения с сервером".to_string()
            )
        );
        // Обрыв в окне.
        assert_eq!(
            classify_download(Some(&probe("ok", 17 * 1024, true, Some(200)))),
            (
                FreezeState::Freeze,
                "загрузка оборвалась на 17 КБ".to_string()
            )
        );
        // Полный файл.
        assert_eq!(
            classify_download(Some(&probe("ok", 37 * 1024, false, Some(200)))),
            (FreezeState::Ok, "получено 37 КБ без обрыва".to_string())
        );
        // Обрыв вне окна.
        assert_eq!(
            classify_download(Some(&probe("ok", 11 * 1024, true, Some(200)))).1,
            "загрузка оборвалась на 11 КБ — вне окна 12–36 КБ, на этот обрыв не похоже"
        );
        // Обрыв прямо на верхней границе — это окно 12–36 КБ (Python IN).
        assert_eq!(
            classify_download(Some(&probe("ok", FREEZE_MAX_BYTES, true, Some(200)))).0,
            FreezeState::Freeze
        );
        // Редирект.
        assert_eq!(
            classify_download(Some(&probe("ok", 3000, false, Some(302)))).1,
            "сервер не отдал файл (код 302)"
        );
        // Маленький файл.
        assert_eq!(
            classify_download(Some(&probe("ok", 1000, false, Some(200)))).1,
            "файл слишком маленький (0 КБ) — не показательно"
        );
    }

    #[test]
    fn confirm_cut_decrypts_repeat() {
        assert_eq!(
            confirm_cut(
                "первая",
                (
                    FreezeState::Freeze,
                    "загрузка оборвалась на 17 КБ".to_string()
                )
            )
            .1,
            "загрузка оборвалась на 17 КБ — дважды подряд"
        );
        assert_eq!(
            confirm_cut(
                "первая",
                (FreezeState::Ok, "получено 64 КБ без обрыва".to_string())
            )
            .1,
            "получено 64 КБ без обрыва со второго раза: первый обрыв был случайным сбоем"
        );
        assert_eq!(
            confirm_cut(
                "первая",
                (
                    FreezeState::Unknown,
                    "нет соединения с сервером".to_string()
                )
            )
            .1,
            "первая, но при повторе обрыв не подтвердился (нет соединения с сервером)"
        );
    }

    fn target(id: &str, provider: &str, url: &str) -> Value {
        serde_json::json!({"id": id, "provider": provider, "url": url})
    }

    #[test]
    fn pick_and_every_python() {
        let targets = vec![
            target("SE.AKM-01", "Akamai", "https://akamai.example/a"),
            target("SE.AKM-02", "Akamai", "https://akamai.example/b"),
            target("SE.AKM-03", "Akamai", "https://akamai.example/c"),
            target("SE.AKM-04", "Akamai", "https://akamai.example/d"),
            target("X.__-1", "Прочий", "https://other.example/a"),
            target("HTTP", "Мимо", "http://http.example/a"),
            target("HETZ-1", "Hetzner", "https://hetzner.example/a"),
        ];
        let picked = pick_freeze_targets(&targets, 2, 3);
        assert_eq!(picked[0].0, "Akamai");
        assert_eq!(picked[0].1.len(), 3);
        assert_eq!(picked[1].0, "Hetzner");
        assert_eq!(picked.len(), 2);
        let every = every_freeze_target(&targets);
        assert_eq!(every.len(), 6);
        assert_eq!(every[1].0, "Akamai");
        assert_eq!(every[1].1.len(), 1);
    }

    #[test]
    fn check_provider_fallback_python() {
        let candidates = vec![
            target("A", "Akamai", "https://first.example/a"),
            target("B", "Akamai", "https://second.example/b"),
        ];
        // Первый адрес отвечает нормально: запасной не зовётся.
        let mut asked: Vec<String> = Vec::new();
        let server = check_provider(
            "Akamai",
            &candidates,
            |host, path| {
                asked.push(format!("{host}{path}"));
                Some(probe("ok", 40 * 1024, false, Some(200)))
            },
            || true,
            None,
        );
        assert_eq!(server.state, FreezeState::Ok);
        assert_eq!(server.text, "получено 40 КБ без обрыва");
        assert_eq!(asked.len(), 1);
        assert_eq!(server.ident, "A");
        assert_eq!(server.name, "Akamai (first.example)");
        // Первый «мимо» (unknown), второй ок: по очереди.
        let server = check_provider(
            "Akamai",
            &candidates,
            |host, _path| {
                if host.starts_with("first") {
                    Some(probe("timeout", 0, false, None))
                } else {
                    Some(probe("ok", 40 * 1024, false, Some(200)))
                }
            },
            || true,
            None,
        );
        assert_eq!(server.state, FreezeState::Ok);
        assert_eq!(server.name, "Akamai (second.example)");
        assert_eq!(server.text, "получено 40 КБ без обрыва");
        // Неизвестное дважды: честный текст про запасные.
        let server = check_provider(
            "Akamai",
            &candidates,
            |host, _path| {
                if host.starts_with("first") {
                    Some(probe("timeout", 0, false, None))
                } else {
                    Some(probe("reset", 0, false, None))
                }
            },
            || true,
            None,
        );
        assert_eq!(
            server.text,
            "не удалось проверить: соединение сброшено (запасные адреса тоже не помогли, всего адресов: 2)"
        );
        // Обрыв подтверждается повтором.
        let mut count = 0;
        let server = check_provider(
            "Akamai",
            &candidates,
            |_host, _path| {
                count += 1;
                Some(probe("ok", 17 * 1024, true, Some(200)))
            },
            || true,
            None,
        );
        assert_eq!(count, 2);
        assert_eq!(server.state, FreezeState::Freeze);
        assert_eq!(server.text, "загрузка оборвалась на 17 КБ — дважды подряд");
    }

    #[test]
    fn check_provider_upload_direction() {
        let target = vec![target("A", "AWS", "https://aws.example/a")];
        // Отправка замирает: направление upload.
        let server = check_provider(
            "AWS",
            &target,
            |_host, _path| Some(probe("ok", 40 * 1024, false, Some(200))),
            || true,
            Some(&|_host, _path| {
                Some(UploadVerdict {
                    code: UPLOAD_BULK_STALLS.to_string(),
                    text: "отправка 64 КБ замирает".to_string(),
                })
            }),
        );
        assert_eq!(server.state, FreezeState::Freeze);
        assert_eq!(server.direction, DIRECTION_UPLOAD);
        assert_eq!(server.text, "загрузка проходит, но отправка 64 КБ замирает");
        // Отправка проходит: уточнение в тексте.
        let server = check_provider(
            "AWS",
            &target,
            |_host, _path| Some(probe("ok", 40 * 1024, false, Some(200))),
            || true,
            Some(&|_host, _path| {
                Some(UploadVerdict {
                    code: UPLOAD_OK.to_string(),
                    text: "отправка данных проходит без обрыва".to_string(),
                })
            }),
        );
        assert_eq!(
            server.text,
            "получено 40 КБ без обрыва; отправка тоже проходит"
        );
    }

    #[test]
    fn check_freeze_counts_on_server() {
        let targets = vec![
            target("A", "Akamai", "https://a.example/a"),
            target("B", "AWS", "https://b.example/b"),
        ];
        let progress: Vec<(usize, usize)> = Vec::new();
        let progress = std::cell::RefCell::new(progress);
        let servers = check_freeze(
            &targets,
            false,
            |_host, _path| Some(probe("ok", 40 * 1024, false, Some(200))),
            None,
            Some(&|_server, ready, total| {
                progress.borrow_mut().push((ready, total));
            }),
            || 0.0,
        );
        let progress = progress.into_inner();
        assert_eq!(progress, vec![(1, 2), (2, 2)]);
        assert_eq!(servers.len(), 2);
        // Полная проверка: каждый адрес отдельным сервером.
        let doubles = vec![
            target("A1", "Akamai", "https://a1.example/a"),
            target("A2", "Akamai", "https://a2.example/a"),
        ];
        let servers = check_freeze(
            &doubles,
            true,
            |_host, _path| Some(probe("ok", 40 * 1024, false, Some(200))),
            None,
            None,
            || 0.0,
        );
        assert_eq!(servers.len(), 2);
        // Бюджет прошёл — запасной не берётся.
        let candidates = vec![
            target("A", "Akamai", "https://first.example/a"),
            target("B", "Akamai", "https://second.example/b"),
        ];
        let when = std::cell::Cell::new(0.0_f64);
        let mut asked = 0;
        let servers = check_freeze(
            &candidates,
            false,
            |_host, _path| {
                asked += 1;
                when.set(when.get() + 20.0);
                Some(probe("timeout", 0, false, None))
            },
            None,
            None,
            || when.get(),
        );
        assert_eq!(asked, 1);
        let server = &servers[0];
        assert_eq!(server.text, "не удалось проверить: сервер не ответил");
    }

    #[test]
    fn summarize_python_messages() {
        let mut fine = FreezeServer::bare("Akamai", "");
        fine.state = FreezeState::Ok;
        let mut frozen = FreezeServer::bare("AWS", "обрыв");
        frozen.state = FreezeState::Freeze;
        // Только fine: ok.
        let report = summarize_freeze(std::slice::from_ref(&fine), None);
        assert_eq!(report.level, Level::Ok);
        assert_eq!(report.headline, "Обрыва загрузки на 16–20 КБ нет");
        // Помесь fine и unknown.
        let (fine_amount, unknown_amount) = (5, 2);
        let mut servers = vec![fine.clone(); fine_amount];
        servers.extend(vec![FreezeServer::bare("unknown", ""); unknown_amount]);
        let report = summarize_freeze(&servers, None);
        assert_eq!(report.level, Level::Ok);
        assert_eq!(
            report.headline,
            "Обрыва на 16–20 КБ нет: проверено 5 из 7 серверов, остальные проверить не удалось"
        );
        // Больше unknown, чем fine: не до конца.
        let mut servers = vec![fine.clone()];
        servers.extend(vec![FreezeServer::bare("unknown", ""); 3]);
        let report = summarize_freeze(&servers, None);
        assert_eq!(report.level, Level::Unknown);
        assert_eq!(
            report.headline,
            "Обрыв на 16–20 КБ проверен не до конца: без обрыва 1 из 4 серверов, остальные не ответили"
        );
        // Ни одного ответа.
        let report = summarize_freeze(&[], None);
        assert_eq!(
            report.headline,
            "Обрыв на 16–20 КБ проверить не удалось: тестовые серверы не ответили"
        );
        // Один обрыв при 4 fine: единый сбой.
        let mut one_cut = vec![frozen.clone()];
        one_cut.extend(vec![fine.clone(); 4]);
        let report = summarize_freeze(&one_cut, None);
        assert_eq!(report.level, Level::Ok);
        assert_eq!(
            report.headline,
            "Обрыва на 16–20 КБ нет: без обрыва 4 из 5 серверов, один оборвался — единичный случай"
        );
        // Обрывы широко: fail + совет (Zapret не запущен).
        let shots = vec![frozen.clone(), frozen.clone(), frozen.clone(), fine.clone()];
        let report = summarize_freeze(&shots, Some(false));
        assert_eq!(report.level, Level::Fail);
        assert_eq!(
            report.headline,
            "Обрывается загрузка с зарубежных серверов на 16–20 КБ: 3 из 4 проверенных серверов"
        );
        assert_eq!(report.advice.len(), 1);
        assert!(report.advice[0].starts_with("Запустите Zapret"));
        // Zapret запущен или неизвестно.
        let report = summarize_freeze(&shots, Some(true));
        assert!(report.advice[0].starts_with("Подберите стратегию"));
        // Отправка замирала: другой текст.
        let mut uploads = vec![FreezeServer {
            direction: DIRECTION_UPLOAD.to_string(),
            ..frozen.clone()
        }];
        uploads.push(fine.clone());
        let report = summarize_freeze(&uploads, None);
        assert_eq!(
            report.headline,
            "Обрывается отправка данных на зарубежные серверы: 1 из 2 проверенных серверов"
        );
        assert_eq!(report.level, Level::Warn);
        // Оба направления.
        let mut mixed = uploads.clone();
        mixed.push(frozen.clone());
        let report = summarize_freeze(&mixed, None);
        assert_eq!(
            report.headline,
            "Обрывается загрузка с зарубежных серверов на 16–20 КБ и отправка данных на них: 2 из 3 проверенных \
             серверов"
        );
    }
}
