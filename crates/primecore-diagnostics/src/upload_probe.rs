//! Порт `src/diagnostics/upload_probe.py` — обрыв при отправке данных: замирает
//! ли соединение, когда данные идут от нас.
//!
//! Проверка загрузки (`freeze_check`) ловит обрыв, когда данные идут к нам.
//! Ограничение работает и в обратную сторону: соединение замирает, когда много
//! отправляем мы. По описанию проекта dpi-checkers считается оно не в байтах,
//! а в пакетах — около двадцати пяти в обе стороны.
//!
//! Чтобы одиночный тайм-аут не выглядел блокировкой, проверка идёт с контролем
//! на том же сервере:
//!
//! 1. **Короткая отправка** — 16 байт. Сервер обязан ответить хоть чем-то
//!    (пусть отказом): иначе он просто не принимает такие запросы, и судить
//!    не по чему.
//! 2. **Большая отправка** — 64 КБ одним потоком.
//! 3. **Отправка мелкими пакетами** — 64 байта, по два байта с паузой: данных
//!    почти нет, а пакетов много.
//!
//! Короткая прошла, а большая замерла — режут по объёму. Большая прошла, а
//! мелкие пакеты замерли — режут по числу пакетов. Сброс соединения сервером
//! на большой отправке выводом не считается: так сервер может сам отказаться
//! от лишних данных.
//!
//! Само сетевое отправление (`post`) пока не реализовано — движок ждёт
//! сетевого транспорта; суд решение ([`judge`]) и план ([`collect`]-сборка) уже
//! в этом модуле.

pub const SMALL_BYTES: usize = 16;
pub const BULK_BYTES: usize = 64 * 1024;
pub const BULK_CHUNK: usize = 4096;
pub const DRIP_BYTES: usize = 64;
pub const DRIP_CHUNK: usize = 2;
pub const DRIP_PAUSE_S: f64 = 0.05;
pub const TIMEOUT_S: f64 = 5.0;
/// Сколько ждать ответа до отправки тела: успел ответить — значит, тела не ждёт.
pub const EARLY_ANSWER_WAIT_S: f64 = 0.6;

/// Сервер прислал ответ HTTP — любой.
pub const POST_ANSWERED: &str = "answered";
/// Сервер ответил, не дождавшись тела: наши данные он не читал.
pub const POST_EARLY: &str = "early";
/// Соединение замерло: ни отправить, ни получить.
pub const POST_STALLED: &str = "stalled";
/// Сброс, отказ, ошибка шифрования.
pub const POST_FAILED: &str = "failed";
pub const POST_CANCELLED: &str = "cancelled";

pub const UPLOAD_OK: &str = "ok";
pub const UPLOAD_BULK_STALLS: &str = "bulk_stalls";
pub const UPLOAD_PACKET_LIMIT: &str = "packet_limit";
pub const UPLOAD_UNKNOWN: &str = "unknown";

/// Итог одной отправки (python `PostResult`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PostResult {
    pub kind: String,
    /// Сколько байт тела успели отдать системе до ответа или сбоя.
    pub sent: usize,
    pub status: Option<u16>,
}

#[cfg(test)]
impl PostResult {
    fn of(kind: &str) -> Self {
        Self { kind: kind.to_string(), sent: 0, status: None }
    }
}

/// python `UploadFacts`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct UploadFacts {
    pub small: PostResult,
    /// `None` — не отправляли: короткая отправка не прошла, сравнивать не с чем.
    pub bulk: Option<PostResult>,
    pub drip: Option<PostResult>,
}

/// Завершение пробы (python `UploadVerdict`).
#[derive(Debug, Clone, PartialEq)]
pub struct UploadVerdict {
    pub code: String,
    pub text: String,
}

impl UploadVerdict {
    fn of(code: &str, text: &str) -> Self {
        Self { code: code.to_string(), text: text.to_string() }
    }
}

/// python `_status`: код из статусной строки; не HTTP — `None`.
#[must_use]
pub fn status(answer: &[u8]) -> Option<u16> {
    if !answer.starts_with(b"HTTP/") {
        return None;
    }
    let text = std::str::from_utf8(answer).ok()?;
    let parts: Vec<&str> = text.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    // python `parts[1].isdigit()`: только цифры целиком.
    if parts[1].is_empty() || !parts[1].bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    parts[1].parse().ok()
}

/// python `_split`: данные кусками `size`.
#[must_use]
pub fn split(data: &[u8], size: usize) -> Vec<Vec<u8>> {
    let mut sizes: Vec<Vec<u8>> = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let end = (offset + size).min(data.len());
        sizes.push(data[offset..end].to_vec());
        offset = end;
    }
    sizes
}

/// python `_post_confirmed`: замирание перепроверяется один раз и засчитывается,
/// только если повторилось. Фильтр режет каждый раз, а сервер, который однажды
/// долго думал над ответом, — нет.
#[must_use]
pub fn post_confirmed(
    host: &str,
    ip: &str,
    path: &str,
    chunks: Vec<Vec<u8>>,
    mut post: impl FnMut(&str, &str, &str, Vec<Vec<u8>>) -> PostResult,
) -> PostResult {
    let mut count = 0;
    let mut send = |chunks: Vec<Vec<u8>>| {
        count += 1;
        post(host, ip, path, chunks)
    };
    let first = send(chunks.clone());
    if first.kind != POST_STALLED {
        return first;
    }
    send(chunks)
}

/// python `collect`: короткая отправка, а если она прошла — большая и мелкими
/// пакетами одновременно (`submit` порождает параллельные задачи, движок).
#[must_use]
pub fn collect(
    host: &str,
    ip: &str,
    path: &str,
    small: impl FnOnce() -> PostResult,
    mut submit: impl FnMut(&str, &str, &str, Vec<Vec<u8>>, bool) -> PostResult,
) -> UploadFacts {
    // Контроль: сервер должен дождаться тела и только потом ответить.
    let first = small();
    if first.kind != POST_ANSWERED {
        return UploadFacts { small: first, ..Default::default() };
    }
    let bulk_trade = split(&random_bytes(BULK_BYTES), BULK_CHUNK);
    let drip_trade = split(&random_bytes(DRIP_BYTES), DRIP_CHUNK);
    let bulk = submit(host, ip, path, bulk_trade, false);
    let drip = submit(host, ip, path, drip_trade, true);
    UploadFacts { small: first, bulk: Some(bulk), drip: Some(drip) }
}

/// python `os.urandom`:
#[must_use]
fn random_bytes(size: usize) -> Vec<u8> {
    (0..size).map(|_| fastrand::u8(..)).collect()
}

/// python `judge`: вывод по отправке.
#[must_use]
pub fn judge(facts: &UploadFacts) -> UploadVerdict {
    let bulk_kind = facts.bulk.as_ref().map_or(String::new(), |bulk| bulk.kind.clone());
    let drip_kind = facts.drip.as_ref().map_or(String::new(), |drip| drip.kind.clone());
    if facts.small.kind == POST_CANCELLED || bulk_kind == POST_CANCELLED || drip_kind == POST_CANCELLED {
        return UploadVerdict::of(UPLOAD_UNKNOWN, "проверку отправки прервали");
    }
    if facts.small.kind == POST_EARLY {
        return UploadVerdict::of(
            UPLOAD_UNKNOWN,
            "сервер отвечает, не дочитав отправленное, — проверить отправку на нём нельзя",
        );
    }
    if facts.small.kind != POST_ANSWERED || facts.bulk.is_none() || facts.drip.is_none() {
        return UploadVerdict::of(UPLOAD_UNKNOWN, "сервер не принимает отправку данных — проверить её не на чем");
    }
    if facts.bulk.as_ref().unwrap().kind == POST_STALLED {
        let kilos = BULK_BYTES / 1024;
        return UploadVerdict::of(
            UPLOAD_BULK_STALLS,
            &format!(
                "отправка {kilos} КБ замирает дважды подряд, хотя короткую отправку тот же сервер принимает"
            ),
        );
    }
    if facts.drip.as_ref().unwrap().kind == POST_STALLED {
        let packets = DRIP_BYTES / DRIP_CHUNK;
        return UploadVerdict::of(
            UPLOAD_PACKET_LIMIT,
            &format!(
                "соединение дважды замирает на {packets} мелких пакетах, хотя большой объём проходит — \
                 режут по числу пакетов, а не по объёму"
            ),
        );
    }
    if facts.bulk.as_ref().unwrap().kind != POST_ANSWERED || facts.drip.as_ref().unwrap().kind != POST_ANSWERED {
        // Сброс вместо ответа: сервер мог сам отказаться от лишних данных.
        return UploadVerdict::of(UPLOAD_UNKNOWN, "сервер оборвал отправку сам — это не похоже на замирание");
    }
    UploadVerdict::of(UPLOAD_OK, "отправка данных проходит без обрыва")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(kind: &str, status: Option<u16>) -> PostResult {
        PostResult { kind: kind.to_string(), sent: 0, status }
    }

    #[test]
    fn status_parsing_python() {
        assert_eq!(status(b"HTTP/1.1 200 OK"), Some(200));
        assert_eq!(status(b"HTTP/1.1 403 Forbidden"), Some(403));
        assert_eq!(status(b"HTTP/1.0 500"), Some(500));
        assert_eq!(status(b""), None);
        assert_eq!(status(b"HTTP/1.1 abc"), None);
        assert_eq!(status(b"200 OK"), None);
        assert_eq!(status(b"HTTP"), None);
    }

    #[test]
    fn split_python_sizes() {
        let data = vec![1, 2, 3, 4, 5];
        assert_eq!(split(&data, 2), vec![vec![1, 2], vec![3, 4], vec![5]]);
        assert_eq!(split(&data, 10), vec![data.clone()]);
        assert_eq!(split(&[], 2).len(), 0);
        let bulk = random_bytes(BULK_BYTES);
        let chunks = split(&bulk, BULK_CHUNK);
        assert_eq!(chunks.len(), BULK_BYTES / BULK_CHUNK);
        assert_eq!(chunks.iter().map(Vec::len).sum::<usize>(), BULK_BYTES);
        let drip = split(&random_bytes(DRIP_BYTES), DRIP_CHUNK);
        assert_eq!(drip.len(), DRIP_BYTES / DRIP_CHUNK);
        assert!(drip.iter().all(|chunk| chunk.len() == DRIP_CHUNK));
    }

    #[test]
    fn post_confirmed_repeats_stall() {
        let mut calls = 0;
        let closed = post_confirmed(
            "h",
            "i",
            "/",
            vec![],
            |_host, _ip, _path, _chunks| {
                calls += 1;
                if calls < 2 { PostResult::of(POST_STALLED) } else { PostResult::of(POST_ANSWERED) }
            },
        );
        assert_eq!(closed.kind, POST_ANSWERED);
        assert_eq!(calls, 2);
        let mut calls = 0;
        let answered = post_confirmed(
            "h",
            "i",
            "/",
            vec![],
            |_host, _ip, _path, _chunks| {
                calls += 1;
                PostResult::of(POST_ANSWERED)
            },
        );
        assert_eq!(answered.kind, POST_ANSWERED);
        assert_eq!(calls, 1);
    }

    #[test]
    fn collect_skips_when_small_refused() {
        let facts = collect("h", "i", "/", || PostResult::of(POST_EARLY), |_, _, _, _, _| panic!("не был вызван"));
        assert_eq!(facts.bulk, None);
        assert_eq!(facts.drip, None);
        let mut calls = 0;
        let facts = collect(
            "h",
            "i",
            "/",
            || PostResult::of(POST_ANSWERED),
            |_host, _ip, _path, _chunks, _drip| {
                calls += 1;
                PostResult::of(POST_ANSWERED)
            },
        );
        assert_eq!(calls, 2);
        assert!(facts.bulk.is_some());
        assert!(facts.drip.is_some());
    }

    #[test]
    fn judge_python_all_paths() {
        let small = kind(POST_ANSWERED, Some(200));
        // Всё хорошо.
        let facts = UploadFacts { small: small.clone(), bulk: Some(kind(POST_ANSWERED, Some(200))), drip: Some(kind(POST_ANSWERED, Some(200))) };
        assert_eq!(judge(&facts), UploadVerdict::of(UPLOAD_OK, "отправка данных проходит без обрыва"));
        // Прервали проверку в разных местах.
        let facts = UploadFacts { small: kind(POST_CANCELLED, None), ..Default::default() };
        assert_eq!(judge(&facts).text, "проверку отправки прервали");
        let facts = UploadFacts {
            small: small.clone(),
            bulk: Some(kind(POST_CANCELLED, None)),
            drip: Some(kind(POST_ANSWERED, Some(200))),
        };
        assert_eq!(judge(&facts).text, "проверку отправки прервали");
        let facts = UploadFacts {
            small: small.clone(),
            bulk: Some(kind(POST_ANSWERED, Some(200))),
            drip: Some(kind(POST_CANCELLED, None)),
        };
        assert_eq!(judge(&facts).text, "проверку отправки прервали");
        // Сервер не читает тело.
        let facts = UploadFacts { small: kind(POST_EARLY, None), bulk: None, drip: None };
        assert_eq!(
            judge(&facts).text,
            "сервер отвечает, не дочитав отправленное, — проверить отправку на нём нельзя"
        );
        // Не на чем проверять.
        for small in ["failed", "stalled"] {
            let facts = UploadFacts { small: kind(small, None), ..Default::default() };
            assert_eq!(judge(&facts).text, "сервер не принимает отправку данных — проверить её не на чем");
        }
        let facts = UploadFacts { small: small.clone(), bulk: None, drip: None };
        assert_eq!(judge(&facts).text, "сервер не принимает отправку данных — проверить её не на чем");
        // Большая отправка замирает.
        let facts = UploadFacts {
            small: small.clone(),
            bulk: Some(kind(POST_STALLED, None)),
            drip: Some(kind(POST_ANSWERED, Some(200))),
        };
        assert_eq!(judge(&facts).code, UPLOAD_BULK_STALLS);
        assert_eq!(
            judge(&facts).text,
            "отправка 64 КБ замирает дважды подряд, хотя короткую отправку тот же сервер принимает"
        );
        // Мелкие пакеты замирают.
        let facts = UploadFacts {
            small: small.clone(),
            bulk: Some(kind(POST_ANSWERED, Some(200))),
            drip: Some(kind(POST_STALLED, None)),
        };
        assert_eq!(judge(&facts).code, UPLOAD_PACKET_LIMIT);
        assert_eq!(
            judge(&facts).text,
            "соединение дважды замирает на 32 мелких пакетах, хотя большой объём проходит — режут по числу \
             пакетов, а не по объёму"
        );
        // Сервер сам сбросил.
        for (bulk, drip) in [(POST_FAILED, POST_ANSWERED), (POST_ANSWERED, POST_FAILED), (POST_FAILED, POST_FAILED)] {
            let facts = UploadFacts {
                small: small.clone(),
                bulk: Some(kind(bulk, None)),
                drip: Some(kind(drip, None)),
            };
            assert_eq!(judge(&facts).text, "сервер оборвал отправку сам — это не похоже на замирание", "{bulk}/{drip}");
        }
    }
}
