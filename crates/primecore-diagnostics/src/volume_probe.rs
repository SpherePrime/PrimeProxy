//! Порт `src/diagnostics/volume_probe.py` — чистая часть: вывод по объёму.
//!
//! Обрыв после 16 КБ у конкретного сайта: по одному соединению подряд уходит
//! много запросов, пока от сервера не наберётся больше 24 КБ. Набралось —
//! обрыва нет; соединение замерло в окне 16 КБ дважды — обрыв. Отправка
//! (`download`, `collect`) — сетевая часть (Chrome-соединение), портируется
//! вместе с `chrome_https`; здесь — константы, типы и чистый вывод `judge`.

use crate::limits::{FREEZE_MAX_BYTES, FREEZE_MIN_BYTES};

/// Сколько набрать, чтобы уверенно сказать «обрыва нет».
pub const TARGET_BYTES: u64 = 48 * 1024;
/// Окно, в котором замирание считается обрывом — общее окно `limits::FREEZE_*`,
/// только нижняя граница сдвинута: фильтр считает и служебные данные шифрования
/// (сертификат сервера — несколько килобайт), а здесь лишь полезный ответ.
pub const CUT_MIN_BYTES: u64 = FREEZE_MIN_BYTES - 4_000;
pub const CUT_MAX_BYTES: u64 = FREEZE_MAX_BYTES;
pub const MAX_REQUESTS: u32 = 60;
pub const TIMEOUT_S: f64 = 5.0;
/// Столько ждём следующих данных: дольше — соединение замерло.
pub const STALL_S: f64 = 3.0;
/// Больше этого одна попытка не длится, сколько бы запросов ни осталось.
pub const BUDGET_S: f64 = 6.0;
/// После стольких ответов видно, наберётся ли объём.
pub const ESTIMATE_AFTER: u32 = 6;

pub const RUN_PASSED: &str = "passed"; // набрали нужный объём
pub const RUN_STALLED: &str = "stalled"; // данные перестали идти
pub const RUN_RESET: &str = "reset"; // соединение сброшено посреди работы
pub const RUN_CLOSED: &str = "closed"; // сервер сам закрыл соединение или объём не набрался
pub const RUN_FAILED: &str = "failed"; // не удалось даже начать
pub const RUN_CANCELLED: &str = "cancelled";

pub const VOLUME_OK: &str = "ok";
pub const VOLUME_CUT: &str = "cut";
pub const VOLUME_UNKNOWN: &str = "unknown";

/// python `VolumeRun`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VolumeRun {
    pub kind: String,
    /// Сколько байт ответа получено по соединению.
    pub received: u64,
    /// Сколько запросов успели отправить.
    pub requests: u32,
}

/// python `VolumeFacts`.
#[derive(Debug, Clone, Default)]
pub struct VolumeFacts {
    pub first: VolumeRun,
    /// None — второй раз не проверяли: первый не замирал.
    pub second: Option<VolumeRun>,
}

/// python `VolumeVerdict`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeVerdict {
    pub code: String,
    pub text: String,
    /// На скольких килобайтах замерло (для вывода «обрыв»).
    pub cut_kb: u64,
}

/// python `_froze_in_window(run)`.
pub fn froze_in_window(run: &VolumeRun) -> bool {
    (run.kind == RUN_STALLED || run.kind == RUN_RESET)
        && run.received >= CUT_MIN_BYTES
        && run.received <= CUT_MAX_BYTES
}

/// python `judge(facts)`.
pub fn judge(facts: &VolumeFacts) -> VolumeVerdict {
    let second_kind = facts
        .second
        .as_ref()
        .map(|run| run.kind.clone())
        .unwrap_or_default();
    if facts.first.kind == RUN_CANCELLED || second_kind == RUN_CANCELLED {
        return VolumeVerdict {
            code: VOLUME_UNKNOWN.to_string(),
            text: "проверку объёма прервали".to_string(),
            cut_kb: 0,
        };
    }
    // Нужный объём мог не набраться, но окно обрыва пройдено без замирания — обрыва нет.
    if facts.first.kind == RUN_PASSED
        || (facts.first.kind == RUN_CLOSED && facts.first.received > CUT_MAX_BYTES)
    {
        return VolumeVerdict {
            code: VOLUME_OK.to_string(),
            text: format!(
                "по одному соединению получено {} КБ без обрыва",
                facts.first.received / 1024
            ),
            cut_kb: 0,
        };
    }
    if froze_in_window(&facts.first) {
        let kb = facts.first.received / 1024;
        if let Some(second) = facts.second.as_ref() {
            if froze_in_window(second) {
                return VolumeVerdict {
                    code: VOLUME_CUT.to_string(),
                    text: format!(
                        "соединение замирает после {kb} КБ — дважды подряд, на {kb} и {} КБ",
                        second.received / 1024
                    ),
                    cut_kb: kb,
                };
            }
            if second.kind == RUN_PASSED {
                return VolumeVerdict {
                    code: VOLUME_UNKNOWN.to_string(),
                    text: format!("один раз соединение замерло на {kb} КБ, при повторе прошло — случайный сбой"),
                    cut_kb: 0,
                };
            }
        }
        return VolumeVerdict {
            code: VOLUME_UNKNOWN.to_string(),
            text: format!(
                "соединение замерло на {kb} КБ, но повтор этого не подтвердил — вывода нет"
            ),
            cut_kb: 0,
        };
    }
    if facts.first.kind == RUN_FAILED {
        return VolumeVerdict {
            code: VOLUME_UNKNOWN.to_string(),
            text: "не удалось соединиться повторно — объём не проверен".to_string(),
            cut_kb: 0,
        };
    }
    if facts.first.kind == RUN_STALLED || facts.first.kind == RUN_RESET {
        return VolumeVerdict {
            code: VOLUME_UNKNOWN.to_string(),
            text: format!(
                "соединение прервалось на {} КБ — это не похоже на обрыв после 16 КБ",
                facts.first.received / 1024
            ),
            cut_kb: 0,
        };
    }
    VolumeVerdict {
        code: VOLUME_UNKNOWN.to_string(),
        text: format!(
            "по одному соединению удалось набрать только {} КБ — на таком объёме обрыв после 16 КБ не проверить",
            facts.first.received / 1024
        ),
        cut_kb: 0,
    }
}

// ---------------------------------------------------------------------------
// Транспорт: запросы по одному соединению «как Chrome»
// ---------------------------------------------------------------------------

use std::sync::Arc;
use std::time::Instant;

use primecore_socketcancel::SocketCancel;

/// python `volume_probe.download(...)` — шлёт запросы `method` подряд по одному
/// соединению «как Chrome» с `ip`, пока не наберётся `target` байт ответа.
///
/// Соединение — как у браузера ([`crate::chrome_https::ChromeConnection`]):
/// то же рукопожатие, браузерные заголовки; сжатие не распаковывается —
/// считаются байты на проводе.
#[allow(clippy::too_many_arguments)]
pub fn download(
    host: &str,
    ip: &str,
    path: &str,
    method: &str,
    target: u64,
    port: u16,
    timeout: f64,
    stall: f64,
    budget: f64,
    cancel: &Arc<SocketCancel>,
) -> VolumeRun {
    let started = Instant::now();
    let mut received = 0u64;
    let mut requests = 0u32;
    // python `_run(kind)`: «Стоп» перекрывает всё, кроме полного набора объёма.
    let finish = |kind: &str, received: u64, requests: u32| -> VolumeRun {
        let kind = if cancel.cancelled() && kind != RUN_PASSED {
            RUN_CANCELLED
        } else {
            kind
        };
        VolumeRun {
            kind: kind.to_string(),
            received,
            requests,
        }
    };
    if cancel.cancelled() {
        return VolumeRun {
            kind: RUN_CANCELLED.to_string(),
            ..VolumeRun::default()
        };
    }
    // В тестах крейта соединение открытое (без рукопожатия) — вся остальная
    // механика запросов та же; рукопожатие проверено живыми тестами
    // chrome_https.
    #[cfg(test)]
    let mut connection = crate::chrome_https::ChromeConnection::insecure_http_for_tests(
        host,
        ip,
        timeout,
        port,
        stall,
        Arc::clone(cancel),
    );
    #[cfg(not(test))]
    let mut connection = crate::chrome_https::ChromeConnection::new(
        host,
        ip,
        timeout,
        port,
        stall,
        false,
        Arc::clone(cancel),
    );
    while requests < MAX_REQUESTS && started.elapsed().as_secs_f64() < budget {
        let before = received;
        let mut enough = |body: &[u8]| before as usize + body.len() >= target as usize;
        let exchange = connection.request(path, method, &mut enough);
        requests += 1;
        received += exchange.received() as u64;
        if exchange.progress.cancelled {
            return finish(RUN_CANCELLED, received, requests);
        }
        if exchange.reconnected {
            // Прежнее соединение закрыли между запросами: счёт по нему
            // кончился, этот запрос — уже не по нему.
            received -= exchange.received() as u64;
            requests -= 1;
            return finish(RUN_CLOSED, received, requests);
        }
        if exchange.progress.stopped_by_us || received >= target {
            return finish(RUN_PASSED, received, requests);
        }
        if exchange.error_code != 0 {
            if requests == 1 && exchange.progress.status.is_none() && !exchange.progress.secured {
                return finish(RUN_FAILED, received, requests);
            }
            if exchange.stalled() {
                return finish(RUN_STALLED, received, requests);
            }
            return finish(
                if exchange.reset() {
                    RUN_RESET
                } else {
                    RUN_CLOSED
                },
                received,
                requests,
            );
        }
        if requests >= ESTIMATE_AFTER
            && received / u64::from(requests) * u64::from(MAX_REQUESTS) <= CUT_MAX_BYTES
        {
            // Если сервер отвечает крошечными ответами и за все запросы не
            // выйти даже за окно обрыва, попытка прекращается сразу.
            return finish(RUN_CLOSED, received, requests);
        }
    }
    finish(RUN_CLOSED, received, requests)
}

/// python `collect(host, ip, path, cancel)` — первая попытка обычными
/// запросами; замерла в окне — вторая, запросами `HEAD`.
pub fn collect(host: &str, ip: &str, path: &str, cancel: &Arc<SocketCancel>) -> VolumeFacts {
    collect_with_port(host, ip, path, 443, cancel)
}

/// То же с явным портом — для живых тестов на локальном сервере.
pub fn collect_with_port(
    host: &str,
    ip: &str,
    path: &str,
    port: u16,
    cancel: &Arc<SocketCancel>,
) -> VolumeFacts {
    let first = download(
        host,
        ip,
        path,
        "GET",
        TARGET_BYTES,
        port,
        TIMEOUT_S,
        STALL_S,
        BUDGET_S,
        cancel,
    );
    if !froze_in_window(&first) || cancel.cancelled() {
        return VolumeFacts {
            first,
            second: None,
        };
    }
    let second = download(
        host,
        ip,
        path,
        "HEAD",
        TARGET_BYTES,
        port,
        TIMEOUT_S,
        STALL_S,
        BUDGET_S,
        cancel,
    );
    VolumeFacts {
        first,
        second: Some(second),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(kind: &str, received: u64) -> VolumeRun {
        VolumeRun {
            kind: kind.to_string(),
            received,
            requests: 1,
        }
    }

    #[test]
    fn verdicts() {
        assert_eq!(
            judge(&VolumeFacts {
                first: run(RUN_CANCELLED, 0),
                second: None
            })
            .text,
            "проверку объёма прервали"
        );
        assert_eq!(
            judge(&VolumeFacts {
                first: run(RUN_PASSED, 50000),
                second: None
            })
            .code,
            VOLUME_OK
        );
        assert_eq!(
            judge(&VolumeFacts {
                first: run(RUN_CLOSED, 50000),
                second: None
            })
            .code,
            VOLUME_OK
        );
        let first = run(RUN_STALLED, 20000);
        assert_eq!(
            judge(&VolumeFacts {
                first: first.clone(),
                second: Some(run(RUN_STALLED, 21000))
            })
            .code,
            VOLUME_CUT
        );
        assert_eq!(
            judge(&VolumeFacts {
                first: first.clone(),
                second: Some(run(RUN_PASSED, 50000))
            })
            .code,
            VOLUME_UNKNOWN
        );
        assert!(judge(&VolumeFacts {
            first,
            second: None
        })
        .text
        .contains("вывода нет"));
        assert_eq!(
            judge(&VolumeFacts {
                first: run(RUN_FAILED, 0),
                second: None
            })
            .text,
            "не удалось соединиться повторно — объём не проверен"
        );
        assert_eq!(
            judge(&VolumeFacts {
                first: run(RUN_STALLED, 10000),
                second: None
            })
            .code,
            VOLUME_UNKNOWN
        );
        assert!(judge(&VolumeFacts {
            first: run(RUN_CLOSED, 10000),
            second: None
        })
        .text
        .contains("не проверить"));
    }

    // --- Живые проверки на локальном сервере (внешней сети нет) ---

    use std::io::{Read as _, Write as _};
    use std::net::TcpListener;

    /// Локальный сервер: на каждый запрос отвечает `size` байтами, соединение
    /// держит открытым (keep-alive).
    fn spawn_volume_server(size: usize, replies: usize) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("сокет слушается");
        let port = listener.local_addr().expect("адрес").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut buffer = [0u8; 4096];
                for index in 0..replies {
                    if stream.read(&mut buffer).is_err() {
                        break;
                    }
                    let body = vec![b'a' + (index % 26) as u8; size];
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n");
                    if stream.write_all(head.as_bytes()).is_err()
                        || stream.write_all(&body).is_err()
                    {
                        break;
                    }
                    let _ = stream.flush();
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        });
        port
    }

    #[test]
    fn download_collects_target_over_one_connection() {
        let port = spawn_volume_server(100, 20);
        let cancel = Arc::new(SocketCancel::new());
        let run = download(
            "site.test",
            "127.0.0.1",
            "/probe",
            "GET",
            350,
            port,
            5.0,
            3.0,
            6.0,
            &cancel,
        );
        assert_eq!(run.kind, RUN_PASSED, "{}", run.kind);
        assert!(run.received >= 350, "получено {}", run.received);
        // Объём набран по одному соединению, без переоткрытий.
        assert!(
            run.requests >= 3 && run.requests < 20,
            "запросов {}",
            run.requests
        );
    }

    #[test]
    fn download_counts_only_one_connection() {
        // Сервер отвечает дважды и закрывает соединение: счёт по нему кончился.
        let port = spawn_volume_server(100, 2);
        let cancel = Arc::new(SocketCancel::new());
        let run = download(
            "site.test",
            "127.0.0.1",
            "/probe",
            "GET",
            10_000,
            port,
            5.0,
            3.0,
            6.0,
            &cancel,
        );
        // Соединение закрылось посреди работы: как у libcurl — пустой ответ
        // (код 52) считается сбросом.
        assert_eq!(run.kind, RUN_RESET, "{}", run.kind);
        assert!(run.received <= 300, "получено {}", run.received);
    }

    #[test]
    fn download_cancelled_returns_cancelled() {
        let cancel = Arc::new(SocketCancel::new());
        cancel.cancel();
        let run = download(
            "site.test",
            "127.0.0.1",
            "/probe",
            "GET",
            350,
            443,
            5.0,
            3.0,
            6.0,
            &cancel,
        );
        assert_eq!(run.kind, RUN_CANCELLED);
        assert_eq!(run.requests, 0);
    }

    #[test]
    fn collect_repeats_only_on_freeze() {
        // Первый прогон замирает в окне (сервер обрывает соединение), второй
        // — запросами HEAD — повторяется.
        let listener = TcpListener::bind("127.0.0.1:0").expect("сокет слушается");
        let port = listener.local_addr().expect("адрес").port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                let mut buffer = [0u8; 4096];
                // Первый прогон: заголовок + немного тела, потом тишина.
                if stream.read(&mut buffer).is_err() {
                    return;
                }
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10000\r\n\r\nab");
                let _ = stream.flush();
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        });
        let cancel = Arc::new(SocketCancel::new());
        let facts = collect_with_port("site.test", "127.0.0.1", "/probe", port, &cancel);
        // Замирание с маленьким телом — не в окне обрыва: второй раз не проверяли.
        assert_eq!(facts.second, None);
        assert!(froze_in_window(&facts.first) || facts.first.kind == RUN_STALLED);
        if froze_in_window(&facts.first) {
            assert!(
                facts.second.is_some(),
                "замирание в окне повторяется HEAD-ом"
            );
        }
    }
}
