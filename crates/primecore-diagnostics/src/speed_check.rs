//! Порт `src/diagnostics/speed_check.py` — скорость: отдают ли зарубежные
//! серверы данные заметно медленнее российских.
//!
//! Блокировка — не единственный способ мешать. Соединение может установиться и
//! данные идти, но медленно: так выглядит замедление и узкий канал за границу.
//! Остальные проверки этого не видят — для них медленный, но идущий поток
//! означает «открывается».
//!
//! Здесь с нескольких серверов качается по два-три мегабайта (не дольше
//! нескольких секунд с каждого) и считается скорость. Сама по себе цифра
//! ничего не значит: она зависит от тарифа. Поэтому зарубежные серверы
//! сравниваются с российскими, измеренными тут же, тем же способом.
//!
//! Вывод «заметно медленнее» делается, только когда медленны все измеренные
//! зарубежные серверы сразу и разница с российскими — в разы. Один медленный
//! сервер — это сам сервер.

use crate::report_text::py_round0;
use crate::verdict::Level;

/// Сколько байт качать с сервера и не дольше скольких секунд.
pub const SAMPLE_BYTES: u64 = 3_000_000;
pub const SAMPLE_SECONDS: f64 = 4.0;
/// Меньше этого — замер не показателен: слишком мало данных, чтобы говорить о скорости.
pub const MIN_BYTES: u64 = 200_000;
/// Во сколько раз зарубежные должны быть медленнее российских, чтобы это назвать.
pub const SLOWER_TIMES: f64 = 8.0;
/// И при этом сами по себе медленные: на быстром тарифе разница в разы ничему не мешает.
pub const SLOW_KBPS: f64 = 250.0; // 2 Мбит/с

/// Один сервер для замера скорости (python `SpeedServer`).
#[derive(Debug, Clone, PartialEq)]
pub struct SpeedServer {
    pub name: String,
    pub host: String,
    pub path: String,
    pub domestic: bool,
}

impl SpeedServer {
    fn new(name: &str, host: &str, path: &str, domestic: bool) -> Self {
        Self { name: name.to_string(), host: host.to_string(), path: path.to_string(), domestic }
    }
}

/// Зарубежные серверы (python `FOREIGN`).
pub fn foreign() -> Vec<SpeedServer> {
    vec![
        SpeedServer::new("OVH (Франция)", "proof.ovh.net", "/files/10Mb.dat", false),
        SpeedServer::new(
            "Leaseweb (Нидерланды)",
            "mirror.leaseweb.com",
            "/alpine/v3.9/releases/x86_64/alpine-extended-3.9.0-x86_64.iso",
            false,
        ),
        SpeedServer::new("Cloudflare", "speed.cloudflare.com", "/__down?bytes=5000000", false),
    ]
}

/// Российские серверы (python `DOMESTIC`).
pub fn domestic() -> Vec<SpeedServer> {
    vec![
        SpeedServer::new("Яндекс", "mirror.yandex.ru", "/ubuntu/ls-lR.gz", true),
        SpeedServer::new("Selectel", "speedtest.selectel.ru", "/10MB", true),
    ]
}

/// Один замер (python `SpeedSample`).
#[derive(Debug, Clone, PartialEq)]
pub struct SpeedSample {
    pub server: SpeedServer,
    /// Килобайт в секунду. `None` — замер не получился или данных слишком мало.
    pub kbps: Option<f64>,
    pub received: u64,
    pub seconds: f64,
}

impl SpeedSample {
    fn failed(server: SpeedServer) -> Self {
        Self { server, kbps: None, received: 0, seconds: 0.0 }
    }
}

/// Итог по скорости (python `SpeedReport`).
#[derive(Debug, Clone, PartialEq)]
pub struct SpeedReport {
    pub level: Level,
    pub headline: String,
    pub samples: Vec<SpeedSample>,
}

/// Серверы по очереди, вперемежку российские и зарубежные: замеры не мешают друг
/// другу.
///
/// `download(сервер)` возвращает (сколько байт пришло, за сколько секунд) или `None`.
#[must_use]
pub fn check_speed(
    mut download: impl FnMut(&SpeedServer) -> Option<(u64, f64)>,
    mut should_stop: Option<impl FnMut() -> bool>,
) -> Vec<SpeedSample> {
    let domestic = domestic();
    let foreign = foreign();
    let mut order: Vec<&SpeedServer> = Vec::new();
    for index in 0..foreign.len().max(domestic.len()) {
        if index < domestic.len() {
            order.push(&domestic[index]);
        }
        if index < foreign.len() {
            order.push(&foreign[index]);
        }
    }
    let mut samples: Vec<SpeedSample> = Vec::new();
    for server in order {
        if should_stop.as_mut().is_some_and(|stop| stop()) {
            break;
        }
        let got = download(server);
        let Some((received, seconds)) = got else {
            samples.push(SpeedSample::failed(server.clone()));
            continue;
        };
        // Мало данных за короткое время — файл кончился, замер не показателен. Мало данных
        // за всё отведённое время — это и есть медленный сервер: выбросить его значило бы
        // не заметить как раз замедление.
        let enough =
            received >= MIN_BYTES || (received > 0 && seconds >= SAMPLE_SECONDS * 0.9);
        let kbps = if enough && seconds > 0.0 { Some(received as f64 / 1024.0 / seconds) } else { None };
        samples.push(SpeedSample { server: server.clone(), kbps, received, seconds });
    }
    samples
}

/// Человекочитаемая скорость (python `speed_text`).
#[must_use]
pub fn speed_text(kbps: Option<f64>) -> String {
    let Some(kbps) = kbps else { return "замер не получился".to_string() };
    let mbit = kbps * 8.0 / 1000.0;
    if mbit >= 10.0 {
        format!("{} Мбит/с", py_round0(mbit))
    } else {
        format!("{mbit:.1} Мбит/с")
    }
}

/// python `statistics.median`: среднее двух средних при чётном числе.
fn median(values: &mut [f64]) -> f64 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let middle = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[middle - 1] + values[middle]) / 2.0
    } else {
        values[middle]
    }
}

/// Итог: медленный ли путь за границу (python `summarize_speed`).
#[must_use]
pub fn summarize_speed(samples: &[SpeedSample]) -> SpeedReport {
    let samples: Vec<SpeedSample> = samples.to_vec();
    let domestic: Vec<f64> =
        samples.iter().filter(|item| item.server.domestic).filter_map(|item| item.kbps).collect();
    let foreign: Vec<f64> =
        samples.iter().filter(|item| !item.server.domestic).filter_map(|item| item.kbps).collect();
    if domestic.is_empty() || foreign.is_empty() {
        let missing = if domestic.is_empty() { "российских" } else { "зарубежных" };
        return SpeedReport {
            level: Level::Unknown,
            headline: format!("Скорость сравнить не удалось: нет замера {missing} серверов"),
            samples,
        };
    }
    let home = domestic.iter().copied().fold(f64::MIN, f64::max);
    let abroad = median(&mut foreign.clone());
    // Медленны должны быть все измеренные зарубежные серверы, и их должно быть не меньше двух.
    let foreign_max = foreign.iter().copied().fold(f64::MIN, f64::max);
    let all_slow = foreign.len() >= 2 && foreign_max * SLOWER_TIMES <= home && foreign_max <= SLOW_KBPS;
    if all_slow {
        let times = home / abroad.max(0.001);
        return SpeedReport {
            level: Level::Warn,
            headline: format!(
                "Зарубежные серверы отдают данные примерно в {} раз медленнее российских: {} против {} — \
                 похоже на замедление или узкий канал за границу",
                py_round0(times),
                speed_text(Some(abroad)),
                speed_text(Some(home))
            ),
            samples,
        };
    }
    SpeedReport {
        level: Level::Ok,
        headline: format!(
            "Заметной разницы в скорости нет: зарубежные серверы — {}, российские — {}",
            speed_text(Some(abroad)),
            speed_text(Some(home))
        ),
        samples,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_interleaved_python() {
        let mut requested: Vec<String> = Vec::new();
        let samples = check_speed(
            |server| {
                requested.push(server.name.clone());
                Some((MIN_BYTES, 1.0))
            },
            Option::<fn() -> bool>::None,
        );
        assert_eq!(
            requested,
            vec!["Яндекс", "OVH (Франция)", "Selectel", "Leaseweb (Нидерланды)", "Cloudflare"]
        );
        // Одинаковый список серверов и в замерах.
        assert_eq!(
            samples.iter().map(|item| item.server.name.clone()).collect::<Vec<_>>(),
            requested
        );
        assert_eq!(samples.first().unwrap().kbps, Some(MIN_BYTES as f64 / 1024.0));
    }

    #[test]
    fn enough_data_python_branches() {
        // Мало байт за всё время — медленный сервер: замер остаётся.
        let slow = check_speed(|_server| Some((100_000, SAMPLE_SECONDS * 0.95)), None::<fn() -> bool>);
        assert!(slow.first().unwrap().kbps.is_some());
        // Мало байт за короткое время — файл кончился: замера нет.
        let short = check_speed(|_server| Some((100_000, 1.0)), None::<fn() -> bool>);
        assert_eq!(short.first().unwrap().kbps, None);
        // Ноль байт при малом времени — тоже нет замера.
        let empty = check_speed(|_server| Some((0, 1.0)), None::<fn() -> bool>);
        assert_eq!(empty.first().unwrap().kbps, None);
        // Отказ соединения.
        let lost = check_speed(|_server| Option::<(u64, f64)>::None, None::<fn() -> bool>);
        assert!(lost.iter().all(|item| item.kbps.is_none()));
        // Останов по просьбе движка: после двух замеров просим останов.
        let mut seen = 0;
        let mut downloads = 0;
        let half = {
            let should_stop = move || {
                seen += 1;
                seen >= 3
            };
            check_speed(
                |_server| {
                    downloads += 1;
                    Some((MIN_BYTES, 1.0))
                },
                Some(should_stop),
            )
        };
        assert_eq!(half.len(), 2);
    }

    #[test]
    fn speed_text_python_writes() {
        assert_eq!(speed_text(None), "замер не получился");
        assert_eq!(speed_text(Some(1250.0)), "10 Мбит/с");
        assert_eq!(speed_text(Some(23.4)), "0.2 Мбит/с");
        assert_eq!(speed_text(Some(500.0)), "4.0 Мбит/с");
    }

    #[test]
    fn summarize_python_verdicts() {
        let sample = |server: SpeedServer, kbps: f64| SpeedSample { server, kbps: Some(kbps), received: MIN_BYTES, seconds: 3.0 };
        // Не с чем сравнивать.
        let report = summarize_speed(&[]);
        assert_eq!(report.level, Level::Unknown);
        assert_eq!(report.headline, "Скорость сравнить не удалось: нет замера российских серверов");
        let dom = domestic();
        let frn = foreign();
        let report = summarize_speed(&[sample(dom[0].clone(), 4000.0)]);
        assert_eq!(report.headline, "Скорость сравнить не удалось: нет замера зарубежных серверов");
        // Хорошая скорость: ok.
        let report = summarize_speed(&[
            sample(dom[0].clone(), 4000.0),
            sample(dom[1].clone(), 5000.0),
            sample(frn[0].clone(), 3000.0),
            sample(frn[1].clone(), 2500.0),
        ]);
        assert_eq!(report.level, Level::Ok);
        assert_eq!(
            report.headline,
            "Заметной разницы в скорости нет: зарубежные серверы — 22 Мбит/с, российские — 40 Мбит/с"
        );
        // Все зарубежные медленные: warn.
        let report = summarize_speed(&[
            sample(dom[0].clone(), 4000.0),
            sample(frn[0].clone(), 20.0),
            sample(frn[1].clone(), 30.0),
        ]);
        assert_eq!(report.level, Level::Warn);
        assert_eq!(
            report.headline,
            "Зарубежные серверы отдают данные примерно в 160 раз медленнее российских: 0.2 Мбит/с против \
             32 Мбит/с — похоже на замедление или узкий канал за границу"
        );
    }
}
