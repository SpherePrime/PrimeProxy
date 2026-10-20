//! Порт `src/diagnostics/name_speed.py` — замедление по имени сайта: сайт
//! открывается, но данные к нему придерживают.
//!
//! Блокировка — не единственный способ мешать сайту. Фильтр может пропустить
//! соединение и ограничить его скорость, если увидел в приветствии имя сайта
//! (так замедляли YouTube). Остальные проверки этого не видят: для них
//! медленный, но идущий поток означает «открывается».
//!
//! Скорость самого сайта ничего не доказывает — она зависит от его серверов.
//! Поэтому здесь сравнение на **одном и том же** постороннем сервере: с него
//! качается один и тот же файл дважды — с его собственным именем (контроль) и
//! с именем проверяемого сайта в приветствии. Сервер отдаёт файл в обоих
//! случаях, дорога одна, сервер один; отличается только имя, которое видит
//! фильтр. Если с именем сайта скорость в разы ниже — замедляют по имени.
//!
//! Единичный медленный замер перепроверяется, и контроль в конце повторяется:
//! вдруг просела сама линия. Проверяются только сайты, которые открылись: у
//! закрытого сайта имя и так режут.
//!
//! Здесь нет сети в выводах: загрузка отделена от решения ([`judge`]), а в
//! сбор ([`collect`]) она передаётся снаружи (как в python `fetch`). Самого
//! TLS-загрузчика пока нет — он появится вместе с сетевым транспортом.

use crate::report_text::py_round0;

/// Сервер, который отдаёт файл при любом имени в приветствии, и большой файл на нём.
pub const SERVER_HOST: &str = "mirror.yandex.ru";
pub const PATH: &str = "/ubuntu/ls-lR.gz";
/// Столько хватает, чтобы скорость была видна: на быстрой линии это доля секунды.
pub const ENOUGH_BYTES: u64 = 600_000;
/// Дольше одной загрузки не ждём: при замедлении до десятков килобайт в секунду этого хватает.
pub const SAMPLE_SECONDS: f64 = 3.0;
pub const CONNECT_TIMEOUT_S: f64 = 4.0;
pub const MAX_NAMES: usize = 6;

/// Во сколько раз с именем сайта должно быть медленнее, чем с именем сервера.
pub const SLOWER_TIMES: f64 = 6.0;
/// И при этом медленно само по себе: 2 Мбит/с.
pub const SLOW_KBPS: f64 = 250.0;
/// Меньше этого замер ни о чём не говорит: файл не начал идти.
pub const MIN_BYTES: u64 = 20_000;

pub const RUN_OK: &str = "ok";
/// Не соединились или не прошло шифрование.
pub const RUN_CONNECT: &str = "connect";
/// Сервер с этим именем файл не отдал.
pub const RUN_REFUSED: &str = "refused";
pub const RUN_CANCELLED: &str = "cancelled";
/// Поток пошёл и оборвался раньше времени: сброс соединения или закрытие, хотя файл намного больше.
pub const RUN_CUT: &str = "cut";

pub const FINE: &str = "ok";
pub const SLOW: &str = "slow";
/// Поток с этим именем обрывают (дважды подряд), а с обычным именем тот же файл идёт.
pub const CUT: &str = "cut";
pub const UNKNOWN: &str = "unknown";

/// Одна загрузка с именем в приветствии (python `NameRun`).
#[derive(Debug, Clone, PartialEq)]
pub struct NameRun {
    pub name: String,
    pub kind: String,
    pub received: u64,
    pub seconds: f64,
}

impl NameRun {
    #[must_use]
    pub fn run(name: &str, kind: &str) -> Self {
        Self { name: name.to_string(), kind: kind.to_string(), received: 0, seconds: 0.0 }
    }

    /// Килобайт в секунду. `None` — замер не получился.
    #[must_use]
    pub fn kbps(&self) -> Option<f64> {
        if self.kind != RUN_OK || self.seconds <= 0.0 || self.received < MIN_BYTES {
            // Мало байт за всё отведённое время — это и есть замедление, а не «нет замера».
            if self.kind == RUN_OK && self.seconds >= SAMPLE_SECONDS * 0.9 {
                return Some(self.received as f64 / 1024.0 / self.seconds);
            }
            return None;
        }
        Some(self.received as f64 / 1024.0 / self.seconds)
    }
}

/// python `NameFacts`: пара контролей в начале, загрузки по именам и контроль в конце.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NameFacts {
    /// Загрузки с собственным именем сервера в начале.
    pub control: Vec<NameRun>,
    /// По каждому имени — одна загрузка или две (вторая — перепроверка медленной).
    pub names: Vec<Vec<NameRun>>,
    /// Контроль в конце — только если какое-то имя шло медленно.
    pub control_after: Vec<NameRun>,
}

/// Вывод по одному имени (python `NameVerdict`).
#[derive(Debug, Clone, PartialEq)]
pub struct NameVerdict {
    pub name: String,
    pub code: String,
    pub text: String,
    pub kbps: Option<f64>,
}

impl NameVerdict {
    fn new(name: &str, code: &str, text: String, kbps: Option<f64>) -> Self {
        Self { name: name.to_string(), code: code.to_string(), text, kbps }
    }
}

/// python `download`: TLS-загрузка с именем в приветствии (сетевая, движок).
/// Здесь пока только текст запроса, который шлётся после рукопожатия.
#[must_use]
pub fn request_bytes(name: &str, path: &str) -> Vec<u8> {
    format!("GET {path} HTTP/1.1\r\nHost: {name}\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
        .into_bytes()
}

/// Первый кусок ответа: либо «сервер файл не отдал», либо всё хорошо
/// (python проверяет `HTTP/1.` и код `200` в первых байтах).
#[must_use]
pub fn head_verdict(head: &[u8]) -> &'static str {
    let ok = head.starts_with(b"HTTP/1.") && head.get(9..12).is_some_and(|code| code == b"200");
    if ok { RUN_OK } else { RUN_REFUSED }
}

/// python `_slow`: замер и сам медленный, и в разы медленнее контроля.
#[must_use]
pub fn slow(run: &NameRun, control_kbps: f64) -> bool {
    match run.kbps() {
        Some(kbps) => kbps <= SLOW_KBPS && kbps * SLOWER_TIMES <= control_kbps,
        None => false,
    }
}

/// Контроль, затем имена по очереди: замеры не делят между собой линию.
///
/// `fetch(имя)` — одна загрузка с этим именем в приветствии.
#[must_use]
pub fn collect(
    names: &[String],
    mut fetch: impl FnMut(&str) -> NameRun,
    mut should_stop: Option<impl FnMut() -> bool>,
) -> NameFacts {
    fn halted(stop: &mut Option<&mut impl FnMut() -> bool>) -> bool {
        stop.as_mut().is_some_and(|stop| stop())
    }
    // Первая загрузка «холодная» и выходит медленнее: контроль меряется дважды, в счёт идёт лучший.
    let start = vec![fetch(SERVER_HOST), fetch(SERVER_HOST)];
    let known: Vec<f64> = start.iter().filter_map(NameRun::kbps).collect();
    if known.is_empty() || halted(&mut should_stop.as_mut()) {
        return NameFacts { control: start, ..Default::default() };
    }
    let mut deduped: Vec<String> = Vec::new();
    for name in names {
        if !deduped.contains(name) {
            deduped.push(name.clone());
        }
    }
    deduped.truncate(MAX_NAMES);
    let mut runs: Vec<Vec<NameRun>> = Vec::new();
    let mut again = false;
    let control_kbps = known.iter().copied().fold(f64::MIN, f64::max);
    for name in deduped {
        if halted(&mut should_stop.as_mut()) {
            break;
        }
        let run = fetch(&name);
        if (slow(&run, control_kbps) || run.kind == RUN_CUT) && !halted(&mut should_stop.as_mut()) {
            // Одному медленному или оборванному замеру не верим.
            again = true;
            runs.push(vec![run, fetch(&name)]);
        } else {
            runs.push(vec![run]);
        }
    }
    // Что-то шло медленно — контроль ещё раз: вдруг просела сама линия.
    let end = if again && !halted(&mut should_stop.as_mut()) { vec![fetch(SERVER_HOST)] } else { Vec::new() };
    NameFacts { control: start, names: runs, control_after: end }
}

/// Человекочитаемая скорость — копия `speed_check.speed_text`.
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

/// (скорость контроля, вывод по каждому имени). Скорость `None` — контроль не
/// получился, выводов нет (python `judge`).
#[must_use]
pub fn judge(facts: &NameFacts) -> (Option<f64>, Vec<NameVerdict>) {
    let known: Vec<f64> = facts.control.iter().filter_map(NameRun::kbps).collect();
    if known.is_empty() {
        return (None, Vec::new());
    }
    let mut control = known.iter().copied().fold(f64::MIN, f64::max);
    let after: Vec<Option<f64>> = facts.control_after.iter().map(NameRun::kbps).collect();
    // Контроль в конце не получился или сам стал медленным — просела линия, медленное имя не улика.
    let sagged = after.iter().any(|kbps| match kbps {
        None => true,
        Some(kbps) => kbps * SLOWER_TIMES <= control,
    });
    if !after.is_empty() && !sagged {
        let after_good = after.iter().filter_map(|kbps| *kbps);
        let min_after = after_good.fold(f64::MAX, f64::min);
        control = control.min(min_after);
    }
    let mut verdicts: Vec<NameVerdict> = Vec::new();
    for runs in &facts.names {
        let name = runs[0].name.as_str();
        let measured: Vec<f64> = runs.iter().filter_map(NameRun::kbps).collect();
        if runs.iter().any(|run| run.kind == RUN_CANCELLED) {
            continue;
        }
        let many = runs.len() > 1;
        if many && runs.iter().all(|run| run.kind == RUN_CUT) {
            // Оборвалось дважды подряд. Контроль в конце не прошёл — рвалась сама линия, имя ни при чём.
            let got = runs.iter().map(|run| run.received).max().unwrap_or(0) / 1024;
            if sagged {
                verdicts.push(NameVerdict::new(
                    name,
                    UNKNOWN,
                    "поток обрывался, но во время замера просела сама линия".to_string(),
                    None,
                ));
            } else {
                verdicts.push(NameVerdict::new(
                    name,
                    CUT,
                    format!(
                        "поток дважды оборвался (самое большее после {got} КБ), а с обычным именем тот же файл \
                         идёт — соединения с этим именем обрывают"
                    ),
                    None,
                ));
            }
            continue;
        }
        if measured.is_empty() {
            let reason = match runs[0].kind.as_str() {
                RUN_REFUSED => "сервер с этим именем файл не отдал",
                RUN_CUT => "поток оборвался, повторить замер не удалось",
                _ => "соединение с этим именем к постороннему серверу не прошло",
            };
            verdicts.push(NameVerdict::new(
                name,
                UNKNOWN,
                format!("скорость не измерить: {reason}"),
                None,
            ));
            continue;
        }
        let best = measured.iter().copied().fold(f64::MIN, f64::max);
        let all_slow = many && runs.iter().all(|run| slow(run, control));
        if all_slow && sagged {
            verdicts.push(NameVerdict::new(
                name,
                UNKNOWN,
                "скорость не сравнить: во время замера просела сама линия".to_string(),
                Some(best),
            ));
        } else if all_slow {
            verdicts.push(NameVerdict::new(
                name,
                SLOW,
                format!(
                    "{} против {} с тем же сервером под его собственным именем — соединения с этим именем замедляют",
                    speed_text(Some(best)),
                    speed_text(Some(control))
                ),
                Some(best),
            ));
        } else {
            verdicts.push(NameVerdict::new(
                name,
                FINE,
                format!("{some} — не медленнее, чем с обычным именем", some = speed_text(Some(best))),
                Some(best),
            ));
        }
    }
    (Some(control), verdicts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_run(name: &str, received: u64, seconds: f64) -> NameRun {
        NameRun { name: name.to_string(), kind: RUN_OK.to_string(), received, seconds }
    }

    fn rate(kbps: f64, seconds: f64) -> (u64, f64) {
        ((kbps * 1024.0 * seconds) as u64, seconds)
    }

    #[test]
    fn kbps_python_rules() {
        assert_eq!(ok_run("x", 0, 0.0).kbps(), None);
        assert_eq!(NameRun::run("x", RUN_REFUSED).kbps(), None);
        // Мало байт за всё время — это замедление, замер остаётся.
        assert!(ok_run("x", 25_000, SAMPLE_SECONDS).kbps().is_some());
        // Мало байт за короткое время — замера нет.
        assert_eq!(ok_run("x", 15_000, 1.0).kbps(), None);
        assert_eq!(ok_run("x", MIN_BYTES, 2.0).kbps(), Some(MIN_BYTES as f64 / 1024.0 / 2.0));
    }

    #[test]
    fn head_verdict_python() {
        assert_eq!(head_verdict(b"HTTP/1.1 200 OK"), RUN_OK);
        assert_eq!(head_verdict(b"HTTP/1.1 404 Not Found"), RUN_REFUSED);
        assert_eq!(head_verdict(b"HTTP/2 200"), RUN_REFUSED);
        assert_eq!(head_verdict(b""), RUN_REFUSED);
    }

    #[test]
    fn request_bytes_python_text() {
        assert_eq!(
            std::str::from_utf8(&request_bytes("a.ru", PATH)).unwrap(),
            format!("GET {PATH} HTTP/1.1\r\nHost: a.ru\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n")
        );
    }

    #[test]
    fn collect_python_schedule() {
        let names: Vec<String> = vec!["a.ru".to_string(), "b.ru".to_string(), "a.ru".to_string()];
        let fast = |name: &str| ok_run(name, rate(2000.0, 2.0).0, 2.0);
        let facts = collect(&names, fast, None::<fn() -> bool>);
        let grouped: Vec<(String, usize)> =
            facts.names.iter().map(|runs| (runs[0].name.clone(), runs.len())).collect();
        assert_eq!(grouped, vec![("a.ru".to_string(), 1), ("b.ru".to_string(), 1)]);
        assert!(facts.control_after.is_empty());
        assert_eq!(facts.control.len(), 2);
        // Медленное имя перепроверяется, контроль в конце повторяется.
        let mut counter = 0;
        let facts = collect(
            &names,
            |name| {
                counter += 1;
                if name != SERVER_HOST {
                    ok_run(name, rate(50.0, SAMPLE_SECONDS).0, SAMPLE_SECONDS)
                } else {
                    ok_run(name, rate(2000.0, 2.0).0, 2.0)
                }
            },
            None::<fn() -> bool>,
        );
        assert!(counter >= 7);
        assert!(facts.names.iter().all(|runs| runs.len() == 2));
        assert_eq!(facts.control_after.len(), 1);
        // Обрыв тоже перепроверяется.
        let facts = collect(
            &["a.ru".to_string()],
            |name| {
                if name == SERVER_HOST {
                    ok_run(name, rate(2000.0, 2.0).0, 2.0)
                } else {
                    NameRun { name: name.to_string(), kind: RUN_CUT.to_string(), received: 40_000, seconds: 0.5 }
                }
            },
            None::<fn() -> bool>,
        );
        assert_eq!(facts.names[0].len(), 2);
        assert_eq!(facts.control_after.len(), 1);
        // Контроль не удался — ничего дальше не меряется.
        let facts = collect(&names, |name| NameRun::run(name, RUN_CONNECT), None::<fn() -> bool>);
        assert!(facts.names.is_empty());
        assert!(facts.control.iter().all(|run| run.kind == RUN_CONNECT));
        // Останов после контроля — имена не проверяются вообще.
        let seen = std::rc::Rc::new(std::cell::Cell::new(0));
        let stop = { let seen = seen.clone(); move || seen.get() >= 2 };
        let mark = |name: &str| {
            seen.set(seen.get() + 1);
            ok_run(name, rate(2000.0, 2.0).0, 2.0)
        };
        let facts = collect(&names, mark, Some(stop));
        assert!(facts.names.is_empty());
    }

    #[test]
    fn judge_python_texts() {
        let control = vec![
            ok_run(SERVER_HOST, rate(1500.0, 2.0).0, 2.0),
            ok_run(SERVER_HOST, rate(1200.0, 2.0).0, 2.0),
        ];
        // Быстрое имя: fine.
        let facts = NameFacts { control: control.clone(), names: vec![vec![ok_run("a.ru", rate(2000.0, 1.0).0, 1.0)]], control_after: Vec::new() };
        let (speed, verdicts) = judge(&facts);
        assert_eq!(speed, Some(1500.0));
        assert_eq!(verdicts.len(), 1);
        assert_eq!(verdicts[0].code, FINE);
        assert_eq!(verdicts[0].text, "16 Мбит/с — не медленнее, чем с обычным именем");
        assert!((verdicts[0].kbps.unwrap() - 2000.0).abs() < 1e-9);
        // Медленное имя дважды: slow.
        let slow_run = ok_run("a.ru", rate(100.0, SAMPLE_SECONDS).0, SAMPLE_SECONDS);
        let facts = NameFacts {
            control: control.clone(),
            names: vec![vec![slow_run.clone(), slow_run.clone()]],
            control_after: Vec::new(),
        };
        let (speed, verdicts) = judge(&facts);
        assert_eq!(speed, Some(1500.0));
        assert_eq!(verdicts[0].code, SLOW);
        assert_eq!(
            verdicts[0].text,
            "0.8 Мбит/с против 12 Мбит/с с тем же сервером под его собственным именем — соединения с этим \
             именем замедляют"
        );
        // Отказ сервера с именем.
        let facts = NameFacts {
            control: control.clone(),
            names: vec![vec![NameRun::run("a.ru", RUN_REFUSED)]],
            control_after: Vec::new(),
        };
        let (_speed, verdicts) = judge(&facts);
        assert_eq!(verdicts[0].code, UNKNOWN);
        assert_eq!(verdicts[0].text, "скорость не измерить: сервер с этим именем файл не отдал");
        // Сняли проверку — имя пропускается.
        let facts = NameFacts {
            control: control.clone(),
            names: vec![vec![NameRun::run("a.ru", RUN_CANCELLED)]],
            control_after: Vec::new(),
        };
        let (_speed, verdicts) = judge(&facts);
        assert!(verdicts.is_empty());
        // Обрыв дважды подряд при живом контроле: cut.
        let cut = NameRun { name: "a.ru".to_string(), kind: RUN_CUT.to_string(), received: 640_000, seconds: 0.4 };
        let facts = NameFacts {
            control: control.clone(),
            names: vec![vec![cut.clone(), cut.clone()]],
            control_after: Vec::new(),
        };
        let (_speed, verdicts) = judge(&facts);
        assert_eq!(verdicts[0].code, CUT);
        assert_eq!(
            verdicts[0].text,
            "поток дважды оборвался (самое большее после 625 КБ), а с обычным именем тот же файл идёт — \
             соединения с этим именем обрывают"
        );
        // Просевший контроль в конце — контроль становится 50, но медленное имя всё ещё
        // медленнее контроля в разы: это slow, а не «просела линия».
        let sagged_after = ok_run(SERVER_HOST, rate(50.0, SAMPLE_SECONDS).0, SAMPLE_SECONDS);
        let facts = NameFacts {
            control,
            names: vec![vec![slow_run.clone(), slow_run]],
            control_after: vec![sagged_after],
        };
        let (speed, verdicts) = judge(&facts);
        assert_eq!(speed, Some(1500.0));
        assert_eq!(verdicts[0].code, UNKNOWN);
        assert_eq!(verdicts[0].text, "скорость не сравнить: во время замера просела сама линия");
    }
}
