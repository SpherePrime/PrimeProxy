//! Порт `src/diagnostics/filter_habits.py` — как работает фильтр: что он делает
//! с началом соединения и режет ли он ECH.
//!
//! От того, КАК фильтр читает начало соединения, зависит, какая стратегия
//! обхода сработает. Одно и то же приветствие (ClientHello) с именем сайта
//! отправляется по-разному (целиком, разрезами пакета, записями TLS) — и видно,
//! какие способы фильтр пропускает. Каждый способ — сравнение на одном адресе:
//! то же дробление с безобидным именем (контроль) и с именем сайта.
//!
//! Здесь нет сети: отправка передаётся снаружи (замыкание [`Send`], как
//! python `send`). Сбор фактов ([`check_split`], [`check_ech`]) отделён от
//! выводов ([`judge_split`], [`judge_ech`]).

use crate::block_cause::{
    HELLO_ALERT, HELLO_CANCELLED, HELLO_CONNECT, HELLO_GARBAGE, HELLO_OK, HELLO_RESET,
    HELLO_TIMEOUT,
};
use crate::browser_hello;

pub const WAY_WHOLE: &str = "whole";
pub const WAY_TCP_FIRST: &str = "tcp_first";
pub const WAY_TCP_BEFORE: &str = "tcp_before";
pub const WAY_TCP_NAME: &str = "tcp_name";
pub const WAY_TCP_SLOW: &str = "tcp_slow";
pub const WAY_TCP_THREE: &str = "tcp_three";
pub const WAY_REC_BEFORE: &str = "rec_before";
pub const WAY_REC_NAME: &str = "rec_name";
pub const WAY_REC_TCP: &str = "rec_tcp";

pub const WAY_TITLES: [(&str, &str); 9] = [
    (WAY_WHOLE, "Целиком, одним пакетом"),
    (WAY_TCP_FIRST, "Разрез пакета после первого байта"),
    (WAY_TCP_BEFORE, "Разрез пакета перед именем сайта"),
    (WAY_TCP_NAME, "Разрез пакета посреди имени"),
    (WAY_TCP_SLOW, "Разрез посреди имени с паузой в секунду"),
    (
        WAY_TCP_THREE,
        "Три куска: первый байт и разрез посреди имени",
    ),
    (WAY_REC_BEFORE, "Две записи TLS, граница перед именем"),
    (WAY_REC_NAME, "Две записи TLS, граница посреди имени"),
    (WAY_REC_TCP, "Две записи TLS двумя пакетами"),
];

pub const WAYS: [&str; 9] = [
    WAY_WHOLE,
    WAY_TCP_FIRST,
    WAY_TCP_BEFORE,
    WAY_TCP_NAME,
    WAY_TCP_SLOW,
    WAY_TCP_THREE,
    WAY_REC_BEFORE,
    WAY_REC_NAME,
    WAY_REC_TCP,
];

/// Разрезы пакета, которые делает и сам Zapret (куски подряд), и разрезы по записям шифрования.
const TCP_WAYS: [&str; 4] = [WAY_TCP_FIRST, WAY_TCP_BEFORE, WAY_TCP_NAME, WAY_TCP_THREE];
/// Способы «разрез по записям шифрования».
const RECORD_WAYS: [&str; 3] = [WAY_REC_BEFORE, WAY_REC_NAME, WAY_REC_TCP];

pub const NEUTRAL_NAME: &str = "example.com";
pub const ECH_OUTER: &str = "cloudflare-ech.com";
pub const ECH_OTHER_OUTER: &str = "example.com";
/// Пауза «с паузой»: заметно дольше, чем фильтр обычно ждёт остаток пакета.
pub const SLOW_PAUSE_S: f64 = 1.0;
/// Пауза между соединениями к одному адресу.
pub const BETWEEN_S: f64 = 0.3;
pub const REPEATS: usize = 2;

pub const PASSED: &str = "passed";
pub const CUT: &str = "cut";
/// Попытки кончились по-разному, и третья не дала перевеса.
pub const UNSTABLE: &str = "unstable";
/// С безобидным именем такое дробление тоже не проходит — способ не оценить.
pub const NO_CONTROL: &str = "no_control";
/// До способа не дошли: вывод уже ясен или проверку сняли.
pub const NOT_RUN: &str = "not_run";

/// Целиком проходит: по имени здесь не режут.
pub const HABIT_NOT_BY_NAME: &str = "not_by_name";
/// Не склеивает пакеты.
pub const HABIT_TCP: &str = "tcp";
/// Склеивает только пришедшее подряд.
pub const HABIT_TIMER: &str = "timer";
/// Пакеты склеивает, записи шифрования — нет.
pub const HABIT_RECORDS: &str = "records";
/// Собирает всё.
pub const HABIT_NONE: &str = "none";
pub const HABIT_UNKNOWN: &str = "unknown";

pub const ECH_BLOCKED: &str = "blocked";
pub const ECH_FINE: &str = "fine";
pub const ECH_UNKNOWN: &str = "unknown";

/// Отправка кусков приветствия: (адрес, куски, пауза) → код ответа `HELLO_*`.
/// Состоятельное замыкание (как callable в python): отдаётся через `&mut`.
pub type Send<'s> = dyn FnMut(&str, &[Vec<u8>], f64) -> String + 's;
/// Передышка между соединениями к одному адресу.
pub type Pause<'p> = dyn Fn(f64) + 'p;

/// Куски приветствия для способа `way` и пауза между ними (python `_parts`).
#[must_use]
pub fn parts(host: &str, way: &str, rnd: &mut browser_hello::Random) -> (Vec<Vec<u8>>, f64) {
    let record = browser_hello::build_hello(host, rnd, false, false);
    let name_at = browser_hello::name_offset(&record, host).unwrap_or(0);
    let middle = name_at + host.len().div_ceil(2);
    let joined = |first: Vec<u8>, second: Vec<u8>| {
        let mut one = first;
        one.extend(second);
        vec![one]
    };
    match way {
        WAY_TCP_FIRST => (vec![record[..1].to_vec(), record[1..].to_vec()], 0.0),
        WAY_TCP_BEFORE => (
            vec![record[..name_at].to_vec(), record[name_at..].to_vec()],
            0.0,
        ),
        WAY_TCP_NAME => (
            vec![record[..middle].to_vec(), record[middle..].to_vec()],
            0.0,
        ),
        WAY_TCP_SLOW => (
            vec![record[..middle].to_vec(), record[middle..].to_vec()],
            SLOW_PAUSE_S,
        ),
        WAY_TCP_THREE => (
            vec![
                record[..1].to_vec(),
                record[1..middle].to_vec(),
                record[middle..].to_vec(),
            ],
            0.0,
        ),
        WAY_REC_BEFORE => {
            let (first, second) = browser_hello::split_record(&record, name_at);
            (joined(first, second), 0.0)
        }
        WAY_REC_NAME => {
            let (first, second) = browser_hello::split_record(&record, middle);
            (joined(first, second), 0.0)
        }
        WAY_REC_TCP => {
            let (first, second) = browser_hello::split_record(&record, middle);
            (vec![first, second], 0.0)
        }
        _ => (vec![record], 0.0),
    }
}

/// Исходы с безобидным именем и с именем сайта (коды `HELLO_*`), по порядку попыток.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WayFacts {
    pub way: &'static str,
    pub control: Vec<String>,
    pub real: Vec<String>,
}

/// Факты по одному адресу (python `SplitFacts`). `final_control` — контроль
/// «целиком с безобидным именем» ещё раз в самом конце; пусто — не делали.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SplitFacts {
    pub host: String,
    pub ip: String,
    pub ways: Vec<WayFacts>,
    pub final_control: String,
    pub cancelled: bool,
}

/// Отказ сервера — тоже ответ сервера: приветствие до него дошло.
fn answered(kind: &str) -> bool {
    kind == HELLO_OK || kind == HELLO_ALERT
}

/// Чужой ответ вместо шифрования — тоже работа фильтра: сервер так не отвечает.
fn cut(kind: &str) -> bool {
    kind == HELLO_RESET || kind == HELLO_TIMEOUT || kind == HELLO_GARBAGE
}

/// `PASSED` / `CUT` по большинству попыток; пусто — перевеса нет.
fn settled(outcomes: &[String]) -> String {
    let passed = outcomes.iter().filter(|kind| answered(kind)).count() as u32;
    let cut_count = outcomes.iter().filter(|kind| cut(kind)).count() as u32;
    if passed >= 2 && passed > cut_count {
        return PASSED.to_string();
    }
    if cut_count >= 2 && cut_count > passed {
        return CUT.to_string();
    }
    // Единственная попытка бывает только у способа, обрезанного тем же исходом,
    // что и приветствие целиком.
    if outcomes.len() == 1 && cut_count > 0 {
        return CUT.to_string();
    }
    String::new()
}

/// Все способы по очереди. `send(ip, куски, пауза)` → код ответа; `pause(секунды)`
/// — передышка между соединениями. Если приветствие целиком проходит или его не
/// с чем сравнить, остальные способы не делаются: вывода из них всё равно не будет.
#[must_use]
pub fn check_split(host: &str, ip: &str, send: &mut Send, pause: &Pause) -> SplitFacts {
    let mut done: Vec<WayFacts> = Vec::new();
    // Чем фильтр режет приветствие целиком (сброс или молчание), если оба раза одинаково.
    let mut known_cut = String::new();

    let mut ask = |name: &str, way: &str| -> String {
        let (piece_list, gap) = parts(name, way, &mut random_salt());
        let kind = (send)(ip, &piece_list, gap);
        pause(BETWEEN_S);
        kind
    };

    let finish = |done: &mut Vec<WayFacts>, final_control: &str, cancelled: bool| SplitFacts {
        host: host.to_string(),
        ip: ip.to_string(),
        ways: done.clone(),
        final_control: final_control.to_string(),
        cancelled,
    };

    for way in WAYS {
        let mut control = vec![ask(NEUTRAL_NAME, way)];
        if !answered(&control[0]) && control[0] != HELLO_CANCELLED {
            // Один несостоявшийся контроль — ещё не «сервер не терпит дробление».
            control.push(ask(NEUTRAL_NAME, way));
        }
        if control.iter().any(|kind| kind == HELLO_CANCELLED) {
            return finish(&mut done, "", true);
        }
        let mut real: Vec<String> = Vec::new();
        if control.iter().any(|kind| answered(kind)) {
            real.push(ask(host, way));
            // Тот же исход, каким фильтр дважды обрезал приветствие целиком, — уже
            // повторное наблюдение, а не единичный сбой. Прочее перепроверяется.
            if !(known_cut == real[0]) {
                for _attempt in 1..REPEATS {
                    real.push(ask(host, way));
                }
                if settled(&real).is_empty() && !real.iter().any(|kind| kind == HELLO_CANCELLED) {
                    real.push(ask(host, way));
                }
            }
        }
        let way_record = WayFacts {
            way,
            control: control.clone(),
            real: real.clone(),
        };
        done.push(way_record);
        if real.iter().any(|kind| kind == HELLO_CANCELLED) {
            return finish(&mut done, "", true);
        }
        if way == WAY_WHOLE {
            if settled(&real) != CUT {
                return finish(&mut done, "", false);
            }
            let mut seen_kinds: Vec<String> = Vec::new();
            for kind in real.iter().filter(|kind| cut(kind)) {
                if !seen_kinds.contains(kind) {
                    seen_kinds.push(kind.clone());
                }
            }
            known_cut = if seen_kinds.len() == 1 {
                seen_kinds[0].clone()
            } else {
                String::new()
            };
        }
    }
    let final_control = ask(NEUTRAL_NAME, WAY_WHOLE);
    let cancelled = final_control == HELLO_CANCELLED;
    finish(&mut done, &final_control, cancelled)
}

/// Случайное соль приветствия здесь не важно: сравнение — на исходах границы,
/// которые не зависят от случайных расширений. Для собранных кусков замыкание
/// `send` передаёт приветствие как есть.
fn random_salt() -> impl FnMut(usize) -> Vec<u8> {
    |size: usize| vec![0u8; size]
}

/// Исходы попыток словами: «сброс ×2», «прошло, сброс, сброс». Пусто — попыток не было.
#[must_use]
pub fn outcomes_text(outcomes: &[String]) -> String {
    let mut counted: Vec<(String, usize)> = Vec::new();
    for kind in outcomes {
        let word = match kind.as_str() {
            HELLO_OK => "прошло",
            HELLO_ALERT => "дошло до сервера",
            HELLO_RESET => "сброс",
            HELLO_TIMEOUT => "молчание",
            HELLO_GARBAGE => "чужой ответ",
            HELLO_CONNECT => "нет соединения",
            _ => "ошибка",
        }
        .to_string();
        match counted.iter_mut().find(|(existing, _)| existing == &word) {
            Some((_, count)) => *count += 1,
            None => counted.push((word, 1)),
        }
    }
    counted
        .iter()
        .map(|(word, count)| {
            if *count == 1 {
                word.clone()
            } else {
                format!("{word} ×{count}")
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn way_state(facts: &WayFacts) -> &'static str {
    if facts.control.is_empty() {
        return NOT_RUN;
    }
    if !facts.control.iter().any(|kind| answered(kind)) {
        return NO_CONTROL;
    }
    match settled(&facts.real).as_str() {
        PASSED => PASSED,
        CUT => CUT,
        _ => UNSTABLE,
    }
}

fn meaning_word(state: &'static str) -> &'static str {
    match state {
        PASSED => WAY_MEANING_PASSED,
        CUT => WAY_MEANING_CUT,
        UNSTABLE => WAY_MEANING_UNSTABLE,
        NO_CONTROL => WAY_MEANING_NO_CONTROL,
        _ => WAY_MEANING_NOT_RUN,
    }
}

const WAY_MEANING_PASSED: &str = "фильтр такое приветствие пропускает";
const WAY_MEANING_CUT: &str = "фильтр его режет";
const WAY_MEANING_UNSTABLE: &str = "попытки кончились по-разному — вывода нет";
const WAY_MEANING_NO_CONTROL: &str =
    "так не проходит и безобидное имя — фильтр это или сервер, не различить";
const WAY_MEANING_NOT_RUN: &str = "не проверялось";

/// Зачем сообщаем: целиком безобидное имя проходит, а разрезанное на пакеты — дважды нет.
pub const MEANING_PACKETS_CUT: &str = "так не проходит и безобидное имя, хотя целиком оно проходит: приветствие, \
     разрезанное в этом месте, рвут с любым именем — фильтр по дороге или защита самого сайта. Дробление здесь \
     бесполезно";

/// Строка способа (python `WayVerdict`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct WayVerdict {
    pub way: &'static str,
    pub state: &'static str,
    /// Что получилось с именем сайта и с безобидным именем — словами.
    pub real: String,
    pub control: String,
    pub meaning: String,
}

/// Вывод по одному сайту (python `SplitVerdict`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SplitVerdict {
    pub host: String,
    pub ip: String,
    pub code: &'static str,
    pub ways: Vec<WayVerdict>,
    pub text: String,
    /// Что из этого следует для выбора стратегии. Пусто — сказать нечего.
    pub advice: &'static str,
}

pub const ADVICE_TCP: &str =
    "Должны работать самые простые стратегии — с дроблением пакета (multisplit, \
     multidisorder). Место разреза берите из строк ниже, где способ проходит.";
pub const ADVICE_TIMER: &str =
    "Простое дробление вряд ли поможет: Zapret шлёт куски подряд, а подряд фильтр их \
     склеивает. Пробуйте стратегии со сменой порядка кусков (multidisorder) и с подделками (fake).";
pub const ADVICE_RECORDS: &str =
    "Дробление пакета не поможет, а дробление записи TLS — должно: ищите стратегии с tlsrec в названии.";
pub const ADVICE_NONE: &str = "Одно дробление здесь не поможет: фильтр собирает приветствие целиком. Пробуйте \
     стратегии с подделками (fake, fakedsplit, hostfakesplit) и с наложением кусков (seqovl) — их эта проверка \
     испытать не может.";

const POSITION_HINT_TCP_FIRST: &str = "после первого байта (pos=1)";
const POSITION_HINT_TCP_BEFORE: &str = "перед именем сайта (pos=host)";
const POSITION_HINT_TCP_NAME: &str = "посреди имени (pos=midsld)";
const POSITION_HINT_TCP_THREE: &str = "тремя кусками (pos=1,midsld)";

/// Вывод по одному сайту. None — проверку сняли.
#[must_use]
pub fn judge_split(facts: &SplitFacts) -> Option<SplitVerdict> {
    if facts.cancelled {
        return None;
    }
    let state_of = |way: &str| -> &'static str {
        match facts.ways.iter().find(|item| item.way == way) {
            Some(item) => way_state(item),
            None => NOT_RUN,
        }
    };
    let st = |way: &str| state_of(way);
    let item_of = |way: &str| facts.ways.iter().find(|item| item.way == way);
    // Целиком безобидное имя проходит, а разрезанное на пакеты — дважды нет: такой
    // разрез здесь не проходит ни с каким именем.
    let packets_cut: Vec<&str> = TCP_WAYS
        .iter()
        .copied()
        .filter(|way| {
            st(way) == NO_CONTROL
                && matches!(st(WAY_WHOLE), PASSED | CUT)
                && item_of(way).is_some_and(|item| item.control.len() > 1)
        })
        .collect();
    let ways_verdict: Vec<WayVerdict> = WAYS
        .iter()
        .map(|way| {
            let state = st(way);
            let found = item_of(way);
            WayVerdict {
                way,
                state,
                real: found.map_or_else(String::new, |item| outcomes_text(&item.real)),
                control: found.map_or_else(String::new, |item| outcomes_text(&item.control)),
                meaning: if packets_cut.contains(way) {
                    MEANING_PACKETS_CUT.to_string()
                } else {
                    meaning_word(state).to_string()
                },
            }
        })
        .collect();

    let verdict = |code: &'static str, text: String, advice: &'static str| {
        Some(SplitVerdict {
            host: facts.host.clone(),
            ip: facts.ip.clone(),
            code,
            ways: ways_verdict.clone(),
            text,
            advice,
        })
    };

    let whole = st(WAY_WHOLE);
    let state = st;
    if whole == PASSED {
        return verdict(
            HABIT_NOT_BY_NAME,
            "приветствие целиком проходит — по имени сайта его здесь не режут".to_string(),
            "",
        );
    }
    if whole == NO_CONTROL {
        return verdict(
            HABIT_UNKNOWN,
            "на этом адресе не проходит даже безобидное имя — сравнивать не с чем, вывода о фильтре нет".to_string(),
            "",
        );
    }
    if whole != CUT {
        return verdict(
            HABIT_UNKNOWN,
            "приветствие целиком режется не каждый раз — сравнивать способы не с чем".to_string(),
            "",
        );
    }
    if !facts.final_control.is_empty() && !answered(&facts.final_control) {
        return verdict(
            HABIT_UNKNOWN,
            "к концу проверки на этом адресе перестало проходить и безобидное имя: похоже, фильтр на время закрыл \
             адрес целиком — результатам по способам верить нельзя"
                .to_string(),
            "",
        );
    }
    let passing_tcp: Vec<String> = TCP_WAYS
        .iter()
        .filter(|way| state(way) == PASSED)
        .map(|way| match *way {
            WAY_TCP_FIRST => POSITION_HINT_TCP_FIRST,
            WAY_TCP_BEFORE => POSITION_HINT_TCP_BEFORE,
            WAY_TCP_NAME => POSITION_HINT_TCP_NAME,
            _ => POSITION_HINT_TCP_THREE,
        })
        .map(str::to_string)
        .collect();
    if !passing_tcp.is_empty() {
        return verdict(
            HABIT_TCP,
            format!(
                "фильтр не склеивает пакеты: приветствие, разрезанное {}, проходит",
                passing_tcp.join(", ")
            ),
            ADVICE_TCP,
        );
    }
    if state(WAY_TCP_NAME) == CUT && state(WAY_TCP_SLOW) == PASSED {
        return verdict(
            HABIT_TIMER,
            "фильтр склеивает куски, пришедшие подряд, но остаток долго не ждёт: с паузой в секунду разрез \
             проходит"
                .to_string(),
            ADVICE_TIMER,
        );
    }
    if RECORD_WAYS.iter().any(|way| state(way) == PASSED) {
        return verdict(
            HABIT_RECORDS,
            "пакеты фильтр склеивает, а записи шифрования — нет: приветствие двумя записями TLS проходит"
                .to_string(),
            ADVICE_RECORDS,
        );
    }
    // «Собирает всё» — только если разрез пакета посреди имени действительно проверен.
    let name_checked = state(WAY_TCP_NAME) == CUT || packets_cut.contains(&WAY_TCP_NAME);
    if name_checked
        && TCP_WAYS
            .iter()
            .chain(RECORD_WAYS.iter())
            .all(|way| matches!(state(way), CUT | NO_CONTROL))
    {
        return verdict(
            HABIT_NONE,
            format!(
                "фильтр собирает приветствие обратно: ни один разрез пакета и записи шифрования не проходит{}",
                if packets_cut.is_empty() { "" } else {
                    "; приветствие, разрезанное у имени сайта, не проходит даже с безобидным именем"
                }
            ),
            ADVICE_NONE,
        );
    }
    verdict(
        HABIT_UNKNOWN,
        "по способам дробления ответы разошлись или их не с чем сравнить — вывода о фильтре нет"
            .to_string(),
        "",
    )
}

/// Факты по ECH (python `EchFacts`): `with_ech` — приветствия с ECH и внешним
/// именем Cloudflare (повторы); `without_ech` — то же имя без ECH; `other_outer` —
/// ECH с другим внешним именем.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EchFacts {
    pub ip: String,
    pub with_ech: Vec<String>,
    pub without_ech: String,
    pub other_outer: String,
}

pub const ADVICE_ECH: &str =
    "Если сайты за Cloudflare не открываются: в Chrome — chrome://flags → Encrypted \
     ClientHello → Disabled; в Firefox — about:config → network.dns.echconfig.enabled = false.";

/// Три приветствия к одному адресу Cloudflare: с ECH и внешним именем;
/// с тем же именем без ECH; с ECH и другим внешним именем.
#[must_use]
pub fn check_ech(ip: &str, send: &mut Send) -> EchFacts {
    let hello = |name: &str, ech: bool| {
        let rnd = &mut random_salt();
        let mut one = browser_hello::build_hello(name, rnd, false, ech);
        vec![std::mem::take(&mut one)]
    };
    let without = (send)(ip, &hello(ECH_OUTER, false), 0.0);
    let other = (send)(ip, &hello(ECH_OTHER_OUTER, true), 0.0);
    let with_ech = (0..REPEATS)
        .map(|_| (send)(ip, &hello(ECH_OUTER, true), 0.0))
        .collect();
    EchFacts {
        ip: ip.to_string(),
        with_ech,
        without_ech: without,
        other_outer: other,
    }
}

/// (код, фраза). Вывод «режут» — только если оба контроля на том же адресе проходят.
#[must_use]
pub fn judge_ech(facts: Option<&EchFacts>) -> (&'static str, String) {
    match facts {
        None => (ECH_UNKNOWN, String::new()),
        Some(facts) => {
            if facts.with_ech.iter().any(|kind| kind == HELLO_CANCELLED)
                || facts.without_ech == HELLO_CANCELLED
                || facts.other_outer == HELLO_CANCELLED
            {
                return (ECH_UNKNOWN, String::new());
            }
            if !answered(&facts.without_ech) || !answered(&facts.other_outer) {
                return (
                    ECH_UNKNOWN,
                    "проверить не удалось: сервер Cloudflare не ответил на контрольное приветствие"
                        .to_string(),
                );
            }
            if !facts.with_ech.is_empty() && facts.with_ech.iter().all(|kind| cut(kind)) {
                return (
                    ECH_BLOCKED,
                    "соединения с шифрованным именем сайта (ECH) к Cloudflare режутся, а такие же без ECH \
                     проходят. Сайты за Cloudflare могут не открываться в браузере, пока в нём включён ECH"
                        .to_string(),
                );
            }
            if !facts.with_ech.is_empty() && facts.with_ech.iter().all(|kind| answered(kind)) {
                return (
                    ECH_FINE,
                    "соединения с шифрованным именем сайта (ECH) к Cloudflare проходят".to_string(),
                );
            }
            (
                ECH_UNKNOWN,
                "соединения с ECH проходят через раз — вывода нет".to_string(),
            )
        }
    }
}

/// Раздел «Как работает фильтр» (python `summarize`). None — показывать нечего.
///
/// `tools` — запущенные Zapret, VPN и другие программы обхода: при них пробы
/// идут через них, и вывод описывает сеть вместе с обходом, а не фильтр.
#[must_use]
pub fn summarize(
    splits: &[&SplitVerdict],
    ech: (&'static str, &str),
    tools: &[String],
) -> Option<serde_json::Value> {
    use serde_json::json;

    let tools: Vec<&str> = tools.iter().map(String::as_str).collect();
    let sites: Vec<serde_json::Value> = splits
        .iter()
        .map(|item| {
            json!({
                "host": item.host,
                "address": item.ip,
                "code": item.code,
                "text": item.text,
                // При работающем обходе совет по стратегиям был бы выведен из искажённых проб.
                "advice": if tools.is_empty() { item.advice } else { "" },
                "ways": item.ways.iter().map(|way| json!({
                    "way": way.way,
                    "title": WAY_TITLES.iter().find(|(code, _)| *code == way.way).map(|(_, title)| *title).unwrap_or(""),
                    "state": way.state,
                    "real": way.real,
                    "control": way.control,
                    "meaning": way.meaning,
                })).collect::<Vec<_>>(),
            })
        })
        .collect();
    let (ech_code, ech_text) = ech;
    if sites.is_empty() && ech_text.is_empty() {
        return None;
    }
    // Общий вывод — только по сайтам, где сравнение состоялось, и только если он у них один.
    let decided: Vec<&&SplitVerdict> = splits
        .iter()
        .filter(|item| {
            matches!(
                item.code,
                HABIT_TCP | HABIT_TIMER | HABIT_RECORDS | HABIT_NONE
            )
        })
        .collect();
    let codes: std::collections::BTreeSet<&str> = decided.iter().map(|item| item.code).collect();
    let advice: &'static str;
    let headline: String;
    if !tools.is_empty() {
        headline = format!(
            "проверка шла вместе с {}: пробные соединения проходят через них, поэтому ниже — поведение сети \
             вместе с обходом, а не фильтра провайдера",
            tools.join(", ")
        );
        advice = "Остановите обход и VPN и повторите проверку — тогда будет видно, как работает сам фильтр.";
    } else if decided.is_empty() {
        headline = if sites.len() == 1 {
            sites[0]["text"]
                .as_str()
                .map(str::to_string)
                .unwrap_or_default()
        } else if !sites.is_empty() {
            "ни по одному сайту сравнение не состоялось — вывода о фильтре нет".to_string()
        } else {
            ech_text.to_string()
        };
        advice = "";
    } else if codes.len() == 1 {
        headline = decided[0].text.clone();
        advice = decided[0].advice;
    } else {
        headline = "на разных сайтах фильтр ведёт себя по-разному — смотрите по каждому отдельно"
            .to_string();
        advice = "";
    }
    let mut headline_chars = headline.chars();
    let first_word = headline_chars
        .next()
        .map(|letter| letter.to_uppercase().to_string())
        .unwrap_or_default();
    let headline = format!("{first_word}{}", headline_chars.as_str());
    Some(json!({
        "headline": headline,
        // Общий вывод кодом — для подбора стратегий; пусто, когда вывода нет или пробы шли через обход.
        "code": if tools.is_empty() && codes.len() == 1 { decided[0].code } else { "" },
        "advice": advice,
        "disturbed": tools,
        "limits": LIMITS,
        "sites": sites,
        "ech": {
            "state": ech_code,
            "text": ech_text,
            "advice": if ech_code == ECH_BLOCKED { ADVICE_ECH } else { "" },
        },
    }))
}

pub const LIMITS: &str =
    "Проверяется только дробление приветствия. Поддельные пакеты, смену порядка кусков и их \
     наложение обычным соединением не сделать — эти приёмы Zapret здесь не испытываются.";

const STATE_WORDS_PASSED: &str = "проходит";
const STATE_WORDS_CUT: &str = "режется";
const STATE_WORDS_UNSTABLE: &str = "через раз";
const STATE_WORDS_NO_CONTROL: &str = "не оценить";
const STATE_WORDS_NOT_RUN: &str = "не проверялось";

/// Строка способа: что вышло с именем сайта, что с безобидным и что это значит.
#[must_use]
pub fn way_text(way: &serde_json::Value) -> String {
    if way["state"] == NOT_RUN {
        return "не проверялось".to_string();
    }
    let string_of = |key: &str| way[key].as_str().map(str::to_string);
    let mut parts: Vec<String> = Vec::new();
    if way["real"].as_str().map(|s| !s.is_empty()).unwrap_or(false) {
        parts.push(format!(
            "с именем сайта: {}",
            string_of("real").unwrap_or_default()
        ));
    }
    if way["control"]
        .as_str()
        .map(|s| !s.is_empty())
        .unwrap_or(false)
    {
        parts.push(format!(
            "с безобидным именем: {}",
            string_of("control").unwrap_or_default()
        ));
    }
    let meaning = string_of("meaning");
    let line = parts.join(" · ");
    match meaning {
        Some(extension) if !extension.is_empty() => format!("{line} — {extension}"),
        _ => line,
    }
}

/// Раздел для текстового отчёта.
#[must_use]
pub fn lines(report: &serde_json::Value) -> Vec<String> {
    let mut out = vec![
        "".to_string(),
        "━━━━━━━━ Как работает фильтр ━━━━━━━━".to_string(),
    ];
    out.push(format!(
        "{} {}",
        if report["disturbed"]
            .as_array()
            .map(|list| !list.is_empty())
            .unwrap_or(false)
        {
            "⚠️"
        } else {
            "ℹ️"
        },
        report["headline"].as_str().unwrap_or("")
    ));
    let advice = report["advice"].as_str().unwrap_or("");
    if !advice.is_empty() {
        out.push(format!("   👉 {advice}"));
    }
    if let Some(sites) = report["sites"].as_array() {
        for site in sites {
            out.push(format!(
                "   {} ({}): {}",
                site["host"].as_str().unwrap_or(""),
                site["address"].as_str().unwrap_or(""),
                site["text"].as_str().unwrap_or("")
            ));
            let site_advice = site["advice"].as_str().unwrap_or("");
            if !site_advice.is_empty() {
                out.push(format!("      👉 {site_advice}"));
            }
            if let Some(ways) = site["ways"].as_array() {
                for way in ways {
                    if way["state"] == NOT_RUN {
                        continue;
                    }
                    let icon = match way["state"].as_str().unwrap_or("") {
                        PASSED => "✅",
                        CUT => "❌",
                        _ => "❔",
                    };
                    let word = match way["state"].as_str().unwrap_or("") {
                        PASSED => STATE_WORDS_PASSED,
                        CUT => STATE_WORDS_CUT,
                        UNSTABLE => STATE_WORDS_UNSTABLE,
                        NO_CONTROL => STATE_WORDS_NO_CONTROL,
                        _ => STATE_WORDS_NOT_RUN,
                    };
                    out.push(format!(
                        "      {icon} {} — {word}: {}",
                        way_title(way),
                        way_text(way)
                    ));
                }
            }
        }
        let limits = report["limits"].as_str().unwrap_or("");
        if !limits.is_empty() {
            out.push(format!("   ℹ️ {limits}"));
        }
    }
    let ech = report["ech"].as_object();
    if let Some(ech) = ech {
        let ech_text = ech["text"].as_str().unwrap_or("");
        if !ech_text.is_empty() {
            let icon = match ech["state"].as_str().unwrap_or("") {
                ECH_BLOCKED => "⚠️",
                ECH_FINE => "✅",
                _ => "❔",
            };
            out.push(format!("{icon} ECH: {ech_text}"));
            let ech_advice = ech["advice"].as_str().unwrap_or("");
            if !ech_advice.is_empty() {
                out.push(format!("   👉 {ech_advice}"));
            }
        }
    }
    out
}

fn way_title(way: &serde_json::Value) -> &str {
    way["title"].as_str().unwrap_or("")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts_of(
        whole_control: Vec<&str>,
        whole_real: Vec<&str>,
        extra: Vec<(&'static str, Vec<&str>)>,
        final_control: &str,
        cancelled: bool,
    ) -> SplitFacts {
        let mut ways = vec![WayFacts {
            way: WAY_WHOLE,
            control: whole_control.iter().map(|kind| kind.to_string()).collect(),
            real: whole_real.iter().map(|kind| kind.to_string()).collect(),
        }];
        for (way, real) in extra {
            ways.push(WayFacts {
                way,
                control: vec![HELLO_OK.to_string()],
                real: real.iter().map(|kind| kind.to_string()).collect(),
            });
        }
        SplitFacts {
            host: "site.org".to_string(),
            ip: "5.6.7.8".to_string(),
            ways,
            final_control: final_control.to_string(),
            cancelled,
        }
    }

    #[test]
    fn judge_split_follows_python() {
        let ok_pending = judge_split(&facts_of(
            vec![HELLO_OK, HELLO_OK],
            vec![HELLO_OK, HELLO_OK, HELLO_OK],
            Vec::new(),
            "",
            false,
        ))
        .unwrap();
        assert_eq!(ok_pending.code, HABIT_NOT_BY_NAME);
        assert_eq!(
            ok_pending.text,
            "приветствие целиком проходит — по имени сайта его здесь не режут"
        );
        assert_eq!(ok_pending.ways[0].real, "прошло ×3");
        assert_eq!(ok_pending.ways[0].control, "прошло ×2");
        assert_eq!(ok_pending.ways[1].state, NOT_RUN);
        assert_eq!(ok_pending.ways[1].meaning, "не проверялось");

        let unknown = judge_split(&facts_of(
            vec![HELLO_TIMEOUT, HELLO_TIMEOUT],
            vec![HELLO_RESET; 3],
            Vec::new(),
            "",
            false,
        ))
        .unwrap();
        assert_eq!(unknown.code, HABIT_UNKNOWN);
        assert_eq!(
            unknown.text,
            "на этом адресе не проходит даже безобидное имя — сравнивать не с чем, вывода о фильтре нет"
        );
        assert_eq!(unknown.ways[0].state, NO_CONTROL);
        assert_eq!(unknown.ways[0].control, "молчание ×2");
        assert_eq!(unknown.ways[0].real, "сброс ×3");

        let shaky = judge_split(&facts_of(
            vec![HELLO_OK],
            vec![HELLO_OK],
            Vec::new(),
            "",
            false,
        ))
        .unwrap();
        assert_eq!(
            shaky.text,
            "приветствие целиком режется не каждый раз — сравнивать способы не с чем"
        );
        assert_eq!(shaky.ways[0].state, UNSTABLE);
        assert_eq!(shaky.ways[0].real, "прошло");
        assert_eq!(
            shaky.ways[0].meaning,
            "попытки кончились по-разному — вывода нет"
        );

        let tcp = judge_split(&facts_of(
            vec![HELLO_OK],
            vec![HELLO_RESET; 3],
            vec![(WAY_TCP_NAME, vec![HELLO_OK, HELLO_OK])],
            "",
            false,
        ))
        .unwrap();
        assert_eq!(tcp.code, HABIT_TCP);
        assert_eq!(tcp.text, "фильтр не склеивает пакеты: приветствие, разрезанное посреди имени (pos=midsld), проходит");
        assert_eq!(tcp.advice, ADVICE_TCP);

        let timer = judge_split(&facts_of(
            vec![HELLO_OK],
            vec![HELLO_RESET; 3],
            vec![
                (WAY_TCP_NAME, vec![HELLO_RESET, HELLO_RESET, HELLO_RESET]),
                (WAY_TCP_SLOW, vec![HELLO_OK, HELLO_OK]),
            ],
            "",
            false,
        ))
        .unwrap();
        assert_eq!(timer.code, HABIT_TIMER);
        assert_eq!(timer.advice, ADVICE_TIMER);

        let records = judge_split(&facts_of(
            vec![HELLO_OK],
            vec![HELLO_RESET; 3],
            vec![
                (WAY_TCP_NAME, vec![HELLO_RESET; 3]),
                (WAY_TCP_SLOW, vec![HELLO_RESET, HELLO_RESET]),
                (WAY_REC_NAME, vec![HELLO_OK, HELLO_OK]),
            ],
            "",
            false,
        ))
        .unwrap();
        assert_eq!(records.code, HABIT_RECORDS);
        assert_eq!(records.advice, ADVICE_RECORDS);

        // Известный сбой в конце: результаты по способам верить нельзя.
        let closed = judge_split(&facts_of(
            vec![HELLO_OK],
            vec![HELLO_RESET; 3],
            vec![(WAY_TCP_NAME, vec![HELLO_RESET; 3])],
            HELLO_RESET,
            false,
        ))
        .unwrap();
        assert_eq!(closed.code, HABIT_UNKNOWN);
        assert!(closed
            .text
            .starts_with("к концу проверки на этом адресе перестало проходить и безобидное имя"));

        let lost = judge_split(&facts_of(
            vec![HELLO_OK],
            vec![HELLO_RESET; 3],
            Vec::new(),
            "",
            false,
        ))
        .unwrap();
        assert_eq!(lost.code, HABIT_UNKNOWN);
        assert_eq!(lost.text, "по способам дробления ответы разошлись или их не с чем сравнить — вывода о фильтре нет");

        assert!(judge_split(&facts_of(Vec::new(), Vec::new(), Vec::new(), "", true)).is_none());
    }

    #[test]
    fn outcomes_text_counts() {
        let reset_multiple = [
            HELLO_RESET.to_string(),
            HELLO_RESET.to_string(),
            HELLO_OK.to_string(),
        ];
        assert_eq!(outcomes_text(&reset_multiple), "сброс ×2, прошло");
        assert_eq!(outcomes_text(&["connect".to_string()]), "нет соединения");
        assert_eq!(
            outcomes_text(&["garbage".to_string(), "garbage".to_string()]),
            "чужой ответ ×2"
        );
        assert_eq!(outcomes_text(&[]), "");
        assert_eq!(outcomes_text(&["whatever".to_string()]), "ошибка");
        assert_eq!(outcomes_text(&["alert".to_string()]), "дошло до сервера");
    }

    #[test]
    fn check_split_walks_ways_with_known_cut() {
        // Каждый контроль ok; real сброс дважды, потом single (тот же known_cut) и прочие.
        let mut script: Vec<&str> = vec![HELLO_OK, HELLO_RESET, HELLO_RESET];
        for way in WAYS.iter().skip(1) {
            let _ = way;
            script.push(HELLO_OK);
            script.push(HELLO_RESET);
        }
        script.push(HELLO_OK); // финальный контроль
        let mut queue = script.clone();
        let mut send = |ip: &str, parts: &[Vec<u8>], gap: f64| -> String {
            let _ = (ip, parts, gap);
            let kind = queue.remove(0);
            kind.to_string()
        };
        let facts = check_split("site.org", "5.6.7.8", &mut send, &|_seconds| {});
        assert!(!facts.cancelled);
        assert_eq!(facts.final_control, "ok");
        let seen: Vec<(&str, Vec<String>, Vec<String>)> = facts
            .ways
            .iter()
            .map(|way| (way.way, way.control.clone(), way.real.clone()))
            .collect();
        assert_eq!(
            seen,
            vec![(
                "whole",
                vec!["ok".to_string()],
                vec!["reset".to_string(), "reset".to_string()]
            ),]
            .into_iter()
            .chain(WAYS.iter().skip(1).map(|way| (
                *way,
                vec![HELLO_OK.to_string()],
                vec![HELLO_RESET.to_string()]
            )))
            .collect::<Vec<_>>()
        );
        let verdict = judge_split(&facts).unwrap();
        assert_eq!(verdict.code, HABIT_NONE);
        // Разрез посреди имени режется с учётом мимо-контроля: single так же как known_cut.
        assert_eq!(
            verdict.text,
            "фильтр собирает приветствие обратно: ни один разрез пакета и записи shифрования не проходит"
                .replace("shифрования", "шифрования")
        );

        // «Стоп» посреди контроля: проверка снята, дальнейшие способы не делаются.
        let mut short = vec![HELLO_OK, HELLO_RESET, HELLO_RESET, HELLO_CANCELLED];
        let mut send_cancel = |ip: &str, parts: &[Vec<u8>], gap: f64| -> String {
            let _ = (ip, parts, gap);
            short.remove(0).to_string()
        };
        let facts_cancel = check_split("s", "i", &mut send_cancel, &|_seconds| {});
        assert!(facts_cancel.cancelled);
        assert_eq!(facts_cancel.ways.len(), 1);
    }

    #[test]
    fn ech_judge_the_cloudflare_way() {
        assert_eq!(judge_ech(None), (ECH_UNKNOWN, String::new()));
        let blocked = EchFacts {
            ip: "1.2.3.4".to_string(),
            with_ech: vec!["reset".to_string(), "reset".to_string()],
            without_ech: "ok".to_string(),
            other_outer: "ok".to_string(),
        };
        let (code, text) = judge_ech(Some(&blocked));
        assert_eq!(code, ECH_BLOCKED);
        assert_eq!(
            text,
            "соединения с шифрованным именем сайта (ECH) к Cloudflare режутся, а такие же без ECH проходят. \
             Сайты за Cloudflare могут не открываться в браузере, пока в нём включён ECH"
        );
        let bad_control = EchFacts {
            ip: "1.2.3.4".to_string(),
            with_ech: vec!["ok".to_string()],
            without_ech: "timeout".to_string(),
            other_outer: "ok".to_string(),
        };
        let (code, text) = judge_ech(Some(&bad_control));
        assert_eq!(code, ECH_UNKNOWN);
        assert_eq!(
            text,
            "проверить не удалось: сервер Cloudflare не ответил на контрольное приветствие"
        );
        let fine = EchFacts {
            ip: "1.2.3.4".to_string(),
            with_ech: vec!["ok".to_string(), "ok".to_string()],
            without_ech: "ok".to_string(),
            other_outer: "ok".to_string(),
        };
        let (code, text) = judge_ech(Some(&fine));
        assert_eq!(code, ECH_FINE);
        assert_eq!(
            text,
            "соединения с шифрованным именем сайта (ECH) к Cloudflare проходят"
        );
        let single_ok = EchFacts {
            ip: "1.2.3.4".to_string(),
            with_ech: vec!["ok".to_string()],
            without_ech: "ok".to_string(),
            other_outer: "ok".to_string(),
        };
        let (code, text) = judge_ech(Some(&single_ok));
        assert_eq!(code, ECH_FINE);
        assert_eq!(
            text,
            "соединения с шифрованным именем сайта (ECH) к Cloudflare проходят"
        );

        let mixed = EchFacts {
            ip: "1.2.3.4".to_string(),
            with_ech: vec!["ok".to_string(), "reset".to_string()],
            without_ech: "ok".to_string(),
            other_outer: "ok".to_string(),
        };
        let (code, text) = judge_ech(Some(&mixed));
        assert_eq!(code, ECH_UNKNOWN);
        assert_eq!(text, "соединения с ECH проходят через раз — вывода нет");
    }

    #[test]
    fn check_ech_organizes_three_hellos() {
        let mut ordered: Vec<(usize, &str)> = Vec::new();
        let mut count = 0;
        let mut send = |ip: &str, parts: &[Vec<u8>], gap: f64| -> String {
            let _ = ip;
            for piece in parts {
                count += 1;
                let _ = piece;
            }
            let kind = format!("hit{count}");
            let note = (parts.len(), gap as usize);
            let _ = note;
            ordered.push((parts.len(), "hit"));
            kind
        };
        let facts = check_ech("1.2.3.4", &mut send);
        assert_eq!(facts.without_ech, "hit1");
        assert_eq!(facts.other_outer, "hit2");
        assert_eq!(facts.with_ech.len(), REPEATS);
        assert_eq!(facts.ip, "1.2.3.4");
        // Одна запись (эхdba-обёртка) для ECH-Приветствия.
        assert_eq!(records_counts(&ordered), vec![1, 1, 1, 1]);
    }

    fn records_counts(ordered: &[(usize, &str)]) -> Vec<usize> {
        ordered.iter().map(|(count, _)| *count).collect()
    }

    #[test]
    fn summarize_and_lines_follow_python() {
        // Нечего показать: и сайтов нет, и ECH не выведен.
        assert!(summarize(&[], ("unknown", ""), &[]).is_none());

        let tcp = judge_split(&facts_of(
            vec![HELLO_OK],
            vec![HELLO_RESET; 3],
            vec![(WAY_TCP_NAME, vec![HELLO_OK, HELLO_OK])],
            "",
            false,
        ))
        .unwrap();
        // Проверка шла вместе с Zapret: советы по стратегиям — пусто, код — пусто.
        let report = summarize(&[&tcp], (ECH_UNKNOWN, ""), &["Zapret".to_string()]).unwrap();
        assert_eq!(report["code"], "");
        assert!(report["headline"]
            .as_str()
            .unwrap()
            .starts_with("Проверка шла вместе с Zapret"));
        assert_eq!(report["sites"][0]["advice"], "");
        assert_eq!(report["disturbed"], serde_json::json!(["Zapret"]));

        let clean_report = summarize(&[&tcp], (ECH_UNKNOWN, ""), &[]).unwrap();
        assert_eq!(clean_report["code"], HABIT_TCP);
        assert_eq!(clean_report["advice"], ADVICE_TCP);
        assert_eq!(clean_report["headline"], "Фильтр не склеивает пакеты: приветствие, разрезанное посреди имени (pos=midsld), проходит");

        // ech отдельно: ни сайтов, ни вывода нет — None; только ech — заголовок из ech.
        let ech_only = summarize(&[], (ECH_UNKNOWN, "проверить не удалось"), &[]).unwrap();
        assert_eq!(ech_only["code"], "");
        assert_eq!(ech_only["headline"], "Проверить не удалось");

        let text = lines(&clean_report);
        let expecting: Vec<String> = vec![
            "".to_string(),
            "━━━━━━━━ Как работает фильтр ━━━━━━━━".to_string(),
            "ℹ️ Фильтр не склеивает пакеты: приветствие, разрезанное посреди имени (pos=midsld), проходит".to_string(),
            format!("   👉 {ADVICE_TCP}"),
            "   site.org (5.6.7.8): фильтр не склеивает пакеты: приветствие, разрезанное посреди имени (pos=midsld), проходит".to_string(),
            format!("      👉 {ADVICE_TCP}"),
            "      ❌ Целиком, одним пакетом — режется: с именем сайта: сброс ×3 · с безобидным именем: прошло — фильтр его режет".to_string(),
            "      ✅ Разрез пакета посреди имени — проходит: с именем сайта: прошло ×2 · с безобидным именем: прошло — фильтр такое приветствие пропускает".to_string(),
            format!("   ℹ️ {LIMITS}"),
        ];
        assert_eq!(text, expecting);

        let disturbed_lines = lines(&report);
        assert!(disturbed_lines[2].starts_with("⚠️ Проверка шла вместе с Zapret"));
    }
}
