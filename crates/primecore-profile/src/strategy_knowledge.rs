//! Порт profile/strategy_list/knowledge.py: что делает стратегия простыми
//! словами по её строкам ``--lua-desync``.

use serde::{Deserialize, Serialize};

const PREFIX: &str = "--lua-desync=";

/// python StepNote: одна настройка шага, показывается плиткой со значком.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepNote {
    pub kind: String,
    pub label: String,
    pub value: String,
    #[serde(default)]
    pub detail: String,
}

impl StepNote {
    pub fn text(&self) -> String {
        let mut value = format!("{}: {}", self.label, self.value);
        if !self.detail.is_empty() {
            value.push_str(" — ");
            value.push_str(&self.detail);
        }
        value
    }

    /// Короткая подпись метки; пояснение уходит в подсказку.
    pub fn chip(&self) -> String {
        match self.kind.as_str() {
            "protection" => {
                let head = self.value.chars().next().map(|c| c.to_lowercase().to_string()).unwrap_or_default();
                let tail = self.value.chars().skip(1).collect::<String>();
                format!("Защита: {head}{tail}")
            }
            kind if kind == "origin" || kind == "overlap" => self.value.clone(),
            "content" => format!("В подделке: {}", self.value),
            "cut" => format!("Разрез: {}", self.value),
            _ => format!("{}: {}", self.label, self.value),
        }
    }

    /// Метки на странице: каждое место разреза — своя короткая метка.
    pub fn chips(&self) -> Vec<String> {
        if self.kind == "cut" {
            let places: Vec<String> = self
                .value
                .split(';')
                .map(|place| place.trim().to_string())
                .filter(|place| !place.is_empty())
                .collect();
            if places.len() > 1 {
                return places
                    .into_iter()
                    .map(|place| format!("Разрез: {place}"))
                    .collect();
            }
        }
        vec![self.chip()]
    }

    pub fn hint(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        if !self.label.is_empty() {
            parts.push(format!("{}.", self.label));
        }
        if !self.detail.is_empty() {
            parts.push(self.detail.clone());
        }
        parts.join(" ")
    }
}

/// python StrategyStep: одна строка стратегии, объяснённая человеку.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StrategyStep {
    pub function: String,
    pub title: String,
    pub text: String,
    #[serde(default)]
    pub why: String,
    #[serde(default)]
    pub notes: Vec<StepNote>,
    #[serde(default)]
    pub cautions: Vec<String>,
    #[serde(default)]
    pub line: String,
    #[serde(default)]
    pub scene: String,
    #[serde(default = "default_family")]
    pub family: String,
}

fn default_family() -> String {
    "other".to_string()
}

impl StrategyStep {
    pub fn caution(&self) -> String {
        self.cautions.join(" ")
    }
}

#[allow(dead_code)]
const SITE_DROPS_FAKES: &str = "Подделки до сайта не доходят или он их отбрасывает, а ваш запрос получает целым.";

type FunctionInfo = (&'static str, &'static str, &'static str, &'static str);

const FUNCTIONS: [(&str, FunctionInfo); 17] = [
    (
        "fake",
        (
            "Подделка",
            "Перед вашим настоящим запросом программа отправляет ещё один — поддельный, с чужим именем сайта.",
            "Фильтр провайдера первым читает подделку, видит разрешённое имя и пропускает соединение. \
             Подделка до сайта не доходит или он её отбрасывает, и отвечает он на настоящий запрос.",
            "",
        ),
    ),
    (
        "multisplit",
        (
            "Нарезка",
            "Ваш запрос разрезается на несколько частей, и они уходят отдельными пакетами по порядку.",
            "Когда разрез проходит внутри имени сайта, имя оказывается разорвано между пакетами. Фильтр, \
             который смотрит каждый пакет по отдельности, целого имени не видит. Сайт склеивает части обратно.",
            "",
        ),
    ),
    (
        "multidisorder",
        (
            "Перестановка",
            "Ваш запрос разрезается на части, и они уходят в обратном порядке: сначала конец, потом начало.",
            "Фильтр ждёт начало запроса первым и не может сложить имя сайта. \
             Сайт расставляет части по номерам и получает запрос целым.",
            "",
        ),
    ),
    (
        "multidisorder_legacy",
        (
            "Перестановка, прежний вариант",
            "Ваш запрос разрезается на части, и они уходят в обратном порядке. Части меняются местами \
             внутри каждого пакета отдельно — так работал первый Zapret.",
            "Фильтр ждёт начало запроса первым и не может сложить имя сайта. \
             Сайт расставляет части по номерам и получает запрос целым.",
            "",
        ),
    ),
    (
        "fakedsplit",
        (
            "Нарезка с подделками",
            "Ваш запрос делится на две части. Каждая уходит между двумя поддельными копиями того же \
             размера с ненастоящим содержимым.",
            CONCAT_FAKE_SPLIT,
            "Пакетов уходит шесть вместо двух.",
        ),
    ),
    (
        "fakeddisorder",
        (
            "Перестановка с подделками",
            "Ваш запрос делится на две части, и вторая уходит первой. Каждая часть идёт между двумя \
             поддельными копиями того же размера.",
            CONCAT_FAKE_DISORDER,
            "Пакетов уходит шесть вместо двух.",
        ),
    ),
    (
        "hostfakesplit",
        (
            "Подмена имени сайта",
            "Ваш запрос режется вокруг имени сайта. Настоящее имя уходит отдельным пакетом, а перед ним \
             и после него — пакеты со случайным поддельным именем той же длины.",
            CONCAT_HOSTFAKE,
            "Работает только там, где имя сайта видно в запросе: обычный HTTP и начало защищённого соединения.",
        ),
    ),
    (
        "syndata",
        (
            "Данные в первом пакете",
            "Соединение начинается со служебного пакета, в котором данных обычно нет. Программа кладёт в него \
             данные и отправляет вместо обычного.",
            "",
            "",
        ),
    ),
    ("send", ("Повтор пакета", "Отправляется копия текущего пакета с изменёнными служебными полями.", "", "")),
    (
        "tcpseg",
        (
            "Отдельный кусок",
            "Выбранный кусок вашего запроса уходит отдельным пакетом.",
            "Позволяет поставить перед куском заглушку, которую сайт отбросит сам, а фильтр примет за данные.",
            "Исходный пакет этот шаг не заменяет: он уйдёт следом, если в стратегии нет шага «сброс пакета».",
        ),
    ),
    (
        "oob",
        (
            "Лишний байт",
            "В начало вашего запроса вставляется один «срочный» байт, который сайт выбросит.",
            "Фильтр читает запрос вместе с лишним байтом и не узнаёт в нём имя сайта.",
            "В обычном режиме работает только с сайтами на Linux, остальным ломает соединение. \
             С шагами нарезки не сочетается. Если профиль сменится посреди соединения, оно оборвётся.",
        ),
    ),
    (
        "wssize",
        (
            "Мелкое окно",
            "Сайту сообщается, что ваш компьютер готов принимать данные только маленькими порциями.",
            "Ответ сайта приходит мелкими кусками, и фильтр не может прочитать его целиком. \
             Рассчитано на соединения, где имя сайта видно в ответе (TLS 1.2).",
            "Снижает скорость. Автор Zapret советует применять, только когда другое не помогает.",
        ),
    ),
    (
        "wsize",
        (
            "Мелкое окно",
            "В ответе сайта подменяется размер порции, которую он готов принять, и ваш компьютер сам \
             отправляет запрос мелкими частями.",
            "Запрос уходит кусками, и фильтр не может прочитать его целиком.",
            "Снижает скорость. Автор Zapret считает приём устаревшим и советует вместо него нарезку.",
        ),
    ),
    (
        "udplen",
        (
            "Длина пакета",
            "К пакету дописываются лишние байты, или он укорачивается.",
            "",
            "При укорочении конец данных обрезается и теряется; дописанные байты терпит не каждая программа.",
        ),
    ),
    ("pktmod", ("Правка пакета", "Меняются служебные поля самого пакета, без подделок.", "", "")),
    ("drop", ("Сброс пакета", "Пакет не отправляется.", "", "")),
    (
        "pass",
        ("Без обхода", "Ничего не делает: трафик идёт как есть.", "", ""),
    ),
];

const CONCAT_FAKE_SPLIT: &str = concat!(
    "Фильтр видит шесть пакетов вместо двух и не знает, какие из них настоящие. ",
    "Подделки до сайта не доходят или он их отбрасывает, а ваш запрос получает целым."
);
const CONCAT_FAKE_DISORDER: &str = concat!(
    "Фильтр видит шесть пакетов в непривычном порядке и не знает, какие из них настоящие. ",
    "Подделки до сайта не доходят или он их отбрасывает, а ваш запрос получает целым."
);
const CONCAT_HOSTFAKE: &str = concat!(
    "Фильтр видит не то имя и пропускает соединение. ",
    "Подделки до сайта не доходят или он их отбрасывает, а ваш запрос получает целым."
);

type OwnInfo = (&'static str, &'static str, &'static str);

/// python _OWN_FUNCTIONS: функции, которых нет в оригинальном Zapret 2.
const OWN_FUNCTIONS: [(&str, OwnInfo); 3] = [
    (
        "fakemultisplit",
        (
            "fakedsplit",
            "Нарезка с подделками в нескольких местах",
            "Ваш запрос режется в нескольких местах, и части уходят вперемешку с поддельными копиями.",
        ),
    ),
    (
        "fakemultidisorder",
        (
            "fakeddisorder",
            "Перестановка с подделками в нескольких местах",
            "Ваш запрос режется в нескольких местах, и части уходят в обратном порядке вперемешку с поддельными копиями.",
        ),
    ),
    (
        "hostfakesplit_multi",
        (
            "hostfakesplit",
            "Подмена имени сайта, несколько имён",
            "Ваш запрос режется вокруг имени сайта. Настоящее имя уходит отдельным пакетом, а перед ним \
             и после него — пакеты с поддельными именами, которые берутся по очереди из списка.",
        ),
    ),
];

/// python _SCENES: какой анимированной схемой показать функцию.
const SCENES: [(&str, &str); 13] = [
    ("fake", "fake"),
    ("multisplit", "multisplit"),
    ("multidisorder", "multidisorder"),
    ("multidisorder_legacy", "multidisorder"),
    ("fakedsplit", "fakedsplit"),
    ("fakemultisplit", "fakedsplit"),
    ("fakeddisorder", "fakeddisorder"),
    ("fakemultidisorder", "fakeddisorder"),
    ("hostfakesplit", "hostfakesplit"),
    ("hostfakesplit_multi", "hostfakesplit"),
    ("tcpseg", "tcpseg"),
    ("oob", "oob"),
    ("syndata", "syndata"),
];

/// python _SENDS_FAKES: функции, шлющие отдельные поддельные пакеты.
const SENDS_FAKES: [&str; 4] = ["fake", "fakedsplit", "fakeddisorder", "hostfakesplit"];
const UDP_BLOB_HINTS: [&str; 6] = ["quic", "stun", "discord", "wireguard", "dht", "udp"];
const UNPROTECTED_FAKE_WARNING: &str =
    "У подделки нет защиты от сайта: она может дойти до него вместе с настоящим запросом и сломать соединение.";

type ProtectionInfo = (&'static str, &'static str, &'static str);

/// python _PROTECTIONS: параметр → (название защиты, как работает, о чём знать).
const PROTECTIONS: [(&str, ProtectionInfo); 14] = [
    (
        "ip_ttl",
        (
            "Короткий путь",
            "Пакету разрешено пройти только несколько узлов сети: до фильтра провайдера он доходит, до сайта — нет.",
            "Число узлов подобрано под конкретного провайдера. У другого подделка может дойти до сайта \
             или, наоборот, не дойти до фильтра.",
        ),
    ),
    (
        "ip_autottl",
        (
            "Короткий путь, подобранный автоматически",
            "Длину пути программа прикидывает сама по ответу сайта.",
            "Длина пути — оценка, а не точное знание. Если определить её не удалось, подделка уйдёт без этой защиты.",
        ),
    ),
    (
        "tcp_md5",
        ("Лишняя подпись", "В пакет добавлена подпись, которой сайт не ждёт, и он пакет отбрасывает.", ""),
    ),
    (
        "badsum",
        ("Испорченная контрольная сумма", "Сайт считает пакет повреждённым и отбрасывает.", ""),
    ),
    (
        "tcp_seq",
        ("Неверный порядковый номер", "Номер вне ожидаемого диапазона: сайт отбрасывает пакет как лишний.", ""),
    ),
    (
        "tcp_ack",
        (
            "Неверный номер подтверждения",
            "Сайт такой пакет отбрасывает.",
            "Надёжно работает вместе с переносом метки времени в начало заголовка (tcp_ts_up).",
        ),
    ),
    (
        "tcp_ts",
        (
            "Старая метка времени",
            "Сайт считает пакет устаревшим и отбрасывает.",
            "Метки времени есть не в каждом соединении. Если их нет, подделка уйдёт без этой защиты.",
        ),
    ),
    (
        "tcp_flags_unset",
        ("Снятый служебный флаг", "Обычно сайт такой пакет не принимает.", ""),
    ),
    (
        "tcp_flags_set",
        ("Лишний служебный флаг", "Обычно сайт такой пакет не принимает.", ""),
    ),
    (
        "ip6_hopbyhop",
        ("Дополнительный заголовок IPv6", "В пакет вставлен лишний служебный заголовок.", ""),
    ),
    (
        "ip6_destopt",
        ("Дополнительный заголовок IPv6", "В пакет вставлен лишний служебный заголовок.", ""),
    ),
    (
        "ip6_routing",
        ("Дополнительный заголовок IPv6", "В пакет вставлен лишний служебный заголовок.", ""),
    ),
    (
        "ip6_ah",
        ("Дополнительный заголовок IPv6", "В пакет вставлен лишний служебный заголовок.", ""),
    ),
    (
        "fool",
        ("Свой приём порчи", "Пакет портит отдельная функция, заданная в стратегии.", ""),
    ),
];

/// Отдельные поддельные пакеты шлют только эти функции; у остальных те же
/// параметры меняют настоящие пакеты шага (docs/manual.md Zapret 2).
const HAS_FAKES: [&str; 4] = ["fake", "fakedsplit", "fakeddisorder", "hostfakesplit"];
/// Перестановка кладёт перекрытие иначе, чем нарезка.
const DISORDER: [&str; 3] = ["multidisorder", "multidisorder_legacy", "fakeddisorder"];

/// python _FAMILIES: значок шага — группа способа обхода функции.
const FAMILIES: [(&str, &str); 14] = [
    ("fake", "fake"),
    ("multisplit", "split"),
    ("tcpseg", "split"),
    ("multidisorder", "disorder"),
    ("multidisorder_legacy", "disorder"),
    ("fakedsplit", "fake_split"),
    ("fakemultisplit", "fake_split"),
    ("fakeddisorder", "fake_disorder"),
    ("fakemultidisorder", "fake_disorder"),
    ("hostfakesplit", "host"),
    ("hostfakesplit_multi", "host"),
    ("syndata", "send"),
    ("send", "send"),
    ("udplen", "fake_udplen"),
];

const TLS_MODS: [(&str, &str); 4] = [
    ("rnd", "случайные служебные поля"),
    ("rndsni", "случайное имя сайта"),
    ("dupsid", "номер сеанса скопирован из настоящего запроса"),
    ("padencap", "настоящие данные спрятаны внутри поля-заполнителя"),
];

const BLOBS: [(&str, &str); 3] = [
    (
        "fake_default_tls",
        "стандартный запрос защищённого соединения к www.microsoft.com",
    ),
    ("fake_default_http", "стандартный HTTP-запрос к www.iana.org"),
    ("fake_default_quic", "заглушка вместо начала соединения QUIC"),
];

/// python _POSITIONS: места разреза запроса словами.
const POSITIONS: [(&str, &str); 7] = [
    // Основная часть имени — «youtube» в www.youtube.com.
    ("midsld", "посередине основной части имени сайта"),
    ("host", "в начале имени сайта"),
    ("endhost", "в конце имени сайта"),
    ("sld", "в начале основной части имени сайта"),
    ("endsld", "в конце основной части имени сайта"),
    ("sniext", "у поля с именем сайта"),
    ("method", "в начале названия запроса (GET, POST)"),
];

const TS_FORWARD: ProtectionInfo = (
    "Метка времени сдвинута вперёд",
    "Пакет не выглядит устаревшим.",
    "Сдвиг метки времени вперёд сайт может и не отбросить: обычно её сдвигают назад.",
);

/// python str.partition: до разделителя, сам разделитель, после.
fn partition(text: &str, separator: char) -> (&str, &str, &str) {
    match text.find(separator) {
        Some(index) => (&text[..index], &text[index..index + 1], &text[index + separator.len_utf8()..]),
        None => (text, "", ""),
    }
}

fn function_info(function: &str) -> Option<&'static FunctionInfo> {
    FUNCTIONS.iter().find(|(key, _)| *key == function).map(|(_, value)| value)
}

fn own_info(function: &str) -> Option<&'static OwnInfo> {
    OWN_FUNCTIONS.iter().find(|(key, _)| *key == function).map(|(_, value)| value)
}

fn scene(function: &str) -> &'static str {
    SCENES.iter().find(|(key, _)| *key == function).map(|(_, value)| *value).unwrap_or("")
}

fn protection(key: &str) -> Option<&'static ProtectionInfo> {
    // python: _PROTECTIONS["ip6_ttl"] = _PROTECTIONS["ip_ttl"] и autottl.
    let known = if key == "ip6_ttl" {
        Some("ip_ttl")
    } else if key == "ip6_autottl" {
        Some("ip_autottl")
    } else {
        None
    }
    .unwrap_or(key);
    PROTECTIONS.iter().find(|(probe, _)| *probe == known).map(|(_, value)| value)
}

fn family(function: &str) -> &'static str {
    FAMILIES.iter().find(|(key, _)| *key == function).map(|(_, value)| *value).unwrap_or("other")
}

fn sends_fakes(function: &str) -> bool {
    SENDS_FAKES.contains(&function)
}

fn has_fakes(function: &str) -> bool {
    HAS_FAKES.contains(&function)
}

fn disorder(function: &str) -> bool {
    DISORDER.contains(&function)
}

fn plural_times(count: usize) -> String {
    if matches!(count % 10, 2..=4) && !matches!(count % 100, 12..=14) {
        return format!("{count} раза");
    }
    format!("{count} раз")
}

/// python _position_words: места разреза словами.
pub fn position_words(value: &str) -> String {
    let mut words: Vec<String> = Vec::new();
    for token in value.split(',').map(|part| part.trim()) {
        if token.is_empty() {
            continue;
        }
        if token.chars().all(|symbol| symbol.is_ascii_digit()) {
            words.push(format!("после {token}-го байта"));
            continue;
        }
        if token.starts_with('-') && token[1..].chars().all(|symbol| symbol.is_ascii_digit()) && token.len() > 1 {
            words.push(format!("за {} байт до конца", &token[1..]));
            continue;
        }
        let base = if token.chars().next().map(|symbol| symbol.is_alphabetic()).unwrap_or(false) {
            token
                .replace(['+', '-'], " ")
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string()
        } else {
            String::new()
        };
        match POSITIONS.iter().find(|(known, _)| *known == base) {
            None => words.push(token.to_string()),
            Some((_, phrase)) => {
                if token == base {
                    words.push(phrase.to_string());
                } else {
                    // Сдвиг от места оставлен как в стратегии.
                    words.push(format!("{phrase} ({token})"));
                }
            }
        }
    }
    words.join("; ")
}

/// python _notes: настройки шага и предупреждения.
fn notes_of(function: &str, parameters: &[(String, String)]) -> (Vec<StepNote>, Vec<String>) {
    let mut notes: Vec<StepNote> = Vec::new();
    let mut cautions: Vec<String> = Vec::new();
    let has_fakes = has_fakes(function);
    for (key, value) in parameters {
        let mut protection = protection(key);
        if key == "tcp_ts" && !value.is_empty() && !value.starts_with('-') {
            protection = Some(&TS_FORWARD);
        }
        if let Some(info) = protection {
            let (name, how, caution) = *info;
            if has_fakes {
                notes.push(StepNote {
                    kind: "protection".to_string(),
                    label: "Защита подделки от сайта".to_string(),
                    value: name.to_string(),
                    detail: how.to_string(),
                });
            } else {
                // У шага нет отдельных подделок: параметр меняет его собственные пакеты.
                notes.push(StepNote {
                    kind: "protection".to_string(),
                    label: "Изменение пакетов шага".to_string(),
                    value: name.to_string(),
                    detail: "Применяется к пакетам этого шага, а не к подделке.".to_string(),
                });
            }
            if !caution.is_empty() && has_fakes {
                cautions.push(caution.to_string());
            }
        } else if key == "seqovl" {
            if disorder(function) {
                notes.push(StepNote {
                    kind: "overlap".to_string(),
                    label: "Перекрытие".to_string(),
                    value: "Ложные байты перед второй частью".to_string(),
                    detail: "Настоящая первая часть потом перезапишет их у сайта.".to_string(),
                });
                cautions.push("Перекрытие при перестановке не работает с сайтами на Windows.".to_string());
            } else {
                notes.push(StepNote {
                    kind: "overlap".to_string(),
                    label: "Перекрытие".to_string(),
                    value: "Заглушка перед первой частью".to_string(),
                    detail: "Сайт отбросит её сам, а фильтр примет за данные. Отдельная защита ей не нужна.".to_string(),
                });
            }
        } else if (key == "blob" || key == "fake_blob") && !value.is_empty() {
            let described = BLOBS
                .iter()
                .find(|(known, _)| known == value)
                .map(|(_, phrase)| phrase.to_string())
                .unwrap_or_else(|| value.clone());
            notes.push(StepNote {
                kind: "content".to_string(),
                label: "Что в подделке".to_string(),
                value: described,
                detail: String::new(),
            });
        } else if key == "pos" && !value.is_empty() {
            let label = if function == "tcpseg" { "Какой кусок" } else { "Где режется запрос" };
            notes.push(StepNote {
                kind: "cut".to_string(),
                label: label.to_string(),
                value: position_words(value),
                detail: String::new(),
            });
        } else if key == "repeats" && value.chars().all(|symbol| symbol.is_ascii_digit()) && !value.is_empty() {
            notes.push(StepNote {
                kind: "repeats".to_string(),
                label: "Повторы".to_string(),
                value: format!("{} подряд", plural_times(value.parse::<usize>().expect("число повторов"))),
                detail: String::new(),
            });
        } else if key == "tls_mod" && !value.is_empty() {
            let mods: Vec<String> = value
                .split(',')
                .filter(|token| !token.is_empty())
                .map(|token| {
                    if let Some(name) = token.strip_prefix("sni=") {
                        format!("имя сайта {name}")
                    } else {
                        TLS_MODS
                            .iter()
                            .find(|(known, _)| *known == token)
                            .map(|(_, phrase)| phrase.to_string())
                            .unwrap_or_else(|| token.to_string())
                    }
                })
                .collect();
            notes.push(StepNote {
                kind: "tweak".to_string(),
                label: "Подделка подправлена".to_string(),
                value: mods.join(", "),
                detail: String::new(),
            });
        } else if key == "hosts" && !value.is_empty() {
            let names: Vec<String> = value
                .split(',')
                .map(|name| name.trim().to_string())
                .filter(|name| !name.is_empty())
                .collect();
            notes.push(StepNote {
                kind: "names".to_string(),
                label: "Поддельные имена".to_string(),
                value: names.join(", "),
                detail: String::new(),
            });
        } else if key == "host" && !value.is_empty() {
            notes.push(StepNote {
                kind: "names".to_string(),
                label: "Образец поддельного имени".to_string(),
                value: value.clone(),
                detail: "Перед ним подставляется случайная часть.".to_string(),
            });
        }
    }
    (notes, cautions)
}

/// python explain_strategy: шаги стратегии по порядку строк ``--lua-desync``.
///
/// udp — стратегия для UDP (QUIC, звонки): там подделкам защита не нужна.
pub fn explain_strategy(args: &str, udp: bool) -> Vec<StrategyStep> {
    let mut steps: Vec<StrategyStep> = Vec::new();
    for raw in args.split('\n') {
        let line = raw.trim();
        if !line.to_lowercase().starts_with(PREFIX) {
            continue;
        }
        let rest = &line[PREFIX.len()..];
        let mut parts = rest.split(':');
        let function = parts.next().map(|part| part.trim().to_lowercase()).unwrap_or_default();
        if function.is_empty() {
            continue;
        }
        let parameters: Vec<(String, String)> = parts
            .map(|part| {
                let (key, _sep, value) = partition(part, '=');
                (key.trim().to_lowercase(), value.trim().to_string())
            })
            .collect();
        let base_function: String = match own_info(&function) {
            Some((base, _title, _text)) => (*base).to_string(),
            None => function.clone(),
        };
        let (mut notes, cautions) = notes_of(&base_function, &parameters);
        let (title, text, why): (String, String, &'static str) = if let Some((base, title, text)) = own_info(&function) {
            notes.push(StepNote {
                kind: "origin".to_string(),
                label: "Откуда приём".to_string(),
                value: "Добавлен в PrimeBypass".to_string(),
                detail: "В оригинальном Zapret 2 его нет.".to_string(),
            });
            let why = function_info(base).map(|(_t, _x, why, _c)| *why).unwrap_or("");
            ((*title).to_string(), (*text).to_string(), why)
        } else if let Some((title, text, why, _caution)) = function_info(&function) {
            ((*title).to_string(), (*text).to_string(), *why)
        } else {
            (
                function.clone(),
                "Собственная функция: в оригинальном Zapret 2 её нет, описания для неё нет.".to_string(),
                "",
            )
        };
        let caution: &str = function_info(&base_function).map(|(_t, _x, _w, caution)| *caution).unwrap_or("");
        let mut own_cautions: Vec<String> = Vec::new();
        if !caution.is_empty() {
            own_cautions.push(caution.to_string());
        }
        let udp_fake = udp
            || parameters.iter().any(|(key, value)| {
                (key == "blob" || key == "fake_blob")
                    && UDP_BLOB_HINTS.iter().any(|hint| value.to_lowercase().contains(hint))
            });
        if sends_fakes(&base_function)
            && !udp_fake
            && !parameters.iter().any(|(key, _value)| protection(key).is_some())
        {
            own_cautions.push(UNPROTECTED_FAKE_WARNING.to_string());
        }
        own_cautions.extend(cautions);
        let mut unique_cautions: Vec<String> = Vec::new();
        for caution in own_cautions {
            if !unique_cautions.contains(&caution) {
                unique_cautions.push(caution);
            }
        }
        steps.push(StrategyStep {
            function: function.clone(),
            title,
            text,
            why: why.to_string(),
            notes,
            cautions: unique_cautions,
            line: line.to_string(),
            scene: scene(&function).to_string(),
            family: family(&function).to_string(),
        });
    }
    steps
}
