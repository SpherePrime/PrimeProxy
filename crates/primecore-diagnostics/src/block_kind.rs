//! Порт `src/diagnostics/block_kind.py` — вид блокировки: одним словом о том,
//! КАК сайту мешают открыться.
//!
//! Проверка собирает много подробностей (на какой ступени оборвалось соединение,
//! что ответил тот же адрес с посторонним именем, сколько килобайт дошло). Для
//! человека из них важен один ответ — чем именно мешают:
//!
//! * **по адресу (IP)** — закрыт сам сервер: до него не доходит ничего, каким
//!   именем сайта ни называйся;
//! * **по имени сайта (SNI)** — сервер жив, но соединение рвут, как только в его
//!   начале названо имя заблокированного сайта;
//! * **обрыв после 16 КБ** — соединение устанавливается, начало страницы
//!   приходит, а дальше данные перестают идти.
//!
//! От вида зависит и лечение: блокировку по имени и обрыв стратегия Zapret
//! обходит, а закрытый адрес — нет.

pub const KIND_IP: &str = "ip";
pub const KIND_SNI: &str = "sni";
pub const KIND_CUT: &str = "cut16";
/// Третий исход между «открывается» и «заблокирован»: сайт открылся, но не каждый раз.
pub const KIND_UNSTABLE: &str = "unstable";
pub const KIND_STUB: &str = "stub";
pub const KIND_CERT: &str = "cert";
/// Сайт блокируют, но чем именно — выяснить не удалось.
pub const KIND_UNCLEAR: &str = "unclear";
/// Соединение не установилось, но что закрыт именно адрес, не подтверждено.
pub const KIND_NO_CONNECT: &str = "noconnect";
/// Обычная программа соединяется, а приветствие с составом браузера — нет.
pub const KIND_FINGERPRINT: &str = "fingerprint";
/// Сайт не открылся и с нашего сервера за рубежом: он не работает сам, это не блокировка.
pub const KIND_DOWN: &str = "down";
/// Дальше — не про отдельный сайт, а про сеть и компьютер целиком.
pub const KIND_DNS: &str = "dns";
pub const KIND_QUIC: &str = "quic";
pub const KIND_VOICE: &str = "voice";
pub const KIND_NETWORK: &str = "network";
pub const KIND_SYSTEM: &str = "system";
pub const KIND_OTHER: &str = "other";

/// `KindInfo` из python: подписи и правило лечения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindInfo {
    pub key: &'static str,
    /// Заголовок группы и подпись плитки.
    pub title: &'static str,
    /// Совсем коротко — для ячейки таблицы.
    pub short: &'static str,
    /// Продолжение фразы «Сайт не открывается: …».
    pub reason: &'static str,
    /// Что это такое простыми словами.
    pub about: &'static str,
    /// Чем лечится. Пусто — общего совета нет, он написан у каждой строки.
    pub cure: &'static str,
}

const _IP: KindInfo = KindInfo {
    key: KIND_IP,
    title: "Бан по адресу (IP)",
    short: "по адресу (IP)",
    reason: "сервер заблокирован по адресу (IP)",
    about:
        "Соединение не проходит, каким именем сайта адрес ни называй, — похоже, закрыт сам адрес \
            сервера или вся его сеть.",
    cure: "Стратегия Zapret здесь помогает редко: нужен другой адрес сервера — \
           DNS-профиль в «Редакторе hosts», другой DNS или VPN.",
};

const _SNI: KindInfo = KindInfo {
    key: KIND_SNI,
    title: "Блокировка по имени (SNI)",
    short: "по имени (SNI)",
    reason: "блокировка по имени сайта (SNI)",
    about: "Сервер жив и отвечает, но соединение рвут, как только в его начале названо имя этого сайта \
            (это открытое поле зовётся SNI).",
    cure: "Именно это обходит Zapret: подберите стратегию для сайта.",
};

const _CUT: KindInfo = KindInfo {
    key: KIND_CUT,
    title: "Обрыв после 16 КБ",
    short: "обрыв после 16 КБ",
    reason: "загрузка обрывается после 16 КБ",
    about: "Соединение устанавливается и начало страницы приходит, но примерно после 16 КБ (около \
            25 пакетов) данные перестают идти — сайт грузится наполовину или «висит».",
    cure: "Обычно Zapret это обходит: подберите стратегию для сайта, который грузится не до конца.",
};

const _FINGERPRINT: KindInfo = KindInfo {
    key: KIND_FINGERPRINT,
    title: "Блокировка по «почерку» браузера",
    short: "по почерку браузера",
    reason: "режут соединения, похожие на браузер",
    about: "Первый пакет шифрованного соединения у каждой программы свой — по нему фильтр отличает \
            браузер от остальных. Соединение, какое открывает Chrome, обрывают, а простое приветствие \
            к тому же серверу проходит: в браузере сайт не открывается, хотя дорога к нему есть.",
    cure: "Подберите стратегию Zapret для сайта: она меняет то, как фильтр видит начало соединения.",
};

const _STUB: KindInfo = KindInfo {
    key: KIND_STUB,
    title: "Страница провайдера о блокировке",
    short: "страница-заглушка",
    reason: "провайдер показывает страницу о блокировке",
    about: "Вместо сайта провайдер отдаёт свою страницу с сообщением о блокировке.",
    cure: "Подберите стратегию Zapret для сайта.",
};

const _CERT: KindInfo = KindInfo {
    key: KIND_CERT,
    title: "Отвечает чужой сервер",
    short: "чужой сервер",
    reason: "вместо настоящего сервера отвечает чужой",
    about: "По адресу сайта отвечает не он: сертификат не его. Так бывает из-за подменённого DNS, \
            устаревшей записи в hosts, антивируса или прокси.",
    cure: "",
};

const _NO_CONNECT: KindInfo = KindInfo {
    key: KIND_NO_CONNECT,
    title: "Не удалось соединиться",
    short: "нет соединения",
    reason: "не удалось соединиться с сервером, причина не ясна",
    about: "Соединение с сервером не установилось, но подтверждения, что закрыт сам адрес, нет. \
            Так бывает из-за устаревшей записи в файле hosts, сбоя сети в момент проверки, антивируса \
            или когда сайт на самом деле открывается другим путём.",
    cure: "Повторите проверку. Если повторяется — посмотрите записи этого сайта в «Редакторе hosts» \
           и попробуйте другой DNS.",
};

const _DOWN: KindInfo = KindInfo {
    key: KIND_DOWN,
    title: "Сайт не работает сам",
    short: "не работает сам",
    reason: "сайт не открывается и из-за рубежа — похоже, он не работает сам",
    about: "Наш сервер в Нидерландах тоже не смог открыть этот сайт. Значит, дело не в блокировке \
            провайдера: сайт выключен, сломан или закрыт для всех.",
    cure: "Zapret здесь не поможет: подождите, пока сайт заработает, и повторите проверку.",
};

const _UNSTABLE: KindInfo = KindInfo {
    key: KIND_UNSTABLE,
    title: "Открываются через раз",
    short: "через раз",
    reason: "открывается через раз",
    about: "Сайт открылся, но не с первой попытки или не по всем своим адресам: фильтр срабатывает не каждый раз. \
            В браузере такой сайт то грузится, то нет.",
    cure: "Подберите стратегию Zapret — с ней сайт будет открываться каждый раз.",
};

const _UNCLEAR: KindInfo = KindInfo {
    key: KIND_UNCLEAR,
    title: "Блокировка, способ не определён",
    short: "способ не определён",
    reason: "соединение блокирует провайдер",
    about: "Соединение обрывается, но выяснить, по имени или по адресу, не получилось.",
    cure: "Попробуйте подобрать стратегию Zapret.",
};

const _DNS: KindInfo = KindInfo {
    key: KIND_DNS,
    title: "DNS",
    short: "DNS",
    reason: "DNS отдаёт неверный адрес",
    about: "DNS — справочная, которая по имени сайта выдаёт его адрес. Провайдер может подменять её ответы.",
    cure: "Включите DNS с шифрованием в разделе «Настройка DNS».",
};

const _QUIC: KindInfo = KindInfo {
    key: KIND_QUIC,
    title: "QUIC (UDP 443)",
    short: "QUIC",
    reason: "QUIC блокируется",
    about: "QUIC — быстрый способ соединения, которым браузер открывает YouTube и многие сайты. \
            Когда его режут, сайт обычно открывается привычным способом, но с задержкой.",
    cure: "",
};

const _VOICE: KindInfo = KindInfo {
    key: KIND_VOICE,
    title: "Голосовые звонки",
    short: "звонки",
    reason: "голосовые серверы не отвечают",
    about: "Звонки в Discord и Telegram идут по UDP — отдельно от сайтов.",
    cure: "",
};

const _NETWORK: KindInfo = KindInfo {
    key: KIND_NETWORK,
    title: "Сеть целиком",
    short: "сеть",
    reason: "нет связи",
    about: "Дело не в отдельном сайте, а в самом подключении.",
    cure: "",
};

const _SYSTEM: KindInfo = KindInfo {
    key: KIND_SYSTEM,
    title: "Этот компьютер",
    short: "компьютер",
    reason: "мешает настройка компьютера",
    about: "Работе мешает что-то на самом компьютере, а не провайдер.",
    cure: "",
};

const _OTHER: KindInfo = KindInfo {
    key: KIND_OTHER,
    title: "Остальное",
    short: "остальное",
    reason: "проверка не дала ответа",
    about: "",
    cure: "",
};

/// python `KINDS: dict[str, KindInfo]`.
pub const KINDS: [KindInfo; 16] = [
    _IP,
    _SNI,
    _CUT,
    _FINGERPRINT,
    _STUB,
    _CERT,
    _NO_CONNECT,
    _DOWN,
    _UNSTABLE,
    _UNCLEAR,
    _DNS,
    _QUIC,
    _VOICE,
    _NETWORK,
    _SYSTEM,
    _OTHER,
];

/// В каком порядке показывать группы: сначала то, что касается сайтов.
pub const KIND_ORDER: [&str; 16] = [
    KIND_NETWORK,
    KIND_SYSTEM,
    KIND_IP,
    KIND_SNI,
    KIND_CUT,
    KIND_UNSTABLE,
    KIND_FINGERPRINT,
    KIND_STUB,
    KIND_CERT,
    KIND_UNCLEAR,
    KIND_NO_CONNECT,
    KIND_DOWN,
    KIND_DNS,
    KIND_QUIC,
    KIND_VOICE,
    KIND_OTHER,
];

/// Соединение установилось, но шифрование не проходит ни с каким именем: это
/// прямое сравнение на одном адресе, поэтому вывод «по адресу» здесь законен.
const CAUSE_BY_ADDRESS: &str = "by_address";

pub fn kind_info(kind: &str) -> Option<KindInfo> {
    KINDS.iter().find(|info| info.key == kind).copied()
}

/// python `kind_info(kind) or KINDS[KIND_OTHER]`.
pub fn kind_info_or_other(kind: &str) -> KindInfo {
    kind_info(kind).unwrap_or(_OTHER)
}

/// python `site_kind(reach, cause, address_confirmed=False)` — вид блокировки
/// сайта по исходу проверки. Пусто — сайт открывается или вывода нет.
///
/// `reach` — значение `ReachState`, `cause` — код причины из уточняющих проб.
/// `address_confirmed` — несоединение перепроверено: не ответил ни один адрес
/// сайта, и другим путём (IPv6, QUIC) он тоже не открылся. Без этого одно
/// неудачное соединение «баном по адресу» не называется: причин у него много.
pub fn site_kind(reach: &str, cause: &str, address_confirmed: bool) -> String {
    if matches!(reach, "ok" | "unknown" | "no_address" | "") {
        return String::new();
    }
    // Страница провайдера — прямое свидетельство, оно важнее косвенных признаков.
    if cause == "stub_page" {
        return KIND_STUB.to_string();
    }
    if reach == "freeze" {
        return KIND_CUT.to_string();
    }
    if reach == "cert" {
        return KIND_CERT.to_string();
    }
    if cause == "by_name" || cause == "name_whitelist" {
        return KIND_SNI.to_string();
    }
    if cause == CAUSE_BY_ADDRESS {
        return KIND_IP.to_string();
    }
    if reach == "ip_block" {
        return if address_confirmed {
            KIND_IP.to_string()
        } else {
            KIND_NO_CONNECT.to_string()
        };
    }
    if reach == "dpi" {
        return KIND_UNCLEAR.to_string();
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_shape() {
        assert_eq!(KINDS.len(), 16);
        assert_eq!(KIND_ORDER.len(), 16);
        assert_eq!(kind_info_or_other(KIND_IP).title, "Бан по адресу (IP)");
        assert_eq!(kind_info_or_other("мимо").key, KIND_OTHER);
        assert!(kind_info(KIND_SNI).is_some());
    }

    #[test]
    fn site_kind_rules() {
        assert_eq!(site_kind("ok", "", false), "");
        assert_eq!(site_kind("unknown", "", false), "");
        assert_eq!(site_kind("no_address", "", false), "");
        assert_eq!(site_kind("dpi", "stub_page", false), KIND_STUB);
        assert_eq!(site_kind("freeze", "", false), KIND_CUT);
        assert_eq!(site_kind("dpi", "stub", false), KIND_UNCLEAR);
        assert_eq!(site_kind("ip_block", "by_name", false), KIND_SNI);
        assert_eq!(site_kind("ip_block", "name_whitelist", false), KIND_SNI);
        assert_eq!(site_kind("ip_block", "by_address", false), KIND_IP);
        assert_eq!(site_kind("ip_block", "", false), KIND_NO_CONNECT);
        assert_eq!(site_kind("ip_block", "", true), KIND_IP);
        assert_eq!(site_kind("cert", "", false), KIND_CERT);
        assert_eq!(site_kind("dpi", "", false), KIND_UNCLEAR);
        assert_eq!(site_kind("dpi", "other", false), KIND_UNCLEAR);
        assert_eq!(site_kind("мимо", "", false), "");
    }
}
