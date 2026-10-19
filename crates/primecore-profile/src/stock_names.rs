//! Порт profile/stock_names.py: прежние стоковые имена профилей.

/// Прежнее стоковое имя → нынешнее.
pub const RENAMED_STOCK_PROFILE_NAMES: [(&str, &str); 22] = [
    ("googlevideo.com (CDN сервера)", "YouTube · видео (googlevideo.com)"),
    ("youtube.com (интерфейс)", "YouTube · сайт и приложение"),
    ("i.ytimg.com (превью роликов)", "YouTube · превью роликов"),
    ("youtube.com (QUIC)", "YouTube · быстрый протокол QUIC"),
    ("youtube.com (RTMPS Россия)", "YouTube · трансляции (RTMPS)"),
    ("discord.com", "Discord · сайт и приложение"),
    ("updates.discord.com", "Discord · обновления"),
    ("discord.media (voice RTC)", "Discord · голос и видео (discord.media)"),
    ("discord (images)", "Discord · картинки"),
    ("Discord UDP (обычно не нужно)", "Discord · UDP (обычно не нужно)"),
    ("GitHub", "GitHub · сайт"),
    ("githubusercontent.com", "GitHub · файлы и картинки"),
    ("WhatsApp", "WhatsApp · сообщения"),
    ("static.whatsapp.net", "WhatsApp · картинки и файлы"),
    ("WhatsApp UDP wide", "WhatsApp · звонки (UDP)"),
    ("Roblox TCP", "Roblox · игра"),
    ("Roblox UDP", "Roblox · игра (UDP)"),
    ("js.rbxcdn.com", "Roblox · скрипты сайта (js.rbxcdn.com)"),
    ("css.rbxcdn.com", "Roblox · оформление сайта (css.rbxcdn.com)"),
    ("tr.rbxcdn.com", "Roblox · картинки (tr.rbxcdn.com)"),
    ("Twitter Images (twimg.com)", "Twitter/X · картинки (twimg.com)"),
    ("git.zapret.moe", "zapret.moe"),
];

/// Нынешнее имя профиля, если name — его прежнее стоковое имя; иначе name как есть.
pub fn current_stock_profile_name(name: &str) -> String {
    let text = name.trim();
    let fold = text.to_lowercase();
    for (old, new) in RENAMED_STOCK_PROFILE_NAMES {
        if old.to_lowercase() == fold {
            return new.to_string();
        }
    }
    text.to_string()
}
