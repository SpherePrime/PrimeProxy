//! Порт `src/diagnostics/services.py` — что проверяет BlockCheck: сервисы, их
//! адреса и режимы проверки.
//!
//! Сервис — то, что человек называет одним словом («Discord»). У него один или
//! несколько адресов: сайт, чат, картинки. Главный адрес (`main`) решает,
//! открывается ли сервис вообще.
//!
//! Режимы:
//!
//! - `SCOPE_MAIN` — Discord и YouTube, ради которых Zapret ставят чаще всего;
//! - `SCOPE_ALL` — ещё популярные сайты и контрольные;
//! - `SCOPE_FULL` — ещё длинный список сайтов, которые блокируют чаще всего
//!   (собран по спискам проектов dpi-detector и rkn-block-checker, лицензия MIT),
//!   и свои домены пользователя.
//!
//! Контрольные сайты нужны для сравнения: если не открываются и они, дело в
//! подключении, а не в блокировках.

use std::sync::LazyLock;

pub const YOUTUBE_HOST: &str = "www.youtube.com";
pub const GOOGLEVIDEO_FALLBACK_HOST: &str = "redirector.googlevideo.com";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub purpose: &'static str,
    pub path: &'static str,
    pub read_body: bool,
    /// Главный адрес сервиса: если он не открывается, не открывается сервис.
    pub main: bool,
    /// Хост видеосервера каждый раз узнаётся у YouTube: он свой у каждого
    /// провайдера и меняется со временем.
    pub discover_googlevideo: bool,
}

impl Target {
    fn plain(host: &str, purpose: &'static str) -> Self {
        Self {
            host: host.to_string(),
            purpose,
            path: "/",
            read_body: false,
            main: false,
            discover_googlevideo: false,
        }
    }

    fn main_site(host: &str, purpose: &'static str) -> Self {
        Self { read_body: true, main: true, ..Self::plain(host, purpose) }
    }

    /// python dataclass `replace(target, main=…, read_body=…, purpose=…)`.
    fn replaced(&self, main: bool, read_body: bool, purpose: &'static str) -> Self {
        Self { main, read_body, purpose, ..self.clone() }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub key: String,
    pub label: String,
    pub targets: Vec<Target>,
    /// Контрольный сайт: его почти никогда не блокируют. Если не открываются
    /// даже контрольные — дело в подключении, а не в блокировках.
    pub control: bool,
    /// Российский контрольный сайт. Если открываются только такие, а зарубежные
    /// контрольные нет — провайдер пропускает лишь разрешённые адреса.
    pub domestic: bool,
}

fn service(key: &str, label: &str, targets: impl Into<Vec<Target>>) -> Service {
    Service { key: key.to_string(), label: label.to_string(), targets: targets.into(), control: false, domestic: false }
}

fn site(key: &str, label: &str, host: &str, control: bool, domestic: bool) -> Service {
    Service { control, domestic, ..service(key, label, vec![Target::main_site(host, "сайт")]) }
}

/// Один сайт по его адресу — так же, как «свой домен» в BlockCheck.
///
/// Если адрес принадлежит известному сервису из нескольких адресов (YouTube,
/// Discord…), вместе с ним проверяются и остальные адреса сервиса: «youtube.com
/// открывается» мало что значит, когда не отвечают видеосерверы.
pub fn site_service(host: &str) -> Service {
    let host = normalize_host(host);
    let mut targets = vec![Target::main_site(&host, "сайт")];
    targets.extend(related_targets(&host));
    Service { control: false, domestic: false, ..service(&format!("user:{host}"), &host, targets) }
}

fn normalize_host(host: &str) -> String {
    host.trim().to_lowercase().trim_end_matches('.').to_string()
}

/// Остальные адреса сервиса, которому принадлежит `host`. Пусто — адрес сам по себе.
///
/// Адрес принадлежит сервису, если он один из его адресов либо лежит в домене
/// его главного адреса (`m.youtube.com` — в домене `www.youtube.com`).
/// Главным в такой проверке остаётся введённый адрес, остальные — побочные.
pub fn related_targets(host: &str) -> Vec<Target> {
    let host = normalize_host(host);
    for (_, service) in SERVICES.iter().chain(EXTRA_SERVICES.iter()).chain(FULL_SERVICES.iter()) {
        if service.targets.len() < 2 {
            continue;
        }
        let base = service
            .targets
            .iter()
            .find(|target| target.main)
            .map(|target| target.host.clone())
            .unwrap_or_else(|| service.targets[0].host.clone());
        let base = base.strip_prefix("www.").map(str::to_string).unwrap_or(base);
        let not_in_service = host != base
            && !host.ends_with(&format!(".{base}"))
            && service.targets.iter().all(|target| target.host != host);
        if not_in_service {
            continue;
        }
        return service
            .targets
            .iter()
            .filter(|target| target.host != host)
            .map(|target| if target.main { target.replaced(false, false, "основной адрес") } else { target.clone() })
            .collect();
    }
    Vec::new()
}

pub const SCOPE_MAIN: &str = "main";
pub const SCOPE_ALL: &str = "all";
/// Всё, что в «Все сайты», плюс DNS-серверы и поиск места фильтра.
pub const SCOPE_FULL: &str = "full";
pub const SCOPE_TITLES: [(&str, &str); 3] =
    [(SCOPE_MAIN, "Discord и YouTube"), (SCOPE_ALL, "Все сайты"), (SCOPE_FULL, "Глубокая диагностика")];

/// Шаги хода проверки: что и в каком порядке показывает экран, пока она идёт.
pub const STEP_SITES: &str = "sites";
pub const STEP_HOSTINGS: &str = "hostings";
pub const STEP_VOICE: &str = "voice";
pub const STEP_IPV6: &str = "ipv6";
pub const STEP_SYSTEM: &str = "system";
pub const STEP_DNS_SERVERS: &str = "dns_servers";
pub const STEP_FILTER: &str = "filter";
pub const PROGRESS_STEPS: [&str; 7] =
    [STEP_SITES, STEP_HOSTINGS, STEP_VOICE, STEP_IPV6, STEP_SYSTEM, STEP_DNS_SERVERS, STEP_FILTER];
/// Шаги, которые идут только в полной проверке.
const FULL_ONLY_STEPS: [&str; 2] = [STEP_DNS_SERVERS, STEP_FILTER];

/// Шаги хода проверки для режима: движок отмечает их, экран показывает строками.
pub fn progress_steps(scope: &str) -> Vec<&'static str> {
    if scope == SCOPE_FULL {
        return PROGRESS_STEPS.to_vec();
    }
    PROGRESS_STEPS.to_vec().into_iter().filter(|step| !FULL_ONLY_STEPS.contains(step)).collect()
}

/// «Discord и YouTube» — то, ради чего Zapret ставят чаще всего.
/// python: `SERVICES: dict[str, Service]` — порядок вставки.
pub static SERVICES: LazyLock<Vec<(&'static str, Service)>> = LazyLock::new(|| {
    vec![
        (
            "discord",
            service(
                "discord",
                "Discord",
                vec![
                    Target::main_site("discord.com", "сайт и вход"),
                    Target::plain("gateway.discord.gg", "чат и статусы"),
                    Target::plain("cdn.discordapp.com", "картинки и файлы"),
                ],
            ),
        ),
        (
            "youtube",
            service(
                "youtube",
                "YouTube",
                vec![
                    Target::main_site(YOUTUBE_HOST, "сайт"),
                    Target { path: "/generate_204", ..Target::plain("i.ytimg.com", "превью видео") },
                    // Через него плеер спрашивает, что и откуда играть: закрыт он — страница есть, а видео крутит загрузку.
                    Target::plain("youtubei.googleapis.com", "служба плеера"),
                    Target {
                        path: "/generate_204",
                        discover_googlevideo: true,
                        ..Target::plain(GOOGLEVIDEO_FALLBACK_HOST, "видео")
                    },
                ],
            ),
        ),
    ]
});

/// Добавляются в режиме «Все сайты».
pub static EXTRA_SERVICES: LazyLock<Vec<(&'static str, Service)>> = LazyLock::new(|| {
    vec![
        (
            "telegram",
            service(
                "telegram",
                "Telegram",
                vec![Target::main_site("telegram.org", "сайт"), Target::plain("web.telegram.org", "веб-версия")],
            ),
        ),
        ("instagram", site("instagram", "Instagram", "www.instagram.com", false, false)),
        ("facebook", site("facebook", "Facebook", "www.facebook.com", false, false)),
        ("x", site("x", "X (Twitter)", "x.com", false, false)),
        ("linkedin", site("linkedin", "LinkedIn", "www.linkedin.com", false, false)),
        ("spotify", site("spotify", "Spotify", "www.spotify.com", false, false)),
        ("rutracker", site("rutracker", "RuTracker", "rutracker.org", false, false)),
        ("google", site("google", "Google", "www.google.com", true, false)),
        ("cloudflare", site("cloudflare", "Cloudflare", "www.cloudflare.com", true, false)),
        ("yandex", site("yandex", "Яндекс", "ya.ru", true, true)),
        ("vk", site("vk", "ВКонтакте", "vk.com", true, true)),
    ]
});

/// Добавляются только в полной проверке: сайты, которые блокируют чаще всего.
/// Отобраны по спискам dpi-detector (Runnin4ik) и rkn-block-checker (MayersScott),
/// оба под лицензией MIT. Здесь нет сайтов, недоступных из России по решению
/// самого сайта: они выглядели бы как блокировка провайдера.
pub static FULL_SERVICES: LazyLock<Vec<(&'static str, Service)>> = LazyLock::new(|| {
    vec![
        (
            "whatsapp",
            service(
                "whatsapp",
                "WhatsApp",
                vec![Target::main_site("web.whatsapp.com", "веб-версия"), Target::plain("www.whatsapp.com", "сайт")],
            ),
        ),
        ("signal", site("signal", "Signal", "signal.org", false, false)),
        ("messenger", site("messenger", "Messenger", "www.messenger.com", false, false)),
        ("twitch", site("twitch", "Twitch", "www.twitch.tv", false, false)),
        ("soundcloud", site("soundcloud", "SoundCloud", "soundcloud.com", false, false)),
        ("dailymotion", site("dailymotion", "Dailymotion", "www.dailymotion.com", false, false)),
        ("patreon", site("patreon", "Patreon", "www.patreon.com", false, false)),
        (
            "github",
            service(
                "github",
                "GitHub",
                vec![Target::main_site("github.com", "сайт"), Target::plain("raw.githubusercontent.com", "файлы")],
            ),
        ),
        ("docker", site("docker", "Docker Hub", "hub.docker.com", false, false)),
        ("chatgpt", site("chatgpt", "ChatGPT", "chatgpt.com", false, false)),
        ("deepl", site("deepl", "DeepL", "www.deepl.com", false, false)),
        ("canva", site("canva", "Canva", "www.canva.com", false, false)),
        ("coursera", site("coursera", "Coursera", "www.coursera.org", false, false)),
        ("proton", site("proton", "Proton", "proton.me", false, false)),
        ("torproject", site("torproject", "Tor Project", "www.torproject.org", false, false)),
        ("amnezia", site("amnezia", "Amnezia", "amnezia.org", false, false)),
        ("meduza", site("meduza", "Meduza", "meduza.io", false, false)),
        ("dw", site("dw", "Deutsche Welle", "www.dw.com", false, false)),
        ("bbc", site("bbc", "BBC", "www.bbc.com", false, false)),
        ("svoboda", site("svoboda", "Радио Свобода", "www.svoboda.org", false, false)),
        ("moscowtimes", site("moscowtimes", "The Moscow Times", "www.themoscowtimes.com", false, false)),
        ("nnmclub", site("nnmclub", "NNM-Club", "nnmclub.to", false, false)),
        ("rezka", site("rezka", "HDRezka", "rezka.ag", false, false)),
        ("speedtest", site("speedtest", "Speedtest", "www.speedtest.net", false, false)),
        ("gosuslugi", site("gosuslugi", "Госуслуги", "www.gosuslugi.ru", true, true)),
    ]
});

/// python `build_services(scope, user_domains=())` — сервисы для проверки:
/// основные, при «Все сайты» — остальные и свои домены, при полной проверке —
/// ещё длинный список часто блокируемых сайтов.
pub fn build_services(scope: &str, user_domains: &[&str]) -> Vec<(String, Service)> {
    let mut services: Vec<(String, Service)> = SERVICES
        .iter()
        .map(|(key, service)| ((*key).to_string(), service.clone()))
        .collect();
    let scope = scope.trim().to_lowercase();
    if scope != SCOPE_ALL && scope != SCOPE_FULL {
        // Свои домены — часть режима «Все сайты»: так написано на экране.
        return services;
    }
    let mut additions = EXTRA_SERVICES.clone();
    if scope == SCOPE_FULL {
        additions.extend(FULL_SERVICES.clone());
    }
    for (key, item) in additions {
        services.push((key.to_string(), item));
    }
    let mut seen = services
        .iter()
        .flat_map(|(_, item)| item.targets.iter().map(|target| target.host.clone()).collect::<Vec<_>>())
        .collect::<Vec<_>>();
    for domain in user_domains {
        let host = normalize_host(domain);
        if !host.is_empty() && !seen.contains(&host) {
            seen.push(host.clone());
            let key = format!("user:{host}");
            services.push((key.clone(), site(&key, &host, &host, false, false)));
        }
    }
    services
}
