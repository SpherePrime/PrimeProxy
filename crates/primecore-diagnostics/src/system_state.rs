//! Порт `src/diagnostics/system_state.py` — что на самом компьютере мешает
//! Zapret или искажает проверки.
//!
//! Сетевые проверки отвечают на вопрос «что блокирует провайдер». Но сайт
//! может не открываться и по причинам на самом компьютере: остановлена служба,
//! без которой драйвер не запускается; антивирус унёс файлы программы;
//! включён прокси; сбиты часы. Здесь всё это собирается в одном месте.
//!
//! Правило модуля — **только чтение**. Ничего не запускается, не останавливается
//! и не правится: проверка, которая молча меняет систему, скрывает от человека
//! то, что он должен был узнать.
//!
//! Сбор (python `collect_facts`, реестр Windows, службы, процесс) портируется
//! следом вместе с движком; здесь — типы фактов, служебные (`tunnel_adapters`,
//! `routed_tunnels`) и весь выборовый (`judge`).

use crate::verdict::Level as DiagnosticLevel;

pub const LEVEL_OK: &str = "ok";
pub const LEVEL_INFO: &str = "info";
pub const LEVEL_WARN: &str = "warn";
pub const LEVEL_FAIL: &str = "fail";
pub const LEVEL_UNKNOWN: &str = "unknown";

// Windows 10 версии 1809: раньше драйвер перехвата не работает.
pub const MIN_WINDOWS_BUILD: i64 = 17763;
pub const LOW_DISK_MB: i64 = 200;
// Сертификаты сайтов перестают проходить проверку при заметном расхождении
// часов. Здесь порог: расхождение в часы, а не в минуты.
pub const CLOCK_SKEW_LIMIT_S: f64 = 3600.0;

fn level_order(level: &str) -> u8 {
    match level {
        LEVEL_FAIL => 0,
        LEVEL_WARN => 1,
        LEVEL_UNKNOWN => 2,
        LEVEL_INFO => 3,
        _ => 4,
    }
}

/// python `worst_level(items)`.
pub fn worst_level(items: &[SystemItem]) -> String {
    if items.is_empty() {
        return LEVEL_OK.to_string();
    }
    let worst = items
        .iter()
        .min_by(|a, b| level_order(&a.level).cmp(&level_order(&b.level)))
        .map(|item| item.level.clone())
        .unwrap_or_else(|| LEVEL_OK.to_string());
    worst
}

/// Признаки VPN-подключения в описании сетевого адаптера.
const TUNNEL_WORDS: [&str; 10] = [
    "wireguard",
    "wintun",
    "tap-windows",
    "openvpn",
    "tailscale",
    "zerotier",
    "amnezia",
    "cloudflare warp",
    "sing-box",
    "vpn",
];

/// python `SystemFacts` — сырые факты. None везде значит «узнать не удалось».
#[derive(Debug, Clone, Default)]
pub struct SystemFacts {
    pub is_admin: Option<bool>,
    pub windows_build: Option<i64>,
    pub in_temp_folder: Option<bool>,
    pub in_onedrive: Option<bool>,
    pub free_mb: Option<i64>,
    /// (проверка состоялась, каких файлов нет, какие повреждены).
    pub integrity: Option<(bool, Vec<String>, Vec<String>)>,
    pub bfe_running: Option<bool>,
    /// Программы, которые мешают драйверу перехвата.
    pub conflicts: Option<Vec<String>>,
    /// Службы GoodbyeDPI, оставшиеся в системе.
    pub goodbyedpi_services: Option<Vec<String>>,
    /// Другие программы обхода и VPN, запущенные сейчас.
    pub bypass_tools: Option<Vec<String>>,
    /// Название антивируса; Пустая строка — не найден.
    pub antivirus: Option<String>,
    /// Адрес ручного прокси и адрес сценария автонастройки; пустая строка — выключено.
    pub proxy_server: Option<String>,
    pub proxy_script: Option<String>,
    /// Названия активных VPN-подключений.
    pub tunnels: Option<Vec<String>>,
    /// Те из них, через которые Windows сейчас шлёт трафик; None — не узнали.
    pub tunnels_routed: Option<Vec<String>>,
    pub hosts_readable: Option<bool>,
    /// Проверяемые сайты, адрес которых задан в файле hosts: (сайт, адрес).
    pub hosts_overrides: Option<Vec<(String, String)>>,
    /// Записи самой программы («Редактор hosts»): (сайт, адрес). None — не узнали.
    pub hosts_managed: Option<Vec<(String, String)>>,
    /// На сколько секунд часы впереди настоящего времени (минус — отстают).
    pub clock_skew_s: Option<f64>,
}

/// python `SystemItem`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemItem {
    pub key: String,
    pub title: String,
    pub level: String,
    pub text: String,
    pub advice: String,
}

/// python `Interface` (набор атрибутов, которые использует `tunnel_adapters`).
#[derive(Debug, Clone, Default)]
pub struct Interface {
    pub index: u32,
    pub ipv6_index: u32,
    pub name: String,
    pub description: String,
    pub connected: bool,
}

/// python `tunnel_adapters(interfaces)` — названия подключённых адаптеров, похожих на VPN.
pub fn tunnel_adapters(interfaces: &[Interface]) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for interface in interfaces {
        if !interface.connected {
            continue;
        }
        let text = format!("{} {}", interface.description, interface.name).to_lowercase();
        // Тип «PPP» бывает и у обычного подключения к провайдеру (PPPoE), поэтому сам
        // по себе VPN не означает: нужно название, похожее на VPN.
        if TUNNEL_WORDS.iter().any(|word| text.contains(word)) {
            let label =
                if interface.name.is_empty() { interface.description.clone() } else { interface.name.clone() };
            if !label.is_empty() && !found.contains(&label) {
                found.push(label);
            }
        }
    }
    found
}

/// python `routed_tunnels(interfaces, ipv4_index, ipv6_index)` — VPN-адаптеры, через
/// которые идёт интернет: подключённый адаптер ещё не значит, что трафик в нём.
pub fn routed_tunnels(interfaces: &[Interface], ipv4_index: u32, ipv6_index: u32) -> Vec<String> {
    let used: std::collections::HashSet<u32> = [ipv4_index, ipv6_index]
        .into_iter()
        .filter(|index| *index != 0)
        .collect();
    let carrying: Vec<Interface> = interfaces
        .iter()
        .filter(|interface| used.contains(&interface.index) || used.contains(&interface.ipv6_index))
        .cloned()
        .collect();
    tunnel_adapters(&carrying)
}

fn unknown(key: &str, title: &str) -> SystemItem {
    SystemItem {
        key: key.to_string(),
        title: title.to_string(),
        level: LEVEL_UNKNOWN.to_string(),
        text: "проверить не удалось".to_string(),
        advice: String::new(),
    }
}

fn short(names: &[String]) -> String {
    const LIMIT: usize = 4;
    if names.len() > LIMIT {
        format!("{} и ещё {}", names[..LIMIT].join(", "), names.len() - LIMIT)
    } else {
        names.join(", ")
    }
}

fn minutes(seconds: f64) -> String {
    let m = (seconds.abs() / 60.0).round() as i64;
    if m < 90 {
        format!("{m} мин")
    } else {
        let h = m as f64 / 60.0;
        if h < 48.0 {
            format!("{} ч", h.round() as i64)
        } else {
            format!("{} дн", (h / 24.0).round() as i64)
        }
    }
}

/// python `judge(facts, zapret_running)` — строки отчёта о системе, в постоянном
/// порядке. `zapret_running` — работает ли сейчас Zapret: если да, «мешающие
/// программы» ему на деле не помешали, и это справка, а не предупреждение.
pub fn judge(facts: &SystemFacts, zapret_running: Option<bool>) -> Vec<SystemItem> {
    let mut items: Vec<SystemItem> = Vec::new();

    let title = "Права администратора";
    match facts.is_admin {
        None => items.push(unknown("admin", title)),
        Some(true) => items.push(SystemItem {
            key: "admin".to_string(),
            title: title.to_string(),
            level: LEVEL_OK.to_string(),
            text: "есть".to_string(),
            advice: String::new(),
        }),
        Some(false) => items.push(SystemItem {
            key: "admin".to_string(),
            title: title.to_string(),
            level: LEVEL_FAIL.to_string(),
            text: "программа запущена без них — драйвер перехвата не запустится".to_string(),
            advice: "Закройте программу и запустите её снова, согласившись на запрос Windows.".to_string(),
        }),
    }

    let title = "Версия Windows";
    match facts.windows_build {
        None => items.push(unknown("windows", title)),
        Some(build) if build >= MIN_WINDOWS_BUILD => items.push(SystemItem {
            key: "windows".to_string(),
            title: title.to_string(),
            level: LEVEL_OK.to_string(),
            text: format!("сборка {build} подходит"),
            advice: String::new(),
        }),
        Some(build) => items.push(SystemItem {
            key: "windows".to_string(),
            title: title.to_string(),
            level: LEVEL_FAIL.to_string(),
            text: format!(
                "сборка {build} слишком старая: нужна Windows 10 версии 1809 (сборка {MIN_WINDOWS_BUILD}) или новее"
            ),
            advice: "Обновите Windows.".to_string(),
        }),
    }

    let title = "Папка программы";
    if facts.in_temp_folder.is_none() && facts.in_onedrive.is_none() {
        items.push(unknown("location", title));
    } else if facts.in_temp_folder == Some(true) {
        items.push(SystemItem {
            key: "location".to_string(),
            title: title.to_string(),
            level: LEVEL_WARN.to_string(),
            text: "программа запущена из временной папки — Windows может удалить её файлы".to_string(),
            advice: "Установите программу обычным установщиком.".to_string(),
        });
    } else if facts.in_onedrive == Some(true) {
        items.push(SystemItem {
            key: "location".to_string(),
            title: title.to_string(),
            level: LEVEL_WARN.to_string(),
            text: "программа лежит в папке OneDrive — синхронизация мешает её файлам".to_string(),
            advice: "Переустановите программу в папку вне OneDrive.".to_string(),
        });
    } else {
        items.push(SystemItem {
            key: "location".to_string(),
            title: title.to_string(),
            level: LEVEL_OK.to_string(),
            text: "расположение подходит".to_string(),
            advice: String::new(),
        });
    }

    let title = "Место на диске";
    match facts.free_mb {
        None => items.push(unknown("disk", title)),
        Some(free) if free < LOW_DISK_MB => items.push(SystemItem {
            key: "disk".to_string(),
            title: title.to_string(),
            level: LEVEL_WARN.to_string(),
            text: format!("свободно всего {free} МБ — может не хватить на журналы и обновление"),
            advice: "Освободите место на диске с программой.".to_string(),
        }),
        Some(free) => {
            let text = if free >= 1024 { format!("свободно {} ГБ", free / 1024) } else { format!("свободно {free} МБ") };
            items.push(SystemItem {
                key: "disk".to_string(),
                title: title.to_string(),
                level: LEVEL_OK.to_string(),
                text,
                advice: String::new(),
            });
        }
    }

    let title = "Файлы программы";
    match facts.integrity.clone() {
        None => items.push(unknown("files", title)),
        Some((checked, missing, corrupted)) => {
            if !checked {
                items.push(SystemItem {
                    key: "files".to_string(),
                    title: title.to_string(),
                    level: LEVEL_INFO.to_string(),
                    text: "сверить не с чем: в установке нет списка файлов".to_string(),
                    advice: String::new(),
                });
            } else if !missing.is_empty() || !corrupted.is_empty() {
                let mut parts: Vec<String> = Vec::new();
                if !missing.is_empty() {
                    parts.push(format!("не хватает: {}", short(&missing)));
                }
                if !corrupted.is_empty() {
                    parts.push(format!("повреждены: {}", short(&corrupted)));
                }
                items.push(SystemItem {
                    key: "files".to_string(),
                    title: title.to_string(),
                    level: LEVEL_FAIL.to_string(),
                    text: format!("{}. Чаще всего файлы забирает в карантин антивирус", parts.join("; ")),
                    advice: "Добавьте папку программы в исключения антивируса и восстановите программу через страницу обновлений.".to_string(),
                });
            } else {
                items.push(SystemItem {
                    key: "files".to_string(),
                    title: title.to_string(),
                    level: LEVEL_OK.to_string(),
                    text: "все на месте".to_string(),
                    advice: String::new(),
                });
            }
        }
    }

    let title = "Служба фильтрации Windows (BFE)";
    match facts.bfe_running {
        None => items.push(unknown("bfe", title)),
        Some(true) => items.push(SystemItem {
            key: "bfe".to_string(),
            title: title.to_string(),
            level: LEVEL_OK.to_string(),
            text: "работает".to_string(),
            advice: String::new(),
        }),
        Some(false) => items.push(SystemItem {
            key: "bfe".to_string(),
            title: title.to_string(),
            level: LEVEL_FAIL.to_string(),
            text: "не работает — без неё драйвер перехвата не запускается".to_string(),
            advice: "Откройте «Службы» Windows, найдите «Служба базовой фильтрации» и запустите её.".to_string(),
        }),
    }

    let title = "Мешающие программы";
    if facts.conflicts.is_none() && facts.goodbyedpi_services.is_none() {
        items.push(unknown("conflicts", title));
    } else {
        let mut found: Vec<String> = facts.conflicts.clone().unwrap_or_default();
        if let Some(services) = facts.goodbyedpi_services.as_ref().filter(|services| !services.is_empty()) {
            found.push(format!("служба GoodbyeDPI ({})", short(services)));
        }
        if !found.is_empty() && zapret_running == Some(true) {
            items.push(SystemItem {
                key: "conflicts".to_string(),
                title: title.to_string(),
                level: LEVEL_INFO.to_string(),
                text: format!(
                    "найдены: {}. Они могут мешать драйверу перехвата, но Zapret сейчас запущен и работает",
                    short(&found)
                ),
                advice: String::new(),
            });
        } else if !found.is_empty() {
            items.push(SystemItem {
                key: "conflicts".to_string(),
                title: title.to_string(),
                level: LEVEL_WARN.to_string(),
                text: format!(
                    "найдены: {}. Они могут занимать тот же драйвер перехвата или мешать его работе",
                    short(&found)
                ),
                advice: "Если Zapret не запускается — закройте эти программы и попробуйте снова.".to_string(),
            });
        } else {
            items.push(SystemItem {
                key: "conflicts".to_string(),
                title: title.to_string(),
                level: LEVEL_OK.to_string(),
                text: "не найдены".to_string(),
                advice: String::new(),
            });
        }
    }

    let title = "Другие программы обхода и VPN";
    if facts.bypass_tools.is_none() && facts.tunnels.is_none() {
        items.push(unknown("bypass", title));
    } else {
        // Подключённый VPN-адаптер и запущенная программа — ещё не «трафик идёт
        // через них»: уверенно сказать это можно, только когда через адаптер
        // проложена дорога в интернет.
        let tunnels = facts.tunnels.clone().unwrap_or_default();
        let routed = facts.tunnels_routed.clone().unwrap_or_default();
        let idle: Vec<String> = match facts.tunnels_routed {
            Some(_) => tunnels.iter().filter(|name| !routed.contains(name)).cloned().collect(),
            None => tunnels.clone(),
        };
        let bypass = facts.bypass_tools.clone().unwrap_or_default();
        let mut parts: Vec<String> = Vec::new();
        if !routed.is_empty() {
            parts.push(format!(
                "интернет сейчас идёт через VPN-подключение: {} — проверки показывают сеть VPN, а не провайдера",
                short(&routed)
            ));
        }
        if facts.tunnels_routed.is_none() && !tunnels.is_empty() {
            parts.push(format!(
                "подключены VPN-адаптеры: {} — идёт ли через них интернет, узнать не удалось",
                short(&tunnels),
            ));
        }
        if !bypass.is_empty() {
            parts.push(format!(
                "запущены: {} — если они сейчас включены, проверки показывают сеть вместе с ними",
                short(&bypass),
            ));
        }
        if !parts.is_empty() {
            items.push(SystemItem {
                key: "bypass".to_string(),
                title: title.to_string(),
                level: LEVEL_INFO.to_string(),
                text: parts.join("; "),
                advice: String::new(),
            });
        } else if !idle.is_empty() {
            items.push(SystemItem {
                key: "bypass".to_string(),
                title: title.to_string(),
                level: LEVEL_OK.to_string(),
                text: format!(
                    "VPN-адаптеры подключены ({}), но интернет идёт не через них — на проверки они не влияют",
                    short(&idle)
                ),
                advice: String::new(),
            });
        } else {
            items.push(SystemItem {
                key: "bypass".to_string(),
                title: title.to_string(),
                level: LEVEL_OK.to_string(),
                text: "не найдены".to_string(),
                advice: String::new(),
            });
        }
    }

    let title = "Антивирус";
    match facts.antivirus.clone() {
        None => items.push(unknown("antivirus", title)),
        Some(name) if !name.is_empty() => items.push(SystemItem {
            key: "antivirus".to_string(),
            title: title.to_string(),
            level: LEVEL_INFO.to_string(),
            text: format!(
                "работает {name}. Если Zapret не запускается или у программы пропадают файлы — причина может быть в нём"
            ),
            advice: "Добавьте папку программы в исключения антивируса.".to_string(),
        }),
        Some(_) => items.push(SystemItem {
            key: "antivirus".to_string(),
            title: title.to_string(),
            level: LEVEL_OK.to_string(),
            text: "сторонний не найден".to_string(),
            advice: String::new(),
        }),
    }

    let title = "Системный прокси";
    if facts.proxy_server.is_none() && facts.proxy_script.is_none() {
        items.push(unknown("proxy", title));
    } else if !facts.proxy_server.clone().unwrap_or_default().is_empty() {
        items.push(SystemItem {
            key: "proxy".to_string(),
            title: title.to_string(),
            level: LEVEL_WARN.to_string(),
            text: format!(
                "включён ({}) — браузеры идут через него, а не напрямую",
                facts.proxy_server.clone().unwrap_or_default()
            ),
            advice: "Если прокси вы не включали, отключите его: Параметры Windows → Сеть и Интернет → Прокси-сервер.".to_string(),
        });
    } else if !facts.proxy_script.clone().unwrap_or_default().is_empty() {
        items.push(SystemItem {
            key: "proxy".to_string(),
            title: title.to_string(),
            level: LEVEL_WARN.to_string(),
            text: format!(
                "задан сценарий автонастройки ({}) — он решает, какие сайты пускать через прокси",
                facts.proxy_script.clone().unwrap_or_default()
            ),
            advice: "Если сценарий вы не задавали, уберите его: Параметры Windows → Сеть и Интернет → Прокси-сервер.".to_string(),
        });
    } else {
        items.push(SystemItem {
            key: "proxy".to_string(),
            title: title.to_string(),
            level: LEVEL_OK.to_string(),
            text: "выключен".to_string(),
            advice: String::new(),
        });
    }

    let title = "Файл hosts";
    if facts.hosts_readable.is_none() && facts.hosts_overrides.is_none() {
        items.push(unknown("hosts", title));
    } else if facts.hosts_readable == Some(false) {
        items.push(SystemItem {
            key: "hosts".to_string(),
            title: title.to_string(),
            level: LEVEL_WARN.to_string(),
            text: "не читается — программа не сможет ни проверить, ни изменить его".to_string(),
            advice: "Откройте страницу «Редактор hosts» и нажмите «Восстановить права».".to_string(),
        });
    } else {
        let overrides = facts.hosts_overrides.clone().unwrap_or_default();
        if !overrides.is_empty() {
            // Записи самой программы («Редактор hosts») — так и задумано; чужие — справка.
            let managed = facts.hosts_managed.clone().unwrap_or_default();
            let ours: std::collections::HashSet<(String, String)> =
                managed.iter().map(|(host, address)| (host.to_lowercase(), address.clone())).collect();
            let foreign: Vec<&(String, String)> = overrides
                .iter()
                .filter(|(host, address)| !ours.contains(&(host.to_lowercase(), address.clone())))
                .collect();
            let own_count = overrides.len() - foreign.len();
            if foreign.is_empty() {
                items.push(SystemItem {
                    key: "hosts".to_string(),
                    title: title.to_string(),
                    level: LEVEL_OK.to_string(),
                    text: format!(
                        "адреса проверяемых сайтов ({own_count}) заданы самой программой через «Редактор hosts» — так и должно быть"
                    ),
                    advice: String::new(),
                });
            } else {
                let foreign_labels: Vec<String> =
                    foreign.iter().map(|(host, address)| format!("{host} → {address}")).collect();
                let own = if own_count > 0 {
                    format!(" Ещё {own_count} — записи самой программы, с ними всё в порядке.")
                } else {
                    String::new()
                };
                items.push(SystemItem {
                    key: "hosts".to_string(),
                    title: title.to_string(),
                    level: LEVEL_INFO.to_string(),
                    text: format!(
                        "в нём заданы адреса проверяемых сайтов не из программы: {}. \
                         Программы берут адрес оттуда, а не у DNS.{own}",
                        short(&foreign_labels)
                    ),
                    advice: String::new(),
                });
            }
        } else {
            items.push(SystemItem {
                key: "hosts".to_string(),
                title: title.to_string(),
                level: LEVEL_OK.to_string(),
                text: "записей для проверяемых сайтов нет".to_string(),
                advice: String::new(),
            });
        }
    }

    let title = "Часы компьютера";
    match facts.clock_skew_s {
        None => items.push(unknown("clock", title)),
        Some(skew) if abs_f64(skew) > CLOCK_SKEW_LIMIT_S => {
            let direction = if skew > 0.0 { "спешат" } else { "отстают" };
            items.push(SystemItem {
                key: "clock".to_string(),
                title: title.to_string(),
                level: LEVEL_WARN.to_string(),
                text: format!(
                    "{direction} на {} — при таком расхождении сайты могут показывать ошибки сертификатов",
                    minutes(skew)
                ),
                advice: "Включите автоматическую установку времени: Параметры Windows → Время и язык → Дата и время.".to_string(),
            });
        }
        Some(_) => items.push(SystemItem {
            key: "clock".to_string(),
            title: title.to_string(),
            level: LEVEL_OK.to_string(),
            text: "идут верно".to_string(),
            advice: String::new(),
        }),
    }

    items
}

fn abs_f64(value: f64) -> f64 {
    if value < 0.0 { -value } else { value }
}

/// python ` wounds SYSTEM_PROBLEM_LEVEL` — какие уровни системы попадают в список проблем
/// (для `problems.rs`).
pub fn problem_level(level: &str) -> Option<DiagnosticLevel> {
    match level {
        LEVEL_FAIL => Some(DiagnosticLevel::Fail),
        LEVEL_WARN => Some(DiagnosticLevel::Warn),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worst_and_problem_level() {
        let items = vec![
            item(LEVEL_OK),
            item(LEVEL_WARN),
            item(LEVEL_FAIL),
        ];
        assert_eq!(worst_level(&items), LEVEL_FAIL);
        assert_eq!(worst_level(&[]), LEVEL_OK);
        assert_eq!(problem_level(LEVEL_FAIL), Some(DiagnosticLevel::Fail));
        assert_eq!(problem_level(LEVEL_UNKNOWN), None);
    }

    fn item(level: &str) -> SystemItem {
        SystemItem {
            key: String::new(),
            title: String::new(),
            level: level.to_string(),
            text: String::new(),
            advice: String::new(),
        }
    }

    #[test]
    fn tunnel_adapters_pure() {
        let provider = Interface {
            name: "Ethernet".to_string(),
            description: "Broadcom NetXtreme".to_string(),
            connected: true,
            ..Default::default()
        };
        let vpn = Interface {
            name: "WireGuard".to_string(),
            description: "WireGuard Tunnel".to_string(),
            connected: true,
            ..Default::default()
        };
        assert_eq!(tunnel_adapters(&[provider.clone(), vpn.clone()]), vec!["WireGuard".to_string()]);
        assert_eq!(tunnel_adapters(&[provider]), Vec::<String>::new());
    }

    #[test]
    fn judge_shape() {
        let facts = SystemFacts::default();
        let items = judge(&facts, None);
        assert!(items.iter().all(|item| item.level == LEVEL_UNKNOWN));
        assert_eq!(items.len(), 12);
    }
}
