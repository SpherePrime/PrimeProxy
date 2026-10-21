//! Linux-раннер nfqws2 (Zapret 2 на Linux): подготовка пресета, план запуска
//! и текст правил nftables.
//!
//! Linux-аналог [`crate::runner_zapret2`] (winws2.exe на Windows). Перехват
//! пакетов на Linux делает nftables: программа получает трафик через NFQUEUE,
//! поэтому вместо флагов `--wf-*` (Windows) здесь `--qnum`/`--fwmark` и
//! правила `queue num N bypass` в таблице `inet zapret2`
//! (см. `docs_platform-flags.md` корня репозитория).
//!
//! Эталоны zapret2 v1.0.6, по которым снята семантика:
//! - `init.d/sysv/functions`: `QNUM=300`, `DESYNC_MARK=0x40000000`,
//!   `DESYNC_MARK_POSTNAT=0x20000000`, `LUAOPT` — три стандартных lua-файла;
//! - `common/linux_daemons.sh` + `common/list.sh` (`filter_apply_hostlist_target`):
//!   маркеры `<HOSTLIST>`/`<HOSTLIST_NOAUTO>` в `NFQWS2_OPT`;
//! - `common/nft.sh`: таблица `inet zapret2`, цепочки-хуки
//!   `prerouting_hook`/`postrouting_hook`/`prenat_hook`/`postnat_hook`,
//!   ifname-сеты `wanif`/`wanif6` и правила `queue num N bypass`.
//!
//! Как и остальные раннеры крейта, модуль держит только решения. Реальный
//! запуск процесса идёт через [`crate::runner::ProcessSpawner`], а применение
//! правил nftables — привилегированная операция: её можно выполнять только
//! через `primecore-privilege` (демон `privd`); клиент privd пока умеет
//! лишь проверку связи, поэтому правила выдаются текстом-планом (`nft -f -`):
//! вызывающий
//! слой передаёт его privd, когда тот получит соответствующее действие.
//! Прямых вызовов sudo/nft в коде нет и быть не должно.

use std::collections::BTreeMap;

use crate::runner::launch_args_from_preset_text;

// --- константы эталона (init.d/sysv/functions) -------------------------------

/// Имя бинарника Linux-движка (на Windows он же называется winws2).
pub const NFQWS2_EXE_BASENAME: &str = "nfqws2";

/// Номер NFQUEUE по умолчанию (эталон `QNUM=${QNUM:-300}`).
pub const NFQWS2_DEFAULT_QNUM: u32 = 300;

/// Метка десинк-трафика (эталон `DESYNC_MARK=${DESYNC_MARK:-0x40000000}`).
/// Правила цепочек-хуков пропускают в очередь только пакеты без этой метки,
/// чтобы зациклить собственные пакеты nfqws2.
pub const NFQWS2_DESYNC_MARK: &str = "0x40000000";

/// Метка постнат-обработки (эталон `DESYNC_MARK_POSTNAT=0x20000000`):
/// в postnat-режиме правило postrouting выставляет её (`mark or`).
pub const NFQWS2_DESYNC_MARK_POSTNAT: &str = "0x20000000";

/// Имя таблицы nftables (эталон `ZAPRET_NFT_TABLE=zapret2`).
pub const NFQWS2_NFT_TABLE: &str = "zapret2";

/// Каталог pid-файлов эталона (`PIDDIR=/var/run`).
pub const NFQWS2_PIDFILE_DIR: &str = "/var/run";

/// Номер демона nfqws2 в стандартном режиме (эталон `do_nfqws $1 1`).
pub const NFQWS2_STD_DAEMON_NUMBER: u32 = 1;

/// Стандартные lua-файлы в порядке эталонного `LUAOPT`
/// (`--lua-init=@<база>/lua/...`).
pub const NFQWS2_LUA_INIT_FILES: [&str; 3] =
    ["zapret-lib.lua", "zapret-antidpi.lua", "zapret-auto.lua"];

/// Маркер подстановки стандартных листов (эталон `HOSTLIST_MARKER`).
pub const NFQWS2_HOSTLIST_MARKER: &str = "<HOSTLIST>";

/// Маркер подстановки автохостлиста как обычного листа
/// (эталон `HOSTLIST_NOAUTO_MARKER`).
pub const NFQWS2_HOSTLIST_NOAUTO_MARKER: &str = "<HOSTLIST_NOAUTO>";

// --- strip_windows_only: переносимая часть пресета ---------------------------

/// Убирает из текста пресета winws2 Windows-only строки-опции `--wf-*`.
///
/// Пресеты winws2 нельзя запускать на Linux целиком: `--wf-tcp-out`,
/// `--wf-raw-part` и остальные `--wf-*` — это слой перехвата WinDivert,
/// которого у nfqws2 нет; профили и стратегии пресета переносимы.
///
/// Формат строк пресета простой (одна опция на строку, все `--wf-*` —
/// в начале строки), поэтому фильтр построчный: убираются только строки,
/// начинающиеся с `--wf-` после обрезки пробелов. Остальной текст, включая
/// комментарии и пустые строки, сохраняется как есть. Функция идемпотентна.
///
/// Ошибка — если `--wf-*` встретился в середине содержательной строки:
/// построчно такой текст разобрать нельзя, и молча оставить Windows-опцию
/// в командной строке nfqws2 тоже нельзя.
pub fn strip_windows_only(preset_text: &str) -> Result<String, String> {
    let text = normalize_preset_text(preset_text);
    let mut kept: Vec<&str> = Vec::new();
    for raw in text.split('\n') {
        let stripped = raw.trim();
        if stripped.starts_with("--wf-") {
            continue;
        }
        if !stripped.starts_with('#') && !stripped.is_empty() && stripped.contains("--wf-") {
            return Err(format!(
                "опция --wf-* в середине строки не удаляется построчно: {stripped}"
            ));
        }
        kept.push(raw);
    }
    Ok(kept.join("\n"))
}

/// Нормализация текста пресета: снятие ведущего BOM и приведение переводов
/// строк к `\n` (как в [`crate::runner::launch_args_from_preset_text`]).
fn normalize_preset_text(text: &str) -> String {
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);
    text.replace("\r\n", "\n").replace('\r', "\n")
}

// --- substitute_hostlist_markers: маркеры стандартных листов ------------------

/// Режим фильтрации по листам (эталон `MODE_FILTER`: none/ipset/hostlist/
/// autohostlist).
///
/// В режимах none и ipset маркеры замещаются пустой строкой: в ipset-режиме
/// листы идут в правила nft как ip-сеты, а не в nfqws2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum HostlistFilterMode {
    /// `none` и `ipset`: маркеры убираются.
    #[default]
    None,
    /// `hostlist`: маркеры замещаются стандартными листами.
    Hostlist,
    /// `autohostlist`: как hostlist, плюс автохостлист
    /// (`<HOSTLIST>` — с авто-наполнением, `<HOSTLIST_NOAUTO>` — обычный лист).
    Autohostlist,
}

/// python/shell-значение `MODE_FILTER` в вариант режима
/// (`none`, `ipset`, `hostlist`, `autohostlist`; пустое — `none`).
#[must_use]
pub fn parse_hostlist_filter_mode(mode_filter: &str) -> HostlistFilterMode {
    match mode_filter.trim().to_lowercase().as_str() {
        "hostlist" => HostlistFilterMode::Hostlist,
        "autohostlist" => HostlistFilterMode::Autohostlist,
        _ => HostlistFilterMode::None,
    }
}

/// Пути стандартных листов для подстановки маркеров.
///
/// Эталон берёт пути из `ipset/` установки zapret2 и включает в параметры
/// только файлы, которые по факту существуют (функция `find_hostlists`);
/// вызывающий слой передаёт сюда уже существующие пути — в ресурсы
/// PrimeProxy имена эталона (`zapret-hosts*.txt`) не перенесены.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostlistSubstitution<'a> {
    /// Режим `MODE_FILTER`.
    pub mode: HostlistFilterMode,
    /// Пользовательский лист (`zapret-hosts-user.txt`).
    pub hostlist_user: Option<&'a str>,
    /// Основной генерируемый лист (`zapret-hosts.txt`).
    pub hostlist: Option<&'a str>,
    /// Исключающий лист (`zapret-hosts-user-exclude.txt`).
    pub hostlist_exclude: Option<&'a str>,
    /// Автохостлист (`zapret-hosts-auto.txt`).
    pub hostlist_auto: Option<&'a str>,
    /// Файл отладочного журнала автохостлиста
    /// (`zapret-hosts-auto-debug.log`); только режим autohostlist.
    pub hostlist_auto_debug: Option<&'a str>,
    /// Дополнительные параметры автохостлиста из config
    /// (`--hostlist-auto-fail-threshold=...` и т.п.); добавляются только
    /// в замещение `<HOSTLIST>`, как parm5..parm12 эталона.
    pub autohostlist_extra_params: Vec<String>,
}

/// Замещает маркеры `<HOSTLIST>` и `<HOSTLIST_NOAUTO>` в тексте пресета
/// параметрами стандартных листов (эталон `filter_apply_hostlist_target`).
///
/// Семантика эталона:
/// - если маркеров в тексте нет, текст возвращается без изменений;
/// - `<HOSTLIST>` замещается параметрами user/main/exclude листов, а в
///   режиме autohostlist — ещё `--hostlist-auto=...` и доп. параметрами;
/// - `<HOSTLIST_NOAUTO>` замещается теми же листами, но автохостлист идёт
///   обычным `--hostlist=...` без авто-наполнения;
/// - в режимах none/ipset маркеры замещаются пустой строкой;
/// - в режиме autohostlist с заданным debug-журналом в конец текста
///   добавляется `--hostlist-auto-debug=...` (эталон дописывает его в конец
///   всей строки параметров).
///
/// Ошибка — если после подстановки в содержательных строках остался
/// неизвестный маркер вида `<HOSTLIST...>`.
pub fn substitute_hostlist_markers(
    preset_text: &str,
    substitution: &HostlistSubstitution<'_>,
) -> Result<String, String> {
    let text = normalize_preset_text(preset_text);
    if !text.contains(NFQWS2_HOSTLIST_MARKER) && !text.contains(NFQWS2_HOSTLIST_NOAUTO_MARKER) {
        return Ok(text);
    }

    let (hostlist_params, noauto_params) = hostlist_replacement_strings(substitution);
    let mut replaced = text
        .replace(NFQWS2_HOSTLIST_NOAUTO_MARKER, &noauto_params)
        .replace(NFQWS2_HOSTLIST_MARKER, &hostlist_params);

    if substitution.mode == HostlistFilterMode::Autohostlist {
        if let Some(debug) = non_empty(substitution.hostlist_auto_debug) {
            replaced.push_str("\n--hostlist-auto-debug=");
            replaced.push_str(debug);
        }
    }

    let leftover = collect_marker_lines(&replaced);
    if !leftover.is_empty() {
        return Err(format!(
            "после подстановки листов остались неизвестные маркеры: {}",
            leftover.join("; ")
        ));
    }
    Ok(replaced)
}

/// Строки-замены для `<HOSTLIST>` и `<HOSTLIST_NOAUTO>`
/// (эталонные `parm` и `parmNA`).
fn hostlist_replacement_strings(substitution: &HostlistSubstitution<'_>) -> (String, String) {
    if substitution.mode == HostlistFilterMode::None {
        return (String::new(), String::new());
    }

    let head = join_some([
        opt_param("--hostlist=", substitution.hostlist_user),
        opt_param("--hostlist=", substitution.hostlist),
        opt_param("--hostlist-exclude=", substitution.hostlist_exclude),
    ]);

    if substitution.mode == HostlistFilterMode::Autohostlist {
        let mut hostlist_params = head.clone();
        if let Some(auto) = non_empty(substitution.hostlist_auto) {
            hostlist_params.push_str(" --hostlist-auto=");
            hostlist_params.push_str(auto);
        }
        for extra in &substitution.autohostlist_extra_params {
            let extra = extra.trim();
            if !extra.is_empty() {
                hostlist_params.push(' ');
                hostlist_params.push_str(extra);
            }
        }
        let mut noauto_params = head;
        if let Some(auto) = non_empty(substitution.hostlist_auto) {
            noauto_params.push_str(" --hostlist=");
            noauto_params.push_str(auto);
        }
        return (hostlist_params, noauto_params);
    }

    (head.clone(), head)
}

fn opt_param(prefix: &str, value: Option<&str>) -> Option<String> {
    non_empty(value).map(|value| format!("{prefix}{value}"))
}

fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn join_some(parts: [Option<String>; 3]) -> String {
    parts.into_iter().flatten().collect::<Vec<_>>().join(" ")
}

/// Содержательные строки с оставшимися маркерами `<HOSTLIST...>`.
fn collect_marker_lines(text: &str) -> Vec<String> {
    let mut leftover = Vec::new();
    for line in text.lines() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if stripped.contains("<HOSTLIST") {
            leftover.push(stripped.to_string());
        }
    }
    leftover
}

// --- nfqws2_launch_plan: план запуска ----------------------------------------

/// План запуска nfqws2 на Linux (аналог [`crate::runner::LaunchPlan`] для
/// winws2 плюс env и pid-файл).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Nfqws2LaunchPlan {
    /// Полный путь к бинарнику nfqws2.
    pub exe: String,
    /// Аргументы запуска в порядке: `--qnum`, `--fwmark`, стандартные
    /// `--lua-init`, строки стратегии пресета.
    pub args: Vec<String>,
    /// Переменные окружения процесса. Эталон особых переменных не задаёт,
    /// поле оставлено для вызывающего слоя.
    pub env: BTreeMap<String, String>,
    /// Рабочий каталог запуска: ресурсы программы. Относительные пути
    /// стратегии (`@lua/...`, `@lists/...`) открываются от него.
    pub cwd: String,
    /// Путь pid-файла демона (эталон `PIDDIR/${DAEMONBASE}_${N}.pid`).
    pub pidfile: String,
}

/// Путь pid-файла nfqws2 (эталон `run_daemon`: `$PIDDIR/$(basename exe)_N.pid`).
#[must_use]
pub fn nfqws2_pidfile(exe_path: &str) -> String {
    let base = exe_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(NFQWS2_EXE_BASENAME);
    format!(
        "{NFQWS2_PIDFILE_DIR}/{}_{}.pid",
        if base.is_empty() {
            NFQWS2_EXE_BASENAME
        } else {
            base
        },
        NFQWS2_STD_DAEMON_NUMBER
    )
}

/// Собирает план запуска nfqws2 из подготовленного текста пресета.
///
/// Порядок аргументов: `--qnum=N`, `--fwmark=...`, три стандартных
/// `--lua-init=@<resources>/lua/...` (эталонный `LUAOPT`), затем строки
/// стратегии из пресета (разбор строк — [`crate::runner::launch_args_from_preset_text`]).
/// Эталон собирает `--fwmark` и lua в `NFQWS2_OPT_BASE`, а `--qnum`
/// добавляет перед стратегией; здесь порядок фиксированный, на результат
/// для nfqws2 он не влияет.
///
/// Текст пресета должен быть подготовлен: Windows-only строки `--wf-*`
/// убираются здесь автоматически (функция идемпотентна), а вот маркеры
/// `<HOSTLIST>`/`<HOSTLIST_NOAUTO>` требуют решения вызывающего — при
/// оставшихся маркерах возвращается ошибка, чтобы не запускать nfqws2
/// с параметром-маркером.
///
/// Если пресет уже подключает стандартный lua-файл относительным путём
/// (`--lua-init=@lua/zapret-lib.lua`), соответствующий абсолютный аргумент
/// не добавляется: один и тот же файл не должен инициализироваться дважды.
pub fn nfqws2_launch_plan(
    exe_path: &str,
    resources_dir: &str,
    preset_text: &str,
    qnum: u32,
    fwmark: &str,
) -> Result<Nfqws2LaunchPlan, String> {
    let preset_text = strip_windows_only(preset_text)?;
    let leftover = collect_marker_lines(&preset_text);
    if !leftover.is_empty() {
        return Err(format!(
            "в пресете остались маркеры листов ({}): сначала substitute_hostlist_markers",
            leftover.join("; ")
        ));
    }

    let preset_args = launch_args_from_preset_text(&preset_text);
    let preset_lua_files: std::collections::HashSet<&str> = preset_args
        .iter()
        .filter_map(|arg| arg.strip_prefix("--lua-init=@"))
        .map(lua_basename)
        .collect();

    let mut args = vec![format!("--qnum={qnum}"), format!("--fwmark={fwmark}")];
    for lua in NFQWS2_LUA_INIT_FILES {
        if preset_lua_files.contains(lua) {
            continue;
        }
        let path = crate::engine::normpath(&crate::engine::join_paths(
            resources_dir,
            &format!("lua/{lua}"),
        ));
        args.push(format!("--lua-init=@{path}"));
    }
    args.extend(preset_args);

    Ok(Nfqws2LaunchPlan {
        exe: exe_path.to_string(),
        args,
        env: BTreeMap::new(),
        cwd: resources_dir.to_string(),
        pidfile: nfqws2_pidfile(exe_path),
    })
}

/// Базовое имя lua-файла из значения `--lua-init=@...`.
fn lua_basename(value: &str) -> &str {
    let trimmed = value.trim();
    trimmed.rsplit(['/', '\\']).next().unwrap_or(trimmed)
}

// --- nft_rules_text: правила перехвата ---------------------------------------

/// Фильтры очереди nfqws2 для правил nftables.
///
/// Порты — эталонные `NFQWS2_PORTS_TCP/UDP` (`config.default`: tcp
/// `80,443`, udp `443`), «первые пакеты» — `NFQWS2_*_PKT_OUT/IN`
/// (эталонные значения `20/10/5/3`): правило очереди получает
/// ограничение `ct original packets 1-N` для исходящих и
/// `ct reply packets 1-N` для входящих ([`nft_reverse_nfqws_filter`],
/// эталон `nft_first_packets`). `None` — протокол не обрабатывается:
/// в эталоне пустой порт снимает все правила этого протокола
/// (`nft_apply_nfqws_in_out`: `[ -n "$2" ] || return`), как и ноль
/// пакетов (`[ "$3" != 0 ]`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Nfqws2NftFilters {
    /// Эталон `DISABLE_IPV4`.
    pub disable_ipv4: bool,
    /// Эталон `DISABLE_IPV6`.
    pub disable_ipv6: bool,
    /// Эталон `POSTNAT`/`POSTNAT_ALL`: правила идут в postnat/prenat,
    /// и исходящее правило выставляет метку `0x20000000`.
    pub postnat: bool,
    /// Эталон `FILTER_TTL_EXPIRED_ICMP`: в postnat-режиме правило
    /// переносит метку в ct mark (`CONNMARKER`), плюс явные
    /// icmp/icmpv6-правила в `prerouting_hook`.
    pub filter_ttl_expired_icmp: bool,
    /// Порты TCP, эталон `NFQWS2_PORTS_TCP`.
    pub tcp_ports: Option<String>,
    /// Порты UDP, эталон `NFQWS2_PORTS_UDP`.
    pub udp_ports: Option<String>,
    /// Эталон `NFQWS2_TCP_PKT_OUT`.
    pub tcp_first_packets_out: u32,
    /// Эталон `NFQWS2_TCP_PKT_IN`.
    pub tcp_first_packets_in: u32,
    /// Эталон `NFQWS2_UDP_PKT_OUT`.
    pub udp_first_packets_out: u32,
    /// Эталон `NFQWS2_UDP_PKT_IN`.
    pub udp_first_packets_in: u32,
}

/// Полный текст правил nftables для перехвата трафика nfqws2
/// (`nft -f -`), воспроизводящий эталон `common/nft.sh`.
///
/// Файл идемпотентен: пустое объявление таблицы гарантирует её
/// существование, `flush table` снимает прошлые правила, повторное
/// объявление создаёт свежую структуру. Внутри: ifname-сеты
/// `wanif`/`wanif6` (заполняются из аргументов, как
/// `nft_fill_ifsets_overload`), сеты исключений `nozapret`/`nozapret6`
/// (их наполняет ipset-подсистема, эталон `ZIPSET_EXCLUDE`; здесь
/// передаются явно), служебные цепочки
/// `postrouting`/`postnat`/`prerouting`/`prenat` и хуки
/// (`postrouting_hook` priority 99, `postnat_hook` 101,
/// `prerouting_hook` -99, `prenat_hook` -101) с переходом `jump`
/// (`nft_activate_chain4/6`: собственные пакеты nfqws2 пропускаются по
/// метке `0x40000000`, ifname-фильтр — только при заданных
/// wan-интерфейсах). В `predefrag`/`predefrag_nfqws` — защита
/// сгенерированных пакетов от сброса по `INVALID` conntrack
/// (`notrack`), как в `nft_create_chains`.
///
/// Правила очереди стоят в служебных цепочках
/// (`queue num N bypass`), фильтр строится из портов и «первых
/// пакетов» (`nft_apply_nfqws_in_out`); в postnat-режиме исходящее
/// правило ставит `meta mark set meta mark or 0x20000000`
/// (`DESYNC_MARK_POSTNAT`) и при `filter_ttl_expired_icmp` добавляет
/// `CONNMARKER`. Правила создаются для ipv4 и ipv6 отдельно
/// (`meta nfproto ...`); отключённая версия IP не получает ни хуков,
/// ни правил очереди.
///
/// Текст-план: применение через privd, не напрямую.
#[must_use]
pub fn nft_rules_text(
    qnum: u32,
    wan_ifaces4: &[&str],
    wan_ifaces6: &[&str],
    nozapret4: &[&str],
    nozapret6: &[&str],
    filters: &Nfqws2NftFilters,
) -> String {
    let post_chain = if filters.postnat {
        "postnat"
    } else {
        "postrouting"
    };
    let pre_chain = if filters.postnat {
        "prenat"
    } else {
        "prerouting"
    };

    // Служебные цепочки и хуки (эталон nft_create_chains); для правил
    // каждого блока — текст после ключевого слова `rule <chain>`.
    let mut chains: Vec<(&str, Vec<String>)> = vec![
        ("postrouting", Vec::new()),
        ("postrouting_hook", Vec::new()),
        ("postnat", Vec::new()),
        ("postnat_hook", Vec::new()),
        ("prerouting", Vec::new()),
        ("prerouting_hook", Vec::new()),
        ("prenat", Vec::new()),
        ("prenat_hook", Vec::new()),
        ("predefrag", Vec::new()),
        ("predefrag_nfqws", Vec::new()),
    ];
    let mut rule = |chain: &str, text: String| {
        for (name, list) in &mut chains {
            if *name == chain {
                list.push(text);
                return;
            }
        }
    };

    // Защита сгенерированных пакетов (эталон nft_create_chains).
    rule(
        "predefrag",
        format!(
            "mark and {NFQWS2_DESYNC_MARK} != 0 jump predefrag_nfqws comment \"nfqws generated : avoid drop by INVALID conntrack state\""
        ),
    );
    rule(
        "predefrag_nfqws",
        format!("mark and {NFQWS2_DESYNC_MARK_POSTNAT} != 0 notrack comment \"postnat traffic\""),
    );
    rule(
        "predefrag_nfqws",
        "ip frag-off & 0x1fff != 0 notrack comment \"ipfrag\"".to_string(),
    );
    rule(
        "predefrag_nfqws",
        "exthdr frag exists notrack comment \"ipfrag\"".to_string(),
    );
    rule(
        "predefrag_nfqws",
        "tcp flags ! syn,rst,ack notrack comment \"datanoack\"".to_string(),
    );

    // FILTER_TTL_EXPIRED_ICMP (эталон: причина — untracked пакеты nfqws2).
    let connmarker = if filters.postnat && filters.filter_ttl_expired_icmp {
        Some(format!("ct mark set ct mark or {NFQWS2_DESYNC_MARK}"))
    } else {
        None
    };
    if filters.filter_ttl_expired_icmp {
        if filters.postnat {
            rule(
                "prerouting_hook",
                "icmp type time-exceeded ct state invalid drop".to_string(),
            );
        } else {
            rule(
                "postrouting_hook",
                format!(
                    "mark and {NFQWS2_DESYNC_MARK} != 0 ct mark set ct mark or {NFQWS2_DESYNC_MARK} comment \"nfqws related : prevent ttl expired socket errors\""
                ),
            );
        }
        if !filters.disable_ipv4 {
            rule(
                "prerouting_hook",
                format!(
                    "icmp type time-exceeded ct mark and {NFQWS2_DESYNC_MARK} != 0 drop comment \"nfqws related : prevent ttl expired socket errors\""
                ),
            );
        }
        if !filters.disable_ipv6 {
            rule(
                "prerouting_hook",
                format!(
                    "icmpv6 type time-exceeded ct mark and {NFQWS2_DESYNC_MARK} != 0 drop comment \"nfqws related : prevent ttl expired socket errors\""
                ),
            );
        }
    }

    // Переходы из хуков в служебные цепочки (nft_activate_chain4/6).
    if !filters.disable_ipv4 {
        rule(
            "postrouting_hook",
            hook_jump_rule(
                post_chain,
                "oifname",
                wan_ifaces4,
                "ip",
                "daddr",
                "@nozapret",
            ),
        );
        rule(
            "prerouting_hook",
            hook_jump_rule(
                pre_chain,
                "iifname",
                wan_ifaces4,
                "ip",
                "saddr",
                "@nozapret",
            ),
        );
    }
    if !filters.disable_ipv6 {
        rule(
            "postrouting_hook",
            hook_jump_rule(
                post_chain,
                "oifname",
                wan_ifaces6,
                "ip6",
                "daddr",
                "@nozapret6",
            ),
        );
        rule(
            "prerouting_hook",
            hook_jump_rule(
                pre_chain,
                "iifname",
                wan_ifaces6,
                "ip6",
                "saddr",
                "@nozapret6",
            ),
        );
    }

    // Правила очереди (nft_apply_nfqws_in_out → nft_fw_nfqws_post/pre):
    // `meta nfproto <f> <filter> [setmark] [connmarker] queue num N bypass`.
    for (proto, ports, packets_out, packets_in) in [
        (
            "tcp",
            filters.tcp_ports.as_deref(),
            filters.tcp_first_packets_out,
            filters.tcp_first_packets_in,
        ),
        (
            "udp",
            filters.udp_ports.as_deref(),
            filters.udp_first_packets_out,
            filters.udp_first_packets_in,
        ),
    ] {
        let Some(ports) = non_empty_str(ports) else {
            continue;
        };
        for (direction_in, first_packets) in [(false, packets_out), (true, packets_in)] {
            if first_packets == 0 {
                continue;
            }
            let (dir, ct) = if direction_in {
                ("sport", "ct reply packets")
            } else {
                ("dport", "ct original packets")
            };
            let filter = format!("{proto} {dir} {{ {ports} }} {ct} 1-{first_packets}");
            for (nfproto, enabled) in [
                ("ipv4", !filters.disable_ipv4),
                ("ipv6", !filters.disable_ipv6),
            ] {
                if !enabled {
                    continue;
                }
                let mut rule_text = format!("meta nfproto {nfproto} {filter}");
                if !direction_in && filters.postnat {
                    rule_text.push_str(&format!(
                        " meta mark set meta mark or {NFQWS2_DESYNC_MARK_POSTNAT}"
                    ));
                }
                if !direction_in {
                    if let Some(marker) = &connmarker {
                        rule_text.push(' ');
                        rule_text.push_str(marker);
                    }
                }
                rule_text.push_str(&format!(" queue num {qnum} bypass"));
                let chain = if direction_in { pre_chain } else { post_chain };
                rule(chain, rule_text);
            }
        }
    }

    // Сборка файла: идемпотентный сброс и полное объявление структуры.
    let mut script = String::from("table inet zapret2 { }\nflush table inet zapret2\n");
    script.push_str(&format!("table inet {NFQWS2_NFT_TABLE} {{\n"));

    let mut wanif_elements = String::new();
    if !filters.disable_ipv4 && !wan_ifaces4.is_empty() {
        wanif_elements = format!(" elements = {{ {} }}", quoted_comma_list(wan_ifaces4));
    }
    script.push_str(&format!(
        "    set wanif {{ type ifname;{wanif_elements} }}\n"
    ));
    let mut wanif6_elements = String::new();
    if !filters.disable_ipv6 && !wan_ifaces6.is_empty() {
        wanif6_elements = format!(" elements = {{ {} }}", quoted_comma_list(wan_ifaces6));
    }
    script.push_str(&format!(
        "    set wanif6 {{ type ifname;{wanif6_elements} }}\n"
    ));
    let mut nozapret_elements = String::new();
    if !filters.disable_ipv4 && !nozapret4.is_empty() {
        nozapret_elements = format!(" elements = {{ {} }}", nozapret4.join(", "));
    }
    script.push_str(&format!(
        "    set nozapret {{ type ipv4_addr; flags interval;{nozapret_elements} }}\n"
    ));
    let mut nozapret6_elements = String::new();
    if !filters.disable_ipv6 && !nozapret6.is_empty() {
        nozapret6_elements = format!(" elements = {{ {} }}", nozapret6.join(", "));
    }
    script.push_str(&format!(
        "    set nozapret6 {{ type ipv6_addr; flags interval;{nozapret6_elements} }}\n"
    ));

    for (chain, hook, priority) in [
        ("postrouting", None, ""),
        ("postrouting_hook", Some("postrouting"), "99"),
        ("postnat", None, ""),
        ("postnat_hook", Some("postrouting"), "101"),
        ("prerouting", None, ""),
        ("prerouting_hook", Some("prerouting"), "-99"),
        ("prenat", None, ""),
        ("prenat_hook", Some("prerouting"), "-101"),
        ("predefrag", Some("output"), "-401"),
        ("predefrag_nfqws", None, ""),
    ] {
        match hook {
            Some(hook) => script.push_str(&format!(
                "    chain {chain} {{ type filter hook {hook} priority {priority};\n"
            )),
            None => script.push_str(&format!("    chain {chain} {{\n")),
        }
        for text in &chains
            .iter()
            .find(|(name, _)| *name == chain)
            .map(|(_, list)| list.clone())
            .unwrap_or_default()
        {
            script.push_str(&format!("        {text}\n"));
        }
        script.push_str("    }\n");
    }

    script.push_str("}\n");
    script
}

/// Переход из цепочки-хука в служебную цепочку (эталон `nft_activate_chain4/6`):
/// собственные пакеты nfqws2 пропускаются по метке; ifname-фильтр по wan-сет
/// добавляется, только если интерфейсы заданы (эталон
/// `nft_wanif_filter_present` — `[ -n "$IFACE_WAN" ]`); назначение —
/// по направлению адреса.
fn hook_jump_rule(
    chain: &str,
    ifname_match: &str,
    wan_ifaces: &[&str],
    family: &str,
    addr_dir: &str,
    nozapret_set: &str,
) -> String {
    let mut rule = format!("meta mark and {NFQWS2_DESYNC_MARK} == 0");
    if !wan_ifaces.is_empty() {
        let set = if family == "ip6" { "wanif6" } else { "wanif" };
        rule.push_str(&format!(" {ifname_match} @{set}"));
    }
    rule.push_str(&format!(
        " {family} {addr_dir} != {nozapret_set} jump {chain}"
    ));
    rule
}

/// Список имён интерфейсов в виде `{ "a", "b" }` (эталон `make_quoted_comma_list`).
fn quoted_comma_list(ifaces: &[&str]) -> String {
    ifaces
        .iter()
        .map(|iface| format!("\"{}\"", iface.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Обратный фильтр для pre-правил (эталон `nft_reverse_nfqws_rule`):
/// `oifname`→`iifname`, `dport`→`sport`, `daddr`→`saddr`,
/// `ct original`→`ct reply`, удаляется условие «не собственный пакет».
#[must_use]
pub fn nft_reverse_nfqws_filter(filter: &str) -> String {
    filter
        .replace("oifname ", "iifname ")
        .replace("dport ", "sport ")
        .replace("daddr ", "saddr ")
        .replace("ct original ", "ct reply ")
        .replace(&format!("mark and {NFQWS2_DESYNC_MARK} == 0 "), "")
}

fn non_empty_str(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

// --- тесты -------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Корень ресурсов репозитория относительно крейта.
    const RESOURCES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../resources");

    fn builtin_files(kind: &str) -> Vec<std::path::PathBuf> {
        let dir = std::path::Path::new(RESOURCES).join("presets").join(kind);
        let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(&dir)
            .unwrap_or_else(|error| panic!("нет папки {kind}: {error}"))
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("txt"))
            .collect();
        files.sort();
        files
    }

    fn builtin_preset_text(name: &str) -> String {
        std::fs::read_to_string(
            std::path::Path::new(RESOURCES)
                .join("presets")
                .join("winws2_builtin")
                .join(name),
        )
        .unwrap_or_else(|error| panic!("нет пресета {name}: {error}"))
    }

    // --- strip_windows_only --------------------------------------------------

    #[test]
    fn strip_removes_wf_lines_from_real_builtin_preset() {
        let text = builtin_preset_text("ALL TCP & UDP discord_urgent_sni.txt");
        let stripped = strip_windows_only(&text).expect("стрип должен пройти");

        assert!(!stripped.contains("--wf-"), "остались --wf-*: {stripped}");
        // Переносимая часть сохранена построчно.
        assert!(stripped.contains("--lua-init=@lua/zapret-lib.lua"));
        assert!(stripped.contains("--ctrack-disable=0"));
        assert!(stripped.contains("--blob=tls_google:@bin/tls_clienthello_www_google_com.bin"));
        assert!(
            stripped.contains("--lua-desync="),
            "стратегии пресета должны остаться"
        );
    }

    #[test]
    fn strip_corpus_is_exactly_input_minus_wf_lines_and_idempotent() {
        let files = builtin_files("winws2_builtin");
        assert!(
            files.len() >= 130,
            "корпус winws2_builtin оскудел: {} файлов",
            files.len()
        );
        let mut wf_lines_total = 0_usize;
        for path in &files {
            let text = std::fs::read_to_string(path).unwrap();
            let stripped = strip_windows_only(&text).expect("стрип должен пройти");

            let expected = normalize_preset_text(&text)
                .split('\n')
                .filter(|line| !line.trim().starts_with("--wf-"))
                .collect::<Vec<_>>()
                .join("\n");
            assert_eq!(stripped, expected, "файл {}", path.display());

            wf_lines_total += normalize_preset_text(&text)
                .split('\n')
                .filter(|line| line.trim().starts_with("--wf-"))
                .count();
            assert_eq!(
                strip_windows_only(&stripped).expect("идемпотентность"),
                stripped,
                "файл {}",
                path.display()
            );
        }
        assert!(
            wf_lines_total >= 500,
            "в корпусе есть --wf-* строки: {wf_lines_total}"
        );
    }

    #[test]
    fn strip_errors_on_embedded_wf_option() {
        let error = strip_windows_only("--filter-tcp=443 --wf-tcp-out=443").expect_err("ошибка");
        assert!(error.contains("--wf-"), "{error}");
    }

    #[test]
    fn strip_keeps_comments_blank_lines_and_bom() {
        let text = "\u{FEFF}# --wf-tcp-out=443\r\n\r\n--wf-udp-out=53\r\n--ctrack-disable=0\r\n";
        let stripped = strip_windows_only(text).expect("стрип должен пройти");
        assert_eq!(stripped, "# --wf-tcp-out=443\n\n--ctrack-disable=0\n");
    }

    // --- substitute_hostlist_markers ------------------------------------------

    fn substitution<'a>(
        mode: HostlistFilterMode,
        paths: [&'a str; 4],
        extra: Vec<String>,
    ) -> HostlistSubstitution<'a> {
        HostlistSubstitution {
            mode,
            hostlist_user: Some(paths[0]),
            hostlist: Some(paths[1]),
            hostlist_exclude: Some(paths[2]),
            hostlist_auto: Some(paths[3]),
            hostlist_auto_debug: None,
            autohostlist_extra_params: extra,
        }
    }

    #[test]
    fn substitute_returns_text_unchanged_without_markers() {
        let text = "--filter-tcp=443\n--lua-desync=fake:blob=tls1\n";
        let result = substitute_hostlist_markers(
            text,
            &substitution(
                HostlistFilterMode::Autohostlist,
                [
                    "/lists/user.txt",
                    "/lists/main.txt",
                    "/lists/exclude.txt",
                    "/lists/auto.txt",
                ],
                Vec::new(),
            ),
        )
        .expect("без маркеров текст не меняется");
        assert_eq!(result, text);
    }

    #[test]
    fn substitute_hostlist_mode_replaces_markers_with_standard_lists() {
        let text = "--filter-tcp=443 <HOSTLIST> --lua-desync=fake\n<HOSTLIST_NOAUTO>\n";
        let result = substitute_hostlist_markers(
            text,
            &substitution(
                HostlistFilterMode::Hostlist,
                [
                    "/lists/user.txt",
                    "/lists/main.txt",
                    "/lists/exclude.txt",
                    "/lists/auto.txt",
                ],
                Vec::new(),
            ),
        )
        .expect("подстановка");

        // <HOSTLIST>: user/main/exclude; автохостлист не в режиме autohostlist.
        assert!(result.contains(
            "--hostlist=/lists/user.txt --hostlist=/lists/main.txt --hostlist-exclude=/lists/exclude.txt"
        ));
        // <HOSTLIST_NOAUTO> в hostlist-режиме — без автохостлиста.
        assert!(!result.contains("--hostlist=/lists/auto.txt"));
        assert!(!result.contains("HOSTLIST"), "{result}");
    }

    #[test]
    fn substitute_autohostlist_mode_adds_auto_list() {
        let text = "<HOSTLIST>\n<HOSTLIST_NOAUTO>\n";
        let result = substitute_hostlist_markers(
            text,
            &substitution(
                HostlistFilterMode::Autohostlist,
                [
                    "/lists/user.txt",
                    "/lists/main.txt",
                    "/lists/exclude.txt",
                    "/lists/auto.txt",
                ],
                vec!["--hostlist-auto-fail-threshold=3".to_string()],
            ),
        )
        .expect("подстановка");

        // <HOSTLIST> — с авто-наполнением и доп. параметрами.
        assert!(result.contains("--hostlist-auto=/lists/auto.txt --hostlist-auto-fail-threshold=3"));
        // <HOSTLIST_NOAUTO> — автохостлист как обычный лист.
        assert!(result.contains("--hostlist=/lists/auto.txt"));
        assert!(!result.contains("HOSTLIST"), "{result}");
    }

    #[test]
    fn substitute_none_mode_removes_markers() {
        let text =
            "--filter-tcp=80 --filter-l7=http <HOSTLIST> --payload=http_req\n<HOSTLIST_NOAUTO>\n";
        let result = substitute_hostlist_markers(
            text,
            &substitution(
                HostlistFilterMode::None,
                [
                    "/lists/user.txt",
                    "/lists/main.txt",
                    "/lists/exclude.txt",
                    "/lists/auto.txt",
                ],
                Vec::new(),
            ),
        )
        .expect("подстановка");

        assert!(!result.contains("HOSTLIST"), "{result}");
        assert!(result.contains("--filter-tcp=80 --filter-l7=http  --payload=http_req"));
        assert!(!result.contains("<HOSTLIST_NOAUTO>"));
    }

    #[test]
    fn substitute_autohostlist_debug_line_appended_once() {
        let text = "<HOSTLIST>\n";
        let substitution = HostlistSubstitution {
            mode: HostlistFilterMode::Autohostlist,
            hostlist_user: None,
            hostlist: None,
            hostlist_exclude: None,
            hostlist_auto: Some("/lists/auto.txt"),
            hostlist_auto_debug: Some("/lists/debug.log"),
            autohostlist_extra_params: Vec::new(),
        };
        let result = substitute_hostlist_markers(text, &substitution).expect("подстановка");

        assert!(result.contains("--hostlist-auto=/lists/auto.txt"));
        assert!(result.ends_with("--hostlist-auto-debug=/lists/debug.log"));
    }

    #[test]
    fn substitute_errors_on_unknown_hostlist_marker() {
        let error = substitute_hostlist_markers(
            "<HOSTLIST>\n<HOSTLIST_UNKNOWN>\n",
            &substitution(
                HostlistFilterMode::Hostlist,
                ["/a", "/b", "/c", "/d"],
                Vec::new(),
            ),
        )
        .expect_err("неизвестный маркер");
        assert!(error.contains("HOSTLIST_UNKNOWN"), "{error}");
    }

    #[test]
    fn substitute_inline_marker_splits_into_launch_args() {
        // Строка из config.default эталона: маркер внутри строки параметров.
        let text = "--filter-tcp=80 --filter-l7=http <HOSTLIST> --payload=http_req\n";
        let result = substitute_hostlist_markers(
            text,
            &substitution(
                HostlistFilterMode::Hostlist,
                [
                    "/lists/user.txt",
                    "/lists/main.txt",
                    "/lists/exclude.txt",
                    "/lists/auto.txt",
                ],
                Vec::new(),
            ),
        )
        .expect("подстановка");

        let args = launch_args_from_preset_text(&result);
        assert_eq!(
            args,
            vec![
                "--filter-tcp=80",
                "--filter-l7=http",
                "--hostlist=/lists/user.txt",
                "--hostlist=/lists/main.txt",
                "--hostlist-exclude=/lists/exclude.txt",
                "--payload=http_req",
            ]
        );
    }

    #[test]
    fn parse_hostlist_filter_mode_accepts_config_values() {
        assert_eq!(parse_hostlist_filter_mode("none"), HostlistFilterMode::None);
        assert_eq!(
            parse_hostlist_filter_mode("ipset"),
            HostlistFilterMode::None
        );
        assert_eq!(
            parse_hostlist_filter_mode("Hostlist"),
            HostlistFilterMode::Hostlist
        );
        assert_eq!(
            parse_hostlist_filter_mode("autohostlist"),
            HostlistFilterMode::Autohostlist
        );
        assert_eq!(parse_hostlist_filter_mode(""), HostlistFilterMode::None);
    }

    // --- nfqws2_launch_plan ---------------------------------------------------

    #[test]
    fn launch_plan_builds_args_in_reference_order() {
        let plan = nfqws2_launch_plan(
            "/opt/zapret2/nfq2/nfqws2",
            "/opt/prime/resources",
            "--lua-desync=fake:blob=tls1\n--ctrack-disable=0\n",
            NFQWS2_DEFAULT_QNUM,
            NFQWS2_DESYNC_MARK,
        )
        .expect("план");

        assert_eq!(plan.exe, "/opt/zapret2/nfq2/nfqws2");
        assert_eq!(
            plan.args,
            vec![
                "--qnum=300",
                "--fwmark=0x40000000",
                "--lua-init=@/opt/prime/resources/lua/zapret-lib.lua",
                "--lua-init=@/opt/prime/resources/lua/zapret-antidpi.lua",
                "--lua-init=@/opt/prime/resources/lua/zapret-auto.lua",
                "--lua-desync=fake:blob=tls1",
                "--ctrack-disable=0",
            ]
        );
        assert!(plan.env.is_empty(), "эталон особых env не задаёт");
        assert_eq!(plan.cwd, "/opt/prime/resources");
        assert_eq!(plan.pidfile, "/var/run/nfqws2_1.pid");
    }

    #[test]
    fn launch_plan_on_real_builtin_preset_has_no_windows_only_args() {
        let text = builtin_preset_text("ALL TCP & UDP discord_urgent_sni.txt");
        let plan = nfqws2_launch_plan(
            "/opt/zapret2/nfq2/nfqws2",
            "/res",
            &text,
            NFQWS2_DEFAULT_QNUM,
            NFQWS2_DESYNC_MARK,
        )
        .expect("план");

        assert!(plan.args.iter().all(|arg| !arg.contains("--wf-")));
        // Стандартные lua из пресета не дублируются абсолютными аргументами:
        // пресет уже подключает @lua/zapret-lib.lua и рядом.
        let lua_args: Vec<&String> = plan
            .args
            .iter()
            .filter(|arg| arg.starts_with("--lua-init=@"))
            .collect();
        let basenames: Vec<&str> = lua_args
            .iter()
            .map(|arg| lua_basename(&arg[12..]))
            .collect();
        let mut sorted = basenames.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            basenames.len(),
            "lua-файлы не должны повторяться"
        );

        let strategy: Vec<&String> = plan
            .args
            .iter()
            .filter(|arg| arg.starts_with("--lua-desync="))
            .collect();
        assert!(
            !strategy.is_empty(),
            "стратегия пресета должна попасть в argv"
        );
    }

    #[test]
    fn launch_plan_errors_on_leftover_markers() {
        let error = nfqws2_launch_plan(
            "/opt/zapret2/nfq2/nfqws2",
            "/res",
            "<HOSTLIST>\n--lua-desync=fake\n",
            NFQWS2_DEFAULT_QNUM,
            NFQWS2_DESYNC_MARK,
        )
        .expect_err("маркеры должны быть подставлены до плана");
        assert!(error.contains("substitute_hostlist_markers"), "{error}");
    }

    #[test]
    fn launch_plan_keeps_custom_lua_from_preset_and_dedups_standard() {
        let plan = nfqws2_launch_plan(
            "/opt/zapret2/nfq2/nfqws2",
            "/res",
            "--lua-init=@lua/custom_funcs.lua\n",
            NFQWS2_DEFAULT_QNUM,
            NFQWS2_DESYNC_MARK,
        )
        .expect("план");

        let lua_args: Vec<&String> = plan
            .args
            .iter()
            .filter(|arg| arg.starts_with("--lua-init=@"))
            .collect();
        assert_eq!(
            lua_args.len(),
            4,
            "3 стандартных + 1 из пресета: {lua_args:?}"
        );
    }

    #[test]
    fn launch_plan_does_not_duplicate_lua_already_in_preset() {
        let plan = nfqws2_launch_plan(
            "/opt/zapret2/nfq2/nfqws2",
            "/res",
            "--lua-init=@lua/zapret-lib.lua\n--lua-init=@lua/zapret-antidpi.lua\n--lua-init=@lua/zapret-auto.lua\n",
            NFQWS2_DEFAULT_QNUM,
            NFQWS2_DESYNC_MARK,
        )
        .expect("план");

        let lua_count = plan
            .args
            .iter()
            .filter(|arg| arg.starts_with("--lua-init=@"))
            .count();
        assert_eq!(
            lua_count, 3,
            "стандартные lua не дублируются: {:?}",
            plan.args
        );
    }

    #[test]
    fn pidfile_follows_reference_scheme() {
        assert_eq!(
            nfqws2_pidfile("/opt/zapret2/nfq2/nfqws2"),
            "/var/run/nfqws2_1.pid"
        );
        assert_eq!(nfqws2_pidfile("/x/nfqws2"), "/var/run/nfqws2_1.pid");
    }

    // --- nft_rules_text --------------------------------------------------------

    /// Полные эталонные фильтры (`config.default`).
    fn default_filters() -> Nfqws2NftFilters {
        Nfqws2NftFilters {
            tcp_ports: Some("80,443".to_string()),
            udp_ports: Some("443".to_string()),
            tcp_first_packets_out: 20,
            tcp_first_packets_in: 10,
            udp_first_packets_out: 5,
            udp_first_packets_in: 3,
            ..Nfqws2NftFilters::default()
        }
    }

    #[test]
    fn nft_rules_text_contains_queue_rules_for_both_families() {
        let filters = default_filters();
        let text = nft_rules_text(
            NFQWS2_DEFAULT_QNUM,
            &["eth0"],
            &["eth1"],
            &[],
            &[],
            &filters,
        );

        assert!(text.contains("table inet zapret2"));
        // Идемпотентный преамбула-сброс и полное объявление структуры.
        assert!(text.starts_with(
            "table inet zapret2 { }\nflush table inet zapret2\ntable inet zapret2 {\n"
        ));
        assert!(text.contains("queue num 300 bypass"));
        assert!(
            text.contains(
                "meta nfproto ipv4 tcp dport { 80,443 } ct original packets 1-20 queue num 300 bypass"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "meta nfproto ipv6 tcp dport { 80,443 } ct original packets 1-20 queue num 300 bypass"
            ),
            "{text}"
        );
        // Входящие — реверсированные правила в prerouting.
        assert!(
            text.contains(
                "meta nfproto ipv4 tcp sport { 80,443 } ct reply packets 1-10 queue num 300 bypass"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "meta nfproto ipv4 udp dport { 443 } ct original packets 1-5 queue num 300 bypass"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "meta nfproto ipv4 udp sport { 443 } ct reply packets 1-3 queue num 300 bypass"
            ),
            "{text}"
        );
        assert!(
            text.contains("chain postrouting_hook { type filter hook postrouting priority 99;"),
            "{text}"
        );
        assert!(
            text.contains("chain prerouting_hook { type filter hook prerouting priority -99;"),
            "{text}"
        );
        assert!(
            !text.contains("meta mark set meta mark or 0x20000000"),
            "без постната метки в правиле очереди нет: {text}"
        );
    }

    #[test]
    fn nft_rules_text_postnat_sets_postnat_mark() {
        let filters = Nfqws2NftFilters {
            tcp_ports: Some("443".to_string()),
            tcp_first_packets_out: 20,
            tcp_first_packets_in: 10,
            postnat: true,
            ..Nfqws2NftFilters::default()
        };
        let text = nft_rules_text(300, &["eth0"], &[], &[], &[], &filters);

        assert!(
            text.contains(
                "meta nfproto ipv4 tcp dport { 443 } ct original packets 1-20 meta mark set meta mark or 0x20000000 queue num 300 bypass"
            ),
            "{text}"
        );
        // Входящее правило без метки и в prenat-цепочке.
        assert!(
            text.contains(
                "meta nfproto ipv4 tcp sport { 443 } ct reply packets 1-10 queue num 300 bypass"
            ),
            "{text}"
        );
        assert!(
            text.contains("chain postnat_hook { type filter hook postrouting priority 101;"),
            "{text}"
        );
        assert!(
            text.contains("chain prenat_hook { type filter hook prerouting priority -101;"),
            "{text}"
        );
    }

    #[test]
    fn nft_rules_text_hook_jumps_skip_own_marked_packets() {
        let filters = Nfqws2NftFilters {
            tcp_ports: Some("443".to_string()),
            tcp_first_packets_out: 20,
            ..Nfqws2NftFilters::default()
        };
        let text = nft_rules_text(300, &["eth0"], &["eth1"], &[], &[], &filters);

        assert!(
            text.contains(
                "meta mark and 0x40000000 == 0 oifname @wanif ip daddr != @nozapret jump postrouting"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "meta mark and 0x40000000 == 0 iifname @wanif ip saddr != @nozapret jump prerouting"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "meta mark and 0x40000000 == 0 oifname @wanif6 ip6 daddr != @nozapret6 jump postrouting"
            ),
            "{text}"
        );
        assert!(
            text.contains("set wanif { type ifname; elements = { \"eth0\" } }"),
            "{text}"
        );
        assert!(
            text.contains("set wanif6 { type ifname; elements = { \"eth1\" } }"),
            "{text}"
        );
    }

    #[test]
    fn nft_rules_text_nozapret_sets_declared_with_elements() {
        let filters = default_filters();
        let text = nft_rules_text(
            300,
            &[],
            &[],
            &["192.168.0.0/16", "10.0.0.0/8"],
            &["fe80::/10"],
            &filters,
        );

        assert!(
            text.contains(
                "set nozapret { type ipv4_addr; flags interval; elements = { 192.168.0.0/16, 10.0.0.0/8 } }"
            ),
            "{text}"
        );
        assert!(
            text.contains(
                "set nozapret6 { type ipv6_addr; flags interval; elements = { fe80::/10 } }"
            ),
            "{text}"
        );
        // Защита сгенерированных пакетов от INVALID conntrack (predefrag).
        assert!(text.contains("jump predefrag_nfqws"), "{text}");
        assert!(text.contains("notrack comment \"ipfrag\""), "{text}");
        assert!(text.contains("notrack comment \"datanoack\""), "{text}");
    }

    #[test]
    fn nft_rules_text_respects_disabled_families_and_missing_filters() {
        let filters = Nfqws2NftFilters {
            disable_ipv6: true,
            tcp_ports: Some("443".to_string()),
            tcp_first_packets_out: 20,
            ..Nfqws2NftFilters::default()
        };
        let text = nft_rules_text(300, &["eth0"], &["eth1"], &[], &[], &filters);

        assert!(text.contains("meta nfproto ipv4"));
        assert!(!text.contains("meta nfproto ipv6"), "{text}");
        assert!(!text.contains("elements { \"eth1\" }"));

        // Пустые порты и нулевые «первые пакеты» снимают правила очереди,
        // как в эталоне (`[ -n "$2" ] || return`, `!= 0`).
        let empty = Nfqws2NftFilters::default();
        assert!(
            !nft_rules_text(300, &["eth0"], &[], &[], &[], &empty).contains("queue num"),
            "без портов правил очереди нет"
        );
        let no_out = Nfqws2NftFilters {
            tcp_ports: Some("443".to_string()),
            tcp_first_packets_out: 0,
            tcp_first_packets_in: 10,
            ..Nfqws2NftFilters::default()
        };
        let text = nft_rules_text(300, &["eth0"], &[], &[], &[], &no_out);
        assert!(
            !text.contains("ct original packets"),
            "нулевые исходящие пакеты снимают post-правило: {text}"
        );
        assert!(text.contains("ct reply packets"), "{text}");
    }

    #[test]
    fn nft_rules_text_connmarker_only_in_postnat_mode() {
        let filters = Nfqws2NftFilters {
            tcp_ports: Some("443".to_string()),
            tcp_first_packets_out: 20,
            postnat: true,
            filter_ttl_expired_icmp: true,
            ..Nfqws2NftFilters::default()
        };
        let text = nft_rules_text(300, &["eth0"], &[], &[], &[], &filters);
        // CONNMARKER стоит в правиле очереди (postnat-режим).
        assert!(
            text.contains(
                "ct original packets 1-20 meta mark set meta mark or 0x20000000 ct mark set ct mark or 0x40000000 queue num"
            ),
            "{text}"
        );
        assert!(
            text.contains("icmp type time-exceeded ct state invalid drop"),
            "{text}"
        );

        let filters = Nfqws2NftFilters {
            tcp_ports: Some("443".to_string()),
            tcp_first_packets_out: 20,
            filter_ttl_expired_icmp: true,
            ..Nfqws2NftFilters::default()
        };
        let text = nft_rules_text(300, &["eth0"], &[], &[], &[], &filters);
        // Без постната: ct-правило в postrouting_hook, но не в правиле очереди.
        assert!(
            text.contains("mark and 0x40000000 != 0 ct mark set ct mark or 0x40000000"),
            "{text}"
        );
        assert!(
            !text.contains("packets 1-20 ct mark set"),
            "в правиле очереди маркера нет: {text}"
        );
    }

    #[test]
    fn reverse_filter_follows_reference_transform() {
        assert_eq!(
            nft_reverse_nfqws_filter("tcp dport 443 ct original packets 1-6"),
            "tcp sport 443 ct reply packets 1-6"
        );
        assert_eq!(
            nft_reverse_nfqws_filter("oifname @wanif ip daddr 1.2.3.4"),
            "iifname @wanif ip saddr 1.2.3.4"
        );
        assert_eq!(
            nft_reverse_nfqws_filter("mark and 0x40000000 == 0 udp dport 443"),
            "udp sport 443"
        );
    }
}
