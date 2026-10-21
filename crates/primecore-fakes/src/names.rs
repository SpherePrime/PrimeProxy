//! Имена blob-ов, которые знает сам winws2 (nfqws2), и аргументы-ссылки
//! на blob. Порт `src/fakes/names.py`.
//!
//! Это правила самого движка, а не данные реестра:
//!
//! - [`NFQWS2_BUILTIN_BLOBS`] nfqws2 загружает сам при старте
//!   (`load_const_blob_to_collection` в nfq2/nfqws.c). Повторное
//!   объявление `--blob=fake_default_tls:...` winws2 отвергает ошибкой
//!   «duplicate blob name», поэтому в реестре и в `--blob=` их быть не
//!   должно;
//! - [`BLOB_REFERENCE_ARG_NAMES`] — аргументы `--lua-desync`, значение
//!   которых является именем blob-а (или hex-литералом `0x..`);
//! - `--blob=ИМЯ:...` кладёт байты в глобальную переменную Lua с этим
//!   именем (`lua_init_blobs` в nfq2/lua.c), причём ДО констант и
//!   функций nfqws2. Поэтому имя своего фейка не должно совпадать:
//!   с ключевыми словами и стандартной библиотекой Lua — иначе фейк
//!   затрёт, например, `string` или `table`, и lua-скрипты сломаются; с
//!   константами и функциями nfqws2 (`lua_init_const` /
//!   `lua_init_functions` в nfq2/lua.c) — они затрут фейк. Имена из
//!   файлов `--lua-init` считаются отдельно, прямо из этих файлов
//!   ([`user::lua_init_names`]).

use std::collections::HashSet;
use std::path::Path;
use std::sync::LazyLock;

/// blob-ы, встроенные в сам движок nfqws2.
pub static NFQWS2_BUILTIN_BLOBS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ["fake_default_tls", "fake_default_http", "fake_default_quic"].into());

/// Аргументы `--lua-desync`, значением которых служит имя blob-а.
pub static BLOB_REFERENCE_ARG_NAMES: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| ["blob", "fake_blob", "pattern", "seqovl_pattern", "fallback"].into());

/// python `_LUA_KEYWORDS_AND_STDLIB`.
const LUA_KEYWORDS_AND_STDLIB: &str = "
and break do else elseif end false for function goto if in local nil not or
repeat return then true until while
_G _VERSION _ENV arg assert bit bit32 collectgarbage coroutine debug dofile
error ffi getfenv getmetatable io ipairs jit load loadfile loadstring math
module next os package pairs pcall print rawequal rawget rawlen rawset require
select setfenv setmetatable string table tonumber tostring type unpack utf8
xpcall
";

/// python `_NFQWS2_LUA_GLOBALS` — константы и функции nfqws2.
const NFQWS2_LUA_GLOBALS: &str = "
NFQWS2_VER NFQWS2_COMPAT_VER qnum divert_port desync_fwmark
DEFAULT_MSS ICMP6_DST_UNREACH ICMP6_DST_UNREACH_ADDR
ICMP6_DST_UNREACH_ADMIN ICMP6_DST_UNREACH_BEYONDSCOPE
ICMP6_DST_UNREACH_NOPORT ICMP6_DST_UNREACH_NOROUTE ICMP6_ECHO_REPLY
ICMP6_ECHO_REQUEST ICMP6_PACKET_TOO_BIG ICMP6_PARAM_PROB
ICMP6_PARAMPROB_HEADER ICMP6_PARAMPROB_NEXTHEADER ICMP6_PARAMPROB_OPTION
ICMP6_TIME_EXCEEDED ICMP6_TIME_EXCEED_REASSEMBLY ICMP6_TIME_EXCEED_TRANSIT
ICMP_BASE_LEN ICMP_DEST_UNREACH ICMP_ECHO ICMP_ECHOREPLY ICMP_INFO_REPLY
ICMP_INFO_REQUEST ICMP_PARAMETERPROB ICMP_REDIRECT ICMP_REDIRECT_HOST
ICMP_REDIRECT_NET ICMP_REDIRECT_TOSHOST ICMP_REDIRECT_TOSNET
ICMP_TIME_EXCEEDED ICMP_TIMESTAMP ICMP_TIMESTAMPREPLY ICMP_TIMXCEED_INTRANS
ICMP_TIMXCEED_REASS ICMP_UNREACH_FILTER_PROHIB ICMP_UNREACH_HOST
ICMP_UNREACH_HOST_PRECEDENCE ICMP_UNREACH_HOST_PROHIB
ICMP_UNREACH_HOST_UNKNOWN ICMP_UNREACH_NEEDFRAG ICMP_UNREACH_NET
ICMP_UNREACH_NET_PROHIB ICMP_UNREACH_NET_UNKNOWN ICMP_UNREACH_PORT
ICMP_UNREACH_PRECEDENCE_CUTOFF ICMP_UNREACH_PROTOCOL ICMP_UNREACH_SRCFAIL
ICMP_UNREACH_TOSHOST ICMP_UNREACH_TOSNET IP6_BASE_LEN IP6F_MORE_FRAG
IP_BASE_LEN IP_DF IP_FLAGMASK IP_MF IP_OFFMASK IPPROTO_AH IPPROTO_DSTOPTS
IPPROTO_ESP IPPROTO_FRAGMENT IPPROTO_HIP IPPROTO_HOPOPTS IPPROTO_ICMP
IPPROTO_ICMPV6 IPPROTO_IP IPPROTO_IPIP IPPROTO_IPV6 IPPROTO_MH IPPROTO_NONE
IPPROTO_ROUTING IPPROTO_SCTP IPPROTO_SHIM6 IPPROTO_TCP IPPROTO_UDP IP_RF
IPTOS_DSCP_MASK IPTOS_ECN_CE IPTOS_ECN_ECT0 IPTOS_ECN_ECT1 IPTOS_ECN_MASK
IPTOS_ECN_NOT_ECT IPV6_FLOWINFO_MASK IPV6_FLOWLABEL_MASK MLD_LISTENER_QUERY
MLD_LISTENER_REDUCTION MLD_LISTENER_REPORT ND_NEIGHBOR_ADVERT
ND_NEIGHBOR_SOLICIT ND_REDIRECT ND_ROUTER_ADVERT ND_ROUTER_SOLICIT
NFQWS2_COMPAT_VER TCP_BASE_LEN TCP_KIND_AO TCP_KIND_END TCP_KIND_FASTOPEN
TCP_KIND_MD5 TCP_KIND_MSS TCP_KIND_NOOP TCP_KIND_SACK TCP_KIND_SACK_PERM
TCP_KIND_SCALE TCP_KIND_TS TH_ACK TH_CWR TH_ECE TH_FIN TH_PUSH TH_RST
TH_SYN TH_URG UDP_BASE_LEN VERDICT_DROP VERDICT_MASK VERDICT_MODIFY
VERDICT_PASS VERDICT_PRESERVE_NEXT
b_ctrack_disable b_daemon b_debug b_ipcache_hostname b_server
aes aes_ctr aes_gcm band bcryptorandom bitand bitget bitlshift bitnot bitnot16
bitnot24 bitnot32 bitnot48 bitnot8 bitor bitrshift bitset bitxor bor brandom
brandom_az brandom_az09 bu16 bu24 bu32 bu48 bu8 bxor clock_getfloattime
clock_gettime conntrack_feed csum_icmp_fix csum_ip4_fix csum_tcp_fix
csum_udp_fix dissect dissect_icmphdr dissect_ip6hdr dissect_iphdr
dissect_tcphdr dissect_udphdr divint DLOG DLOG_CONDUP DLOG_ERR execution_plan
execution_plan_cancel get_ifaddrs getpid get_source_ip gettid gmtime
gunzip_end gunzip_inflate gunzip_init gzip_deflate gzip_end gzip_init hash
hkdf instance_cutoff localtime lua_cutoff memcpy ntop parse_hex pton
raw_packet rawsend rawsend_dissect reconstruct_dissect reconstruct_icmphdr
reconstruct_ip6hdr reconstruct_iphdr reconstruct_tcphdr reconstruct_udphdr
resolve_multi_pos resolve_pos resolve_range stat swap16 swap24 swap32 swap48
timegm timelocal timer_del timer_enum timer_info timer_set tls_mod u16 u16add
u24 u24add u32 u32add u48 u48add u8 u8add uname
";

/// python `NFQWS2_LUA_RESERVED_NAMES` — имена, которые `--blob=` занимать
/// не может.
pub static NFQWS2_LUA_RESERVED_NAMES: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    (LUA_KEYWORDS_AND_STDLIB
        .split_whitespace()
        .chain(NFQWS2_LUA_GLOBALS.split_whitespace()))
    .collect()
});

/// python `lua_init_names(install_root)` — функции и верхнеуровневые
/// глобалы файлов обязательного блока `--lua-init`
/// ([`primecore_profile::winws2_preset_source::WINWS2_LUA_INIT_PATHS`]).
/// Отсутствующий файл просто пропускается.
///
/// Имена — присваивания `ИМЯ =` в начале строки (не `==`) и объявления
/// `function ИМЯ(` (python: `_LUA_TOP_LEVEL_GLOBAL_RE` +
/// `_LUA_FUNCTION_RE`); сравнение имён потом без учёта регистра
/// ([`casefold_set`]).
#[must_use]
pub fn lua_init_names(install_root: &Path) -> HashSet<String> {
    let mut names: HashSet<String> = HashSet::new();
    for init_path in primecore_profile::winws2_preset_source::WINWS2_LUA_INIT_PATHS {
        let path = install_root.join(init_path);
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        collect_lua_names(&text, &mut names);
    }
    names
}

/// python `_casefold_set` — имена в нижнем регистре для сравнения
/// без учёта регистра.
#[must_use]
pub fn casefold_set<'a, I: Iterator<Item = &'a str>>(names: I) -> HashSet<String> {
    names.map(|name| name.to_lowercase()).collect()
}

/// Ищет присваивания `ИМЯ =` (в начале строки, не `==`) и объявления
/// `function ИМЯ(` (python: `_LUA_TOP_LEVEL_GLOBAL_RE`,
/// `_LUA_FUNCTION_RE`).
fn collect_lua_names(text: &str, out: &mut HashSet<String>) {
    for line in text.lines() {
        let trimmed = line.trim_start();
        // function ИМЯ(...) — с любым отступом.
        if let Some(rest) = trimmed.strip_prefix("function ") {
            let name = rest.split('(').next().unwrap_or("").trim();
            if is_lua_identifier(name) {
                out.insert(name.to_string());
            }
            continue;
        }
        // python: `^[A-Za-z_][A-Za-z0-9_]*\s*=(?!=)` — идентификатор строго
        // с первой позиции строки (отступа быть не должно), пробелы ПОСЛЕ
        // имени допустимы, `==` не считается.
        if line.starts_with([' ', '\t']) {
            continue;
        }
        let Some((name, after)) = line.split_once('=') else {
            continue;
        };
        if after.starts_with('=') {
            continue;
        }
        let name = name.trim();
        if is_lua_identifier(name) {
            out.insert(name.to_string());
        }
    }
}

/// Python-regex идентификатора Lua: `[A-Za-z_]\w*`.
fn is_lua_identifier(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_blobs_match_python() {
        // Эталон от python: NFQWS2_BUILTIN_BLOBS.
        for name in ["fake_default_tls", "fake_default_http", "fake_default_quic"] {
            assert!(NFQWS2_BUILTIN_BLOBS.contains(name));
        }
        assert_eq!(NFQWS2_BUILTIN_BLOBS.len(), 3);
    }

    #[test]
    fn blob_reference_args_match_python() {
        for name in ["blob", "fake_blob", "pattern", "seqovl_pattern", "fallback"] {
            assert!(BLOB_REFERENCE_ARG_NAMES.contains(name));
        }
        assert!(!BLOB_REFERENCE_ARG_NAMES.contains("desync"));
    }

    #[test]
    fn reserved_names_match_python() {
        // Эталон от python: длина словаря и отдельные имена из обеих частей.
        let expected: HashSet<&str> = LUA_KEYWORDS_AND_STDLIB
            .split_whitespace()
            .chain(NFQWS2_LUA_GLOBALS.split_whitespace())
            .collect();
        assert_eq!(NFQWS2_LUA_RESERVED_NAMES.len(), expected.len());
        assert!(NFQWS2_LUA_RESERVED_NAMES.contains("string"));
        assert!(NFQWS2_LUA_RESERVED_NAMES.contains("dissect"));
        assert!(NFQWS2_LUA_RESERVED_NAMES.contains("VERDICT_DROP"));
        assert!(NFQWS2_LUA_RESERVED_NAMES.contains("local")); // ключевое слово
        assert!(!NFQWS2_LUA_RESERVED_NAMES.contains("tls_google"));
    }

    #[test]
    fn lua_init_names_reads_assignments_and_functions() {
        let root = std::env::temp_dir().join(format!("primecore-fakes-lua-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("lua")).unwrap();
        std::fs::write(
            root.join("lua/custom_funcs.lua"),
            "FAKE_MARKER = 1\nfunction my_helper(arg) end\nlocal ok = true\ncmp == 2\nok2=3\n  indented = 5\n",
        )
        .unwrap();
        std::fs::write(root.join("lua/чужой.txt"), "не lua").unwrap();
        let names = lua_init_names(&root);
        assert!(names.contains("FAKE_MARKER"));
        assert!(names.contains("my_helper"));
        // python: `local ok = true` НЕ даёт имени (^ без \s* перед
        // идентификатором; "local" не следует сразу за "=").
        assert!(!names.contains("ok"));
        // `cmp == 2` — не присваивание (= в python-regex исключён).
        assert!(!names.contains("cmp"));
        // `ok2=3` — пробелы вокруг "=" не обязательны.
        assert!(names.contains("ok2"));
        // Отступ перед присваиванием python не ловит (^ без \s*).
        assert!(!names.contains("indented"));
        // Читается только фиксированный список WINWS2_LUA_INIT_PATHS.
        std::fs::write(root.join("lua/extra.lua"), "EXTRA_NAME = 1\n").unwrap();
        assert!(!lua_init_names(&root).contains("EXTRA_NAME"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
