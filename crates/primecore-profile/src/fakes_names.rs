//! Порт `src/fakes/names.py` (вырезка для blob-объявлений) — правила
//! движка winws2, а не данные реестра. Полный кластер fakes — отдельно.

/// nfqws2 загружает при старте сам (`load_const_blob_to_collection`):
/// повторное объявление отвергается «duplicate blob name».
pub const NFQWS2_BUILTIN_BLOBS: [&str; 3] = [
    "fake_default_tls",
    "fake_default_http",
    "fake_default_quic",
];

/// Аргументы `--lua-desync`, значение которых — имя blob-а (или hex `0x..`).
pub const BLOB_REFERENCE_ARG_NAMES: [&str; 5] = [
    "blob",
    "fake_blob",
    "pattern",
    "seqovl_pattern",
    "fallback",
];

/// python frozenset-проверки: содержит.
pub fn blob_reference_arg_name(name: &str) -> bool {
    BLOB_REFERENCE_ARG_NAMES.contains(&name)
}

pub fn builtin_blob(name: &str) -> bool {
    NFQWS2_BUILTIN_BLOBS.contains(&name)
}
