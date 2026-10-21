//! Порт `src/winws_log_analyzer` (чистая часть) — разбор debug-лога winws2.
//!
//! Лог состоит из преамбулы (профили, hostlist/ipset) и повторяющихся
//! блоков `packet: id=N len=... outbound|inbound ...` … `packet: id=N
//! reinject ...|drop`. Поддерживается только Windows-формат (winws2);
//! Linux-формат nfqws намеренно не поддерживается — такие строки
//! попадают в `unrecognized_packet_lines`, чтобы дрейф формата был виден
//! в сводке.
//!
//! Qt-воркер (`WinwsLogParseWorker`) и страницы интерфейса — платформенные:
//! чтение файла и сигналы прогресса остаются у вызывающего слоя
//! ([`parser::parse_winws_log_stream`] принимает замыкания прогресса и
//! отмены).

pub mod filters;
pub mod models;
pub mod parser;
