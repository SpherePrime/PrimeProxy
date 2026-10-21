//! Порт `src/winws_runtime` — рантайм движков winws/winws2 (zapret).
//!
//! Переносятся чистые решения python-пакета: разбор стартового вывода,
//! диагностика тихого падения по коду выхода и логу, классификация сбоев
//! запуска и сборка командной строки из preset-файла.
//!
//! Платформенные действия (реальный запуск процесса, опрос служб Windows,
//! журналы Defender, антивирус) в крейт не входят: они идут через трейты
//! [`runner::ProcessSpawner`] и [`health::SystemProbes`]/[`health::SilentExitProbes`],
//! а здесь остаются решения — порядок аргументов, таблицы кодов ошибок
//! WinDivert, тексты причин и правила ретраев.
//!
//! PyQt6-интерфейс пакета (`winws_runtime.ui`-обёртки) в Rust не переносится.

pub mod commands;
pub mod engine;
pub mod health;
pub mod launch;
pub mod output;
pub mod restart;
pub mod runner;
pub mod runner_zapret1;
pub mod runner_zapret2;
pub mod spawn_failure;
pub mod windivert;
