//! Полные пути к системным утилитам Windows.
//!
//! Вызов по имени ищет программу в PATH, и при установленном Git Bash или
//! MSYS вместо `whoami.exe` из System32 запускается одноимённая утилита
//! coreutils с другим синтаксисом. Поэтому системные программы берутся из
//! `%SystemRoot%\System32` явно.

use std::path::PathBuf;
use std::process::Command;

fn system32() -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    PathBuf::from(root).join("System32")
}

/// Команда для утилиты из System32 (`whoami`, `taskkill`, `tasklist`…).
#[must_use]
pub fn system_command(name: &str) -> Command {
    Command::new(system32().join(format!("{name}.exe")))
}

/// Команда Windows PowerShell 5 с безопасными флагами запуска.
#[must_use]
pub fn powershell(script: &str) -> Command {
    let mut command = Command::new(
        system32()
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe"),
    );
    let script = format!("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; {script}");
    command.args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", &script]);
    command
}
