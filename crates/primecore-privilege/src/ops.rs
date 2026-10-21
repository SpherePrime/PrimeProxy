//! Операции демон-помощника `privd`: настоящий привилегированный слой.
//!
//! Протокол: одна строка соединения = один JSON-запрос, одна строка =
//! один JSON-ответ. Поддерживаются операции:
//!
//! - `{"op":"ping"}` → `{"ok":true}`;
//! - `{"op":"nft","script":"…"}` → исполнить `nft -f -` (текст правил в
//!   stdin), ответ `{"ok":true,"output":"…"}` или `{"ok":false,"error":"…"}`;
//! - `{"op":"nft_delete","table":"…"}` → `nft delete table inet <table>`;
//!   отсутствие таблицы — не ошибка;
//! - `{"op":"daemon","exe":"…","args":[…],"cwd":"…","env":{…},"pidfile":"…"}`
//!   → породить демона (stdout/stderr наследуются — демон живёт дольше
//!   соединения), pid пишется в pidfile и запоминается; ответ
//!   `{"ok":true,"pid":N}`;
//! - `{"op":"kill","pid":N}` → завершить процесс (свои — `Child::kill`,
//!   чужие — `/bin/kill -TERM`);
//! - `{"op":"status","pid":N}` → `{"ok":true,"running":bool}`;
//! - `{"op":"dns_set","servers":["1.1.1.1",…],"ifname":"eth0"}` →
//!   `resolvectl dns <ifname> <серверы…>`; интерфейс обязателен —
//!   `resolvectl dns` без имени интерфейса список не меняет.
//!
//! Для совместимости с ранним клиентом (`connect_and_ping`) любая не-JSON
//! строка отвечает `{"ok":true}` — как старый «пинг».
//!
//! Исполнение внешних команд спрятано за трейтом [`CommandExecutor`]:
//! тесты подставляют фейк и не запускают настоящие привилегированные
//! команды. Обёртка над сокетом — трейт [`PrivilegedOps`]; бинарник
//! `privd` подставляет [`RealOps`].

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

// ─────────────────────────── протокол ─────────────────────────────────

/// Запрос демона: одна строка JSON с тегом `op`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum OpRequest {
    /// Проверка живости.
    Ping,
    /// Применить полный текст правил (`nft -f -`).
    Nft {
        /// Полный текст правил nftables.
        script: String,
    },
    /// Удалить таблицу `inet <table>` (отсутствие таблицы — не ошибка).
    NftDelete {
        /// Имя таблицы.
        table: String,
    },
    /// Породить демона; stdout/stderr наследуются от `privd`.
    Daemon {
        /// Полный путь к бинарнику.
        exe: String,
        /// Аргументы запуска.
        #[serde(default)]
        args: Vec<String>,
        /// Рабочий каталог запуска.
        cwd: String,
        /// Переменные окружения процесса.
        #[serde(default)]
        env: BTreeMap<String, String>,
        /// Путь pid-файла (туда пишется pid демона).
        pidfile: String,
    },
    /// Завершить процесс по pid.
    Kill {
        /// PID процесса.
        pid: u32,
    },
    /// Спросить, жив ли процесс.
    Status {
        /// PID процесса.
        pid: u32,
    },
    /// Задать DNS-серверы интерфейсу через `resolvectl dns`.
    DnsSet {
        /// Адреса DNS-серверов (порядок как в запросе).
        #[serde(default)]
        servers: Vec<String>,
        /// Имя сетевого интерфейса; `resolvectl dns` без него не работает.
        #[serde(default)]
        ifname: Option<String>,
    },
}

/// Разобрать строку-запрос. Не-JSON строка — не запрос: `None`
/// (совместимость: на неё демон отвечает `{"ok":true}`).
#[must_use]
pub fn parse_request(line: &str) -> Option<OpRequest> {
    serde_json::from_str(line.trim()).ok()
}

// ─────────────────────────── исполнитель команд ───────────────────────

/// Порождённый демон: pid и (у реального исполнителя) живой `Child`,
/// чтобы демон не превратился в зомби.
pub struct SpawnedDaemon {
    /// PID демона.
    pub pid: u32,
    /// Настоящий процесс (есть только у реального исполнителя).
    pub child: Option<Child>,
}

/// Исполнитель внешних команд. Трейт нужен, чтобы обработчик операций
/// можно было тестировать без настоящих привилегированных команд.
pub trait CommandExecutor: Send {
    /// Запустить команду; `stdin` (если задан) уходит на вход, собранные
    /// stdout+stderr возвращаются одной строкой. Ненулевой код возврата —
    /// `Err` с тем же текстом.
    ///
    /// # Errors
    /// Ошибка запуска/ожидания или ненулевой код возврата — человеко-читаемый
    /// текст.
    fn run(&self, exe: &str, args: &[String], stdin: Option<&str>) -> Result<String, String>;

    /// Породить демона: stdout/stderr наследуются (демон живёт дольше
    /// соединения), stdin — пусто. Возвращает pid.
    ///
    /// # Errors
    /// Ошибка запуска — человеко-читаемый текст.
    fn spawn_daemon(
        &self,
        exe: &str,
        args: &[String],
        cwd: &str,
        env: &BTreeMap<String, String>,
    ) -> Result<SpawnedDaemon, String>;

    /// Завершить чужой процесс (`/bin/kill -TERM`); отсутствие процесса —
    /// не ошибка.
    ///
    /// # Errors
    /// Ошибка запуска `kill` или другой сбой — человеко-читаемый текст.
    fn kill_pid(&self, pid: u32) -> Result<(), String>;

    /// Жив ли процесс (не из наших): `/bin/kill -0`.
    ///
    /// # Errors
    /// Ошибка запуска `kill` — человеко-читаемый текст.
    fn pid_running(&self, pid: u32) -> Result<bool, String>;
}

/// Реальный исполнитель: `std::process::Command`.
#[derive(Debug, Clone, Copy, Default)]
pub struct RealExecutor;

impl CommandExecutor for RealExecutor {
    fn run(&self, exe: &str, args: &[String], stdin: Option<&str>) -> Result<String, String> {
        let mut command = Command::new(exe);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stdin.is_some() {
            command.stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("не удалось запустить {exe}: {error}"))?;
        if let Some(input) = stdin {
            let mut pipe = child
                .stdin
                .take()
                .ok_or_else(|| format!("stdin {exe} недоступен"))?;
            pipe.write_all(input.as_bytes())
                .and_then(|()| pipe.flush())
                .map_err(|error| format!("не удалось передать данные в {exe}: {error}"))?;
            // drop(pipe) закрывает stdin — команда видит конец ввода.
        }
        let output = child
            .wait_with_output()
            .map_err(|error| format!("{exe} не дождался ответа: {error}"))?;
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if output.status.success() {
            Ok(combined)
        } else {
            Err(combined)
        }
    }

    fn spawn_daemon(
        &self,
        exe: &str,
        args: &[String],
        cwd: &str,
        env: &BTreeMap<String, String>,
    ) -> Result<SpawnedDaemon, String> {
        let mut command = Command::new(exe);
        command
            .args(args)
            .current_dir(cwd)
            // Вывод демона уходит в stdout/stderr самого privd: демон живёт
            // дольше соединения, читать его трубы нельзя.
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        for (key, value) in env {
            command.env(key, value);
        }
        let child = command
            .spawn()
            .map_err(|error| format!("не удалось запустить {exe}: {error}"))?;
        let pid = child.id();
        Ok(SpawnedDaemon {
            pid,
            child: Some(child),
        })
    }

    fn kill_pid(&self, pid: u32) -> Result<(), String> {
        let output = Command::new("/bin/kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .map_err(|error| format!("не удалось запустить kill: {error}"))?;
        if output.status.success() || no_such_process(&output.stderr) {
            Ok(())
        } else {
            Err(format!(
                "kill {pid}: {}",
                text_or_no_details(&output.stderr)
            ))
        }
    }

    fn pid_running(&self, pid: u32) -> Result<bool, String> {
        let status = Command::new("/bin/kill")
            .arg("-0")
            .arg(pid.to_string())
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|error| format!("не удалось запустить kill: {error}"))?;
        Ok(status.success())
    }
}

/// `true`, если `kill` сообщил об отсутствии процесса (idempotent-убийство).
fn no_such_process(stderr: &[u8]) -> bool {
    String::from_utf8_lossy(stderr)
        .to_lowercase()
        .contains("no such process")
}

/// Текст потера одной строкой; пустой — «нет пояснений».
fn text_or_no_details(bytes: &[u8]) -> String {
    let trimmed = String::from_utf8_lossy(bytes).trim().to_string();
    if trimmed.is_empty() {
        "нет пояснений".to_string()
    } else {
        trimmed
    }
}

/// `true`, если nft сообщил об отсутствии таблицы (idempotent-удаление).
#[must_use]
pub fn nft_table_missing(output: &str) -> bool {
    let text = output.to_lowercase();
    text.contains("no such file") || text.contains("not found") || text.contains("no such table")
}

// ─────────────────────────── обработчик операций ──────────────────────

/// Аргументы установки DNS (`resolvectl dns IFACE SRV1 SRV2…`).
///
/// Имя интерфейса обязательно: `resolvectl dns` без интерфейса только
/// показывает текущие серверы, а не задаёт их.
///
/// # Errors
/// Интерфейс не указан или список серверов пуст — текст ошибки.
pub fn build_dns_set_args(ifname: Option<&str>, servers: &[String]) -> Result<Vec<String>, String> {
    let Some(ifname) = ifname.map(str::trim).filter(|name| !name.is_empty()) else {
        return Err("интерфейс не указан: resolvectl dns требует имя интерфейса".to_string());
    };
    let servers: Vec<&str> = servers
        .iter()
        .map(|server| server.trim())
        .filter(|server| !server.is_empty())
        .collect();
    if servers.is_empty() {
        return Err("список DNS-серверов пуст".to_string());
    }
    let mut args = vec!["dns".to_string(), ifname.to_string()];
    args.extend(servers.iter().map(|server| (*server).to_string()));
    Ok(args)
}

/// Обработчик операций демона: разбор запроса + исполнение через
/// [`CommandExecutor`]. Свои демоны (запущенные через `op daemon`)
/// запоминаются по pid-файлу, чтобы `kill`/`status` работали без внешних
/// вызовов и чтобы порождённые процессы не оставались зомби.
pub struct Ops<E: CommandExecutor> {
    executor: E,
    daemons: Mutex<HashMap<String, SpawnedDaemon>>,
}

impl<E: CommandExecutor> Ops<E> {
    /// Новый обработчик с заданным исполнителем команд.
    #[must_use]
    pub fn new(executor: E) -> Self {
        Self {
            executor,
            daemons: Mutex::new(HashMap::new()),
        }
    }

    /// Обработать одну строку-запрос, вернуть строку-ответ (без `\n`).
    #[must_use]
    pub fn dispatch(&mut self, request: &str) -> String {
        let trimmed = request.trim();
        // Не-JSON строка (в том числе пустая) — старое поведение «пинга».
        if serde_json::from_str::<serde_json::Value>(trimmed).is_err() {
            return ok_line(json!({ "ok": true }));
        }
        // JSON есть, но на запрос не похож — ошибка разбора.
        let Some(parsed) = parse_request(trimmed) else {
            let error =
                serde_json::from_str::<OpRequest>(trimmed).expect_err("разбор уже провален выше");
            return error_line(format!("не удалось разобрать запрос: {error}"));
        };
        match parsed {
            OpRequest::Ping => ok_line(json!({ "ok": true })),
            OpRequest::Nft { script } => self.op_nft(&script),
            OpRequest::NftDelete { table } => self.op_nft_delete(&table),
            OpRequest::Daemon {
                exe,
                args,
                cwd,
                env,
                pidfile,
            } => self.op_daemon(&exe, &args, &cwd, &env, &pidfile),
            OpRequest::Kill { pid } => self.op_kill(pid),
            OpRequest::Status { pid } => self.op_status(pid),
            OpRequest::DnsSet { servers, ifname } => self.op_dns_set(ifname.as_deref(), &servers),
        }
    }

    fn op_nft(&self, script: &str) -> String {
        let args = vec!["-f".to_string(), "-".to_string()];
        match self.executor.run("nft", &args, Some(script)) {
            Ok(output) => ok_line(json!({ "ok": true, "output": output })),
            Err(error) => error_line(error),
        }
    }

    fn op_nft_delete(&self, table: &str) -> String {
        let args = vec![
            "delete".to_string(),
            "table".to_string(),
            "inet".to_string(),
            table.to_string(),
        ];
        match self.executor.run("nft", &args, None) {
            Ok(output) => ok_line(json!({ "ok": true, "output": output })),
            Err(error) => {
                // Отсутствие таблицы — норма для idempotent-удаления.
                if nft_table_missing(&error) {
                    ok_line(json!({ "ok": true, "output": error }))
                } else {
                    error_line(error)
                }
            }
        }
    }

    fn op_daemon(
        &mut self,
        exe: &str,
        args: &[String],
        cwd: &str,
        env: &BTreeMap<String, String>,
        pidfile: &str,
    ) -> String {
        match self.executor.spawn_daemon(exe, args, cwd, env) {
            Ok(spawned) => {
                let pid = spawned.pid;
                self.daemons
                    .lock()
                    .expect("таблица демонов не отравлена")
                    .insert(pidfile.to_string(), spawned);
                write_pidfile(pidfile, pid);
                ok_line(json!({ "ok": true, "pid": pid }))
            }
            Err(error) => error_line(error),
        }
    }

    fn op_kill(&mut self, pid: u32) -> String {
        let key = self
            .daemons
            .lock()
            .expect("таблица демонов не отравлена")
            .iter()
            .find(|(_, entry)| entry.pid == pid)
            .map(|(key, _)| key.clone());
        if let Some(key) = key {
            let entry = self
                .daemons
                .lock()
                .expect("таблица демонов не отравлена")
                .remove(&key);
            if let Some(mut child) = entry.and_then(|entry| entry.child) {
                let result = child
                    .kill()
                    .map_err(|error| format!("не удалось завершить процесс: {error}"))
                    .and_then(|()| {
                        child
                            .wait()
                            .map(|_status| ())
                            .map_err(|error| format!("не дождались завершения: {error}"))
                    });
                return match result {
                    Ok(()) => ok_line(json!({ "ok": true })),
                    Err(error) => error_line(error),
                };
            }
        }
        match self.executor.kill_pid(pid) {
            Ok(()) => ok_line(json!({ "ok": true })),
            Err(error) => error_line(error),
        }
    }

    fn op_status(&mut self, pid: u32) -> String {
        let mut daemons = self.daemons.lock().expect("таблица демонов не отравлена");
        let entry = daemons.values_mut().find(|entry| entry.pid == pid);
        let running = match entry {
            Some(SpawnedDaemon {
                child: Some(child), ..
            }) => match child.try_wait() {
                Ok(Some(_status)) => false,
                Ok(None) => true,
                Err(_) => self.executor.pid_running(pid).unwrap_or(false),
            },
            _ => self.executor.pid_running(pid).unwrap_or(false),
        };
        ok_line(json!({ "ok": true, "running": running }))
    }

    /// `resolvectl dns <ifname> <серверы…>`: изменения DNS — привилегированная
    /// операция, потому и живёт здесь, а не в сервере.
    fn op_dns_set(&self, ifname: Option<&str>, servers: &[String]) -> String {
        match build_dns_set_args(ifname, servers) {
            Ok(args) => match self.executor.run("resolvectl", &args, None) {
                Ok(output) => ok_line(json!({ "ok": true, "output": output })),
                Err(error) => error_line(error),
            },
            Err(error) => error_line(error),
        }
    }
}

/// Пишет pid демона в pid-файл (ошибка не проваливает операцию: pid
/// и так возвращается в ответе).
fn write_pidfile(pidfile: &str, pid: u32) {
    if pidfile.trim().is_empty() {
        return;
    }
    if let Some(parent) = std::path::Path::new(pidfile).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let _ = std::fs::write(pidfile, format!("{pid}\n"));
}

/// Строка успешного ответа.
fn ok_line(value: Value) -> String {
    value.to_string()
}

/// Строка ответа с ошибкой.
fn error_line(error: String) -> String {
    json!({ "ok": false, "error": error }).to_string()
}

/// Руки демона: обработка строк соединения. Бинарник `privd` подставляет
/// [`RealOps`], тесты — свои фейки.
pub trait PrivilegedOps: Send {
    /// Обработать одну строку-запрос, вернуть строку-ответ (без `\n`).
    fn handle(&mut self, request: &str) -> String;
}

impl<E: CommandExecutor> PrivilegedOps for Ops<E> {
    fn handle(&mut self, request: &str) -> String {
        self.dispatch(request)
    }
}

/// Руки живого демона: реальный исполнитель команд.
pub type RealOps = Ops<RealExecutor>;

// ─────────────────── тестовая поддержка (для всего крейта) ────────────

#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    /// Запись вызова `run`: команда, аргументы, stdin.
    pub type RunRecord = (String, Vec<String>, Option<String>);

    /// Фейковый исполнитель: команды не запускает, только запоминает.
    pub struct FakeExecutor {
        pub runs: Mutex<Vec<RunRecord>>,
        pub run_result: Mutex<Option<Result<String, String>>>,
        pub spawns: Mutex<Vec<String>>,
        pub spawn_result: Option<Result<u32, String>>,
        pub kill_calls: Mutex<Vec<u32>>,
        pub running: Mutex<HashMap<u32, bool>>,
    }

    impl FakeExecutor {
        pub fn new() -> Self {
            Self {
                runs: Mutex::new(Vec::new()),
                run_result: Mutex::new(Some(Ok("правила применены\n".to_string()))),
                spawns: Mutex::new(Vec::new()),
                spawn_result: Some(Ok(7)),
                kill_calls: Mutex::new(Vec::new()),
                running: Mutex::new(HashMap::new()),
            }
        }

        pub fn failing_run(message: &str) -> Self {
            let fake = Self::new();
            *fake.run_result.lock().unwrap() = Some(Err(message.to_string()));
            fake
        }
    }

    impl CommandExecutor for FakeExecutor {
        fn run(&self, exe: &str, args: &[String], stdin: Option<&str>) -> Result<String, String> {
            self.runs.lock().unwrap().push((
                exe.to_string(),
                args.to_vec(),
                stdin.map(str::to_string),
            ));
            self.run_result
                .lock()
                .unwrap()
                .clone()
                .expect("результат run задан")
        }

        fn spawn_daemon(
            &self,
            exe: &str,
            _args: &[String],
            _cwd: &str,
            _env: &BTreeMap<String, String>,
        ) -> Result<SpawnedDaemon, String> {
            self.spawns.lock().unwrap().push(exe.to_string());
            match &self.spawn_result {
                Some(Ok(pid)) => {
                    self.running.lock().unwrap().insert(*pid, true);
                    Ok(SpawnedDaemon {
                        pid: *pid,
                        child: None,
                    })
                }
                Some(Err(error)) => Err(error.clone()),
                None => Err("spawn сорвался".to_string()),
            }
        }

        fn kill_pid(&self, pid: u32) -> Result<(), String> {
            self.kill_calls.lock().unwrap().push(pid);
            self.running.lock().unwrap().insert(pid, false);
            Ok(())
        }

        fn pid_running(&self, pid: u32) -> Result<bool, String> {
            Ok(self
                .running
                .lock()
                .unwrap()
                .get(&pid)
                .copied()
                .unwrap_or(false))
        }
    }

    /// tmpdir с уникальным именем.
    pub fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "primecore-privilege-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("часы идут")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("tmpdir создан");
        dir
    }

    /// Сервер-нитка: обслуживает до `connections` соединений (каждое —
    /// сколько угодно строк), потом завершается.
    pub fn serve_bounded(
        listener: UnixListener,
        mut ops: Box<dyn PrivilegedOps>,
        connections: usize,
    ) {
        std::thread::spawn(move || {
            for (served, stream) in listener.incoming().enumerate() {
                if served >= connections {
                    break;
                }
                let Ok(mut stream) = stream else { break };
                let mut reader = BufReader::new(stream.try_clone().expect("клон сокета"));
                let mut line = String::new();
                loop {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {
                            let reply = ops.handle(&line);
                            if writeln!(stream, "{reply}").is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
    }
}

// ─────────────────────────── тесты ────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::tests_support::{serve_bounded, tmpdir, FakeExecutor};
    use super::*;
    use crate::client;
    use serde_json::json;
    use std::os::unix::net::UnixListener;

    fn value(line: &str) -> Value {
        serde_json::from_str(line).expect("ответ всегда JSON")
    }

    #[test]
    fn parse_request_reads_every_operation() {
        assert_eq!(parse_request(r#"{"op":"ping"}"#), Some(OpRequest::Ping));
        assert_eq!(
            parse_request(r#"{"op":"nft","script":"add table inet t"}"#),
            Some(OpRequest::Nft {
                script: "add table inet t".to_string()
            })
        );
        assert_eq!(
            parse_request(r#"{"op":"nft_delete","table":"zapret2"}"#),
            Some(OpRequest::NftDelete {
                table: "zapret2".to_string()
            })
        );
        assert_eq!(
            parse_request(
                r#"{"op":"daemon","exe":"/bin/nfqws2","args":["--qnum=300"],
                    "cwd":"/opt","env":{"MARK":"0x40000000"},"pidfile":"/run/n.pid"}"#
            ),
            Some(OpRequest::Daemon {
                exe: "/bin/nfqws2".to_string(),
                args: vec!["--qnum=300".to_string()],
                cwd: "/opt".to_string(),
                env: BTreeMap::from([("MARK".to_string(), "0x40000000".to_string())]),
                pidfile: "/run/n.pid".to_string(),
            })
        );
        assert_eq!(
            parse_request(r#"{"op":"kill","pid":42}"#),
            Some(OpRequest::Kill { pid: 42 })
        );
        assert_eq!(
            parse_request(r#"{"op":"status","pid":42}"#),
            Some(OpRequest::Status { pid: 42 })
        );
        // Дефолты: args/env можно не присылать.
        assert_eq!(
            parse_request(r#"{"op":"daemon","exe":"/bin/x","cwd":"/","pidfile":"/run/x.pid"}"#),
            Some(OpRequest::Daemon {
                exe: "/bin/x".to_string(),
                args: Vec::new(),
                cwd: "/".to_string(),
                env: BTreeMap::new(),
                pidfile: "/run/x.pid".to_string(),
            })
        );
    }

    #[test]
    fn parse_request_rejects_garbage() {
        assert_eq!(parse_request("ping"), None);
        assert_eq!(parse_request(""), None);
        assert_eq!(parse_request(r#"{"op":"nft"}"#), None);
        assert_eq!(parse_request(r#"{"op":"wat"}"#), None);
        assert_eq!(parse_request(r#"{"op":"kill","pid":-1}"#), None);
    }

    #[test]
    fn non_json_line_answers_ok_for_ping_compatibility() {
        let mut ops = Ops::new(FakeExecutor::new());
        for line in ["ping", "hello privd", "   ", ""] {
            let reply = value(&ops.dispatch(line));
            assert_eq!(reply["ok"], true, "строка {line:?}: {reply}");
            assert!(reply.get("error").is_none());
        }
    }

    #[test]
    fn malformed_json_request_answers_error() {
        let mut ops = Ops::new(FakeExecutor::new());
        let reply = value(&ops.dispatch(r#"{"op":"nft"}"#));
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().is_some_and(|e| !e.is_empty()));
    }

    #[test]
    fn nft_op_feeds_script_to_stdin() {
        let mut ops = Ops::new(FakeExecutor::new());
        let reply = value(&ops.dispatch(r#"{"op":"nft","script":"add table inet t"}"#));
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["output"], "правила применены\n");
        let runs = ops.executor.runs.lock().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].0, "nft");
        assert_eq!(runs[0].1, vec!["-f".to_string(), "-".to_string()]);
        assert_eq!(runs[0].2.as_deref(), Some("add table inet t"));
    }

    #[test]
    fn nft_failure_answers_error() {
        let mut ops = Ops::new(FakeExecutor::failing_run("Error: syntax error"));
        let reply = value(&ops.dispatch(r#"{"op":"nft","script":"мусор"}"#));
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "Error: syntax error");
    }

    #[test]
    fn nft_delete_missing_table_is_not_an_error() {
        let mut ops = Ops::new(FakeExecutor::failing_run(
            "Error: No such file or directory",
        ));
        let reply = value(&ops.dispatch(r#"{"op":"nft_delete","table":"zapret2"}"#));
        assert_eq!(reply["ok"], true, "{reply}");
        // Другая ошибка удаления — ошибка.
        let mut ops = Ops::new(FakeExecutor::failing_run("Error: permission denied"));
        let reply = value(&ops.dispatch(r#"{"op":"nft_delete","table":"zapret2"}"#));
        assert_eq!(reply["ok"], false);
    }

    #[test]
    fn daemon_spawn_kill_status_flow() {
        let dir = tmpdir("daemon-flow");
        let pidfile = dir.join("nfqws2.pid");
        let pidfile_json = serde_json::to_string(&pidfile.to_string_lossy()).expect("путь");
        let mut ops = Ops::new(FakeExecutor::new());
        let request = format!(
            r#"{{"op":"daemon","exe":"/opt/nfqws2","args":["--qnum=300"],
                "cwd":"/opt","env":{{}},"pidfile":{pidfile_json}}}"#
        );
        let reply = value(&ops.dispatch(&request));
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["pid"], 7);

        // pid-файл записан.
        let pid_text = std::fs::read_to_string(&pidfile).expect("pid-файл");
        assert_eq!(pid_text.trim(), "7");

        let reply = value(&ops.dispatch(r#"{"op":"status","pid":7}"#));
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["running"], true);

        let reply = value(&ops.dispatch(r#"{"op":"kill","pid":7}"#));
        assert_eq!(reply["ok"], true);

        let reply = value(&ops.dispatch(r#"{"op":"status","pid":7}"#));
        assert_eq!(reply["running"], false);
        assert_eq!(*ops.executor.kill_calls.lock().unwrap(), vec![7]);
    }

    #[test]
    fn daemon_spawn_failure_answers_error() {
        let mut fake = FakeExecutor::new();
        fake.spawn_result = None;
        let mut ops = Ops::new(fake);
        let reply = value(&ops.dispatch(
            r#"{"op":"daemon","exe":"/opt/nfqws2","args":[],"cwd":"/opt","env":{},"pidfile":"/run/n.pid"}"#,
        ));
        assert_eq!(reply["ok"], false);
        assert_eq!(reply["error"], "spawn сорвался");
    }

    #[test]
    fn kill_and_status_of_foreign_pid_go_to_executor() {
        let mut ops = Ops::new(FakeExecutor::new());
        ops.executor.running.lock().unwrap().insert(99, true);
        let reply = value(&ops.dispatch(r#"{"op":"kill","pid":99}"#));
        assert_eq!(reply["ok"], true);
        assert_eq!(*ops.executor.kill_calls.lock().unwrap(), vec![99]);

        let reply = value(&ops.dispatch(r#"{"op":"status","pid":99}"#));
        assert_eq!(reply["running"], false);
    }

    #[test]
    fn nft_table_missing_recognizes_nft_phrases() {
        assert!(nft_table_missing("Error: No such file or directory"));
        assert!(nft_table_missing("нет такой таблицы: no such table"));
        assert!(!nft_table_missing("Error: permission denied"));
    }

    // ── живой unix-сокет: клиент ↔ фейковые руки ─────────────────────

    struct EchoOps {
        prefix: String,
    }

    impl PrivilegedOps for EchoOps {
        fn handle(&mut self, request: &str) -> String {
            format!(
                "{}{}}}",
                self.prefix,
                serde_json::to_string(request.trim()).expect("строка всегда сериализуется")
            )
        }
    }

    #[test]
    fn request_roundtrip_over_real_socket() {
        let dir = tmpdir("roundtrip");
        let sock_path = dir.join("test.sock");
        let listener = UnixListener::bind(&sock_path).expect("сокет привязан");
        serve_bounded(
            listener,
            Box::new(EchoOps {
                prefix: "{\"ok\":true,\"echo\":".to_string(),
            }),
            4,
        );

        let sock = sock_path.to_string_lossy().into_owned();
        let reply = client::request(&sock, r#"{"op":"ping"}"#).expect("ответ");
        assert_eq!(
            serde_json::from_str::<Value>(&reply).expect("JSON"),
            json!({"ok": true, "echo": "{\"op\":\"ping\"}"})
        );
        // Несколько запросов подряд — каждый в своём соединении.
        let reply = client::request(&sock, "старый пинг").expect("ответ");
        assert!(serde_json::from_str::<Value>(&reply).is_ok());

        // connect_and_ping: сервер отвечает ok:true на любую строку.
        client::connect_and_ping(&sock).expect("пинг прошёл");
    }

    #[test]
    fn request_fails_when_socket_is_absent() {
        let dir = tmpdir("absent");
        let missing = dir.join("нет-такого.sock");
        let error = client::request(&missing.to_string_lossy(), r#"{"op":"ping"}"#)
            .expect_err("сокета нет");
        assert!(error.contains("не удалось подключиться"), "{error}");
    }

    #[test]
    fn request_talks_to_real_ops_handler_over_socket() {
        let dir = tmpdir("real-ops");
        let sock_path = dir.join("ops.sock");
        let listener = UnixListener::bind(&sock_path).expect("сокет привязан");
        serve_bounded(listener, Box::new(Ops::new(FakeExecutor::new())), 2);

        let sock = sock_path.to_string_lossy().into_owned();
        let reply = value(
            &client::request(&sock, r#"{"op":"nft","script":"add table inet t"}"#)
                .expect("ответ nft"),
        );
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["output"], "правила применены\n");

        let reply =
            value(&client::request(&sock, r#"{"op":"status","pid":1234}"#).expect("ответ status"));
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["running"], false);
    }

    #[test]
    fn build_dns_set_args_requires_interface_and_servers() {
        let servers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        assert_eq!(
            build_dns_set_args(Some("eth0"), &servers).expect("аргументы собраны"),
            vec![
                "dns".to_string(),
                "eth0".to_string(),
                "1.1.1.1".to_string(),
                "8.8.8.8".to_string()
            ]
        );
        // Без интерфейса resolvectl dns список не задаёт — отказ.
        let error = build_dns_set_args(None, &servers).expect_err("нет интерфейса");
        assert!(error.contains("интерфейс"), "{error}");
        // Пустое имя интерфейса — то же, что отсутствующее.
        assert!(build_dns_set_args(Some("  "), &servers).is_err());
        // Пустой список серверов — нечего задавать.
        let error = build_dns_set_args(Some("eth0"), &[]).expect_err("серверов нет");
        assert!(error.contains("пуст"), "{error}");
        // Пустые и неаккуратные элементы отфильтровываются, имя триммится.
        let messy = vec!["  ".to_string(), " 1.0.0.1 ".to_string()];
        assert_eq!(
            build_dns_set_args(Some(" wlan0 "), &messy).expect("аргументы собраны"),
            vec![
                "dns".to_string(),
                "wlan0".to_string(),
                "1.0.0.1".to_string()
            ]
        );
    }

    #[test]
    fn dns_set_op_runs_resolvectl_with_interface() {
        let mut ops = Ops::new(FakeExecutor::new());
        let reply = value(
            &ops.dispatch(r#"{"op":"dns_set","servers":["1.1.1.1","8.8.8.8"],"ifname":"eth0"}"#),
        );
        assert_eq!(reply["ok"], true);
        let runs = ops.executor.runs.lock().unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].0, "resolvectl");
        assert_eq!(
            runs[0].1,
            vec![
                "dns".to_string(),
                "eth0".to_string(),
                "1.1.1.1".to_string(),
                "8.8.8.8".to_string()
            ]
        );
        assert_eq!(runs[0].2, None);
    }

    #[test]
    fn dns_set_op_answers_error_without_interface() {
        let mut ops = Ops::new(FakeExecutor::new());
        let reply = value(&ops.dispatch(r#"{"op":"dns_set","servers":["1.1.1.1"]}"#));
        assert_eq!(reply["ok"], false);
        assert!(reply["error"]
            .as_str()
            .is_some_and(|error| error.contains("интерфейс")));
        // Команда не запускалась.
        assert!(ops.executor.runs.lock().unwrap().is_empty());
    }
}
