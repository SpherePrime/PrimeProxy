//! Команды запуска/остановки/перезапуска DPI как чистые планы.
//!
//! Порт тонкой обёртки `winws_runtime/runtime/commands.py`. Python-версия —
//! это диспетчеризация к объекту-владельцу рантайма (`launch_runtime`),
//! связанному с QThread. Здесь остаётся сама дисциплина команд: команда без
//! владельца не выполняется и возвращает `false`, параметры нормализуются
//! до вызова, а владелец описан трейтом [`LaunchRuntimeOwner`].
//!
//! PyQt-инициализации (`init_*`) и координатор пресетов — это сборка
//! Qt-объектов, в крейт они не переносятся.

/// Владелец рантайма запуска DPI (python `runtime_owner`).
///
/// Реализация живёт в приложении; в тестах — записи вызовов.
pub trait LaunchRuntimeOwner {
    /// python `runtime_owner.is_running()`.
    fn is_running(&self) -> bool;

    /// python `runtime_owner.start_dpi_async(...)`.
    fn start_dpi(&mut self, command: StartDpiCommand);

    /// python `runtime_owner.stop_dpi_async(...)`.
    fn stop_dpi(&mut self, command: StopDpiCommand);

    /// python `runtime_owner.restart_dpi_async(...)`.
    fn restart_dpi(&mut self, command: RestartDpiCommand);

    /// python `runtime_owner.switch_presets_async(method)`.
    fn switch_presets(&mut self, method: Option<&str>);

    /// python `runtime_owner.stop_and_exit_async(on_stopped)`.
    fn stop_and_exit(&mut self);

    /// python `runtime_owner.cleanup_threads()`.
    fn cleanup_threads(&mut self);
}

/// Параметры python `start_dpi_async`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartDpiCommand {
    pub selected_mode: Option<String>,
    pub launch_method: Option<String>,
    pub skip_conflict_prompt: bool,
    pub startup_autostart: bool,
}

/// Параметры python `stop_dpi_async`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StopDpiCommand {
    pub force_cleanup: bool,
    pub cleanup_services: bool,
}

/// Параметры python `restart_dpi_async`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestartDpiCommand {
    pub force_full_stop: bool,
    pub target_launch_method: Option<String>,
}

/// python `is_dpi_running`: без владельца DPI не считается запущенным.
#[must_use]
pub fn is_dpi_running(owner: Option<&dyn LaunchRuntimeOwner>) -> bool {
    owner.is_some_and(|owner| owner.is_running())
}

/// python `start_dpi_async`: `false` — владельца нет.
pub fn start_dpi(owner: Option<&mut dyn LaunchRuntimeOwner>, command: StartDpiCommand) -> bool {
    match owner {
        Some(owner) => {
            owner.start_dpi(command);
            true
        }
        None => false,
    }
}

/// python `stop_dpi_async`: `false` — владельца нет.
pub fn stop_dpi(owner: Option<&mut dyn LaunchRuntimeOwner>, command: StopDpiCommand) -> bool {
    match owner {
        Some(owner) => {
            owner.stop_dpi(command);
            true
        }
        None => false,
    }
}

/// python `restart_dpi_async`: `false` — владельца нет.
pub fn restart_dpi(owner: Option<&mut dyn LaunchRuntimeOwner>, command: RestartDpiCommand) -> bool {
    match owner {
        Some(owner) => {
            owner.restart_dpi(command);
            true
        }
        None => false,
    }
}

/// python `switch_presets_async`: `false` — владельца нет.
pub fn switch_presets(owner: Option<&mut dyn LaunchRuntimeOwner>, method: Option<&str>) -> bool {
    match owner {
        Some(owner) => {
            owner.switch_presets(method);
            true
        }
        None => false,
    }
}

/// python `stop_and_exit_async`: `false` — владельца нет.
pub fn stop_and_exit(owner: Option<&mut dyn LaunchRuntimeOwner>) -> bool {
    match owner {
        Some(owner) => {
            owner.stop_and_exit();
            true
        }
        None => false,
    }
}

/// python `cleanup_launch_threads`: `false` — владельца нет.
pub fn cleanup_launch_threads(owner: Option<&mut dyn LaunchRuntimeOwner>) -> bool {
    match owner {
        Some(owner) => {
            owner.cleanup_threads();
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct RecordingOwner {
        running: bool,
        calls: RefCell<Vec<String>>,
    }

    impl LaunchRuntimeOwner for RecordingOwner {
        fn is_running(&self) -> bool {
            self.running
        }
        fn start_dpi(&mut self, _command: StartDpiCommand) {
            self.calls.borrow_mut().push("start".to_string());
        }
        fn stop_dpi(&mut self, _command: StopDpiCommand) {
            self.calls.borrow_mut().push("stop".to_string());
        }
        fn restart_dpi(&mut self, _command: RestartDpiCommand) {
            self.calls.borrow_mut().push("restart".to_string());
        }
        fn switch_presets(&mut self, _method: Option<&str>) {
            self.calls.borrow_mut().push("switch".to_string());
        }
        fn stop_and_exit(&mut self) {
            self.calls.borrow_mut().push("stop_and_exit".to_string());
        }
        fn cleanup_threads(&mut self) {
            self.calls.borrow_mut().push("cleanup".to_string());
        }
    }

    #[test]
    fn missing_owner_returns_false_without_calls() {
        // python: runtime_feature.objects.launch_runtime is None → False.
        assert!(!is_dpi_running(None));
        assert!(!start_dpi(None, StartDpiCommand::default()));
        assert!(!stop_dpi(None, StopDpiCommand::default()));
        assert!(!restart_dpi(None, RestartDpiCommand::default()));
        assert!(!switch_presets(None, Some("zapret2_mode")));
        assert!(!stop_and_exit(None));
        assert!(!cleanup_launch_threads(None));
    }

    #[test]
    fn commands_reach_the_owner() {
        let mut owner = RecordingOwner {
            running: true,
            ..RecordingOwner::default()
        };

        assert!(is_dpi_running(Some(&owner)));
        assert!(start_dpi(
            Some(&mut owner),
            StartDpiCommand {
                launch_method: Some("zapret2_mode".to_string()),
                ..StartDpiCommand::default()
            }
        ));
        assert!(stop_dpi(
            Some(&mut owner),
            StopDpiCommand {
                force_cleanup: true,
                cleanup_services: false,
            }
        ));
        assert!(restart_dpi(
            Some(&mut owner),
            RestartDpiCommand {
                force_full_stop: true,
                target_launch_method: Some("zapret1_mode".to_string()),
            }
        ));
        assert!(switch_presets(Some(&mut owner), None));
        assert!(stop_and_exit(Some(&mut owner)));
        assert!(cleanup_launch_threads(Some(&mut owner)));

        assert_eq!(
            *owner.calls.borrow(),
            vec![
                "start".to_string(),
                "stop".to_string(),
                "restart".to_string(),
                "switch".to_string(),
                "stop_and_exit".to_string(),
                "cleanup".to_string(),
            ]
        );
    }

    #[test]
    fn stopped_owner_reports_not_running_but_accepts_commands() {
        let mut owner = RecordingOwner::default();
        assert!(!is_dpi_running(Some(&owner)));
        assert!(start_dpi(Some(&mut owner), StartDpiCommand::default()));
    }
}
