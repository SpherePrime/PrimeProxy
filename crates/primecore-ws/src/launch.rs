//! Точки входа запуска: выбор раннера по exe и состояние рантайма DPI.
//!
//! Порт чистых частей `winws_runtime/runners/runner_factory.py`
//! (выбор раннера по имени exe) и `winws_runtime/state/launch_runtime_service.py`
//! (переходы runtime-состояния: фазы, busy, ошибка, PID). Глобальный
//! singleton runner-а python заменён здесь на явные решения: какой класс
//! раннера соответствует exe и какие переходы состояния допустимы.
//!
//! Хранение состояния в `MainWindowStateStore` и опрос живости процесса —
//! платформенные/прикладные действия, они остаются за вызывающим; здесь —
//! правила переходов.

use primecore_mode::{normalize_launch_method, EXE_NAME_WINWS2};

/// Какой раннер обслуживает выбранный exe (python-классы
/// `Winws1StrategyRunner`/`Winws2StrategyRunner`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum RunnerKind {
    /// winws.exe — Zapret 1.
    Winws1,
    /// winws2.exe — Zapret 2.
    Winws2,
}

impl RunnerKind {
    /// python-имя класса раннера, для текстов лога.
    #[must_use]
    pub fn python_class_name(self) -> &'static str {
        match self {
            RunnerKind::Winws1 => "Winws1StrategyRunner",
            RunnerKind::Winws2 => "Winws2StrategyRunner",
        }
    }
}

/// python `runner_factory.get_strategy_runner`: выбор раннера по exe-файлу.
///
/// winws2.exe выбирает Zapret 2, любой другой exe — Zapret 1.
#[must_use]
pub fn runner_kind_for_exe(winws_exe_path: &str) -> RunnerKind {
    let exe_name = winws_exe_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_lowercase();
    if exe_name == EXE_NAME_WINWS2 {
        RunnerKind::Winws2
    } else {
        RunnerKind::Winws1
    }
}

// --- launch_runtime_service.py: переходы runtime-состояния -------------------

/// Снимок runtime-состояния DPI (python `LaunchRuntimeSnapshot`).
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct LaunchRuntimeSnapshot {
    pub phase: String,
    pub running: bool,
    pub last_error: String,
    pub launch_method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
}

impl LaunchRuntimeSnapshot {
    /// Начальный снимок: `stopped`, пустые поля.
    #[must_use]
    pub fn initial() -> Self {
        Self::default()
    }

    /// python `current_phase`.
    #[must_use]
    pub fn current_phase(&self) -> &str {
        &self.phase
    }

    /// python `is_running`: фаза должна быть именно «running».
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.running && self.phase == "running"
    }
}

/// Приватное tracking-состояние сервиса
/// (python `_LaunchRuntimeTrackingState`): нужен только мониторингу процесса,
/// в общий UI state не попадает.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LaunchTrackingState {
    pub expected_process: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    pub missing_probe_count: u32,
}

/// Чистое ядро `LaunchRuntimeService`: переходы состояния без хранилища.
///
/// python-версия пишет в `MainWindowStateStore`; здесь изменения применяются
/// к снимку напрямую, а вызывающий решает, куда их публиковать.
#[derive(Debug, Clone, Default)]
pub struct LaunchRuntimeState {
    snapshot: LaunchRuntimeSnapshot,
    tracking: LaunchTrackingState,
    busy: bool,
    busy_text: String,
}

impl LaunchRuntimeState {
    /// python `build_initial_ui_state`: начальная фаза с учётом автозапуска.
    ///
    /// `dpi_autostart_enabled && launch_supported` → `autostart_pending`,
    /// иначе `stopped`; ручной запуск готов — busy с текстом подготовки.
    #[must_use]
    pub fn build_initial(
        launch_method: &str,
        dpi_autostart_enabled: bool,
        launch_supported: bool,
    ) -> Self {
        let phase = if dpi_autostart_enabled && launch_supported {
            "autostart_pending"
        } else {
            "stopped"
        };
        let preparing_manual_launch = phase == "stopped" && launch_supported;
        Self {
            snapshot: LaunchRuntimeSnapshot {
                phase: phase.to_string(),
                running: false,
                last_error: String::new(),
                launch_method: normalize_launch_method(Some(launch_method), Some("")),
                pid: None,
            },
            tracking: LaunchTrackingState::default(),
            busy: preparing_manual_launch,
            busy_text: if preparing_manual_launch {
                "Подготовка запуска...".to_string()
            } else {
                String::new()
            },
        }
    }

    /// python `snapshot`.
    #[must_use]
    pub fn snapshot(&self) -> &LaunchRuntimeSnapshot {
        &self.snapshot
    }

    /// python-поле busy из UI state.
    #[must_use]
    pub fn busy(&self) -> (&bool, &str) {
        (&self.busy, &self.busy_text)
    }

    /// python-поле tracking state.
    #[must_use]
    pub fn tracking(&self) -> &LaunchTrackingState {
        &self.tracking
    }

    /// python `set_busy`.
    pub fn set_busy(&mut self, busy: bool, text: &str) {
        self.busy = busy;
        self.busy_text = text.to_string();
    }

    /// python `begin_start`.
    pub fn begin_start(&mut self, launch_method: Option<&str>, expected_process: &str) {
        self.tracking = LaunchTrackingState {
            expected_process: expected_process.trim().to_lowercase(),
            pid: None,
            missing_probe_count: 0,
        };
        self.snapshot.phase = "starting".to_string();
        self.snapshot.running = false;
        self.snapshot.last_error = String::new();
        if let Some(method) = launch_method {
            self.snapshot.launch_method = normalize_launch_method(Some(method), Some(""));
        }
    }

    /// python `mark_autostart_pending`.
    pub fn mark_autostart_pending(&mut self, launch_method: Option<&str>, expected_process: &str) {
        self.tracking = LaunchTrackingState {
            expected_process: expected_process.trim().to_lowercase(),
            pid: None,
            missing_probe_count: 0,
        };
        self.snapshot.phase = "autostart_pending".to_string();
        self.snapshot.running = false;
        self.snapshot.last_error = String::new();
        if let Some(method) = launch_method {
            self.snapshot.launch_method = normalize_launch_method(Some(method), Some(""));
        }
    }

    /// python `begin_stop`.
    pub fn begin_stop(&mut self) {
        self.snapshot.phase = "stopping".to_string();
        self.snapshot.running = false;
        self.snapshot.last_error = String::new();
    }

    /// python `mark_running`: фаза running, PID и счётчик пропаданий сброшены.
    pub fn mark_running(&mut self, pid: Option<u32>, expected_process: Option<&str>) {
        let next_expected = expected_process
            .map(|value| value.trim().to_lowercase())
            .unwrap_or_else(|| self.tracking.expected_process.clone());
        let next_pid = pid.or(self.tracking.pid);
        self.tracking = LaunchTrackingState {
            expected_process: next_expected,
            pid: next_pid,
            missing_probe_count: 0,
        };
        self.snapshot.phase = "running".to_string();
        self.snapshot.running = true;
        self.snapshot.last_error = String::new();
        self.snapshot.pid = next_pid;
    }

    /// python `mark_start_failed`.
    pub fn mark_start_failed(&mut self, error: &str) {
        self.tracking.pid = None;
        self.tracking.missing_probe_count = 0;
        self.snapshot.phase = "failed".to_string();
        self.snapshot.running = false;
        self.snapshot.last_error = error.to_string();
    }

    /// python `mark_stopped`: tracking сбрасывается; ошибка очищается
    /// по флагу.
    pub fn mark_stopped(&mut self, clear_error: bool) {
        self.tracking = LaunchTrackingState::default();
        self.snapshot.phase = "stopped".to_string();
        self.snapshot.running = false;
        if clear_error {
            self.snapshot.last_error = String::new();
        }
    }

    /// python `bootstrap_probe`: стартовая сверка с реальностью при старте
    /// программы. `running_since` и опрос процесса — за вызывающим.
    pub fn bootstrap_probe(
        &mut self,
        running: bool,
        launch_method: Option<&str>,
        expected_process: &str,
    ) {
        let current_phase = self.snapshot.phase.clone();
        self.tracking = LaunchTrackingState {
            expected_process: if running || current_phase == "autostart_pending" {
                expected_process.trim().to_lowercase()
            } else {
                String::new()
            },
            pid: None,
            missing_probe_count: 0,
        };
        let phase = if running {
            "running"
        } else if current_phase == "autostart_pending" {
            "autostart_pending"
        } else {
            "stopped"
        };
        self.snapshot.phase = phase.to_string();
        self.snapshot.running = running;
        self.snapshot.last_error = String::new();
        if running {
            self.snapshot.pid = None;
        }
        if let Some(method) = launch_method {
            self.snapshot.launch_method = normalize_launch_method(Some(method), Some(""));
        }
    }

    /// python `_increment_missing_probe_count`: процесс не найден в снимке.
    pub fn increment_missing_probe_count(&mut self) -> u32 {
        self.tracking.missing_probe_count += 1;
        self.tracking.missing_probe_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_kind_selects_by_exe_name() {
        // Сверено с python runner_factory.get_strategy_runner.
        assert_eq!(
            runner_kind_for_exe(r"C:\Zapret\exe\winws2.exe"),
            RunnerKind::Winws2
        );
        assert_eq!(
            runner_kind_for_exe(r"C:\Zapret\exe\WINWS2.EXE"),
            RunnerKind::Winws2
        );
        assert_eq!(
            runner_kind_for_exe(r"C:\Zapret\exe\winws.exe"),
            RunnerKind::Winws1
        );
        assert_eq!(runner_kind_for_exe(""), RunnerKind::Winws1);
        assert_eq!(
            runner_kind_for_exe("/opt/zapret/winws2.exe").python_class_name(),
            "Winws2StrategyRunner"
        );
        assert_eq!(
            runner_kind_for_exe("/opt/zapret/winws.exe").python_class_name(),
            "Winws1StrategyRunner"
        );
    }

    #[test]
    fn initial_phase_uses_autostart_and_support() {
        // Сверено с python build_initial_ui_state.
        let manual = LaunchRuntimeState::build_initial("zapret2_mode", false, true);
        assert_eq!(manual.snapshot().phase, "stopped");
        assert_eq!(manual.snapshot().launch_method, "zapret2_mode");
        assert_eq!(manual.busy(), (&true, "Подготовка запуска..."));

        let autostart = LaunchRuntimeState::build_initial("zapret1_mode", true, true);
        assert_eq!(autostart.snapshot().phase, "autostart_pending");
        assert_eq!(autostart.busy(), (&false, ""));

        let unsupported = LaunchRuntimeState::build_initial("zapret1_mode", true, false);
        assert_eq!(unsupported.snapshot().phase, "stopped");

        // Метод нормализуется.
        let normalized = LaunchRuntimeState::build_initial("ZAPRET1_MODE ", false, false);
        assert_eq!(normalized.snapshot().launch_method, "zapret1_mode");
    }

    #[test]
    fn lifecycle_transitions_follow_python_service() {
        // Порядок python begin_start → mark_running → begin_stop → mark_stopped.
        let mut state = LaunchRuntimeState::build_initial("zapret2_mode", false, false);

        state.begin_start(Some("zapret2_mode"), r"C:\Zapret\EXE\winws2.exe");
        assert_eq!(state.snapshot().phase, "starting");
        assert!(!state.snapshot().running);
        assert_eq!(
            state.tracking().expected_process,
            r"c:\zapret\exe\winws2.exe"
        );
        assert_eq!(state.tracking().pid, None);

        state.mark_running(Some(4321), None);
        assert_eq!(state.snapshot().phase, "running");
        assert!(state.snapshot().is_running());
        assert_eq!(state.snapshot().pid, Some(4321));
        assert_eq!(state.tracking().missing_probe_count, 0);

        state.begin_stop();
        assert_eq!(state.snapshot().phase, "stopping");
        assert!(!state.snapshot().is_running());

        state.mark_stopped(true);
        assert_eq!(state.snapshot().phase, "stopped");
        assert_eq!(state.tracking().expected_process, "");
        assert_eq!(state.tracking().pid, None);
    }

    #[test]
    fn start_failure_keeps_error_until_next_start() {
        // Сверено с python mark_start_failed / begin_start.
        let mut state = LaunchRuntimeState::build_initial("zapret2_mode", false, false);
        state.begin_start(Some("zapret2_mode"), "");
        state.mark_start_failed("winws2 не запустился");
        assert_eq!(state.snapshot().phase, "failed");
        assert!(!state.snapshot().running);
        assert_eq!(state.snapshot().last_error, "winws2 не запустился");

        // Новый старт стирает ошибку.
        state.begin_start(None, "");
        assert_eq!(state.snapshot().phase, "starting");
        assert_eq!(state.snapshot().last_error, "");
    }

    #[test]
    fn mark_stopped_keeps_error_when_requested() {
        let mut state = LaunchRuntimeState::build_initial("zapret2_mode", false, false);
        state.mark_start_failed("сбой");
        state.mark_stopped(false);
        assert_eq!(state.snapshot().phase, "stopped");
        assert_eq!(state.snapshot().last_error, "сбой");
        state.mark_stopped(true);
        assert_eq!(state.snapshot().last_error, "");
    }

    #[test]
    fn bootstrap_probe_trusts_observed_reality() {
        // Сверено с python bootstrap_probe.
        let mut state = LaunchRuntimeState::build_initial("zapret2_mode", false, false);
        state.bootstrap_probe(true, None, "winws2.exe");
        assert_eq!(state.snapshot().phase, "running");
        assert!(state.snapshot().running);
        assert_eq!(state.tracking().expected_process, "winws2.exe");

        // autostart_pending сохраняется, если обход не запущен.
        let mut pending = LaunchRuntimeState::build_initial("zapret2_mode", true, true);
        pending.bootstrap_probe(false, None, "winws2.exe");
        assert_eq!(pending.snapshot().phase, "autostart_pending");
        assert!(!pending.snapshot().running);

        // Обычный stopped — tracking пуст.
        let mut stopped = LaunchRuntimeState::build_initial("zapret2_mode", false, false);
        stopped.bootstrap_probe(false, None, "winws2.exe");
        assert_eq!(stopped.snapshot().phase, "stopped");
        assert_eq!(stopped.tracking().expected_process, "");

        // Метод обновляется, если передан.
        let mut with_method = LaunchRuntimeState::build_initial("zapret2_mode", false, false);
        with_method.bootstrap_probe(false, Some("zapret1_mode"), "");
        assert_eq!(with_method.snapshot().launch_method, "zapret1_mode");
    }

    #[test]
    fn missing_probe_count_increments() {
        // Сверено с python _increment_missing_probe_count.
        let mut state = LaunchRuntimeState::build_initial("zapret2_mode", false, false);
        state.begin_start(Some("zapret2_mode"), "winws2.exe");
        assert_eq!(state.increment_missing_probe_count(), 1);
        assert_eq!(state.increment_missing_probe_count(), 2);
        // mark_running сбрасывает счётчик.
        state.mark_running(Some(7), None);
        assert_eq!(state.tracking().missing_probe_count, 0);
    }

    #[test]
    fn set_busy_carries_text() {
        let mut state = LaunchRuntimeState::build_initial("zapret2_mode", false, false);
        state.set_busy(true, "Применяем пресет...");
        assert_eq!(state.busy(), (&true, "Применяем пресет..."));
        state.set_busy(false, "");
        assert_eq!(state.busy(), (&false, ""));
    }
}
