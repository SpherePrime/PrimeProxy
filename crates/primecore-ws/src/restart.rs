//! Повторный запуск и переключение пресетов: решения о том, что делать с
//! отложенными запросами.
//!
//! Порт чистых решений `winws_runtime/runtime/restart_flow.py`. Python-версия
//! неотделима от QThread/QTimer и объекта-владельца (`runtime_owner`), поэтому
//! здесь переносятся сами решения — порядок проверок, лимиты ожиданий и
//! тексты логов; вызовы потоков, таймеров и службы состояния остаются за
//! вызывающим.
//!
//! Правило владения процессом (python `_redirect_preset_switch_if_owner_differs`):
//! быстрое переключение пресета допустимо только внутри того же режима запуска.
//! Если активен другой режим — выполняется полный stop+start.

use primecore_mode::{is_preset_launch_method, normalize_launch_method};

/// Фаза «starting» без живого потока запуска — короткое окно; 200 повторов по
/// 150 мс (~30 с) страхуют от вечного ожидания (python
/// `_PRESETS_SWITCH_MAX_STARTING_WAITS`).
pub const PRESETS_SWITCH_MAX_STARTING_WAITS: u32 = 200;

/// Решение по отложенному переключению пресетов
/// (порядок python `process_pending_presets_switch`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingPresetsSwitchDecision {
    /// Нечего обрабатывать: запрошенное поколение уже завершено.
    AlreadyCompleted,
    /// Метод не preset: busy снимается, переключение не выполняется.
    SkipNotPresetMethod,
    /// Отложено: поток ещё работает; повтор через паузу (python 150 мс).
    DeferRetry,
    /// DPI не запущен и фаза «starting» не подтвердилась: переключение
    /// пропадает, поколение считается завершённым.
    SkipNotRunning,
    /// Активен другой режим запуска: нужен полный stop+start.
    RedirectFullRestart,
    /// Запустить worker переключения пресета.
    StartWorker { method: String, generation: u64 },
}

/// Вход решения по отложенному переключению пресетов.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PresetsSwitchState {
    /// python `_presets_switch_requested_generation`.
    pub requested_generation: u64,
    /// python `_presets_switch_completed_generation`.
    pub completed_generation: u64,
    /// python `_presets_switch_method` либо launch_method снимка рантайма.
    pub requested_method: String,
    /// launch_method из снимка службы рантайма.
    pub runtime_launch_method: String,
    /// python `_presets_switch_thread.isRunning()`.
    pub switch_thread_running: bool,
    /// python `_dpi_start_thread.isRunning()`.
    pub start_thread_running: bool,
    /// python `_dpi_stop_thread.isRunning()`.
    pub stop_thread_running: bool,
    /// python `runtime_owner.is_running()`.
    pub running: bool,
    /// python `snapshot.phase` (строкой; «starting» откладывает решение).
    pub runtime_phase: String,
    /// python `_presets_switch_starting_waits`.
    pub starting_waits: u32,
}

/// Решение по отложенному переключению пресетов
/// (python `process_pending_presets_switch`).
///
/// Порядок проверок и лимиты соответствуют python: поколения, метод, три
/// потока, фаза «starting» с лимитом ожиданий, затем правило владения.
#[must_use]
pub fn pending_presets_switch_decision(state: &PresetsSwitchState) -> PendingPresetsSwitchDecision {
    let target_generation = state.requested_generation;
    if target_generation <= state.completed_generation {
        return PendingPresetsSwitchDecision::AlreadyCompleted;
    }

    let launch_method = if state.requested_method.trim().is_empty() {
        state.runtime_launch_method.trim().to_lowercase()
    } else {
        state.requested_method.trim().to_lowercase()
    };
    if !is_preset_launch_method(Some(&launch_method)) {
        return PendingPresetsSwitchDecision::SkipNotPresetMethod;
    }

    if state.switch_thread_running || state.start_thread_running || state.stop_thread_running {
        return PendingPresetsSwitchDecision::DeferRetry;
    }

    if !state.running {
        let starting = state.runtime_phase.trim().to_lowercase() == "starting";
        if starting && state.starting_waits < PRESETS_SWITCH_MAX_STARTING_WAITS {
            // Запуск объявлен, но его поток ещё не виден (или уже закончился,
            // а фаза не опубликована): ждём, а не теряем переключение.
            return PendingPresetsSwitchDecision::DeferRetry;
        }
        return PendingPresetsSwitchDecision::SkipNotRunning;
    }

    if preset_switch_owner_redirect(state.running, &state.runtime_launch_method, &launch_method) {
        return PendingPresetsSwitchDecision::RedirectFullRestart;
    }

    PendingPresetsSwitchDecision::StartWorker {
        method: launch_method,
        generation: target_generation,
    }
}

/// python `_redirect_preset_switch_if_owner_differs`: нужно ли перенаправить
/// быстрое переключение на полный stop+start.
///
/// Единое правило владения: fast switch допустим только внутри режима.
#[must_use]
pub fn preset_switch_owner_redirect(
    active_running: bool,
    active_launch_method: &str,
    target_launch_method: &str,
) -> bool {
    if !active_running {
        return false;
    }
    let active = normalize_launch_method(Some(active_launch_method), Some(""));
    active != target_launch_method
}

/// Решение по отложенному перезапуску DPI
/// (порядок python `process_pending_restart_request`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PendingRestartDecision {
    /// Нечего обрабатывать: запрошенное поколение уже завершено.
    AlreadyCompleted,
    /// Отложено: поток ещё работает; повтор через паузу.
    DeferRetry,
    /// Сначала останавливается текущий процесс.
    StopFirst { force_full_stop: bool },
    /// Запуск актуального выбранного пресета.
    Start { target_launch_method: String },
}

/// Вход решения по отложенному перезапуску DPI.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestartRequestState {
    /// python `_restart_request_generation`.
    pub requested_generation: u64,
    /// python `_restart_completed_generation`.
    pub completed_generation: u64,
    /// python `_restart_force_stop_generation` (0 — нет требования).
    pub force_stop_generation: u64,
    /// python `_dpi_start_thread.isRunning()`.
    pub start_thread_running: bool,
    /// python `_dpi_stop_thread.isRunning()`.
    pub stop_thread_running: bool,
    /// python `_presets_switch_thread.isRunning()`.
    pub switch_thread_running: bool,
    /// python `runtime_owner.is_running()`.
    pub running: bool,
    /// python `_restart_target_launch_method`.
    pub target_launch_method: String,
}

/// Решение по отложенному перезапуску DPI
/// (python `process_pending_restart_request`).
#[must_use]
pub fn pending_restart_decision(state: &RestartRequestState) -> PendingRestartDecision {
    let target_generation = state.requested_generation;
    if target_generation <= state.completed_generation {
        return PendingRestartDecision::AlreadyCompleted;
    }

    let force_full_stop = state.force_stop_generation == target_generation;

    if state.start_thread_running || state.stop_thread_running || state.switch_thread_running {
        return PendingRestartDecision::DeferRetry;
    }

    if state.running || force_full_stop {
        return PendingRestartDecision::StopFirst { force_full_stop };
    }

    PendingRestartDecision::Start {
        target_launch_method: normalize_launch_method(Some(&state.target_launch_method), Some("")),
    }
}

/// python `restart_dpi_async`: что зафиксировать при запросе перезапуска.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestartRequest {
    /// Новое значение `_restart_request_generation`.
    pub generation: u64,
    /// Новое значение `_restart_force_stop_generation` (None — не менять).
    pub force_stop_generation: Option<u64>,
    /// Новое значение `_restart_target_launch_method`.
    pub target_launch_method: String,
}

/// Формирует запись о запросе перезапуска (python `restart_dpi_async`).
#[must_use]
pub fn request_restart(
    current_request_generation: u64,
    force_full_stop: bool,
    target_launch_method: Option<&str>,
) -> RestartRequest {
    let generation = current_request_generation + 1;
    let normalized = normalize_launch_method(target_launch_method, Some(""));
    RestartRequest {
        generation,
        force_stop_generation: if force_full_stop {
            Some(generation)
        } else {
            None
        },
        target_launch_method: normalized,
    }
}

/// python `switch_presets_async` до владельца: что делать с запросом
/// переключения пресетов без QThread.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresetsSwitchRequest {
    /// Метод не preset — вместо переключения выполняется обычный перезапуск.
    FallbackRestart,
    /// Отложено на debounce-таймер.
    ScheduleDebounce { method: String, delay_ms: u64 },
    /// Отменить debounce и запросить переключение с новым поколением.
    Request { method: String, generation: u64 },
}

/// Формирует решение по запросу переключения пресетов
/// (python `switch_presets_async`).
///
/// Сначала debounce, потом смена владельца: иначе при чужом владельце каждый
/// щелчок сразу начинал полный stop+start, минуя склейку быстрых щелчков.
#[must_use]
pub fn request_presets_switch(
    current_generation: u64,
    requested_method: Option<&str>,
    runtime_launch_method: &str,
    delay_ms: u64,
) -> PresetsSwitchRequest {
    let method = requested_method
        .filter(|m| !m.trim().is_empty())
        .unwrap_or(runtime_launch_method)
        .trim()
        .to_lowercase();
    if !is_preset_launch_method(Some(&method)) {
        return PresetsSwitchRequest::FallbackRestart;
    }
    if delay_ms > 0 {
        return PresetsSwitchRequest::ScheduleDebounce { method, delay_ms };
    }
    PresetsSwitchRequest::Request {
        method,
        generation: current_generation + 1,
    }
}

/// python `handle_presets_switch_finished`: устаревшее ли завершение.
///
/// `skipped_as_stale` или поколение меньше запрошенного — завершение устарело.
#[must_use]
pub fn presets_switch_finish_is_stale(
    requested_generation: u64,
    finished_generation: u64,
    skipped_as_stale: bool,
) -> bool {
    skipped_as_stale || finished_generation < requested_generation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_state() -> PresetsSwitchState {
        PresetsSwitchState {
            requested_generation: 1,
            completed_generation: 0,
            requested_method: "zapret2_mode".to_string(),
            runtime_launch_method: "zapret2_mode".to_string(),
            switch_thread_running: false,
            start_thread_running: false,
            stop_thread_running: false,
            running: true,
            runtime_phase: "running".to_string(),
            starting_waits: 0,
        }
    }

    #[test]
    fn completed_generation_is_a_noop() {
        let mut state = base_state();
        state.completed_generation = 1;
        assert_eq!(
            pending_presets_switch_decision(&state),
            PendingPresetsSwitchDecision::AlreadyCompleted
        );
    }

    #[test]
    fn non_preset_method_skips_switch() {
        // Порядок python: метод проверяется до потоков.
        let mut state = base_state();
        state.requested_method = "orchestra_mode".to_string();
        state.switch_thread_running = true;
        assert_eq!(
            pending_presets_switch_decision(&state),
            PendingPresetsSwitchDecision::SkipNotPresetMethod
        );
    }

    #[test]
    fn busy_threads_defer_the_switch() {
        for flag in [
            "switch_thread_running",
            "start_thread_running",
            "stop_thread_running",
        ] {
            let mut state = base_state();
            match flag {
                "switch_thread_running" => state.switch_thread_running = true,
                "start_thread_running" => state.start_thread_running = true,
                _ => state.stop_thread_running = true,
            }
            assert_eq!(
                pending_presets_switch_decision(&state),
                PendingPresetsSwitchDecision::DeferRetry,
                "{flag}"
            );
        }
    }

    #[test]
    fn starting_phase_defers_until_limit() {
        let mut state = base_state();
        state.running = false;
        state.runtime_phase = "starting".to_string();
        state.starting_waits = 0;
        assert_eq!(
            pending_presets_switch_decision(&state),
            PendingPresetsSwitchDecision::DeferRetry
        );

        // Лимит достигнут — переключение пропадает.
        state.starting_waits = PRESETS_SWITCH_MAX_STARTING_WAITS;
        assert_eq!(
            pending_presets_switch_decision(&state),
            PendingPresetsSwitchDecision::SkipNotRunning
        );

        // Не-starting фаза — пропадает сразу.
        state.runtime_phase = "idle".to_string();
        state.starting_waits = 0;
        assert_eq!(
            pending_presets_switch_decision(&state),
            PendingPresetsSwitchDecision::SkipNotRunning
        );
    }

    #[test]
    fn owner_redirect_requires_full_restart() {
        // Активен zapret1, целевой пресет zapret2: полный stop+start.
        let mut state = base_state();
        state.runtime_launch_method = "zapret1_mode".to_string();
        assert_eq!(
            pending_presets_switch_decision(&state),
            PendingPresetsSwitchDecision::RedirectFullRestart
        );
    }

    #[test]
    fn same_owner_starts_worker() {
        let state = base_state();
        assert_eq!(
            pending_presets_switch_decision(&state),
            PendingPresetsSwitchDecision::StartWorker {
                method: "zapret2_mode".to_string(),
                generation: 1,
            }
        );
    }

    #[test]
    fn method_falls_back_to_runtime_snapshot() {
        let mut state = base_state();
        state.requested_method = String::new();
        state.runtime_launch_method = "ZAPRET2_MODE".to_string();
        assert_eq!(
            pending_presets_switch_decision(&state),
            PendingPresetsSwitchDecision::StartWorker {
                method: "zapret2_mode".to_string(),
                generation: 1,
            }
        );
    }

    #[test]
    fn owner_redirect_rule_matches_python() {
        // python _redirect_preset_switch_if_owner_differs.
        assert!(preset_switch_owner_redirect(
            true,
            "zapret1_mode",
            "zapret2_mode"
        ));
        assert!(!preset_switch_owner_redirect(
            true,
            "zapret2_mode",
            "zapret2_mode"
        ));
        assert!(!preset_switch_owner_redirect(
            false,
            "zapret1_mode",
            "zapret2_mode"
        ));
        // Нормализация метода: регистр и пробелы не важны.
        assert!(!preset_switch_owner_redirect(
            true,
            "ZAPRET2_MODE ",
            "zapret2_mode"
        ));
    }

    fn base_restart() -> RestartRequestState {
        RestartRequestState {
            requested_generation: 1,
            completed_generation: 0,
            force_stop_generation: 0,
            start_thread_running: false,
            stop_thread_running: false,
            switch_thread_running: false,
            running: true,
            target_launch_method: String::new(),
        }
    }

    #[test]
    fn restart_completed_generation_is_a_noop() {
        let mut state = base_restart();
        state.completed_generation = 1;
        assert_eq!(
            pending_restart_decision(&state),
            PendingRestartDecision::AlreadyCompleted
        );
    }

    #[test]
    fn restart_busy_threads_defer() {
        for (flag, value) in [("start", true), ("stop", false)] {
            let mut state = base_restart();
            if flag == "start" {
                state.start_thread_running = value;
            } else {
                state.stop_thread_running = !value;
            }
            assert_eq!(
                pending_restart_decision(&state),
                PendingRestartDecision::DeferRetry,
                "{flag}"
            );
        }
        let mut state = base_restart();
        state.switch_thread_running = true;
        assert_eq!(
            pending_restart_decision(&state),
            PendingRestartDecision::DeferRetry
        );
    }

    #[test]
    fn restart_stops_first_when_running() {
        let state = base_restart();
        assert_eq!(
            pending_restart_decision(&state),
            PendingRestartDecision::StopFirst {
                force_full_stop: false
            }
        );
    }

    #[test]
    fn restart_force_full_stop_stops_even_when_not_running() {
        let mut state = base_restart();
        state.running = false;
        state.force_stop_generation = 1;
        assert_eq!(
            pending_restart_decision(&state),
            PendingRestartDecision::StopFirst {
                force_full_stop: true
            }
        );
    }

    #[test]
    fn restart_starts_with_normalized_method() {
        let mut state = base_restart();
        state.running = false;
        state.target_launch_method = "zapret1_mode".to_string();
        assert_eq!(
            pending_restart_decision(&state),
            PendingRestartDecision::Start {
                target_launch_method: "zapret1_mode".to_string(),
            }
        );
    }

    #[test]
    fn request_restart_increments_generation_and_marks_force_stop() {
        // Сверено с python restart_dpi_async.
        let request = request_restart(2, true, Some("zapret2_mode"));
        assert_eq!(request.generation, 3);
        assert_eq!(request.force_stop_generation, Some(3));
        assert_eq!(request.target_launch_method, "zapret2_mode");

        let request = request_restart(2, false, None);
        assert_eq!(request.generation, 3);
        assert_eq!(request.force_stop_generation, None);
        assert_eq!(request.target_launch_method, "");
    }

    #[test]
    fn presets_switch_request_debounces_before_owner_change() {
        // Сверено с python switch_presets_async: сначала debounce.
        let request = request_presets_switch(0, Some("zapret2_mode"), "zapret2_mode", 300);
        assert_eq!(
            request,
            PresetsSwitchRequest::ScheduleDebounce {
                method: "zapret2_mode".to_string(),
                delay_ms: 300,
            }
        );

        let request = request_presets_switch(4, None, "zapret1_mode", 0);
        assert_eq!(
            request,
            PresetsSwitchRequest::Request {
                method: "zapret1_mode".to_string(),
                generation: 5,
            }
        );

        // Не preset-метод — обычный перезапуск.
        assert_eq!(
            request_presets_switch(0, Some("orchestra_mode"), "orchestra_mode", 0),
            PresetsSwitchRequest::FallbackRestart
        );
    }

    #[test]
    fn stale_finish_detection_matches_python() {
        // python handle_presets_switch_finished.
        assert!(presets_switch_finish_is_stale(5, 4, false));
        assert!(presets_switch_finish_is_stale(5, 5, true));
        assert!(!presets_switch_finish_is_stale(5, 5, false));
        assert!(!presets_switch_finish_is_stale(5, 6, false));
    }
}
