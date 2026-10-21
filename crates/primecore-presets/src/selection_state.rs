//! Порт `presets/state.py` — состояние выбранного source-пресета.

/// Текущее состояние выбранного source preset-а (python `PresetSelectionState`).
///
/// Source preset остаётся единственным источником истины для direct-запуска.
/// Не возвращать runtime launch.txt, временные копии или fallback-пути как
/// каноническое состояние выбранного preset-а.
///
/// Исключение по цепочке запуска: winws2 runner может создать временный
/// @config-файл как адаптер для самого winws2.exe. Такой файл не является
/// выбранным preset-ом и не должен попадать в UI, settings или manifest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PresetSelectionState {
    pub method: String,
    pub engine: String,
    pub selected_preset_file_name: String,
    pub selected_preset_name: String,
    pub selected_source_path: String,
    pub display_name: String,
    pub summary: String,
    pub selected_profile_key: String,
    pub selected_profile_name: String,
    pub profile_count: i64,
    pub enabled_profile_count: i64,
    pub active_strategy_count: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_is_empty() {
        let state = PresetSelectionState::default();
        assert_eq!(state.method, "");
        assert_eq!(state.selected_preset_file_name, "");
        assert_eq!(state.profile_count, 0);
        assert_eq!(state, PresetSelectionState::default());
    }
}
