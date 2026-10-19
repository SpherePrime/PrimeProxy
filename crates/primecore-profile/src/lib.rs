//! Порт `src/profile` — модели профилей и разбор стратегий.
//!
//! Дальше крейту добавляются parser/serializer/plan и т.п.; здесь пока
//! models (структуры) и winws2 (разбор --lua-desync-стратегии).

pub mod conditions_text;
pub mod display_items;
pub mod editable_settings;
pub mod derived_cache;
pub mod list_interpreter;
pub mod list_apply_signature;
pub mod filter_switch;
pub mod icons;
pub mod fakes_names;
pub mod identity;
pub mod key_resolution;
pub mod match_filters;
pub mod models;
pub mod parser;
pub mod preset_blob_declarations;
pub mod serializer;
pub mod folder_store;
pub mod settings;
pub mod state;
pub mod folders;
pub mod folder_ordering;
pub mod stock_names;
pub mod strategy_catalog;
pub mod sha1;
pub mod strategy_facts;
pub mod strategy_families;
pub mod strategy_knowledge;
pub mod strategy_plan;
pub mod strategy_state;
pub mod strategy_usage;
pub mod strategy_shape;
pub mod strategy_visuals;
pub mod winws1;
pub mod winws2;
pub mod winws2_preset_source;
pub mod winws2_transport;

pub use models::{
    build_profile_logical_key, build_profile_persistent_key, logical_list_value,
    Profile, ProfileAction, ProfileActionArg, ProfileMatch, ProfileSegment, Preset, Strategy,
    Winws1Strategy, Winws2Strategy, ENGINE_WINWS1, ENGINE_WINWS2,
};
