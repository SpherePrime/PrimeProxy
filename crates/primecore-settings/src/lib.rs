//! Крейт настроек: schema-константы, нормализаторы (normalize.py) и
//! хранилище sqlite (settings/store.py) — в следующих коммитах.

pub mod app_settings;
mod normalize;
pub mod schema;
pub mod store;

pub use normalize::*;
