// src/gui/mod.rs

pub mod http;
pub mod types;
pub mod ws;

// Flat re-exports so callers can write `gui::GuiEvent` instead of `gui::types::GuiEvent`
pub use types::{GuiCommand, GuiEvent, GuiFileInfo};
