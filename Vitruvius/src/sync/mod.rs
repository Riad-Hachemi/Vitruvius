// src/sync/mod.rs
pub mod handler;
pub use handler::{on_command, on_swarm_event, check_stalls, PeerDownload};
