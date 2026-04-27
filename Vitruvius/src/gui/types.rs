// src/gui/types.rs
//
// All types that cross the WebSocket boundary between the browser and the backend.
//   GuiCommand  — browser → backend  (user actions)
//   GuiEvent    — backend → browser  (state updates, log lines, transfer progress)
//   GuiFileInfo — one row in a FolderListing

use serde::{Deserialize, Serialize};

// ─── Browser → Backend ────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
pub enum GuiCommand {
    /// Set (or change) the local sync folder
    SetFolder {
        path: String,
    },
    /// Dial a peer — addr is optional when mDNS already knows it
    DialPeer {
        peer_id: String,
        addr: Option<String>,
    },
    /// Manually request the file list from a connected peer
    RequestSync {
        peer_id: String,
    },
    /// Close the connection to a peer
    Disconnect {
        peer_id: String,
    },

    ApprovePeer {
        peer_id: String,
    },
    DenyPeer {
        peer_id: String,
    },

    /// Decrypt a `<name>.vit` file from the sync folder out to a plaintext
    /// destination on disk. Used by the GUI's "Decrypt File" button.
    DecryptFile {
        /// Logical filename (no `.vit` suffix); resolved against the current
        /// sync folder.
        name: String,
        /// Absolute destination path for the decrypted plaintext.
        dest: String,
    },
}

// ─── Backend → Browser ────────────────────────────────────────────────────────

#[derive(Serialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum GuiEvent {
    /// Sent once on startup — this node's own identity
    Identity { peer_id: String, node_name: String },
    /// A peer appeared on the LAN (mDNS discovery)
    PeerDiscovered {
        peer_id: String,
        addr: String,
        node_name: String,
    },
    /// TCP connection to a peer is open
    PeerConnected { peer_id: String, node_name: String },
    /// A peer connection was closed
    PeerDisconnected { peer_id: String },
    /// An outgoing dial attempt failed
    DialFailed {
        peer_id: Option<String>,
        error: String,
    },
    /// The contents of the local sync folder (sent after SetFolder and on reconnect)
    FolderListing { files: Vec<GuiFileInfo> },
    /// A new file transfer has started
    TransferStarted {
        peer_id: String,
        file_name: String,
        total_chunks: usize,
        file_size: u64,
    },
    /// One chunk was received (verified = BLAKE3 hash matched)
    ChunkReceived {
        peer_id: String,
        file_name: String,
        chunk_index: usize,
        total_chunks: usize,
        verified: bool,
    },
    /// All chunks received, file written to disk successfully
    TransferComplete { peer_id: String, file_name: String },
    /// The remote peer's folder is empty or not set
    RemoteEmpty { peer_id: String },
    // sends when the folder is set ,  to later on , set up the watcher
    /// A protocol-level error message from a peer
    PeerError { peer_id: String, message: String },

    PeerApprovalRequired {
        peer_id: String,
        display_name: String,
    },
    /// A log line — mirrors the tracing output into the GUI console
    Log { level: String, message: String },

    /// Snapshot of the node's zero-knowledge posture. Sent once per WS
    /// connect and again whenever vault settings change. The GUI uses this
    /// to render the "Vault" status pill in the header.
    VaultStatus {
        vault_mode: bool,
        encrypted_protocol: bool,
        /// Short fingerprint of the at-rest vault key (or "—" when off).
        key_fingerprint: String,
    },
}

// ─── One file in a FolderListing ─────────────────────────────────────────────

#[derive(Serialize, Debug, Clone)]
pub struct GuiFileInfo {
    pub name: String,
    pub size: u64,
    pub chunks: usize,
}
