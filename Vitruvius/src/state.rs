// src/state.rs
//
// Shared mutable state for the running node.
// Wrapped in Arc<Mutex<AppState>> and accessed from the swarm loop, the
// WebSocket handler, and the GUI command handler.
//
// Notes for v0.2 (zero-knowledge):
//   * `peer_keys` are the per-peer transport keys (TOFU-derived OR mirrored
//     from a shared --key-path).
//   * `vault_key` is the on-disk at-rest key, never shared with peers.
//   * `inbound_file_ids` and `outbound_file_ids` map the opaque 16-byte file
//     ids carried on the wire to/from real relative paths.
//   * `key_for_peer` returns the transport key for the peer if we have one;
//     unlike v0.1, it does NOT silently fall back to a global key. Callers
//     decide what to do when no key is available.

use libp2p::PeerId;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

pub struct AppState {
    /// peer_id string → last known multiaddr (populated by mDNS)
    pub known_addrs: HashMap<String, String>,
    /// set of peers with an open TCP connection right now
    pub connected_peers: HashSet<PeerId>,
    /// the local folder this node is syncing (None until the user sets it)
    pub sync_path: Option<PathBuf>,
    /// this device's human-readable hostname
    pub node_name: String,
    /// peer_id string → hostname, learned from FolderAnnouncement / Manifest
    pub peer_names: HashMap<String, String>,
    /// peers we have already sent a FolderAnnouncement to in this session.
    pub announced_to: HashSet<PeerId>,
    pub writing_files: HashSet<PathBuf>,
    pub deleting_files: HashSet<PathBuf>,
    pub recently_notified: HashMap<String, std::time::Instant>,

    /// Per-peer transport key (32 bytes). Populated by TOFU exchange OR by
    /// the operator distributing a shared --key-path file to every peer.
    pub peer_keys: HashMap<PeerId, [u8; 32]>,
    /// Pending X25519 secrets while a TOFU handshake is in flight.
    pub pending_exchanges: HashMap<PeerId, [u8; 32]>,
    /// Operator-supplied shared key (--key-path). Mirrored into `peer_keys`
    /// per-connection; not consulted directly during sync.
    pub encryption_key: Option<[u8; 32]>,
    /// X25519 public keys of peers that have proposed a TOFU exchange and
    /// are waiting for the local user's approval.
    pub pending_approvals: HashMap<PeerId, [u8; 32]>,

    // ── v0.2 zero-knowledge state ────────────────────────────────────────────
    /// 32-byte at-rest key — used to encrypt/decrypt the local `*.vit` vault
    /// blobs. Independent from any transport key. Stored on disk in a key
    /// file (mode 0600); kept in memory only for the lifetime of the node.
    pub vault_key: Option<[u8; 32]>,
    /// True when the sync folder uses the encrypted vault layout (`*.vit`
    /// files). False = legacy plaintext-on-disk mode.
    pub vault_mode: bool,
    /// True when this node should send/accept the encrypted-protocol variants
    /// (EncryptedManifest, EncryptedChunkRequest, EncryptedChunkResponse).
    /// Defaulted to true; can be turned off with --no-encrypted-protocol for
    /// debugging or backwards-compatibility tests.
    pub encrypted_protocol: bool,

    /// For files we are SERVING to a peer: file_id → local rel_path.
    /// Built when we send our EncryptedManifest to that peer; used to
    /// resolve incoming EncryptedChunkRequest.
    pub outbound_file_ids: HashMap<PeerId, HashMap<[u8; 16], String>>,
    /// For files we are RECEIVING from a peer: file_id → metadata snapshot
    /// (file_name, total_chunks, blinded_chunk_hashes, file_size). Populated
    /// when we decrypt their EncryptedManifest.
    pub inbound_file_ids: HashMap<PeerId, HashMap<[u8; 16], InboundFileInfo>>,
}

/// Information the receiver needs to verify and reassemble a file once it
/// has decoded an EncryptedManifest from the sender.
#[derive(Clone, Debug)]
pub struct InboundFileInfo {
    pub file_name: String,
    pub file_size: u64,
    pub total_chunks: u32,
    pub blinded_chunk_hashes: Vec<[u8; 32]>,
}

impl AppState {
    pub fn new(node_name: String) -> Self {
        Self {
            known_addrs: HashMap::new(),
            connected_peers: HashSet::new(),
            sync_path: None,
            node_name,
            peer_names: HashMap::new(),
            announced_to: HashSet::new(),
            writing_files: HashSet::new(),
            deleting_files: HashSet::new(),
            recently_notified: HashMap::new(),
            peer_keys: HashMap::new(),
            pending_exchanges: HashMap::new(),
            pending_approvals: HashMap::new(),
            encryption_key: None,
            vault_key: None,
            vault_mode: false,
            encrypted_protocol: true,
            outbound_file_ids: HashMap::new(),
            inbound_file_ids: HashMap::new(),
        }
    }

    /// True when ANY transport encryption is configured.
    /// (Either a per-peer TOFU key exists, or an operator-distributed
    /// shared key is loaded.)
    pub fn is_encrypted(&self) -> bool {
        self.encryption_key.is_some() || !self.peer_keys.is_empty()
    }

    /// Return the transport key for this specific peer, if any. v0.2
    /// **does not** fall back to the operator-shared key automatically: that
    /// fallback is performed only at TOFU-acceptance time when we mirror the
    /// shared key into `peer_keys` for connecting peers. This makes the
    /// encryption boundary explicit per-peer.
    pub fn key_for_peer(&self, peer: &libp2p::PeerId) -> Option<[u8; 32]> {
        self.peer_keys.get(peer).copied()
    }

    /// Persist a TOFU-derived (or shared-key-mirrored) transport key for a
    /// peer. Persistence happens first so a crash right after does not lose
    /// the key.
    pub fn set_peer_key(&mut self, peer: libp2p::PeerId, key: [u8; 32]) {
        if let Err(e) = crate::tofu::store_peer_key(&peer.to_string(), &key) {
            tracing::warn!("Could not persist TOFU key for {}: {}", peer, e);
        }
        self.peer_keys.insert(peer, key);
    }

    /// Mirror an operator-supplied shared transport key into the per-peer
    /// table without persisting it (the operator already manages the file
    /// out-of-band).
    pub fn mirror_shared_key(&mut self, peer: libp2p::PeerId) {
        if let Some(k) = self.encryption_key {
            self.peer_keys.entry(peer).or_insert(k);
        }
    }
}

// ─── Determine this device's display name ────────────────────────────────────
pub fn get_node_name() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    if let Ok(h) = std::fs::read_to_string("/etc/hostname") {
        let h = h.trim().to_string();
        if !h.is_empty() {
            return h;
        }
    }
    "Vitruvius-Node".to_string()
}

// ─── Short display version of a PeerId for logs ──────────────────────────────
pub fn short_id(peer_id: &str) -> String {
    let s = peer_id.strip_prefix("12D3KooW").unwrap_or(peer_id);
    s[..s.len().min(8)].to_string()
}
