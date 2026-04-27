// src/network.rs
//
// Wire protocol for Vitruvius.
//
// Two coexisting modes:
//
//   1. Legacy plaintext-mode messages (Manifest / ChunkRequest / ChunkResponse)
//      — used when the local node has no transport key for the peer.
//
//   2. Zero-knowledge metadata-encrypted variants
//      (EncryptedManifest / EncryptedChunkRequest / EncryptedChunkResponse)
//      — used when a transport key (TOFU-derived or shared --key-path) is
//      available. Filenames, file sizes, and plaintext content hashes are
//      hidden from anyone who does not hold the transport key.
//
// Wire-level summary of the encrypted variants:
//
//   EncryptedManifest      — `ciphertext` is ChaCha20-Poly1305 of CBOR-encoded
//                             `EncryptedManifestPayload` { node, files: Vec<EncryptedFileEntry> }.
//                             AAD = b"vitv02-manifest". Nonce prepended.
//
//   EncryptedChunkRequest  — file_id is a 16-byte BLAKE3-derived id from
//                             (transport_key, rel_path). Opaque to relays.
//
//   EncryptedChunkResponse — `data` is encrypt_with_aad(transport_key,
//                             plaintext_chunk, chunk_aad(file_id, idx)).
//                             `blinded_hash` = BLAKE3-derive("…chunk-hash",
//                             transport_key, plaintext_hash). Lets the receiver
//                             verify integrity without ever seeing plaintext
//                             hashes on the wire.

use anyhow::Result;
use libp2p::{mdns, request_response, PeerId, StreamProtocol, Swarm};
use serde::{Deserialize, Serialize};
use std::time::Duration;

// =============================================================================
// Legacy plaintext file entry (used inside `Manifest`)
// =============================================================================
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileEntry {
    pub file_name: String,
    pub file_size: u64,
    pub total_chunks: usize,
    pub chunk_hashes: Vec<[u8; 32]>,
}

// =============================================================================
// New: per-file entry inside an EncryptedManifest payload.
// File names live INSIDE the encrypted blob — relays never see them.
// =============================================================================
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedFileEntry {
    /// The original relative path. Inside the encryption envelope, so a
    /// relay sees only random-looking ciphertext bytes.
    pub file_name: String,
    /// 16-byte opaque id used on the wire for ChunkRequest/ChunkResponse.
    /// Both peers derive the same id from (transport_key, file_name).
    pub file_id: [u8; 16],
    pub file_size: u64,
    pub total_chunks: u32,
    /// Plaintext-hash blinded with the transport key. Same plaintext + same
    /// transport key → same blinded hash, so dedup still works between
    /// paired peers, but a relay holding a known file cannot recognise it
    /// by hashing it themselves.
    pub blinded_chunk_hashes: Vec<[u8; 32]>,
}

/// Cleartext payload that gets serialised, then encrypted, and shipped as
/// `EncryptedManifest.ciphertext`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedManifestPayload {
    pub node_name: String,
    pub files: Vec<EncryptedFileEntry>,
}

// =============================================================================
// Sync messages
// =============================================================================
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SyncMessage {
    // ── Announcements ────────────────────────────────────────────────────────
    FolderAnnouncement {
        node_name: String,
    },

    // ── Legacy plaintext requests / responses ────────────────────────────────
    ManifestRequest,
    ChunkRequest {
        file_name: String,
        chunk_index: usize,
    },
    Manifest {
        node_name: String,
        files: Vec<FileEntry>,
    },
    ChunkResponse {
        file_name: String,
        chunk_index: usize,
        data: Vec<u8>,
        hash: [u8; 32],
    },

    // ── Zero-knowledge variants (v0.2) ───────────────────────────────────────
    /// Manifest with all metadata encrypted; only the encrypted blob travels
    /// on the wire. Receiver decrypts with the transport key shared with this
    /// peer.
    EncryptedManifest {
        /// Layout: [12-byte nonce][CBOR(EncryptedManifestPayload) ct + 16-byte tag].
        ciphertext: Vec<u8>,
    },
    /// Request a chunk by opaque file id — relays cannot link this to a
    /// real filename without the transport key.
    EncryptedChunkRequest {
        file_id: [u8; 16],
        chunk_index: u32,
    },
    /// Response carrying an AEAD-protected chunk. Integrity verification is
    /// done against `blinded_hash`, not against a plaintext hash.
    EncryptedChunkResponse {
        file_id: [u8; 16],
        chunk_index: u32,
        /// AEAD ciphertext: encrypt_with_aad(transport_key, plaintext,
        /// chunk_aad(file_id, chunk_index)). Layout = [12B nonce][ct+16B tag].
        data: Vec<u8>,
        /// Blinded plaintext-hash so the receiver can verify integrity
        /// without ever seeing a recognisable BLAKE3.
        blinded_hash: [u8; 32],
    },

    // ── Misc ─────────────────────────────────────────────────────────────────
    Empty,
    Ack,
    Error {
        message: String,
    },
    FileChanged {
        file_name: String,
    },
    FileDeleted {
        file_name: String,
    },

    KeyExchangePropose {
        public_key: [u8; 32],
    },
    KeyExchangeAccept {
        public_key: [u8; 32],
    },

    TransferComplete {
        file_name: String,
    },
}

#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct MyBehaviour {
    pub mdns: mdns::tokio::Behaviour,
    pub rr: request_response::cbor::Behaviour<SyncMessage, SyncMessage>,
}

pub async fn setup_network() -> Result<Swarm<MyBehaviour>> {
    let local_key = crate::identity::load_or_create_keypair()?;
    let local_peer_id = PeerId::from(local_key.public());
    println!("--- Vitruvius Node ---");
    println!("YOUR ID: {}", local_peer_id);

    let config = request_response::Config::default()
        .with_request_timeout(Duration::from_secs(120))
        .with_max_concurrent_streams(64);

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let mdns =
                mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?;
            let rr = request_response::cbor::Behaviour::<SyncMessage, SyncMessage>::new(
                [(
                    StreamProtocol::new("/vitruvius/sync/1.1"),
                    request_response::ProtocolSupport::Full,
                )],
                config,
            );
            Ok(MyBehaviour { mdns, rr })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(900)))
        .build();

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
    Ok(swarm)
}
