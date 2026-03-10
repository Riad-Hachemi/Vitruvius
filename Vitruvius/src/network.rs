// src/network.rs
use anyhow::Result;
use libp2p::{PeerId, StreamProtocol, Swarm, mdns, request_response};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileEntry {
    pub file_name:    String,
    pub file_size:    u64,
    pub total_chunks: usize,
    pub chunk_hashes: Vec<[u8; 32]>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SyncMessage {
    // ── Announcements ────────────────────────────────────────────────────────
    /// Sent to all connected peers when a sync folder is set.
    /// Means: "I now have files — please request my manifest."
    FolderAnnouncement { node_name: String },

    // ── Requests ─────────────────────────────────────────────────────────────
    ManifestRequest,
    ChunkRequest { file_name: String, chunk_index: usize },

    // ── Responses ────────────────────────────────────────────────────────────
    Manifest { node_name: String, files: Vec<FileEntry> },
    ChunkResponse { file_name: String, chunk_index: usize, data: Vec<u8>, hash: [u8; 32] },
    Empty,
    Error { message: String },

    // ── Notifications ─────────────────────────────────────────────────────────
    TransferComplete { file_name: String },
}

#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct MyBehaviour {
    pub mdns: mdns::tokio::Behaviour,
    pub rr:   request_response::cbor::Behaviour<SyncMessage, SyncMessage>,
}

pub async fn setup_network() -> Result<Swarm<MyBehaviour>> {
    let local_key     = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("--- Vitruvius Node ---");
    println!("YOUR ID: {}", local_peer_id);

    let config = request_response::Config::default()
        .with_request_timeout(Duration::from_secs(120));

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_behaviour(|key| {
            let mdns = mdns::tokio::Behaviour::new(
                mdns::Config::default(),
                key.public().to_peer_id(),
            )?;
            let rr = request_response::cbor::Behaviour::<SyncMessage, SyncMessage>::new(
                [(
                    StreamProtocol::new("/vitruvius/sync/1.0"),
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
