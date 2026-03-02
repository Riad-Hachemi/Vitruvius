// src/network.rs
use anyhow::Result;
use libp2p::{PeerId, StreamProtocol, Swarm, mdns, request_response};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SyncMessage {
    /// Request to sync a file  
    Request { file_name: String },

    /// File metadata (chunk count, size, hashes)  
    Metadata {
        file_name: String,
        total_chunks: usize,
        file_size: u64,
        chunk_hashes: Vec<[u8; 32]>,
    },

    /// Request for a specific chunk  
    ChunkRequest { chunk_index: usize },

    /// Response containing a single chunk  
    ChunkResponse {
        chunk_index: usize,
        data: Vec<u8>,
        hash: [u8; 32],
    },

    /// Transfer completed successfully  
    TransferComplete,

    /// Remote folder is empty  
    Empty,

    /// Error message  
    Error { message: String },
}

#[derive(libp2p::swarm::NetworkBehaviour)]
pub struct MyBehaviour {
    pub mdns: mdns::tokio::Behaviour,
    pub rr: request_response::cbor::Behaviour<SyncMessage, SyncMessage>,
}

pub async fn setup_network() -> Result<Swarm<MyBehaviour>> {
    let local_key = libp2p::identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    println!("--- Vitruvius Node ---");
    println!("YOUR ID: {}", local_peer_id);

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
            let mut config = request_response::Config::default();

            // Shorter timeout for individual chunks
            #[allow(deprecated)]
            config.set_request_timeout(Duration::from_secs(10));

            let rr = libp2p::request_response::cbor::Behaviour::<SyncMessage, SyncMessage>::new(
                [(
                    StreamProtocol::new("/vitruvius/sync/1.0"),
                    request_response::ProtocolSupport::Full,
                )],
                config,
            );
            Ok(MyBehaviour { mdns, rr })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(30)))
        .build();

    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    Ok(swarm)
}
