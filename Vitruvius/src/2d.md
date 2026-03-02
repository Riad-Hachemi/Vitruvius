mod network;
mod storage;
mod sync;

use anyhow::Result;
use dialoguer::Input;
use libp2p::Multiaddr;
use libp2p::{
    PeerId, Swarm, SwarmBuilder, futures::StreamExt, mdns, noise, swarm::SwarmEvent, tcp, yamux,
};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use std::{collections::HashMap, error::Error};
use tracing::{info, warn};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    info!(" Starting Vitruvius...");

    let mut swarm = crate::network::setup_network().await?;
    let mut discoverd_peers: HashMap<PeerId, Vec<Multiaddr>> = HashMap::new();

    info!("✓ Network initialized");

    loop {
        tokio::select! {
             event = swarm.select_next_some() => {

                 crate::network::handle_swarm_event(&mut swarm).await?;

             }

            // TODO: Handle file system events from watcher
            // event = watcher_rx.recv() => {
            //     handle_file_event(event).await;
            // }

            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down...");
                break;
            }
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  WEEK 1 DAY 3-4: FILE TRANSFER
// ─────────────────────────────────────────────────────────────────────────────

/// Send a file to a peer
async fn send_file(peer_id: PeerId, file_path: &str) -> Result<()> {
    // TODO: Implement file sending
    // 1. Read file from disk
    // 2. Get file metadata (name, size, modified time)
    // 3. Send metadata to peer first
    // 4. Send file content
    // 5. Wait for acknowledgment

    info!("TODO: File transfer not yet implemented");
    Ok(())
}

/// Receive a file from a peer
async fn receive_file(peer_id: PeerId, data: Vec<u8>) -> Result<()> {
    // TODO: Implement file receiving
    // 1. Parse incoming data
    // 2. Validate metadata
    // 3. Write to disk in sync directory
    // 4. Send acknowledgment to sender

    info!("TODO: File receive not yet implemented");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  WEEK 1 DAY 5-6: CHUNKING & HASHING
// ─────────────────────────────────────────────────────────────────────────────

/// Split a file into chunks and compute BLAKE3 hash for each
fn chunk_file(file_path: &str) -> Result<Vec<Chunk>> {
    // TODO: Implement file chunking
    // 1. Read file
    // 2. Split into 1MB chunks
    // 3. Hash each chunk with BLAKE3
    // 4. Return vector of Chunk structs

    const CHUNK_SIZE: usize = 1024 * 1024; // 1MB

    info!("TODO: File chunking not yet implemented");
    Ok(vec![])
}

/// Verify a chunk's integrity using BLAKE3 hash
fn verify_chunk(chunk: &[u8], expected_hash: &[u8; 32]) -> bool {
    // TODO: Implement chunk verification
    // 1. Hash the chunk data with BLAKE3
    // 2. Compare with expected hash
    // 3. Return true if match, false otherwise

    let computed_hash = blake3::hash(chunk);
    computed_hash.as_bytes() == expected_hash
}

/// Send chunks to a peer with hash verification
async fn send_chunks(peer_id: PeerId, chunks: Vec<Chunk>) -> Result<()> {
    // TODO: Implement chunked transfer
    // 1. For each chunk:
    //    a. Send chunk data + hash
    //    b. Wait for verification response
    //    c. Retry if verification fails

    info!("TODO: Chunk transfer not yet implemented");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  WEEK 2 DAY 8-9: FILE WATCHING
// ─────────────────────────────────────────────────────────────────────────────

/// Setup file watcher on sync directory
async fn setup_file_watcher(sync_dir: &str) -> Result<()> {
    // TODO: Implement file watcher
    // 1. Create notify watcher
    // 2. Watch sync directory recursively
    // 3. Setup channel to send events to main loop
    // 4. Handle Create, Modify, Delete events

    info!("TODO: File watcher not yet implemented");
    Ok(())
}

/// Handle a file system event
async fn handle_file_event(event: notify::Event) -> Result<()> {
    // TODO: Implement event handling
    // Match on event.kind:
    // - EventKind::Create => queue file for sending
    // - EventKind::Modify => re-chunk and send delta
    // - EventKind::Remove => notify peers to delete

    info!("File event: {:?}", event);
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  WEEK 2 DAY 10-11: DELTA SYNC
// ─────────────────────────────────────────────────────────────────────────────

/// Compare chunk hashes to detect what changed in a file
fn compute_delta(old_chunks: &[Chunk], new_chunks: &[Chunk]) -> Vec<usize> {
    // TODO: Implement delta detection
    // 1. Compare old and new chunk hashes
    // 2. Return indices of chunks that changed
    // 3. Only these chunks need to be sent

    vec![]
}

/// Send only the chunks that changed
async fn send_delta(peer_id: PeerId, file_path: &str, changed_indices: Vec<usize>) -> Result<()> {
    // TODO: Implement delta sync
    // 1. Send message: "UPDATE file_path, chunks: [indices]"
    // 2. Send only the changed chunks
    // 3. Receiver reconstructs full file using cached unchanged chunks

    info!("TODO: Delta sync not yet implemented");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
//  WEEK 2 DAY 12-13: BIDIRECTIONAL SYNC
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve conflict when both peers modified the same file
fn resolve_conflict(
    local_version: &FileMetadata,
    remote_version: &FileMetadata,
) -> ConflictResolution {
    // TODO: Implement conflict resolution
    // For now: Last-Write-Wins strategy
    // 1. Compare modification timestamps
    // 2. Keep the newer version
    // 3. Later: can add user-prompted resolution or versioning

    if local_version.modified_time > remote_version.modified_time {
        ConflictResolution::KeepLocal
    } else {
        ConflictResolution::KeepRemote
    }
}

// ─────────────────────────────────────────────────────────────────────────────
//  DATA STRUCTURES
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Chunk {
    index: usize,
    data: Vec<u8>,
    hash: [u8; 32],
}

#[derive(Debug, Clone)]
struct FileMetadata {
    path: String,
    size: u64,
    modified_time: u64,
    chunks: Vec<[u8; 32]>, // Hash of each chunk
}

#[derive(Debug)]
enum ConflictResolution {
    KeepLocal,
    KeepRemote,
    UserPrompt, // For future implementation
}

// ─────────────────────────────────────────────────────────────────────────────
//  MODULES (create these files)
// ─────────────────────────────────────────────────────────────────────────────

// Create src/network.rs for all P2P networking code
// Create src/sync.rs for sync logic and delta detection
// Create src/storage.rs for file I/O and chunk management
