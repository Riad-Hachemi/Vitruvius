// src/storage.rs
use anyhow::Result;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use tracing::{error, info};

use crate::network::SyncMessage;

const CHUNK_SIZE: usize = 1024 * 1024; // 1 MB

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileMetadata {
    pub file_name: String,
    pub total_chunks: usize,
    pub file_size: u64,
    pub chunk_hashes: Vec<[u8; 32]>,
}

pub struct FileTransferState {
    pub metadata: Option<FileMetadata>,
    pub received_chunks: HashMap<usize, Vec<u8>>,
    pub file_path: PathBuf,
}

impl FileTransferState {
    pub fn new(file_path: PathBuf) -> Self {
        Self {
            metadata: None,
            received_chunks: HashMap::new(),
            file_path,
        }
    }
}

/// Build file metadata (name, size, per-chunk BLAKE3 hashes) without keeping
/// all chunk data in memory.
pub async fn get_file_metadata(sync_path: &PathBuf) -> Result<SyncMessage> {
    info!("Building metadata for {:?}", sync_path);

    if let Ok(entries) = fs::read_dir(sync_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let file_name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or_default()
                    .to_string();

                let mut file = File::open(&path)?;
                let file_size = file.metadata()?.len();
                let total_chunks = ((file_size as usize) + CHUNK_SIZE - 1) / CHUNK_SIZE;

                let mut chunk_hashes = Vec::with_capacity(total_chunks);
                let mut buf = vec![0u8; CHUNK_SIZE];

                for _ in 0..total_chunks {
                    let n = file.read(&mut buf)?;
                    let hash: [u8; 32] = blake3::hash(&buf[..n]).into();
                    chunk_hashes.push(hash);
                }

                info!("Metadata ready: {} ({} chunks)", file_name, total_chunks);
                return Ok(SyncMessage::Metadata {
                    file_name,
                    total_chunks,
                    file_size,
                    chunk_hashes,
                });
            }
        }
    }

    Ok(SyncMessage::Empty)
}

/// Read and return a single chunk by index using seek (O(1) I/O, not O(n)).
pub async fn get_chunk(sync_path: &PathBuf, chunk_index: usize) -> Result<SyncMessage> {
    if let Ok(entries) = fs::read_dir(sync_path) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_file() {
                let mut file = File::open(&path)?;
                let offset   = (chunk_index * CHUNK_SIZE) as u64;
                file.seek(SeekFrom::Start(offset))?;

                let mut buf = vec![0u8; CHUNK_SIZE];
                let n = file.read(&mut buf)?;
                if n == 0 {
                    return Ok(SyncMessage::Error {
                        message: format!("Chunk {} out of range", chunk_index),
                    });
                }
                buf.truncate(n);
                let hash: [u8; 32] = blake3::hash(&buf).into();

                return Ok(SyncMessage::ChunkResponse {
                    chunk_index,
                    data: buf,
                    hash,
                });
            }
        }
    }

    Ok(SyncMessage::Error { message: "File not found".into() })
}

/// Verify a chunk against an expected hash from the FileMetadata,
/// NOT the hash reported by the sender (which could be spoofed).
pub fn verify_chunk(data: &[u8], expected_hash: &[u8; 32]) -> bool {
    let computed: [u8; 32] = blake3::hash(data).into();
    computed == *expected_hash
}

/// Store an already-verified chunk and reassemble when all chunks are present.
/// Returns Ok(true) when the file is complete.
pub async fn process_received_chunk(
    peer_id: PeerId,
    chunk_index: usize,
    data: Vec<u8>,
    _sender_hash: [u8; 32], // ignored — verification done against metadata hashes upstream
    transfer_state: &mut FileTransferState,
) -> Result<bool> {
    info!("Storing chunk {} from {}", chunk_index, peer_id);
    transfer_state.received_chunks.insert(chunk_index, data);

    if let Some(metadata) = &transfer_state.metadata {
        if transfer_state.received_chunks.len() == metadata.total_chunks {
            reassemble_file(transfer_state)?;
            info!("File reassembled: {}", metadata.file_name);
            return Ok(true);
        }
    }

    Ok(false)
}

fn reassemble_file(state: &FileTransferState) -> Result<()> {
    let metadata = state
        .metadata
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No metadata"))?;

    let out = state.file_path.join(&metadata.file_name);
    let mut file = File::create(&out)?;

    for i in 0..metadata.total_chunks {
        let chunk = state
            .received_chunks
            .get(&i)
            .ok_or_else(|| anyhow::anyhow!("Missing chunk {}", i))?;
        file.write_all(chunk)?;
    }

    file.sync_all()?;
    info!("Wrote {:?}", out);
    Ok(())
}
