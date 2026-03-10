// src/storage.rs
use anyhow::{Context, Result};
use libp2p::PeerId;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use tracing::{error, info};

use crate::network::{FileEntry, SyncMessage};

pub const CHUNK_SIZE: u64 = 512 * 1024; // 512 KB

// ─── Metadata for one file (in-memory, no data) ───────────────────────────────
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub file_name:    String,
    pub total_chunks: usize,
    pub file_size:    u64,
    pub chunk_hashes: Vec<[u8; 32]>,
}

// ─── State for one in-progress incoming transfer ──────────────────────────────
pub struct FileTransferState {
    pub metadata:        Option<FileMetadata>,
    pub received_chunks: HashMap<usize, Vec<u8>>,
    pub sync_dir:        PathBuf,
    pub next_request:    usize,   // sliding-window watermark
}

impl FileTransferState {
    pub fn new(sync_dir: PathBuf) -> Self {
        Self { metadata: None, received_chunks: HashMap::new(), sync_dir, next_request: 0 }
    }
}

// ─── Compute metadata for one file (hash every chunk, keep no data) ───────────
fn compute_file_metadata(path: &PathBuf) -> Result<FileMetadata> {
    let mut file = File::open(path)
        .with_context(|| format!("Cannot open {:?}", path))?;
    let file_size = file.metadata()?.len();
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("unknown").to_string();

    let total_chunks = ((file_size + CHUNK_SIZE - 1) / CHUNK_SIZE).max(1) as usize;
    let mut chunk_hashes = Vec::with_capacity(total_chunks);
    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    for _ in 0..total_chunks {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        chunk_hashes.push(blake3::hash(&buf[..n]).into());
    }
    Ok(FileMetadata { file_name, total_chunks, file_size, chunk_hashes })
}

// ─── Scan directory and return metadata for every regular file ─────────────────
pub async fn list_folder(sync_path: &PathBuf) -> Result<Vec<FileMetadata>> {
    let mut result = Vec::new();
    let entries = fs::read_dir(sync_path)
        .with_context(|| format!("Cannot read {:?}", sync_path))?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }
        match compute_file_metadata(&path) {
            Ok(m)  => result.push(m),
            Err(e) => error!("Skipping {:?}: {}", path, e),
        }
    }
    result.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    Ok(result)
}

// ─── Build SyncMessage::Manifest from the folder ──────────────────────────────
pub async fn get_manifest(sync_path: &PathBuf, node_name: &str) -> Result<SyncMessage> {
    let files = list_folder(sync_path).await?;
    if files.is_empty() {
        return Ok(SyncMessage::Empty);
    }
    let entries = files.into_iter().map(|m| FileEntry {
        file_name:    m.file_name,
        file_size:    m.file_size,
        total_chunks: m.total_chunks,
        chunk_hashes: m.chunk_hashes,
    }).collect();
    Ok(SyncMessage::Manifest { node_name: node_name.to_string(), files: entries })
}

// ─── Serve one chunk by seeking — O(1), does NOT re-read the entire file ───────
pub async fn get_chunk(sync_path: &PathBuf, file_name: &str, chunk_index: usize) -> Result<SyncMessage> {
    let file_path = sync_path.join(file_name);
    let mut file = File::open(&file_path)
        .with_context(|| format!("Cannot open {:?}", file_path))?;

    let offset = chunk_index as u64 * CHUNK_SIZE;
    file.seek(SeekFrom::Start(offset))?;

    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    let n = file.read(&mut buf)?;
    if n == 0 {
        return Ok(SyncMessage::Error {
            message: format!("Chunk {} is past end of file", chunk_index),
        });
    }
    buf.truncate(n);
    let hash: [u8; 32] = blake3::hash(&buf).into();
    Ok(SyncMessage::ChunkResponse { file_name: file_name.to_string(), chunk_index, data: buf, hash })
}

// ─── Verify a chunk against the stored hash ────────────────────────────────────
pub fn verify_chunk(data: &[u8], expected: &[u8; 32]) -> bool {
    blake3::hash(data).as_bytes() == expected
}

// ─── Store chunk; write file if all chunks present; return true when done ──────
pub async fn process_chunk(
    _peer_id: PeerId,
    chunk_index: usize,
    data: Vec<u8>,
    ts: &mut FileTransferState,
) -> Result<bool> {
    ts.received_chunks.insert(chunk_index, data);
    let meta = match &ts.metadata { Some(m) => m, None => return Ok(false) };
    if ts.received_chunks.len() < meta.total_chunks { return Ok(false); }

    // All chunks present — reassemble in order
    let out_path = ts.sync_dir.join(&meta.file_name);
    let mut out = File::create(&out_path)
        .with_context(|| format!("Cannot create {:?}", out_path))?;
    for i in 0..meta.total_chunks {
        match ts.received_chunks.get(&i) {
            Some(d) => out.write_all(d)?,
            None    => return Err(anyhow::anyhow!("Missing chunk {} during reassembly", i)),
        }
    }
    out.sync_all()?;
    info!("✅ File written: {:?}", out_path);
    Ok(true)
}
