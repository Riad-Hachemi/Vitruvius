// src/storage.rs
//
// Identifiers: every file is referenced by its forward-slash relative path
// from the sync root. e.g. "report.pdf", "photos/img001.jpg".
//
// ── Encryption layers (v0.2 zero-knowledge) ──────────────────────────────────
//
// There are now THREE places encryption can be applied:
//
//   AT REST   — Vault mode. Files are stored as `<rel>.vit` containers
//                encrypted with the local `vault_key`. A `*.vit` file has
//                a 40-byte header followed by per-chunk records. The header
//                contains a random `file_uuid` that AAD-binds every chunk
//                to its origin file (cross-file swaps fail decryption).
//
//   IN TRANSIT — Per-chunk ChaCha20-Poly1305 with the per-peer transport
//                key, AAD = (file_id || chunk_index). Replay across files or
//                across positions is rejected.
//
//   IN METADATA — The manifest (filenames, sizes, chunk hashes) is sealed
//                into a single AEAD blob. Plaintext content hashes are
//                "blinded" with the transport key (BLAKE3-derive) so a
//                relay holding a known file cannot recognise it by hashing.
//
// The plaintext content hashes themselves are still computed and live ONLY
// inside the encrypted manifest blob and inside `*.vit` chunk headers on
// the local disk; they never travel as plaintext on the wire.

use anyhow::{anyhow, Context, Result};
use libp2p::PeerId;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{error, info};

use crate::crypto;
use crate::network::{
    EncryptedFileEntry, EncryptedManifestPayload, FileEntry, SyncMessage,
};

pub const CHUNK_SIZE: u64 = 512 * 1024; // 512 KB
pub const VAULT_EXT: &str = "vit";
const VAULT_MAGIC: &[u8; 8] = b"VITV01\0\0";
const VAULT_HEADER_LEN: usize = 8 + 16 + 4 + 8 + 4; // 40 bytes
const VAULT_PER_CHUNK_HASH_LEN: usize = 32;
const VAULT_PER_CHUNK_LEN_PREFIX: usize = 4;
const MANIFEST_AAD: &[u8] = b"vitv02-manifest";

// =============================================================================
// File-metadata structs
// =============================================================================
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub file_name: String,
    pub total_chunks: usize,
    pub file_size: u64,
    /// Plaintext-hash of each chunk. In vault mode this is read from the
    /// `*.vit` header without ever decrypting; in legacy mode it is computed
    /// by hashing the plaintext file.
    pub chunk_hashes: Vec<[u8; 32]>,
}

pub struct FileTransferState {
    pub metadata: Option<FileMetadata>,
    pub received_chunks: HashMap<usize, Vec<u8>>,
    pub sync_dir: PathBuf,
    pub next_request: usize,
    pub last_activity: Instant,
    /// Opaque file id for encrypted-protocol transfers. None = legacy plaintext.
    pub file_id: Option<[u8; 16]>,
}

impl FileTransferState {
    pub fn new(sync_dir: PathBuf) -> Self {
        Self {
            metadata: None,
            received_chunks: HashMap::new(),
            sync_dir,
            next_request: 0,
            last_activity: Instant::now(),
            file_id: None,
        }
    }

    pub fn missing_chunks(&self) -> Vec<usize> {
        let total = self.metadata.as_ref().map(|m| m.total_chunks).unwrap_or(0);
        (0..total).filter(|i| !self.received_chunks.contains_key(i)).collect()
    }
}

#[derive(Debug, Clone)]
pub struct PendingFile {
    pub file_name: String,
    pub total_chunks: usize,
    pub file_size: u64,
    pub chunk_hashes: Vec<[u8; 32]>,
    /// Opaque id for encrypted-protocol transfers. None = legacy plaintext.
    pub file_id: Option<[u8; 16]>,
}

impl From<&FileEntry> for PendingFile {
    fn from(fe: &FileEntry) -> Self {
        PendingFile {
            file_name: fe.file_name.clone(),
            total_chunks: fe.total_chunks,
            file_size: fe.file_size,
            chunk_hashes: fe.chunk_hashes.clone(),
            file_id: None,
        }
    }
}

// =============================================================================
// Path helpers
// =============================================================================
fn relative_path(root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(root).ok().and_then(|rel| {
        let s = rel
            .components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/");
        if s.is_empty() { None } else { Some(s) }
    })
}

fn rel_to_abs(root: &Path, rel: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    for c in rel.split('/') {
        p.push(c);
    }
    p
}

fn rel_to_vault_abs(root: &Path, rel: &str) -> PathBuf {
    let mut p = rel_to_abs(root, rel);
    let new_name = format!("{}.{}", p.file_name().unwrap().to_string_lossy(), VAULT_EXT);
    p.set_file_name(new_name);
    p
}

fn unsafe_rel_path(rel: &str) -> bool {
    rel.contains("..") || rel.starts_with('/') || rel.contains('\\')
}

// =============================================================================
// Legacy plaintext-on-disk metadata + chunk I/O
// =============================================================================
fn compute_file_metadata_plain(root: &Path, abs_path: &Path) -> Result<FileMetadata> {
    let file_name = relative_path(root, abs_path)
        .ok_or_else(|| anyhow!("Cannot make relative path for {:?}", abs_path))?;
    let mut file = File::open(abs_path).with_context(|| format!("Cannot open {:?}", abs_path))?;
    let file_size = file.metadata()?.len();

    let total_chunks = ((file_size + CHUNK_SIZE - 1) / CHUNK_SIZE).max(1) as usize;
    let mut chunk_hashes = Vec::with_capacity(total_chunks);
    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    for _ in 0..total_chunks {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        // FIX: hash only the bytes we actually read, not the whole buffer.
        chunk_hashes.push(blake3::hash(&buf[..n]).into());
    }
    Ok(FileMetadata { file_name, total_chunks, file_size, chunk_hashes })
}

fn walk_dir_plain(root: &Path, dir: &Path, results: &mut Vec<FileMetadata>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            error!("Cannot read dir {:?}: {}", dir, e);
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_dir_plain(root, &path, results);
        } else if path.is_file() {
            // Skip *.vit files in plaintext mode — they are vault containers.
            if path.extension().and_then(|s| s.to_str()) == Some(VAULT_EXT) {
                continue;
            }
            match compute_file_metadata_plain(root, &path) {
                Ok(m) => results.push(m),
                Err(e) => error!("Skipping {:?}: {}", path, e),
            }
        }
    }
}

// =============================================================================
// Vault-mode metadata + chunk I/O
// =============================================================================

/// Read a vault file header. Returns (file_uuid, total_chunks, original_size).
fn read_vault_header(file: &mut File) -> Result<([u8; 16], u32, u64)> {
    file.seek(SeekFrom::Start(0))?;
    let mut hdr = [0u8; VAULT_HEADER_LEN];
    file.read_exact(&mut hdr).context("vault header read")?;
    if &hdr[0..8] != VAULT_MAGIC {
        return Err(anyhow!("not a vault file (bad magic)"));
    }
    let mut file_uuid = [0u8; 16];
    file_uuid.copy_from_slice(&hdr[8..24]);
    let total_chunks = u32::from_le_bytes([hdr[24], hdr[25], hdr[26], hdr[27]]);
    let original_size = u64::from_le_bytes([
        hdr[28], hdr[29], hdr[30], hdr[31], hdr[32], hdr[33], hdr[34], hdr[35],
    ]);
    Ok((file_uuid, total_chunks, original_size))
}

/// Read all per-chunk plaintext hashes by walking the vault file
/// sequentially. Cheap: it never decrypts payload bytes, only seeks past them.
fn read_vault_chunk_hashes(file: &mut File, total_chunks: u32) -> Result<Vec<[u8; 32]>> {
    file.seek(SeekFrom::Start(VAULT_HEADER_LEN as u64))?;
    let mut out = Vec::with_capacity(total_chunks as usize);
    for _ in 0..total_chunks {
        let mut hash = [0u8; VAULT_PER_CHUNK_HASH_LEN];
        file.read_exact(&mut hash)?;
        let mut len_buf = [0u8; VAULT_PER_CHUNK_LEN_PREFIX];
        file.read_exact(&mut len_buf)?;
        let block_len = u32::from_le_bytes(len_buf) as i64;
        out.push(hash);
        // Skip past the AEAD block.
        file.seek(SeekFrom::Current(block_len))?;
    }
    Ok(out)
}

fn vault_chunk_aad(file_uuid: &[u8; 16], chunk_index: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16 + 16 + 4);
    aad.extend_from_slice(b"vitv02-vault\0\0\0\0");
    aad.extend_from_slice(file_uuid);
    aad.extend_from_slice(&chunk_index.to_le_bytes());
    aad
}

/// Decrypt one chunk from a vault file.
pub fn vault_read_chunk(
    vault_file_path: &Path,
    chunk_index: u32,
    vault_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let mut f = File::open(vault_file_path)
        .with_context(|| format!("vault open {:?}", vault_file_path))?;
    let (file_uuid, total_chunks, _orig_size) = read_vault_header(&mut f)?;
    if chunk_index >= total_chunks {
        return Err(anyhow!("chunk {} >= total {}", chunk_index, total_chunks));
    }
    f.seek(SeekFrom::Start(VAULT_HEADER_LEN as u64))?;
    for i in 0..total_chunks {
        let mut hash = [0u8; VAULT_PER_CHUNK_HASH_LEN];
        f.read_exact(&mut hash)?;
        let mut len_buf = [0u8; VAULT_PER_CHUNK_LEN_PREFIX];
        f.read_exact(&mut len_buf)?;
        let block_len = u32::from_le_bytes(len_buf) as usize;
        if i == chunk_index {
            let mut block = vec![0u8; block_len];
            f.read_exact(&mut block)?;
            let aad = vault_chunk_aad(&file_uuid, chunk_index);
            let plaintext = crypto::decrypt_with_aad(vault_key, &block, &aad)
                .context("vault chunk decrypt failed (wrong vault key?)")?;
            return Ok(plaintext);
        } else {
            f.seek(SeekFrom::Current(block_len as i64))?;
        }
    }
    Err(anyhow!("chunk {} not found in vault", chunk_index))
}

/// Write a `<rel>.vit` vault file from plaintext chunks. Generates a fresh
/// random file_uuid for AAD binding. The output file's parents are created
/// if missing. Returns the absolute path written.
pub fn vault_write_file_from_plaintext_chunks(
    sync_root: &Path,
    rel_path: &str,
    plaintext_chunks: &[Vec<u8>],
    vault_key: &[u8; 32],
) -> Result<PathBuf> {
    if unsafe_rel_path(rel_path) {
        return Err(anyhow!("unsafe path: {}", rel_path));
    }
    let target = rel_to_vault_abs(sync_root, rel_path);
    if let Some(p) = target.parent() {
        fs::create_dir_all(p).ok();
    }

    // Random file_uuid.
    let mut file_uuid = [0u8; 16];
    use rand::TryRng;
    rand::rng()
        .try_fill_bytes(&mut file_uuid)
        .map_err(|e| anyhow!("RNG: {e}"))?;

    let total_chunks: u32 = plaintext_chunks
        .len()
        .try_into()
        .map_err(|_| anyhow!("too many chunks"))?;
    let original_size: u64 = plaintext_chunks.iter().map(|c| c.len() as u64).sum();

    let mut f = File::create(&target)
        .with_context(|| format!("vault create {:?}", target))?;

    // Header.
    f.write_all(VAULT_MAGIC)?;
    f.write_all(&file_uuid)?;
    f.write_all(&total_chunks.to_le_bytes())?;
    f.write_all(&original_size.to_le_bytes())?;
    f.write_all(&[0u8; 4])?; // reserved

    // Chunks.
    for (i, chunk) in plaintext_chunks.iter().enumerate() {
        let plaintext_hash: [u8; 32] = blake3::hash(chunk).into();
        let aad = vault_chunk_aad(&file_uuid, i as u32);
        let block = crypto::encrypt_with_aad(vault_key, chunk, &aad)
            .context("vault chunk encrypt")?;
        let block_len: u32 = block.len().try_into().map_err(|_| anyhow!("chunk too big"))?;
        f.write_all(&plaintext_hash)?;
        f.write_all(&block_len.to_le_bytes())?;
        f.write_all(&block)?;
    }

    // Tighten perms.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&target)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&target, perms)?;
    }

    f.sync_all()?;
    Ok(target)
}

/// Decrypt a whole vault file out to a plaintext destination. Used by the
/// GUI "decrypt file" command and by the CLI `export` subcommand.
pub fn vault_export_to_plaintext(
    vault_file_path: &Path,
    vault_key: &[u8; 32],
    dest_path: &Path,
) -> Result<u64> {
    let mut f = File::open(vault_file_path)
        .with_context(|| format!("vault open {:?}", vault_file_path))?;
    let (file_uuid, total_chunks, original_size) = read_vault_header(&mut f)?;
    if let Some(p) = dest_path.parent() {
        fs::create_dir_all(p).ok();
    }
    let mut out = File::create(dest_path)?;
    f.seek(SeekFrom::Start(VAULT_HEADER_LEN as u64))?;
    for i in 0..total_chunks {
        let mut _hash = [0u8; VAULT_PER_CHUNK_HASH_LEN];
        f.read_exact(&mut _hash)?;
        let mut len_buf = [0u8; VAULT_PER_CHUNK_LEN_PREFIX];
        f.read_exact(&mut len_buf)?;
        let block_len = u32::from_le_bytes(len_buf) as usize;
        let mut block = vec![0u8; block_len];
        f.read_exact(&mut block)?;
        let aad = vault_chunk_aad(&file_uuid, i);
        let plaintext = crypto::decrypt_with_aad(vault_key, &block, &aad)
            .context("vault export decrypt")?;
        out.write_all(&plaintext)?;
    }
    out.sync_all()?;
    Ok(original_size)
}

fn compute_file_metadata_vault(root: &Path, abs_path: &Path) -> Result<FileMetadata> {
    // Strip the .vit extension to recover the user-visible filename.
    let mut visible = abs_path.to_path_buf();
    let stem = abs_path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("bad vault filename {:?}", abs_path))?;
    let stripped = stem
        .strip_suffix(&format!(".{}", VAULT_EXT))
        .ok_or_else(|| anyhow!("not a .vit file"))?;
    visible.set_file_name(stripped);
    let file_name = relative_path(root, &visible)
        .ok_or_else(|| anyhow!("vault file outside root: {:?}", abs_path))?;

    let mut f = File::open(abs_path).with_context(|| format!("vault open {:?}", abs_path))?;
    let (_uuid, total_chunks, original_size) = read_vault_header(&mut f)?;
    let chunk_hashes = read_vault_chunk_hashes(&mut f, total_chunks)?;
    Ok(FileMetadata {
        file_name,
        total_chunks: total_chunks as usize,
        file_size: original_size,
        chunk_hashes,
    })
}

fn walk_dir_vault(root: &Path, dir: &Path, results: &mut Vec<FileMetadata>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            error!("Cannot read dir {:?}: {}", dir, e);
            return;
        }
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_dir_vault(root, &path, results);
        } else if path.is_file()
            && path.extension().and_then(|s| s.to_str()) == Some(VAULT_EXT)
        {
            match compute_file_metadata_vault(root, &path) {
                Ok(m) => results.push(m),
                Err(e) => error!("Skipping bad vault file {:?}: {}", path, e),
            }
        }
    }
}

// =============================================================================
// Public folder listing
// =============================================================================
pub async fn list_folder(sync_root: &PathBuf) -> Result<Vec<FileMetadata>> {
    list_folder_modal(sync_root, false, None).await
}

/// Vault-mode-aware folder listing. When `vault_mode` is true, the function
/// reads `*.vit` files; otherwise it falls back to legacy plaintext walking.
pub async fn list_folder_modal(
    sync_root: &PathBuf,
    vault_mode: bool,
    _vault_key: Option<&[u8; 32]>,
) -> Result<Vec<FileMetadata>> {
    let mut result = Vec::new();
    if vault_mode {
        walk_dir_vault(sync_root.as_path(), sync_root.as_path(), &mut result);
    } else {
        walk_dir_plain(sync_root.as_path(), sync_root.as_path(), &mut result);
    }
    result.sort_by(|a, b| a.file_name.cmp(&b.file_name));
    Ok(result)
}

// =============================================================================
// Manifest builders
// =============================================================================

/// Legacy plaintext manifest — used when no transport key is available for
/// the requesting peer.
pub async fn get_manifest(sync_root: &PathBuf, node_name: &str) -> Result<SyncMessage> {
    let files = list_folder(sync_root).await?;
    if files.is_empty() {
        return Ok(SyncMessage::Empty);
    }
    let entries = files
        .into_iter()
        .map(|m| FileEntry {
            file_name: m.file_name,
            file_size: m.file_size,
            total_chunks: m.total_chunks,
            chunk_hashes: m.chunk_hashes,
        })
        .collect();
    Ok(SyncMessage::Manifest {
        node_name: node_name.to_string(),
        files: entries,
    })
}

/// Build an `EncryptedManifest`. Returns the SyncMessage AND the
/// outbound `file_id → rel_path` map the caller must remember so it can
/// later resolve incoming `EncryptedChunkRequest`s.
pub async fn get_encrypted_manifest(
    sync_root: &PathBuf,
    node_name: &str,
    transport_key: &[u8; 32],
    vault_mode: bool,
    vault_key: Option<&[u8; 32]>,
) -> Result<(SyncMessage, HashMap<[u8; 16], String>)> {
    let files = list_folder_modal(sync_root, vault_mode, vault_key).await?;
    if files.is_empty() {
        return Ok((SyncMessage::Empty, HashMap::new()));
    }

    let mut entries = Vec::with_capacity(files.len());
    let mut id_map: HashMap<[u8; 16], String> = HashMap::new();
    for m in &files {
        let file_id = crypto::blind_filename(transport_key, &m.file_name);
        let blinded_chunk_hashes: Vec<[u8; 32]> = m
            .chunk_hashes
            .iter()
            .map(|h| crypto::blind_chunk_hash(transport_key, h))
            .collect();
        entries.push(EncryptedFileEntry {
            file_name: m.file_name.clone(),
            file_id,
            file_size: m.file_size,
            total_chunks: m.total_chunks as u32,
            blinded_chunk_hashes,
        });
        id_map.insert(file_id, m.file_name.clone());
    }

    let payload = EncryptedManifestPayload {
        node_name: node_name.to_string(),
        files: entries,
    };
    let cbor = serde_cbor::to_vec(&payload).context("manifest cbor")?;
    let ciphertext = crypto::encrypt_with_aad(transport_key, &cbor, MANIFEST_AAD)
        .context("manifest encrypt")?;

    Ok((SyncMessage::EncryptedManifest { ciphertext }, id_map))
}

/// Decrypt an `EncryptedManifest.ciphertext`. Returns the inner payload
/// (filenames, file ids, sizes, blinded hashes).
pub fn decrypt_manifest(
    transport_key: &[u8; 32],
    ciphertext: &[u8],
) -> Result<EncryptedManifestPayload> {
    let cbor = crypto::decrypt_with_aad(transport_key, ciphertext, MANIFEST_AAD)
        .context("manifest decrypt failed (wrong transport key?)")?;
    let payload: EncryptedManifestPayload =
        serde_cbor::from_slice(&cbor).context("manifest cbor parse")?;
    Ok(payload)
}

// =============================================================================
// Chunk I/O
// =============================================================================

/// Read one plaintext chunk from local storage, transparently handling
/// vault mode vs plaintext mode.
fn read_local_chunk_plain(
    sync_root: &Path,
    rel_path: &str,
    chunk_index: usize,
    vault_mode: bool,
    vault_key: Option<&[u8; 32]>,
) -> Result<Vec<u8>> {
    if unsafe_rel_path(rel_path) {
        return Err(anyhow!("unsafe path: {}", rel_path));
    }

    if vault_mode {
        let vault_key = vault_key.ok_or_else(|| anyhow!("vault mode without vault_key"))?;
        let abs = rel_to_vault_abs(sync_root, rel_path);
        return vault_read_chunk(&abs, chunk_index as u32, vault_key);
    }

    let abs = rel_to_abs(sync_root, rel_path);
    let mut file = File::open(&abs).with_context(|| format!("Cannot open {:?}", abs))?;
    file.seek(SeekFrom::Start(chunk_index as u64 * CHUNK_SIZE))?;
    let mut buf = vec![0u8; CHUNK_SIZE as usize];
    let n = file.read(&mut buf)?;
    if n == 0 {
        return Err(anyhow!("chunk {} past end of {}", chunk_index, rel_path));
    }
    buf.truncate(n);
    Ok(buf)
}

/// Legacy plaintext-protocol chunk serve. Encrypts in transit if a
/// transport key is supplied (the encryption_key parameter), otherwise
/// returns plaintext bytes.
pub async fn get_chunk(
    sync_root: &PathBuf,
    rel_path: &str,
    chunk_index: usize,
    encryption_key: Option<&[u8; 32]>,
) -> Result<SyncMessage> {
    get_chunk_modal(sync_root, rel_path, chunk_index, encryption_key, false, None).await
}

/// Vault-mode-aware variant of `get_chunk`.
pub async fn get_chunk_modal(
    sync_root: &PathBuf,
    rel_path: &str,
    chunk_index: usize,
    transport_key: Option<&[u8; 32]>,
    vault_mode: bool,
    vault_key: Option<&[u8; 32]>,
) -> Result<SyncMessage> {
    let plaintext = match read_local_chunk_plain(sync_root, rel_path, chunk_index, vault_mode, vault_key) {
        Ok(p) => p,
        Err(e) => {
            return Ok(SyncMessage::Error { message: e.to_string() });
        }
    };
    let hash: [u8; 32] = blake3::hash(&plaintext).into();
    let data = match transport_key {
        Some(key) => crypto::encrypt(key, &plaintext)
            .map_err(|e| anyhow!("Chunk encryption failed: {e}"))?,
        None => plaintext,
    };
    Ok(SyncMessage::ChunkResponse {
        file_name: rel_path.to_string(),
        chunk_index,
        data,
        hash,
    })
}

/// Build an `EncryptedChunkResponse` (AAD-bound, blinded-hash, opaque-id).
pub async fn get_encrypted_chunk(
    sync_root: &PathBuf,
    rel_path: &str,
    file_id: [u8; 16],
    chunk_index: u32,
    transport_key: &[u8; 32],
    vault_mode: bool,
    vault_key: Option<&[u8; 32]>,
) -> Result<SyncMessage> {
    let plaintext = read_local_chunk_plain(
        sync_root,
        rel_path,
        chunk_index as usize,
        vault_mode,
        vault_key,
    )?;
    let plain_hash: [u8; 32] = blake3::hash(&plaintext).into();
    let blinded_hash = crypto::blind_chunk_hash(transport_key, &plain_hash);
    let aad = crypto::chunk_aad(&file_id, chunk_index);
    let data = crypto::encrypt_with_aad(transport_key, &plaintext, &aad)
        .context("encrypted-chunk AEAD")?;
    Ok(SyncMessage::EncryptedChunkResponse {
        file_id,
        chunk_index,
        data,
        blinded_hash,
    })
}

/// Verify a plaintext chunk against an expected plaintext hash.
pub fn verify_chunk(data: &[u8], expected: &[u8; 32]) -> bool {
    blake3::hash(data).as_bytes() == expected
}

/// Verify a plaintext chunk against a TRANSPORT-KEY-BLINDED expected hash.
pub fn verify_chunk_blinded(
    plaintext: &[u8],
    expected_blinded: &[u8; 32],
    transport_key: &[u8; 32],
) -> bool {
    let plain_hash: [u8; 32] = blake3::hash(plaintext).into();
    let blinded = crypto::blind_chunk_hash(transport_key, &plain_hash);
    blinded == *expected_blinded
}

// =============================================================================
// Reassembly
// =============================================================================

/// Reassemble a transferred file. Vault-mode writes a `*.vit` container;
/// otherwise it writes the plaintext file as before.
pub async fn reassemble_modal(
    ts: &FileTransferState,
    vault_mode: bool,
    vault_key: Option<&[u8; 32]>,
) -> Result<PathBuf> {
    let meta = ts
        .metadata
        .as_ref()
        .ok_or_else(|| anyhow!("No metadata during reassembly"))?;

    if vault_mode {
        let vault_key = vault_key.ok_or_else(|| anyhow!("vault mode without vault_key"))?;
        let mut chunks = Vec::with_capacity(meta.total_chunks);
        for i in 0..meta.total_chunks {
            let c = ts
                .received_chunks
                .get(&i)
                .ok_or_else(|| anyhow!("Missing chunk {} during vault reassembly of {}", i, meta.file_name))?;
            chunks.push(c.clone());
        }
        let path = vault_write_file_from_plaintext_chunks(&ts.sync_dir, &meta.file_name, &chunks, vault_key)?;
        info!("Written vault: {:?}", path);
        return Ok(path);
    }

    let mut out_path = ts.sync_dir.clone();
    for component in meta.file_name.split('/') {
        out_path.push(component);
    }
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("Cannot create dirs {:?}", parent))?;
    }
    let mut out = File::create(&out_path).with_context(|| format!("Cannot create {:?}", out_path))?;
    for i in 0..meta.total_chunks {
        match ts.received_chunks.get(&i) {
            Some(d) => out.write_all(d)?,
            None => return Err(anyhow!("Missing chunk {} during reassembly of {}", i, meta.file_name)),
        }
    }
    out.sync_all()?;
    info!("Written: {:?}", out_path);
    Ok(out_path)
}

/// Backward-compatible reassemble (legacy plaintext-on-disk).
pub async fn reassemble(ts: &FileTransferState) -> Result<PathBuf> {
    reassemble_modal(ts, false, None).await
}

// =============================================================================
// Local dedup index
// =============================================================================
pub async fn build_chunk_index(sync_root: &PathBuf) -> HashMap<[u8; 32], (String, usize)> {
    build_chunk_index_modal(sync_root, false, None).await
}

pub async fn build_chunk_index_modal(
    sync_root: &PathBuf,
    vault_mode: bool,
    vault_key: Option<&[u8; 32]>,
) -> HashMap<[u8; 32], (String, usize)> {
    let mut index = HashMap::new();
    let files = match list_folder_modal(sync_root, vault_mode, vault_key).await {
        Ok(f) => f,
        Err(_) => return index,
    };
    for file in files {
        for (chunk_index, hash) in file.chunk_hashes.iter().enumerate() {
            index.entry(*hash).or_insert_with(|| (file.file_name.clone(), chunk_index));
        }
    }
    index
}

pub async fn read_local_chunk(
    sync_root: &PathBuf,
    rel_path: &str,
    chunk_index: usize,
) -> Option<Vec<u8>> {
    read_local_chunk_modal(sync_root, rel_path, chunk_index, false, None).await
}

pub async fn read_local_chunk_modal(
    sync_root: &PathBuf,
    rel_path: &str,
    chunk_index: usize,
    vault_mode: bool,
    vault_key: Option<&[u8; 32]>,
) -> Option<Vec<u8>> {
    read_local_chunk_plain(sync_root, rel_path, chunk_index, vault_mode, vault_key).ok()
}

// =============================================================================
// Bulk vault import — used by the `vitruvius import` subcommand.
// Walks `source_dir` recursively and writes corresponding `*.vit` containers
// under `target_dir`.
// =============================================================================
pub fn import_plaintext_dir_into_vault(
    source_dir: &Path,
    target_dir: &Path,
    vault_key: &[u8; 32],
) -> Result<usize> {
    fs::create_dir_all(target_dir).ok();
    let mut count = 0usize;
    fn recurse(
        src_root: &Path,
        cur: &Path,
        target_root: &Path,
        vault_key: &[u8; 32],
        count: &mut usize,
    ) -> Result<()> {
        for entry in fs::read_dir(cur)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                recurse(src_root, &path, target_root, vault_key, count)?;
            } else if path.is_file() {
                if path.extension().and_then(|s| s.to_str()) == Some(VAULT_EXT) {
                    continue; // already encrypted
                }
                let rel = relative_path(src_root, &path)
                    .ok_or_else(|| anyhow!("rel path failed for {:?}", path))?;
                let mut f = File::open(&path)?;
                let mut chunks: Vec<Vec<u8>> = Vec::new();
                let mut buf = vec![0u8; CHUNK_SIZE as usize];
                loop {
                    let n = f.read(&mut buf)?;
                    if n == 0 {
                        break;
                    }
                    chunks.push(buf[..n].to_vec());
                }
                if chunks.is_empty() {
                    chunks.push(Vec::new());
                }
                vault_write_file_from_plaintext_chunks(target_root, &rel, &chunks, vault_key)?;
                *count += 1;
            }
        }
        Ok(())
    }
    recurse(source_dir, source_dir, target_dir, vault_key, &mut count)?;
    Ok(count)
}

// =============================================================================
// Legacy wrapper kept for compat
// =============================================================================
#[allow(dead_code)]
pub async fn process_chunk(
    _peer_id: PeerId,
    chunk_index: usize,
    data: Vec<u8>,
    ts: &mut FileTransferState,
) -> Result<bool> {
    ts.received_chunks.insert(chunk_index, data);
    let total = ts.metadata.as_ref().map(|m| m.total_chunks).unwrap_or(0);
    if ts.received_chunks.len() < total {
        return Ok(false);
    }
    reassemble(ts).await?;
    Ok(true)
}

// =============================================================================
// Open-options helper used by tests for appending vaults. Public for tests.
// =============================================================================
#[cfg(test)]
pub fn _open_for_append(p: &Path) -> Result<File> {
    Ok(OpenOptions::new().append(true).open(p)?)
}

// =============================================================================
// Tests
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn tmpdir(label: &str) -> PathBuf {
        let mut p = env::temp_dir();
        p.push(format!(
            "vitruvius_test_{}_{}_{}",
            label,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn vault_round_trip_one_chunk() {
        let dir = tmpdir("vault1");
        let key = [0x42u8; 32];
        let chunks = vec![b"hello vault world".to_vec()];
        let path = vault_write_file_from_plaintext_chunks(&dir, "hello.txt", &chunks, &key).unwrap();
        let pt = vault_read_chunk(&path, 0, &key).unwrap();
        assert_eq!(pt, b"hello vault world");
    }

    #[test]
    fn vault_round_trip_multi_chunk() {
        let dir = tmpdir("vaultN");
        let key = [0x33u8; 32];
        let chunks: Vec<Vec<u8>> =
            (0..5).map(|i| vec![i as u8; 1234]).collect();
        let path = vault_write_file_from_plaintext_chunks(&dir, "data.bin", &chunks, &key).unwrap();
        for i in 0..5u32 {
            let pt = vault_read_chunk(&path, i, &key).unwrap();
            assert_eq!(pt, vec![i as u8; 1234]);
        }
    }

    #[test]
    fn vault_wrong_key_fails() {
        let dir = tmpdir("vaultwrong");
        let k1 = [0xAAu8; 32];
        let k2 = [0xBBu8; 32];
        let chunks = vec![b"secret".to_vec()];
        let path = vault_write_file_from_plaintext_chunks(&dir, "x.txt", &chunks, &k1).unwrap();
        assert!(vault_read_chunk(&path, 0, &k2).is_err());
    }

    #[tokio::test]
    async fn vault_listing_recovers_original_metadata() {
        let dir = tmpdir("vaultlist");
        let key = [0x55u8; 32];
        let chunks: Vec<Vec<u8>> =
            (0..3).map(|i| vec![i as u8; 17]).collect();
        vault_write_file_from_plaintext_chunks(&dir, "report.pdf", &chunks, &key).unwrap();
        let listing = list_folder_modal(&dir, true, Some(&key)).await.unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].file_name, "report.pdf");
        assert_eq!(listing[0].total_chunks, 3);
        assert_eq!(listing[0].file_size, 51);
        assert_eq!(listing[0].chunk_hashes.len(), 3);
    }

    #[test]
    fn vault_export_round_trip() {
        let dir = tmpdir("vaultexport");
        let key = [0x77u8; 32];
        let chunks = vec![vec![1u8; 100], vec![2u8; 200]];
        let path = vault_write_file_from_plaintext_chunks(&dir, "f.bin", &chunks, &key).unwrap();
        let mut dest = dir.clone();
        dest.push("decrypted.bin");
        vault_export_to_plaintext(&path, &key, &dest).unwrap();
        let mut out = Vec::new();
        File::open(&dest).unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 300);
        assert_eq!(&out[..100], &vec![1u8; 100][..]);
        assert_eq!(&out[100..], &vec![2u8; 200][..]);
    }

    #[tokio::test]
    async fn encrypted_manifest_round_trip() {
        let dir = tmpdir("encmf");
        let vk = [0x10u8; 32];
        let tk = [0x20u8; 32];
        let chunks = vec![b"abc".to_vec()];
        vault_write_file_from_plaintext_chunks(&dir, "doc.txt", &chunks, &vk).unwrap();
        let (msg, id_map) =
            get_encrypted_manifest(&dir, "node", &tk, true, Some(&vk)).await.unwrap();
        let ct = match msg {
            SyncMessage::EncryptedManifest { ciphertext } => ciphertext,
            _ => panic!("expected EncryptedManifest"),
        };
        let payload = decrypt_manifest(&tk, &ct).unwrap();
        assert_eq!(payload.node_name, "node");
        assert_eq!(payload.files.len(), 1);
        assert_eq!(payload.files[0].file_name, "doc.txt");
        assert_eq!(id_map.get(&payload.files[0].file_id).unwrap(), "doc.txt");
    }
}
