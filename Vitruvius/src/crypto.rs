// src/crypto.rs
//
// All symmetric encryption / decryption primitives for Vitruvius.
//
// Algorithms:
//   - ChaCha20-Poly1305 — authenticated encryption with associated data (AEAD).
//     A single bit flip in either ciphertext, nonce, or AAD makes decryption fail.
//   - BLAKE3 (keyed mode) — for domain-separated subkey derivation and for
//     "blinding" filenames and plaintext content hashes so they cannot be
//     recognised by an observer who does not hold the key.
//
// Wire format for an encrypted chunk:
//     [ 12 bytes nonce ][ ciphertext + 16-byte Poly1305 tag ]
//
// The nonce is randomly generated per chunk. Never reuse a nonce with the
// same key. AAD is bound to (file_id || chunk_index) when the encrypt-with-AAD
// API is used — this prevents replay-across-position and replay-across-file.
//
// Key-material lifecycle:
//   - 32-byte symmetric keys are wrapped in `SecretKey` so they are zeroized
//     on drop (compiler-enforced, see the `zeroize` crate).
//   - On Unix, `generate_key` writes the key file with mode 0o600.

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::TryRng;
use std::fs;
use std::path::Path;
use tracing::warn;
use zeroize::{Zeroize, ZeroizeOnDrop};

// =============================================================================
// SecretKey — wrapper that zeroes its bytes when dropped
// =============================================================================
//
// Use `SecretKey` for any 32-byte symmetric key that lives longer than a
// single function call (e.g. `AppState.peer_keys`, `AppState.vault_key`).
// For ephemeral function-local arrays, the existing `[u8; 32]` API still
// works — those get zeroed automatically when the array goes out of scope
// only if you explicitly call `.zeroize()`, so prefer `SecretKey` everywhere.

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey(pub [u8; 32]);

impl SecretKey {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    /// Random 32-byte key from the OS RNG.
    pub fn random() -> Result<Self> {
        let mut k = [0u8; 32];
        rand::rng()
            .try_fill_bytes(&mut k)
            .map_err(|e| anyhow!("RNG error: {e}"))?;
        Ok(Self(k))
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the actual bytes.
        write!(f, "SecretKey(<redacted, fp={}>)", short_fingerprint(&self.0))
    }
}

/// Short hex fingerprint of a 32-byte key (first 8 bytes of BLAKE3) — safe
/// to display in logs and the GUI to let users compare keys without leaking
/// the key itself.
pub fn short_fingerprint(key: &[u8; 32]) -> String {
    let h = blake3::hash(key);
    hex::encode(&h.as_bytes()[..8])
}

// =============================================================================
// Key file I/O
// =============================================================================

/// Write 32 random bytes to `path` with mode 0o600 on Unix.
pub fn generate_key(path: &Path) -> Result<()> {
    let key = SecretKey::random()?;
    fs::write(path, key.as_bytes())?;
    set_owner_only_permissions(path)?;
    println!("Key written to: {} (mode 0600)", path.display());
    println!("Copy this file to every peer. Keep it secret.");
    Ok(())
}

/// Load a 32-byte key file. Returns an error if size is wrong or unreadable.
pub fn load_key(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path)?;
    if bytes.len() != 32 {
        return Err(anyhow!(
            "Key file must be exactly 32 bytes, got {}. \
             Did you generate it with --generate-key?",
            bytes.len()
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    // Best-effort tighten perms in case the file came from somewhere lax.
    let _ = set_owner_only_permissions(path);
    Ok(key)
}

/// Set file mode to 0o600 on Unix; no-op on other platforms.
fn set_owner_only_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    let _ = path; // silence unused on non-unix
    Ok(())
}

// =============================================================================
// AEAD — encrypt / decrypt
// =============================================================================

/// Encrypt with no associated data. Layout: [12B nonce][ct+16B tag].
pub fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    encrypt_with_aad(key, plaintext, &[])
}

/// Decrypt the format produced by `encrypt`. No AAD.
pub fn decrypt(key: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
    decrypt_with_aad(key, data, &[])
}

/// Encrypt with associated additional data. The AAD is authenticated but
/// NOT encrypted; the receiver must supply the same AAD to decrypt.
///
/// We use AAD to bind a chunk to its (file_id, chunk_index) — preventing
/// an attacker from swapping chunks across files or across positions, and
/// preventing replay of a chunk into a different slot.
pub fn encrypt_with_aad(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    rand::rng()
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| anyhow!("RNG error: {e}"))?;

    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, Payload { msg: plaintext, aad })
        .map_err(|e| anyhow!("Encryption failed: {e}"))?;

    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a payload produced by `encrypt_with_aad`. AAD must match exactly.
pub fn decrypt_with_aad(key: &[u8; 32], data: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 12 + 16 {
        return Err(anyhow!(
            "Data too short ({} bytes) to be a valid encrypted chunk",
            data.len()
        ));
    }
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = ChaCha20Poly1305::new(key.into());

    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|_| {
            warn!("FATAL: AEAD decryption failed — wrong key, wrong AAD, or tampered data");
            anyhow!("Decryption failed — wrong key, wrong context, or data was tampered with")
        })
}

// =============================================================================
// BLAKE3-based key derivation and metadata blinding
// =============================================================================

/// Derive a 32-byte subkey from a master key and a context string.
/// Uses BLAKE3 keyed mode so the master key never touches the wire.
/// Different `context` strings produce independent subkeys.
pub fn derive_subkey(master: &[u8; 32], context: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(master);
    hasher.update(context.as_bytes());
    let mut out = [0u8; 32];
    hasher.finalize_xof().fill(&mut out);
    out
}

/// Hash a relative path under a transport key, returning a 16-byte opaque
/// identifier. Both peers using the same transport key derive the same id
/// — letting them refer to a file without ever putting the filename on the
/// wire. Different keys produce uncorrelated ids.
pub fn blind_filename(transport_key: &[u8; 32], rel_path: &str) -> [u8; 16] {
    let mut h = blake3::Hasher::new_derive_key("vitruvius v0.2 file-id");
    h.update(transport_key);
    h.update(b"\x00");
    h.update(rel_path.as_bytes());
    let full = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full.as_bytes()[..16]);
    out
}

/// "Blind" a plaintext content hash with the transport key. Same plaintext
/// + same key → same blinded hash (so dedup still works between paired
/// peers), but a relay that does not hold the key cannot recognise a
/// known file by its public BLAKE3.
pub fn blind_chunk_hash(transport_key: &[u8; 32], plaintext_hash: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key("vitruvius v0.2 chunk-hash");
    h.update(transport_key);
    h.update(b"\x00");
    h.update(plaintext_hash);
    let full = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(full.as_bytes());
    out
}

/// Build the AAD bytes that are bound into a transport-encrypted chunk.
/// Layout: ascii tag || file_id (16B) || chunk_index_le (4B).
pub fn chunk_aad(file_id: &[u8; 16], chunk_index: u32) -> [u8; 16 + 4 + 16] {
    const TAG: &[u8; 16] = b"vitv02-chunk\0\0\0\0";
    let mut out = [0u8; 16 + 4 + 16];
    out[..16].copy_from_slice(TAG);
    out[16..32].copy_from_slice(file_id);
    out[32..36].copy_from_slice(&chunk_index.to_le_bytes());
    out
}

// =============================================================================
// Tests
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [0xAB; 32]
    }

    #[test]
    fn round_trip_small() {
        let key = test_key();
        let plaintext = b"hello vitruvius";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn round_trip_empty() {
        let key = test_key();
        let encrypted = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn nonces_are_unique() {
        let key = test_key();
        let a = encrypt(&key, b"same input").unwrap();
        let b = encrypt(&key, b"same input").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn tamper_detection() {
        let key = test_key();
        let mut encrypted = encrypt(&key, b"secret data").unwrap();
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let key_a = [0xAAu8; 32];
        let key_b = [0xBBu8; 32];
        let encrypted = encrypt(&key_a, b"secret").unwrap();
        assert!(decrypt(&key_b, &encrypted).is_err());
    }

    #[test]
    fn short_data_fails() {
        let key = test_key();
        assert!(decrypt(&key, &[0u8; 10]).is_err());
    }

    // ── New tests for AEAD-with-AAD / blinding / derivation ────────────────

    #[test]
    fn aad_round_trip() {
        let key = test_key();
        let aad = chunk_aad(&[0x42; 16], 7);
        let ct = encrypt_with_aad(&key, b"hello", &aad).unwrap();
        let pt = decrypt_with_aad(&key, &ct, &aad).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn aad_mismatch_fails() {
        let key = test_key();
        let aad1 = chunk_aad(&[0x42; 16], 7);
        let aad2 = chunk_aad(&[0x42; 16], 8); // different chunk index
        let ct = encrypt_with_aad(&key, b"hello", &aad1).unwrap();
        assert!(decrypt_with_aad(&key, &ct, &aad2).is_err());
    }

    #[test]
    fn aad_swap_file_fails() {
        let key = test_key();
        let aad1 = chunk_aad(&[0x11; 16], 0);
        let aad2 = chunk_aad(&[0x22; 16], 0); // different file_id
        let ct = encrypt_with_aad(&key, b"hello", &aad1).unwrap();
        assert!(decrypt_with_aad(&key, &ct, &aad2).is_err());
    }

    #[test]
    fn blinded_filenames_deterministic_per_key() {
        let k1 = [0x01u8; 32];
        let k2 = [0x02u8; 32];
        let a = blind_filename(&k1, "secret/path.txt");
        let b = blind_filename(&k1, "secret/path.txt");
        let c = blind_filename(&k2, "secret/path.txt");
        assert_eq!(a, b, "deterministic for same key+path");
        assert_ne!(a, c, "different keys must yield different ids");
    }

    #[test]
    fn blinded_chunk_hash_hides_plaintext_hash() {
        let key = test_key();
        let hash = [0x99u8; 32];
        let blinded = blind_chunk_hash(&key, &hash);
        assert_ne!(blinded, hash, "blinded must differ from plaintext hash");
        // Recomputing yields the same blinded value.
        assert_eq!(blinded, blind_chunk_hash(&key, &hash));
    }

    #[test]
    fn derive_subkey_is_context_separated() {
        let master = test_key();
        let a = derive_subkey(&master, "ctx-A");
        let b = derive_subkey(&master, "ctx-B");
        assert_ne!(a, b);
        // Same context yields the same subkey.
        assert_eq!(a, derive_subkey(&master, "ctx-A"));
    }

    #[test]
    fn fingerprint_does_not_leak_full_key() {
        let key = test_key();
        let fp = short_fingerprint(&key);
        assert_eq!(fp.len(), 16); // 8 bytes hex
        assert!(!fp.contains("ab"), "fingerprint is hash, not raw bytes");
    }

    #[test]
    fn secret_key_debug_is_redacted() {
        let sk = SecretKey::new(test_key());
        let s = format!("{:?}", sk);
        assert!(s.contains("redacted"));
        assert!(!s.contains("AB"));
    }
}
