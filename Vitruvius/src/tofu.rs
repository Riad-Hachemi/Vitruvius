// src/tofu.rs
//
// TOFU (Trust On First Use) key exchange for Vitruvius.
//
// Protocol overview:
//
//   1. On first connection to a peer, we generate an ephemeral X25519 keypair.
//   2. We send KeyExchangePropose { public_key } to the peer.
//   3. The peer responds with KeyExchangeAccept { public_key } containing their public key.
//   4. Both sides run X25519 DH and pass the result through BLAKE3 to derive a
//      32-byte ChaCha20-Poly1305 key.
//   5. The derived key is stored to disk keyed by the peer's libp2p PeerId string.
//   6. On reconnect, the stored key is reused — no re-exchange needed.
//
// Security model:
//
//   This is SSH-style TOFU: we accept the peer's key on first contact and pin it.
//   If the peer's key changes on a subsequent connection (e.g. they regenerated their
//   libp2p identity), we warn and refuse — this is the intended behaviour.
//
//   There is no protection against MITM on the *first* connection. A MITM attacker
//   present on the first handshake can intercept and substitute both public keys,
//   becoming an invisible relay. This is an accepted limitation of TOFU and is
//   identical to the SSH first-connect model.
//
//   Future hardening: out-of-band fingerprint verification (display the derived key's
//   BLAKE3 fingerprint to the user on both peers so they can compare them manually).
//
// Storage:
//
//   Keys are persisted to `vitruvius_tofu.json` in the current working directory.
//   Format: { "<peer_id>": "<hex-encoded 32-byte key>", ... }
//
//   The file is created on first exchange and updated on each new peer.
//   Losing this file means all peers will re-exchange on next contact (safe).

use anyhow::Result;
use rand_core::OsRng;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use x25519_dalek::{PublicKey, StaticSecret};

const STORE_FILE: &str = "vitruvius_tofu.json";

fn vitruvius_dir() -> PathBuf {
    let mut p = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push(".vitruvius");
    fs::create_dir_all(&p).ok();
    p
}

fn store_path() -> PathBuf {
    vitruvius_dir().join(STORE_FILE)
}

fn load_store() -> HashMap<String, String> {
    fs::read_to_string(store_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_store(store: &HashMap<String, String>) -> Result<()> {
    let path = store_path();
    let json = serde_json::to_string_pretty(store)?;
    fs::write(&path, json)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Look up the stored derived key for a peer.
/// Returns None if this peer has never been seen before.
pub fn get_peer_key(peer_id: &str) -> Option<[u8; 32]> {
    let store = load_store();
    let hex_key = store.get(peer_id)?;
    let bytes = hex::decode(hex_key).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

/// Persist a derived key for a peer.
pub fn store_peer_key(peer_id: &str, key: &[u8; 32]) -> Result<()> {
    let mut store = load_store();
    store.insert(peer_id.to_string(), hex::encode(key));
    save_store(&store)
}

/// Check whether we have already exchanged keys with a peer.
pub fn has_peer_key(peer_id: &str) -> bool {
    get_peer_key(peer_id).is_some()
}

// ─── Key generation ───────────────────────────────────────────────────────────

/// Generate a new X25519 keypair for a pending key exchange.
/// Returns (secret_bytes, public_key_bytes).
/// The secret is returned as raw bytes so it can be stored in AppState
/// (which requires Send + Sync types).
pub fn generate_keypair() -> ([u8; 32], [u8; 32]) {
    // OsRng here comes from rand_core 0.6, which is the version x25519-dalek
    // was compiled against. Using rand::rng() causes a trait-impl conflict
    // because the project's main rand crate is on a newer rand_core.
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret.to_bytes(), public.to_bytes())
}

// ─── Key derivation ───────────────────────────────────────────────────────────

/// Compute the final 32-byte ChaCha20 key from our X25519 secret and the peer's public key.
///
/// Steps:
///   1. Reconstruct StaticSecret from stored bytes.
///   2. Run X25519 Diffie-Hellman → 32-byte shared secret.
///   3. Hash with BLAKE3 for domain separation and uniform distribution.
///
/// Both peers call this function with their own secret and the other's public key,
/// and both arrive at the same 32-byte output.
pub fn derive_shared_key(
    our_secret_bytes: &[u8; 32],
    their_public_bytes: &[u8; 32],
) -> Result<[u8; 32]> {
    let secret = StaticSecret::from(*our_secret_bytes);
    let their_public = PublicKey::from(*their_public_bytes);
    let shared = secret.diffie_hellman(&their_public);
    // BLAKE3 as KDF — provides uniform output and domain separation.
    // Using a context string ensures this key can never be misused elsewhere.
    let key_material =
        blake3::derive_key("vitruvius 2024 tofu key derivation v1", shared.as_bytes());
    Ok(key_material)
}

/// Produce a short human-readable fingerprint of a derived key for display.
/// Users can compare this across both peers to verify no MITM occurred.
pub fn key_fingerprint(key: &[u8; 32]) -> String {
    let hash = blake3::hash(key);
    let bytes = hash.as_bytes();
    // Display as 4 groups of 4 hex bytes, e.g. "a1b2c3d4:e5f60708:..."
    bytes[..16]
        .chunks(4)
        .map(hex::encode)
        .collect::<Vec<_>>()
        .join(":")
}
