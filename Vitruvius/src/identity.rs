// src/identity.rs
//
// Persistent libp2p identity for Vitruvius.
// Stored in ~/.vitruvius/vitruvius_peer.key with 0o600 permissions.
// On first run a fresh Ed25519 keypair is generated and saved.
// On subsequent runs the same keypair is loaded — giving a stable PeerId.

use anyhow::Result;
use libp2p::identity::Keypair;
use std::fs;
use std::path::PathBuf;

const KEY_FILE: &str = "vitruvius_peer.key";

fn vitruvius_dir() -> PathBuf {
    let mut p = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push(".vitruvius");
    fs::create_dir_all(&p).ok();
    p
}

pub fn load_or_create_keypair() -> Result<Keypair> {
    let path = vitruvius_dir().join(KEY_FILE);

    if path.exists() {
        match fs::read(&path) {
            Ok(bytes) => match Keypair::from_protobuf_encoding(&bytes) {
                Ok(kp) => {
                    tracing::info!("Loaded persistent identity from {}", path.display());
                    return Ok(kp);
                }
                Err(e) => {
                    tracing::warn!(
                        "Identity file at {} is corrupt ({}), generating new keypair",
                        path.display(),
                        e
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Could not read {}: {} — generating new keypair",
                    path.display(),
                    e
                );
            }
        }
    }

    let kp = Keypair::generate_ed25519();
    let bytes = kp.to_protobuf_encoding()?;
    fs::write(&path, &bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    }

    tracing::info!("Generated new persistent identity at {}", path.display());
    Ok(kp)
}
