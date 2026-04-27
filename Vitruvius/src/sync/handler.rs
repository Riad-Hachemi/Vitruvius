// src/sync/handler.rs
//
// ── Download scheduler design ─────────────────────────────────────────────────
//
// THE BUG WE ARE FIXING:
//   When a manifest with N files arrives, the old code fired N × WINDOW chunk
//   requests simultaneously. With 84 files × 8 = 672 concurrent requests, the
//   TCP stream buffer overflows → "Broken pipe" → disconnection → reconnect →
//   same blast again → infinite crash loop.
//
// THE FIX — a two-level queue:
//
//   pending_files: VecDeque<PendingFile>
//     Files from the manifest that we know we need but haven't started yet.
//     Populated when a manifest arrives. Never touches the network.
//
//   active_transfers: HashMap<file_name, FileTransferState>
//     Files currently being downloaded (chunk requests in-flight).
//     Capped at MAX_CONCURRENT_FILES at all times.
//
//   When a file completes → remove from active → pop from pending → start next.
//   This keeps concurrent streams at MAX_CONCURRENT_FILES × WINDOW = 3 × 4 = 12.
//   Well within libp2p's 64-stream limit even for thousands of files.
//
// ── Encryption design ─────────────────────────────────────────────────────────
//
// All encryption/decryption is confined to two points:
//
//   SEND:    storage::get_chunk() encrypts the plaintext chunk just before it
//            is placed into ChunkResponse.data. The plaintext hash is still
//            placed into ChunkResponse.hash for the receiver to verify.
//
//   RECEIVE: on_response() (ChunkResponse arm) decrypts ChunkResponse.data
//            BEFORE verifying the hash and BEFORE storing into received_chunks.
//            This means received_chunks always contains plaintext, and
//            reassemble() writes plaintext to disk unchanged.
//
// The encryption key is read from AppState on every chunk operation.
// No key (None) → plaintext mode, fully backward-compatible.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use libp2p::{mdns, request_response, swarm::SwarmEvent, Multiaddr, PeerId, Swarm};
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info, warn};

use crate::crypto;
use crate::gui::{GuiCommand, GuiEvent, GuiFileInfo};
use crate::network::{MyBehaviour, MyBehaviourEvent, SyncMessage};
use crate::state::{short_id, AppState, InboundFileInfo};
use crate::storage::{self, FileMetadata, FileTransferState, PendingFile};
use crate::tofu;

/// Chunks in-flight per active file.
const WINDOW: usize = 4;

/// Maximum files downloading at the same time.
const MAX_CONCURRENT_FILES: usize = 3;

/// Seconds without a chunk before a file is considered stalled.
const STALL_SECS: u64 = 20;

// ─── Per-peer download state ──────────────────────────────────────────────────
pub struct PeerDownload {
    pub active: HashMap<String, FileTransferState>,
    pub queue: VecDeque<PendingFile>,
}

impl PeerDownload {
    fn new() -> Self {
        Self {
            active: HashMap::new(),
            queue: VecDeque::new(),
        }
    }
}

// =============================================================================
// GUI COMMAND HANDLER
// =============================================================================

pub async fn on_command(
    cmd: GuiCommand,
    swarm: &mut Swarm<MyBehaviour>,
    state: Arc<Mutex<AppState>>,
    event_tx: &mpsc::UnboundedSender<GuiEvent>,
    watch_tx: &mpsc::UnboundedSender<PathBuf>,
    node_name: &str,
) {
    match cmd {
        GuiCommand::ApprovePeer { peer_id } => {
            if let Ok(pid) = peer_id.parse::<PeerId>() {
                let their_public = state.lock().await.pending_approvals.remove(&pid);
                match their_public {
                    None => {
                        log(
                            event_tx,
                            "WARN",
                            format!("No pending approval for {}", short_id(&peer_id)),
                        );
                    }
                    Some(their_pub) => {
                        let (our_secret, our_public) = tofu::generate_keypair();
                        match tofu::derive_shared_key(&our_secret, &their_pub) {
                            Ok(derived_key) => {
                                let fingerprint = tofu::key_fingerprint(&derived_key);
                                state.lock().await.set_peer_key(pid, derived_key);
                                // Send our public key so initiator can derive the same key.
                                swarm.behaviour_mut().rr.send_request(
                                    &pid,
                                    SyncMessage::KeyExchangeAccept {
                                        public_key: our_public,
                                    },
                                );
                                log(
                                    event_tx,
                                    "OK",
                                    format!(
                                        "Approved {} — key established | fingerprint: {}",
                                        short_id(&peer_id),
                                        fingerprint
                                    ),
                                );
                            }
                            Err(e) => {
                                log(event_tx, "ERROR", format!("Key derivation failed: {e}"));
                            }
                        }
                    }
                }
            }
        }

        GuiCommand::DenyPeer { peer_id } => {
            if let Ok(pid) = peer_id.parse::<PeerId>() {
                state.lock().await.pending_approvals.remove(&pid);
                log(
                    event_tx,
                    "WARN",
                    format!(
                        "Denied sync request from {} — disconnecting",
                        short_id(&peer_id)
                    ),
                );
                let _ = swarm.disconnect_peer_id(pid);
            }
        }
        GuiCommand::SetFolder { path } => {
            let p = PathBuf::from(&path);
            if !p.exists() {
                if let Err(e) = fs::create_dir_all(&p) {
                    return log(event_tx, "ERROR", format!("Cannot create folder: {e}"));
                }
            }
            let abs = match fs::canonicalize(&p) {
                Ok(a) => a,
                Err(e) => return log(event_tx, "ERROR", format!("Bad path: {e}")),
            };
            let _ = watch_tx.send(abs.clone());

            // Log encryption status when folder is set so the user knows the mode.
            let encrypted = state.lock().await.is_encrypted();
            if encrypted {
                log(
                    event_tx,
                    "OK",
                    "Encryption enabled — chunks will be encrypted before sending".into(),
                );
            } else {
                log(event_tx, "WARN", "No key loaded — running in plaintext mode. Use --key-path to enable encryption.".into());
            }

            match storage::list_folder(&abs).await {
                Ok(files) => {
                    let listing: Vec<GuiFileInfo> = files
                        .iter()
                        .map(|f| GuiFileInfo {
                            name: f.file_name.clone(),
                            size: f.file_size,
                            chunks: f.total_chunks,
                        })
                        .collect();
                    let count = listing.len();
                    let _ = event_tx.send(GuiEvent::FolderListing { files: listing });
                    log(
                        event_tx,
                        "OK",
                        format!("Sync folder set: {} ({count} file(s))", abs.display()),
                    );
                }
                Err(e) => log(
                    event_tx,
                    "WARN",
                    format!("Folder set but listing failed: {e}"),
                ),
            }

            let connected: Vec<PeerId> = {
                let mut st = state.lock().await;
                st.sync_path = Some(abs);
                st.announced_to.clear();
                st.connected_peers.iter().cloned().collect()
            };

            for peer in connected {
                let pid_str = peer.to_string();
                state.lock().await.announced_to.insert(peer);
                swarm.behaviour_mut().rr.send_request(
                    &peer,
                    SyncMessage::FolderAnnouncement {
                        node_name: node_name.to_string(),
                    },
                );
                // Request their manifest too — they may already have a folder.
                swarm
                    .behaviour_mut()
                    .rr
                    .send_request(&peer, SyncMessage::ManifestRequest);
                log(
                    event_tx,
                    "INFO",
                    format!(
                        "Announced folder to {} and requested their manifest",
                        short_id(&pid_str)
                    ),
                );
            }
        }

        GuiCommand::DialPeer { peer_id, addr } => {
            let addr_str = addr.or_else(|| {
                state
                    .try_lock()
                    .ok()
                    .and_then(|s| s.known_addrs.get(&peer_id).cloned())
            });
            match addr_str {
                None => log(
                    event_tx,
                    "WARN",
                    format!("No address known for {}", short_id(&peer_id)),
                ),
                Some(a) => match a.parse::<Multiaddr>() {
                    Err(e) => log(event_tx, "ERROR", format!("Invalid multiaddr: {e}")),
                    Ok(ma) => {
                        log(
                            event_tx,
                            "INFO",
                            format!("Dialing {} …", short_id(&peer_id)),
                        );
                        if let Err(e) = swarm.dial(ma) {
                            log(event_tx, "ERROR", format!("Dial error: {e}"));
                        }
                    }
                },
            }
        }

        GuiCommand::RequestSync { peer_id } => {
            if let Ok(pid) = peer_id.parse::<PeerId>() {
                log(
                    event_tx,
                    "INFO",
                    format!("Requesting manifest from {} …", short_id(&peer_id)),
                );
                swarm
                    .behaviour_mut()
                    .rr
                    .send_request(&pid, SyncMessage::ManifestRequest);
            }
        }

        GuiCommand::Disconnect { peer_id } => {
            if let Ok(pid) = peer_id.parse::<PeerId>() {
                let _ = swarm.disconnect_peer_id(pid);
            }
        }

        GuiCommand::DecryptFile { name, dest } => {
            // Resolve <sync>/<name>.vit and write decrypted plaintext to `dest`.
            let (sync_path, vault_key) = {
                let st = state.lock().await;
                (st.sync_path.clone(), st.vault_key)
            };
            let key = match vault_key {
                Some(k) => k,
                None => {
                    log(
                        event_tx,
                        "ERROR",
                        "DecryptFile: no vault key loaded — start with --vault".into(),
                    );
                    return;
                }
            };
            let folder = match sync_path {
                Some(p) => p,
                None => {
                    log(event_tx, "ERROR", "DecryptFile: no sync folder set".into());
                    return;
                }
            };
            let mut vault_path = folder.clone();
            for c in name.split('/') {
                vault_path.push(c);
            }
            let new_name = format!("{}.vit", vault_path.file_name().unwrap().to_string_lossy());
            vault_path.set_file_name(new_name);
            if !vault_path.exists() {
                log(
                    event_tx,
                    "ERROR",
                    format!("DecryptFile: {} not found", vault_path.display()),
                );
                return;
            }
            let dest_path = std::path::PathBuf::from(&dest);
            match storage::vault_export_to_plaintext(&vault_path, &key, &dest_path) {
                Ok(n) => log(
                    event_tx,
                    "OK",
                    format!("Decrypted {name} → {dest} ({n} bytes)"),
                ),
                Err(e) => log(
                    event_tx,
                    "ERROR",
                    format!("DecryptFile failed for {name}: {e}"),
                ),
            }
        }
    }
}

// =============================================================================
// STALL CHECKER
// =============================================================================

pub async fn check_stalls(
    swarm: &mut Swarm<MyBehaviour>,
    event_tx: &mpsc::UnboundedSender<GuiEvent>,
    transfers: &mut HashMap<PeerId, PeerDownload>,
) {
    let timeout = Duration::from_secs(STALL_SECS);

    for (peer, dl) in transfers.iter_mut() {
        for (file_name, ts) in dl.active.iter_mut() {
            if ts.last_activity.elapsed() < timeout {
                continue;
            }
            if ts.metadata.is_none() {
                continue;
            }

            let missing = ts.missing_chunks();
            if missing.is_empty() {
                continue;
            }

            let total = ts.metadata.as_ref().map(|m| m.total_chunks).unwrap_or(0);
            warn!(
                "Stall: {} ({}/{}) — re-requesting {} chunks",
                file_name,
                ts.received_chunks.len(),
                total,
                missing.len()
            );
            log(
                event_tx,
                "WARN",
                format!(
                    "Stall on {file_name} — re-requesting {} chunks",
                    missing.len()
                ),
            );

            let to_req = missing.len().min(WINDOW);
            let file_id_opt = ts.file_id;
            for &ci in missing.iter().take(to_req) {
                let req = match file_id_opt {
                    Some(file_id) => SyncMessage::EncryptedChunkRequest {
                        file_id,
                        chunk_index: ci as u32,
                    },
                    None => SyncMessage::ChunkRequest {
                        file_name: file_name.clone(),
                        chunk_index: ci,
                    },
                };
                swarm.behaviour_mut().rr.send_request(peer, req);
            }
            if let Some(&last_ci) = missing.iter().take(to_req).last() {
                ts.next_request = ts.next_request.max(last_ci + 1);
            }
            ts.last_activity = std::time::Instant::now();
        }
    }
}

// =============================================================================
// SWARM EVENT HANDLER
// =============================================================================

pub async fn on_swarm_event(
    event: SwarmEvent<MyBehaviourEvent>,
    swarm: &mut Swarm<MyBehaviour>,
    state: Arc<Mutex<AppState>>,
    event_tx: &mpsc::UnboundedSender<GuiEvent>,
    transfers: &mut HashMap<PeerId, PeerDownload>,
) {
    match event {
        SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
            for (peer_id, addr) in list {
                let pid_str = peer_id.to_string();
                let addr_str = addr.to_string();
                state
                    .lock()
                    .await
                    .known_addrs
                    .insert(pid_str.clone(), addr_str.clone());
                let display = peer_display_name(&state, &pid_str).await;
                info!("mDNS: {} at {}", pid_str, addr_str);
                let _ = event_tx.send(GuiEvent::PeerDiscovered {
                    peer_id: pid_str,
                    addr: addr_str,
                    node_name: display,
                });
            }
        }

        SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
            for (peer_id, _) in list {
                state.lock().await.known_addrs.remove(&peer_id.to_string());
            }
        }

        SwarmEvent::ConnectionEstablished { peer_id, .. } => {
            let pid_str = peer_id.to_string();
            state.lock().await.connected_peers.insert(peer_id);
            info!("Connected to {}", pid_str);

            let display = peer_display_name(&state, &pid_str).await;
            let _ = event_tx.send(GuiEvent::PeerConnected {
                peer_id: pid_str.clone(),
                node_name: display.clone(),
            });
            log(event_tx, "OK", format!("Connected to {display}"));

            let (have_folder, my_name) = folder_status(&state).await;
            if have_folder {
                state.lock().await.announced_to.insert(peer_id);
                swarm.behaviour_mut().rr.send_request(
                    &peer_id,
                    SyncMessage::FolderAnnouncement { node_name: my_name },
                );
                // Also proactively request their manifest in case they already
                // have a folder set and won't announce first.
                swarm
                    .behaviour_mut()
                    .rr
                    .send_request(&peer_id, SyncMessage::ManifestRequest);
                log(
                    event_tx,
                    "INFO",
                    format!(
                        "Folder already set — announced to {} and requesting their manifest",
                        short_id(&pid_str)
                    ),
                );
            }
            let (no_global_key, already_have_key) = {
                let st = state.lock().await;
                let no_global = st.encryption_key.is_none();
                let already = st.peer_keys.contains_key(&peer_id) || tofu::has_peer_key(&pid_str);
                (no_global, already)
            };
            if no_global_key && !already_have_key {
                // Only the peer with the lexicographically lower PeerId initiates.
                // This prevents both sides sending KeyExchangePropose simultaneously,
                // which causes a race where both call set_peer_key twice with
                // different ephemeral secrets, producing mismatched final keys.
                let local_id = swarm.local_peer_id().to_string();
                if local_id < pid_str {
                    let (secret_bytes, public_bytes) = tofu::generate_keypair();
                    state
                        .lock()
                        .await
                        .pending_exchanges
                        .insert(peer_id, secret_bytes);
                    swarm.behaviour_mut().rr.send_request(
                        &peer_id,
                        SyncMessage::KeyExchangePropose {
                            public_key: public_bytes,
                        },
                    );
                    log(
                        event_tx,
                        "INFO",
                        format!("Initiating TOFU key exchange with {} …", short_id(&pid_str)),
                    );
                } else {
                    log(
                        event_tx,
                        "INFO",
                        format!("Waiting for TOFU proposal from {} …", short_id(&pid_str)),
                    );
                }
            } else if already_have_key {
                // Load the persisted key back into memory for this session.
                if let Some(key) = tofu::get_peer_key(&pid_str) {
                    state.lock().await.peer_keys.insert(peer_id, key);
                    log(
                        event_tx,
                        "OK",
                        format!("Loaded stored TOFU key for {}", short_id(&pid_str)),
                    );
                }
            }
        }

        SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            let pid_str = peer_id.to_string();
            {
                let mut st = state.lock().await;
                st.connected_peers.remove(&peer_id);
                st.announced_to.remove(&peer_id);
            }
            transfers.remove(&peer_id);
            let reason = cause.map(|e| e.to_string()).unwrap_or_default();
            warn!("Closed: {} — {}", pid_str, reason);
            let _ = event_tx.send(GuiEvent::PeerDisconnected {
                peer_id: pid_str.clone(),
            });
            log(
                event_tx,
                "WARN",
                format!("Disconnected from {} ({reason})", short_id(&pid_str)),
            );
        }

        SwarmEvent::Behaviour(MyBehaviourEvent::Rr(request_response::Event::Message {
            peer,
            message,
        })) => {
            let pid_str = peer.to_string();
            match message {
                request_response::Message::Request {
                    channel, request, ..
                } => on_request(request, channel, peer, &pid_str, swarm, &state, event_tx).await,
                request_response::Message::Response { response, .. } => {
                    on_response(response, peer, &pid_str, swarm, &state, event_tx, transfers).await
                }
            }
        }

        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            let pid_str = peer_id.map(|p| p.to_string());
            warn!("Dial failed {:?}: {}", pid_str, error);
            let _ = event_tx.send(GuiEvent::DialFailed {
                peer_id: pid_str,
                error: error.to_string(),
            });
        }

        _ => {}
    }
}

// =============================================================================
// UPLOADER — serve an incoming request
// =============================================================================

async fn on_request(
    request: SyncMessage,
    channel: request_response::ResponseChannel<SyncMessage>,
    peer: PeerId,
    pid_str: &str,
    swarm: &mut Swarm<MyBehaviour>,
    state: &Arc<Mutex<AppState>>,
    event_tx: &mpsc::UnboundedSender<GuiEvent>,
) {
    match request {
        SyncMessage::FolderAnnouncement {
            node_name: peer_name,
        } => {
            state
                .lock()
                .await
                .peer_names
                .insert(pid_str.to_string(), peer_name.clone());
            log(
                event_tx,
                "INFO",
                format!("{peer_name} announced their folder — requesting their manifest …"),
            );
            let _ = swarm
                .behaviour_mut()
                .rr
                .send_response(channel, SyncMessage::Ack);

            // ── THE MISSING REQUEST ───────────────────────────────────────────
            // The peer just told us "I have files."  Actually request their
            // manifest now so sync happens automatically without the user
            // having to click "Request Sync" every time.
            swarm
                .behaviour_mut()
                .rr
                .send_request(&peer, SyncMessage::ManifestRequest);

            let (have_folder, my_name) = folder_status(state).await;
            if have_folder {
                let already = state.lock().await.announced_to.contains(&peer);
                if !already {
                    state.lock().await.announced_to.insert(peer);
                    swarm.behaviour_mut().rr.send_request(
                        &peer,
                        SyncMessage::FolderAnnouncement { node_name: my_name },
                    );
                }
            }
        }

        SyncMessage::ManifestRequest => {
            // Mirror the operator-shared key into the per-peer table so the
            // rest of the request handler can rely on key_for_peer(peer).
            {
                let mut st = state.lock().await;
                if !st.peer_keys.contains_key(&peer) && st.encryption_key.is_some() {
                    st.mirror_shared_key(peer);
                }
            }
            let (path, my_name, peer_key, vault_mode, vault_key, encrypted_protocol) = {
                let st = state.lock().await;
                (
                    st.sync_path.clone(),
                    st.node_name.clone(),
                    st.key_for_peer(&peer),
                    st.vault_mode,
                    st.vault_key,
                    st.encrypted_protocol,
                )
            };
            match path {
                None => {
                    log(
                        event_tx,
                        "INFO",
                        format!(
                            "{} requested manifest — no folder set yet",
                            short_id(pid_str)
                        ),
                    );
                    let _ = swarm
                        .behaviour_mut()
                        .rr
                        .send_response(channel, SyncMessage::Empty);
                }
                Some(ref p) => {
                    if encrypted_protocol && peer_key.is_some() {
                        let key = peer_key.unwrap();
                        log(
                            event_tx,
                            "INFO",
                            format!(
                                "{} requested our manifest — sending ENCRYPTED",
                                short_id(pid_str)
                            ),
                        );
                        let (resp, id_map) = match storage::get_encrypted_manifest(
                            p,
                            &my_name,
                            &key,
                            vault_mode,
                            vault_key.as_ref(),
                        )
                        .await
                        {
                            Ok((m, ids)) => (m, ids),
                            Err(e) => {
                                let _ = swarm.behaviour_mut().rr.send_response(
                                    channel,
                                    SyncMessage::Error { message: e.to_string() },
                                );
                                return;
                            }
                        };
                        // Remember which file_ids we just told this peer about
                        // so we can resolve their EncryptedChunkRequest.
                        state
                            .lock()
                            .await
                            .outbound_file_ids
                            .insert(peer, id_map);
                        let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
                    } else {
                        log(
                            event_tx,
                            "INFO",
                            format!("{} requested our manifest (plaintext)", short_id(pid_str)),
                        );
                        let resp: SyncMessage = storage::get_manifest(p, &my_name)
                            .await
                            .unwrap_or_else(|e: anyhow::Error| SyncMessage::Error {
                                message: e.to_string(),
                            });
                        let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
                    }
                }
            }
        }

        SyncMessage::EncryptedChunkRequest {
            file_id,
            chunk_index,
        } => {
            let (path, peer_key, vault_mode, vault_key, rel_path) = {
                let st = state.lock().await;
                let rel = st
                    .outbound_file_ids
                    .get(&peer)
                    .and_then(|m| m.get(&file_id).cloned());
                (
                    st.sync_path.clone(),
                    st.key_for_peer(&peer),
                    st.vault_mode,
                    st.vault_key,
                    rel,
                )
            };
            let resp = match (path, peer_key, rel_path) {
                (Some(p), Some(key), Some(rel)) => storage::get_encrypted_chunk(
                    &p,
                    &rel,
                    file_id,
                    chunk_index,
                    &key,
                    vault_mode,
                    vault_key.as_ref(),
                )
                .await
                .unwrap_or_else(|e| SyncMessage::Error {
                    message: e.to_string(),
                }),
                _ => SyncMessage::Error {
                    message: "Encrypted chunk request: missing key/folder/id mapping".into(),
                },
            };
            if matches!(resp, SyncMessage::EncryptedChunkResponse { .. }) {
                log(
                    event_tx,
                    "INFO",
                    format!(
                        "→ encrypted chunk [{chunk_index}] to {}",
                        short_id(pid_str)
                    ),
                );
            }
            let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
        }

        SyncMessage::ChunkRequest {
            ref file_name,
            chunk_index,
        } => {
            // Grab both the sync path and the encryption key in one lock.
            let (path, enc_key) = {
                let st = state.lock().await;
                (st.sync_path.clone(), st.key_for_peer(&peer))
            };

            match path {
                None => {
                    let _ = swarm.behaviour_mut().rr.send_response(
                        channel,
                        SyncMessage::Error {
                            message: "No sync folder".into(),
                        },
                    );
                }
                Some(ref p) => {
                    // Pass encryption key into get_chunk — it encrypts transparently.
                    let resp: SyncMessage =
                        storage::get_chunk(p, file_name, chunk_index, enc_key.as_ref())
                            .await
                            .unwrap_or_else(|e: anyhow::Error| SyncMessage::Error {
                                message: e.to_string(),
                            });
                    if matches!(resp, SyncMessage::ChunkResponse { .. }) {
                        let enc_indicator = if enc_key.is_some() { "" } else { "" };
                        log(
                            event_tx,
                            "INFO",
                            format!(
                                "{enc_indicator}-> {file_name} [{chunk_index}] to {}",
                                short_id(pid_str)
                            ),
                        );
                    }
                    let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
                }
            }
        }

        SyncMessage::TransferComplete { ref file_name } => {
            log(
                event_tx,
                "OK",
                format!("{} confirmed receipt of {file_name}", short_id(pid_str)),
            );
            let _ = swarm
                .behaviour_mut()
                .rr
                .send_response(channel, SyncMessage::Ack);
        }

        SyncMessage::FileChanged { ref file_name } => {
            let _ = swarm
                .behaviour_mut()
                .rr
                .send_response(channel, SyncMessage::Ack);

            let sync_path = state.lock().await.sync_path.clone();
            if let Some(ref path) = sync_path {
                let mut full_path = path.clone();
                for component in file_name.split('/') {
                    full_path.push(component);
                }
                state.lock().await.deleting_files.insert(full_path.clone());
                let _ = std::fs::remove_file(&full_path);
                let state2 = Arc::clone(state);
                let value = full_path.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(2000)).await;
                    state2.lock().await.deleting_files.remove(&value);
                });

                log(
                    event_tx,
                    "INFO",
                    format!(
                        "{} changed on {} — re-requesting",
                        file_name,
                        short_id(pid_str)
                    ),
                );

                swarm
                    .behaviour_mut()
                    .rr
                    .send_request(&peer, SyncMessage::ManifestRequest);
            }
        }

        SyncMessage::FileDeleted { ref file_name } => {
            let _ = swarm
                .behaviour_mut()
                .rr
                .send_response(channel, SyncMessage::Ack);

            let sync_path = state.lock().await.sync_path.clone();
            if let Some(ref path) = sync_path {
                let mut full_path = path.clone();
                for component in file_name.split('/') {
                    full_path.push(component);
                }
                if let Err(e) = std::fs::remove_file(&full_path) {
                    log(
                        event_tx,
                        "WARN",
                        format!("Could not delete {file_name}: {e}"),
                    );
                } else {
                    log(
                        event_tx,
                        "OK",
                        format!("{file_name} deleted (peer removed it)"),
                    );
                }
            }
        }
        SyncMessage::KeyExchangePropose {
            public_key: their_public,
        } => {
            // Check if we already have a key for this peer — ignore duplicate proposals.
            let already_keyed = {
                let st = state.lock().await;
                st.peer_keys.contains_key(&peer) || tofu::has_peer_key(pid_str)
            };
            if already_keyed {
                // This peer is already trusted (in our TOFU store) but they are
                // proposing a new exchange — meaning they lost their key store.
                // Re-key silently without requiring user approval again: generate
                // a new ephemeral pair, derive a fresh shared key, and respond
                // with KeyExchangeAccept so both sides agree on the new key.
                let (secret_bytes, our_public) = tofu::generate_keypair();
                match tofu::derive_shared_key(&secret_bytes, &their_public) {
                    Ok(derived_key) => {
                        let fingerprint = tofu::key_fingerprint(&derived_key);
                        state.lock().await.set_peer_key(peer, derived_key);
                        let _ = swarm.behaviour_mut().rr.send_response(
                            channel,
                            SyncMessage::KeyExchangeAccept {
                                public_key: our_public,
                            },
                        );
                        log(
                            event_tx,
                            "OK",
                            format!(
                                "Re-keyed with already-trusted {} | fingerprint: {}",
                                short_id(pid_str),
                                fingerprint
                            ),
                        );
                    }
                    Err(e) => {
                        log(event_tx, "ERROR", format!("Re-keying failed: {e}"));
                        let _ = swarm
                            .behaviour_mut()
                            .rr
                            .send_response(channel, SyncMessage::Ack);
                    }
                }
                return;
            }

            // Store their public key — don't derive anything yet.
            // The user must explicitly approve this peer before we respond.
            state
                .lock()
                .await
                .pending_approvals
                .insert(peer, their_public);

            let display = peer_display_name(state, pid_str).await;
            log(
                event_tx,
                "WARN",
                format!(
                    "Peer {} is requesting to sync — waiting for your approval",
                    display
                ),
            );

            let _ = event_tx.send(GuiEvent::PeerApprovalRequired {
                peer_id: pid_str.to_string(),
                display_name: display,
            });

            // Don't send KeyExchangeAccept yet — we send Ack to keep the channel alive.
            let _ = swarm
                .behaviour_mut()
                .rr
                .send_response(channel, SyncMessage::Ack);
        }
        SyncMessage::KeyExchangeAccept {
            public_key: their_public,
        } => {
            // We receive this when the remote peer's user approved us.
            // Retrieve our ephemeral secret and derive the shared key.
            let our_secret = state.lock().await.pending_exchanges.remove(&peer);
            match our_secret {
                None => {
                    log(
                        event_tx,
                        "WARN",
                        format!(
                            "KeyExchangeAccept from {} but no pending exchange — ignoring",
                            short_id(pid_str)
                        ),
                    );
                }
                Some(secret_bytes) => match tofu::derive_shared_key(&secret_bytes, &their_public) {
                    Ok(derived_key) => {
                        let fingerprint = tofu::key_fingerprint(&derived_key);
                        state.lock().await.set_peer_key(peer, derived_key);
                        log(
                            event_tx,
                            "OK",
                            format!(
                                "TOFU established with {} | fingerprint: {}",
                                short_id(pid_str),
                                fingerprint
                            ),
                        );
                    }
                    Err(e) => {
                        log(event_tx, "ERROR", format!("Key derivation failed: {e}"));
                    }
                },
            }
            let _ = swarm
                .behaviour_mut()
                .rr
                .send_response(channel, SyncMessage::Ack);
        }

        _ => {
            let _ = swarm.behaviour_mut().rr.send_response(
                channel,
                SyncMessage::Error {
                    message: "Unexpected request type".into(),
                },
            );
        }
    }
}

// =============================================================================
// DOWNLOADER — handle a response to one of our requests
// =============================================================================

async fn on_response(
    response: SyncMessage,
    peer: PeerId,
    pid_str: &str,
    swarm: &mut Swarm<MyBehaviour>,
    state: &Arc<Mutex<AppState>>,
    event_tx: &mpsc::UnboundedSender<GuiEvent>,
    transfers: &mut HashMap<PeerId, PeerDownload>,
) {
    match response {
        SyncMessage::Ack => {}
        SyncMessage::KeyExchangeAccept {
            public_key: their_public,
        } => {
            // We initiated — retrieve our pending secret and derive the shared key.
            let our_secret = state.lock().await.pending_exchanges.remove(&peer);

            match our_secret {
                None => {
                    log(event_tx, "WARN",
                    format!("Received KeyExchangeAccept from {} but no pending exchange found — ignoring",
                            short_id(pid_str)));
                }
                Some(secret_bytes) => match tofu::derive_shared_key(&secret_bytes, &their_public) {
                    Ok(derived_key) => {
                        let fingerprint = tofu::key_fingerprint(&derived_key);
                        state.lock().await.set_peer_key(peer, derived_key);
                        log(
                            event_tx,
                            "OK",
                            format!(
                                "TOFU: key exchange complete with {} | fingerprint: {}",
                                short_id(pid_str),
                                fingerprint,
                            ),
                        );
                    }
                    Err(e) => {
                        log(event_tx, "ERROR", format!("Key derivation failed: {e}"));
                    }
                },
            }
        }

        SyncMessage::EncryptedManifest { ciphertext } => {
            let peer_key = state.lock().await.key_for_peer(&peer);
            let key = match peer_key {
                Some(k) => k,
                None => {
                    log(
                        event_tx,
                        "WARN",
                        format!(
                            "EncryptedManifest from {} but no transport key — ignoring",
                            short_id(pid_str)
                        ),
                    );
                    return;
                }
            };
            let payload = match storage::decrypt_manifest(&key, &ciphertext) {
                Ok(p) => p,
                Err(e) => {
                    log(
                        event_tx,
                        "ERROR",
                        format!("Manifest decrypt failed from {}: {e}", short_id(pid_str)),
                    );
                    return;
                }
            };
            let peer_name = payload.node_name.clone();
            state
                .lock()
                .await
                .peer_names
                .insert(pid_str.to_string(), peer_name.clone());

            if payload.files.is_empty() {
                log(
                    event_tx,
                    "INFO",
                    format!("{peer_name} encrypted manifest had no files"),
                );
                return;
            }

            let (sync_path, vault_mode) = {
                let st = state.lock().await;
                (st.sync_path.clone(), st.vault_mode)
            };
            let sync_path = match sync_path {
                Some(p) => p,
                None => {
                    log(
                        event_tx,
                        "WARN",
                        "Received encrypted manifest but no sync folder set!".into(),
                    );
                    return;
                }
            };

            // Cache id → InboundFileInfo so we can later look up filenames
            // when EncryptedChunkResponse arrives.
            let mut info_map: HashMap<[u8; 16], InboundFileInfo> = HashMap::new();
            for fe in &payload.files {
                info_map.insert(
                    fe.file_id,
                    InboundFileInfo {
                        file_name: fe.file_name.clone(),
                        file_size: fe.file_size,
                        total_chunks: fe.total_chunks,
                        blinded_chunk_hashes: fe.blinded_chunk_hashes.clone(),
                    },
                );
            }
            state
                .lock()
                .await
                .inbound_file_ids
                .insert(peer, info_map);

            let dl = transfers.entry(peer).or_insert_with(PeerDownload::new);
            let mut newly_queued = 0usize;
            for fe in &payload.files {
                if rel_path_exists(&sync_path, &fe.file_name) {
                    continue;
                }
                if vault_mode && vault_path_exists(&sync_path, &fe.file_name) {
                    continue;
                }
                if dl.active.contains_key(&fe.file_name) {
                    continue;
                }
                if dl.queue.iter().any(|p| p.file_name == fe.file_name) {
                    continue;
                }

                dl.queue.push_back(PendingFile {
                    file_name: fe.file_name.clone(),
                    total_chunks: fe.total_chunks as usize,
                    file_size: fe.file_size,
                    // For encrypted-protocol files, chunk_hashes carries the
                    // BLINDED hashes — receiver verifies against these via
                    // verify_chunk_blinded(plaintext, expected, transport_key).
                    chunk_hashes: fe.blinded_chunk_hashes.clone(),
                    file_id: Some(fe.file_id),
                });
                newly_queued += 1;
            }

            let total_pending = dl.active.len() + dl.queue.len();
            if total_pending == 0 {
                log(
                    event_tx,
                    "OK",
                    format!("All files from {peer_name} already synced"),
                );
                return;
            }

            log(
                event_tx,
                "INFO",
                format!(
                    "{peer_name} (encrypted): {newly_queued} file(s) queued ({} active, {} waiting)",
                    dl.active.len(),
                    dl.queue.len()
                ),
            );

            start_queued_files(peer, &sync_path, dl, swarm, event_tx, pid_str);
        }

        SyncMessage::Manifest {
            node_name: peer_name,
            ref files,
        } => {
            state
                .lock()
                .await
                .peer_names
                .insert(pid_str.to_string(), peer_name.clone());

            if files.is_empty() {
                log(
                    event_tx,
                    "INFO",
                    format!("{peer_name} manifest returned no files"),
                );
                return;
            }

            let sync_path = match state.lock().await.sync_path.clone() {
                Some(p) => p,
                None => {
                    log(
                        event_tx,
                        "WARN",
                        "Received manifest but no sync folder set — set one first!".into(),
                    );
                    return;
                }
            };

            let dl = transfers.entry(peer).or_insert_with(PeerDownload::new);

            let mut newly_queued = 0usize;
            for fe in files {
                if rel_path_exists(&sync_path, &fe.file_name) {
                    continue;
                }
                if dl.active.contains_key(&fe.file_name) {
                    continue;
                }
                if dl.queue.iter().any(|p| p.file_name == fe.file_name) {
                    continue;
                }

                dl.queue.push_back(PendingFile::from(fe));
                newly_queued += 1;
            }

            let total_pending = dl.active.len() + dl.queue.len();
            if total_pending == 0 {
                log(
                    event_tx,
                    "OK",
                    format!("All files from {peer_name} already synced — nothing to do"),
                );
                return;
            }

            log(
                event_tx,
                "INFO",
                format!(
                    "{peer_name}: {newly_queued} file(s) queued ({} active, {} waiting)",
                    dl.active.len(),
                    dl.queue.len()
                ),
            );

            start_queued_files(peer, &sync_path, dl, swarm, event_tx, pid_str);
        }

        SyncMessage::Empty => {
            let _ = event_tx.send(GuiEvent::RemoteEmpty {
                peer_id: pid_str.to_string(),
            });
            log(
                event_tx,
                "INFO",
                format!("{} has no sync folder set yet", short_id(pid_str)),
            );
        }

        SyncMessage::ChunkResponse {
            ref file_name,
            chunk_index,
            ref data,
            hash: _,
        } => {
            let sync_path = match state.lock().await.sync_path.clone() {
                Some(p) => p,
                None => return,
            };

            // ── DECRYPTION ────────────────────────────────────────────────────
            // Decrypt BEFORE hash verification. The hash in the manifest is a
            // plaintext hash, so we must have plaintext before we can verify it.
            // If no key is set, pass the data through unchanged (plaintext mode).
            let enc_key = state.lock().await.key_for_peer(&peer);
            let plaintext = match enc_key {
                Some(ref key) => {
                    match crypto::decrypt(key, data) {
                        Ok(pt) => pt,
                        Err(e) => {
                            log(
                                event_tx,
                                "ERROR",
                                format!(
                                    "{file_name} chunk {chunk_index} decryption failed: {e}. \
                                     Check that all peers use the same key file."
                                ),
                            );
                            // Retry the chunk — the sender may have had a transient error.
                            swarm.behaviour_mut().rr.send_request(
                                &peer,
                                SyncMessage::ChunkRequest {
                                    file_name: file_name.clone(),
                                    chunk_index,
                                },
                            );
                            return;
                        }
                    }
                }
                None => data.clone(),
            };

            let dl = match transfers.get_mut(&peer) {
                Some(d) => d,
                None => return,
            };

            let ts = match dl.active.get_mut(file_name) {
                Some(t) => t,
                None => return,
            };

            let expected: Option<[u8; 32]> = ts
                .metadata
                .as_ref()
                .and_then(|m| m.chunk_hashes.get(chunk_index))
                .copied();

            // Verify hash against PLAINTEXT — always.
            let verified = expected
                .map(|h| storage::verify_chunk(&plaintext, &h))
                .unwrap_or(false);

            let total = ts.metadata.as_ref().map(|m| m.total_chunks).unwrap_or(0);

            let _ = event_tx.send(GuiEvent::ChunkReceived {
                peer_id: pid_str.to_string(),
                file_name: file_name.clone(),
                chunk_index,
                total_chunks: total,
                verified,
            });

            if !verified {
                log(
                    event_tx,
                    "ERROR",
                    format!("{file_name} chunk {chunk_index} hash mismatch — retrying"),
                );
                swarm.behaviour_mut().rr.send_request(
                    &peer,
                    SyncMessage::ChunkRequest {
                        file_name: file_name.clone(),
                        chunk_index,
                    },
                );
                return;
            }

            // Store PLAINTEXT in received_chunks — reassemble() writes it directly to disk.
            ts.received_chunks.insert(chunk_index, plaintext);
            ts.last_activity = std::time::Instant::now();

            if ts.next_request < total {
                swarm.behaviour_mut().rr.send_request(
                    &peer,
                    SyncMessage::ChunkRequest {
                        file_name: file_name.clone(),
                        chunk_index: ts.next_request,
                    },
                );
                ts.next_request += 1;
            }

            log(
                event_tx,
                "INFO",
                format!("{file_name}  {}/{total}", chunk_index + 1),
            );

            if ts.received_chunks.len() < total {
                return;
            }
            let dest_path = {
                let meta = ts.metadata.as_ref().unwrap(); // safe: we checked len above
                let mut p = ts.sync_dir.clone();
                for component in meta.file_name.split('/') {
                    p.push(component);
                }
                p
            };
            state.lock().await.writing_files.insert(dest_path.clone());

            let (vm_done, vk_done) = {
                let st = state.lock().await;
                (st.vault_mode, st.vault_key)
            };
            match storage::reassemble_modal(ts, vm_done, vk_done.as_ref()).await {
                Ok(written_path) => {
                    let fname = file_name.clone();

                    let _ = event_tx.send(GuiEvent::TransferComplete {
                        peer_id: pid_str.to_string(),
                        file_name: fname.clone(),
                    });

                    log(event_tx, "OK", format!("  {fname} saved to disk"));

                    swarm.behaviour_mut().rr.send_request(
                        &peer,
                        SyncMessage::TransferComplete {
                            file_name: fname.clone(),
                        },
                    );

                    dl.active.remove(&fname);
                    start_queued_files(peer, &sync_path, dl, swarm, event_tx, pid_str);

                    let state2 = Arc::clone(state);
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                        state2.lock().await.writing_files.remove(&written_path);
                    });

                    if !dl.queue.is_empty() || !dl.active.is_empty() {
                        log(
                            event_tx,
                            "INFO",
                            format!(
                                "{} active download(s), {} in queue",
                                dl.active.len(),
                                dl.queue.len()
                            ),
                        );
                    } else {
                        log(
                            event_tx,
                            "OK",
                            format!("All downloads from {} complete!", short_id(pid_str)),
                        );
                    }
                }

                Err(e) => {
                    error!("Reassembly error for {file_name}: {e}");
                    log(
                        event_tx,
                        "ERROR",
                        format!("Failed to write {file_name}: {e}"),
                    );
                }
            }
        }

        SyncMessage::EncryptedChunkResponse {
            file_id,
            chunk_index,
            ref data,
            blinded_hash: _,
        } => {
            let (sync_path, vault_mode, vault_key, peer_key) = {
                let st = state.lock().await;
                (
                    st.sync_path.clone(),
                    st.vault_mode,
                    st.vault_key,
                    st.key_for_peer(&peer),
                )
            };
            let sync_path = match sync_path {
                Some(p) => p,
                None => return,
            };
            let key = match peer_key {
                Some(k) => k,
                None => {
                    log(
                        event_tx,
                        "ERROR",
                        format!(
                            "EncryptedChunkResponse from {} but no transport key",
                            short_id(pid_str)
                        ),
                    );
                    return;
                }
            };
            // Resolve file_name from inbound id map.
            let file_name = match state
                .lock()
                .await
                .inbound_file_ids
                .get(&peer)
                .and_then(|m| m.get(&file_id))
                .map(|i| i.file_name.clone())
            {
                Some(n) => n,
                None => {
                    log(
                        event_tx,
                        "WARN",
                        format!("Unknown file_id from {}", short_id(pid_str)),
                    );
                    return;
                }
            };

            let aad = crypto::chunk_aad(&file_id, chunk_index);
            let plaintext = match crypto::decrypt_with_aad(&key, data, &aad) {
                Ok(pt) => pt,
                Err(e) => {
                    log(
                        event_tx,
                        "ERROR",
                        format!("AEAD-decrypt failed for {file_name} chunk {chunk_index}: {e}"),
                    );
                    swarm.behaviour_mut().rr.send_request(
                        &peer,
                        SyncMessage::EncryptedChunkRequest { file_id, chunk_index },
                    );
                    return;
                }
            };
            let chunk_index_us = chunk_index as usize;

            let dl = match transfers.get_mut(&peer) {
                Some(d) => d,
                None => return,
            };
            let ts = match dl.active.get_mut(&file_name) {
                Some(t) => t,
                None => return,
            };

            let expected_blinded: Option<[u8; 32]> = ts
                .metadata
                .as_ref()
                .and_then(|m| m.chunk_hashes.get(chunk_index_us))
                .copied();
            let verified = expected_blinded
                .map(|h| storage::verify_chunk_blinded(&plaintext, &h, &key))
                .unwrap_or(false);
            let total = ts.metadata.as_ref().map(|m| m.total_chunks).unwrap_or(0);

            let _ = event_tx.send(GuiEvent::ChunkReceived {
                peer_id: pid_str.to_string(),
                file_name: file_name.clone(),
                chunk_index: chunk_index_us,
                total_chunks: total,
                verified,
            });

            if !verified {
                log(
                    event_tx,
                    "ERROR",
                    format!("{file_name} chunk {chunk_index_us} BLINDED hash mismatch — retrying"),
                );
                swarm.behaviour_mut().rr.send_request(
                    &peer,
                    SyncMessage::EncryptedChunkRequest { file_id, chunk_index },
                );
                return;
            }

            ts.received_chunks.insert(chunk_index_us, plaintext);
            ts.last_activity = std::time::Instant::now();

            if ts.next_request < total {
                swarm.behaviour_mut().rr.send_request(
                    &peer,
                    SyncMessage::EncryptedChunkRequest {
                        file_id,
                        chunk_index: ts.next_request as u32,
                    },
                );
                ts.next_request += 1;
            }

            log(event_tx, "INFO", format!("{file_name}  {}/{total} (enc)", chunk_index_us + 1));

            if ts.received_chunks.len() < total {
                return;
            }

            let dest_path = {
                let meta = ts.metadata.as_ref().unwrap();
                let mut p = ts.sync_dir.clone();
                for component in meta.file_name.split('/') {
                    p.push(component);
                }
                p
            };
            state.lock().await.writing_files.insert(dest_path.clone());

            match storage::reassemble_modal(ts, vault_mode, vault_key.as_ref()).await {
                Ok(written_path) => {
                    let _ = event_tx.send(GuiEvent::TransferComplete {
                        peer_id: pid_str.to_string(),
                        file_name: file_name.clone(),
                    });
                    log(event_tx, "OK", format!("  {file_name} saved to disk"));

                    swarm.behaviour_mut().rr.send_request(
                        &peer,
                        SyncMessage::TransferComplete {
                            file_name: file_name.clone(),
                        },
                    );
                    dl.active.remove(&file_name);
                    start_queued_files(peer, &sync_path, dl, swarm, event_tx, pid_str);

                    let state2 = Arc::clone(state);
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                        state2.lock().await.writing_files.remove(&written_path);
                    });
                }
                Err(e) => {
                    error!("Reassembly error for {file_name}: {e}");
                    log(
                        event_tx,
                        "ERROR",
                        format!("Failed to write {file_name}: {e}"),
                    );
                }
            }
        }

        SyncMessage::Error { message } => {
            let _ = event_tx.send(GuiEvent::PeerError {
                peer_id: pid_str.to_string(),
                message: message.clone(),
            });
            log(
                event_tx,
                "ERROR",
                format!("Error from {}: {message}", short_id(pid_str)),
            );
        }

        _ => {
            warn!("Unexpected response from {}", pid_str);
        }
    }
}

// =============================================================================
// SCHEDULER
// =============================================================================

fn start_queued_files(
    peer: PeerId,
    sync_path: &PathBuf,
    dl: &mut PeerDownload,
    swarm: &mut Swarm<MyBehaviour>,
    event_tx: &mpsc::UnboundedSender<GuiEvent>,
    pid_str: &str,
) {
    while dl.active.len() < MAX_CONCURRENT_FILES {
        let pf = match dl.queue.pop_front() {
            Some(f) => f,
            None => break,
        };

        if rel_path_exists(sync_path, &pf.file_name) {
            log(
                event_tx,
                "INFO",
                format!("{} already on disk — skipping", pf.file_name),
            );
            continue;
        }

        let index = {
            let sp = sync_path.clone();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(storage::build_chunk_index(&sp))
            })
        };

        let mut ts = FileTransferState::new(sync_path.clone());
        ts.metadata = Some(FileMetadata {
            file_name: pf.file_name.clone(),
            total_chunks: pf.total_chunks,
            file_size: pf.file_size,
            chunk_hashes: pf.chunk_hashes.clone(),
        });
        ts.file_id = pf.file_id;

        // Local dedup is only meaningful when both the manifest's hashes and
        // the local index speak the same hash space, which is plaintext-mode
        // legacy. Skip dedup for encrypted-protocol files (blinded hashes)
        // and for vault-mode (files at rest are *.vit blobs).
        let dedup_eligible = pf.file_id.is_none();
        let mut local_hits = 0usize;
        if dedup_eligible {
            for (chunk_index, hash) in pf.chunk_hashes.iter().enumerate() {
                if let Some((src_file, src_chunk)) = index.get(hash) {
                    let sp = sync_path.clone();
                    let src_file = src_file.clone();
                    let src_chunk = *src_chunk;
                    let data = tokio::task::block_in_place(|| {
                        tokio::runtime::Handle::current()
                            .block_on(storage::read_local_chunk(&sp, &src_file, src_chunk))
                    });
                    if let Some(bytes) = data {
                        ts.received_chunks.insert(chunk_index, bytes);
                        local_hits += 1;
                    }
                }
            }
        }

        let total = pf.total_chunks;
        let needed: Vec<usize> = (0..total)
            .filter(|i| !ts.received_chunks.contains_key(i))
            .collect();

        if local_hits > 0 {
            log(
                event_tx,
                "INFO",
                format!(
                    "{} — {}/{} chunks from local cache, {} to download",
                    pf.file_name,
                    local_hits,
                    total,
                    needed.len()
                ),
            );
        }

        if needed.is_empty() {
            log(
                event_tx,
                "OK",
                format!("{} — fully deduped, 0 bytes from network", pf.file_name),
            );

            let _ = event_tx.send(GuiEvent::TransferStarted {
                peer_id: pid_str.to_string(),
                file_name: pf.file_name.clone(),
                total_chunks: pf.total_chunks,
                file_size: pf.file_size,
            });

            let fname = pf.file_name.clone();
            let etx = event_tx.clone();
            let pid = pid_str.to_string();
            tokio::task::block_in_place(|| {
                tokio::runtime::Handle::current().block_on(async {
                    match storage::reassemble(&ts).await {
                        Ok(_) => {
                            let _ = etx.send(GuiEvent::TransferComplete {
                                peer_id: pid.clone(),
                                file_name: fname.clone(),
                            });
                            log(&etx, "OK", format!("{fname} written from local data"));
                        }
                        Err(e) => {
                            log(&etx, "ERROR", format!("Reassembly failed for {fname}: {e}"));
                        }
                    }
                })
            });
            continue;
        }

        log(
            event_tx,
            "INFO",
            format!(
                "⬇  {} — {} chunks, {} KB",
                pf.file_name,
                pf.total_chunks,
                pf.file_size / 1024
            ),
        );

        let _ = event_tx.send(GuiEvent::TransferStarted {
            peer_id: pid_str.to_string(),
            file_name: pf.file_name.clone(),
            total_chunks: pf.total_chunks,
            file_size: pf.file_size,
        });

        let count = needed.len().min(WINDOW);
        for &ci in needed.iter().take(count) {
            let req = match pf.file_id {
                Some(file_id) => SyncMessage::EncryptedChunkRequest {
                    file_id,
                    chunk_index: ci as u32,
                },
                None => SyncMessage::ChunkRequest {
                    file_name: pf.file_name.clone(),
                    chunk_index: ci,
                },
            };
            swarm.behaviour_mut().rr.send_request(&peer, req);
        }
        ts.next_request = needed.get(count).copied().unwrap_or(total);

        dl.active.insert(pf.file_name.clone(), ts);
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn rel_path_exists(sync_root: &std::path::PathBuf, rel: &str) -> bool {
    let mut p = sync_root.clone();
    for component in rel.split('/') {
        p.push(component);
    }
    p.exists()
}

fn vault_path_exists(sync_root: &std::path::PathBuf, rel: &str) -> bool {
    let mut p = sync_root.clone();
    for component in rel.split('/') {
        p.push(component);
    }
    let new_name = format!("{}.vit", p.file_name().unwrap().to_string_lossy());
    p.set_file_name(new_name);
    p.exists()
}

fn log(tx: &mpsc::UnboundedSender<GuiEvent>, level: &str, message: String) {
    let _ = tx.send(GuiEvent::Log {
        level: level.into(),
        message,
    });
}

async fn folder_status(state: &Arc<Mutex<AppState>>) -> (bool, String) {
    let st = state.lock().await;
    (st.sync_path.is_some(), st.node_name.clone())
}

async fn peer_display_name(state: &Arc<Mutex<AppState>>, pid_str: &str) -> String {
    let st = state.lock().await;
    st.peer_names
        .get(pid_str)
        .cloned()
        .unwrap_or_else(|| format!("Node-{}", short_id(pid_str)))
}
