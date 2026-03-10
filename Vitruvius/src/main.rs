// src/main.rs
mod network;
mod storage;

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use libp2p::{Multiaddr, PeerId, mdns, request_response, swarm::SwarmEvent};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{error, info, warn};

use crate::network::{MyBehaviourEvent, SyncMessage};
use crate::storage::FileTransferState;

const GUI_HTML: &str = include_str!("../gui/vitruvius_gui.html");

// ─── GUI → Backend ────────────────────────────────────────────────────────────
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum GuiCommand {
    SetFolder   { path: String },
    DialPeer    { peer_id: String, addr: Option<String> },
    RequestSync { peer_id: String },
    Disconnect  { peer_id: String },
}

// ─── Backend → GUI ────────────────────────────────────────────────────────────
#[derive(Serialize, Debug, Clone)]
#[serde(tag = "type")]
enum GuiEvent {
    Identity         { peer_id: String, node_name: String },
    PeerDiscovered   { peer_id: String, addr: String, node_name: String },
    PeerConnected    { peer_id: String, node_name: String },
    PeerDisconnected { peer_id: String },
    DialFailed       { peer_id: Option<String>, error: String },
    FolderListing    { files: Vec<GuiFileInfo> },
    TransferStarted  { peer_id: String, file_name: String, total_chunks: usize, file_size: u64 },
    ChunkReceived    { peer_id: String, file_name: String, chunk_index: usize, total_chunks: usize, verified: bool },
    TransferComplete { peer_id: String, file_name: String },
    RemoteEmpty      { peer_id: String },
    PeerError        { peer_id: String, message: String },
    Log              { level: String, message: String },
}

#[derive(Serialize, Debug, Clone)]
struct GuiFileInfo { name: String, size: u64, chunks: usize }

struct AppState {
    known_addrs:     HashMap<String, String>,  // peer_id → multiaddr
    connected_peers: HashSet<PeerId>,          // currently connected
    sync_path:       Option<PathBuf>,
    node_name:       String,
    // peer_id → node_name (learned from FolderAnnouncement / Manifest)
    peer_names:      HashMap<String, String>,
}

fn get_node_name() -> String {
    if let Ok(h) = std::env::var("HOSTNAME") {
        let h = h.trim().to_string();
        if !h.is_empty() { return h; }
    }
    if let Ok(h) = fs::read_to_string("/etc/hostname") {
        let h = h.trim().to_string();
        if !h.is_empty() { return h; }
    }
    "Vitruvius-Node".to_string()
}

fn short_id(peer_id: &str) -> String {
    // 12D3KooWXXXXXXXX → first 8 chars after the prefix
    let s = peer_id.strip_prefix("12D3KooW").unwrap_or(peer_id);
    s[..s.len().min(8)].to_string()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    // CLI args: --http-port N --ws-port N
    let args: Vec<String> = std::env::args().collect();
    let mut http_port: u16 = 9000;
    let mut ws_port:   u16 = 9001;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--http-port" => { i += 1; if let Some(v) = args.get(i) { http_port = v.parse().unwrap_or(9000); } }
            "--ws-port"   => { i += 1; if let Some(v) = args.get(i) { ws_port   = v.parse().unwrap_or(9001); } }
            _ => {}
        }
        i += 1;
    }

    let node_name = get_node_name();
    info!("Node: {} | HTTP :{} | WS :{}", node_name, http_port, ws_port);

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<GuiEvent>();
    let (cmd_tx,       cmd_rx)   = mpsc::unbounded_channel::<GuiCommand>();

    let state = Arc::new(Mutex::new(AppState {
        known_addrs:     HashMap::new(),
        connected_peers: HashSet::new(),
        sync_path:       None,
        node_name:       node_name.clone(),
        peer_names:      HashMap::new(),
    }));

    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<String>(512);
    let broadcast_tx = Arc::new(broadcast_tx);

    // Forward mpsc → broadcast
    {
        let btx = Arc::clone(&broadcast_tx);
        tokio::spawn(async move {
            while let Some(evt) = event_rx.recv().await {
                if let Ok(json) = serde_json::to_string(&evt) {
                    let _ = btx.send(json);
                }
            }
        });
    }

    // HTTP server: serves GUI
    {
        let listener = TcpListener::bind(format!("0.0.0.0:{}", http_port)).await?;
        info!("GUI  →  http://127.0.0.1:{}", http_port);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_http(stream, ws_port));
            }
        });
    }

    // WebSocket server
    let mut swarm = crate::network::setup_network().await?;
    let my_peer_id = swarm.local_peer_id().to_string();

    {
        let listener    = TcpListener::bind(format!("0.0.0.0:{}", ws_port)).await?;
        let cmd_tx2     = cmd_tx.clone();
        let btx2        = Arc::clone(&broadcast_tx);
        let my_id2      = my_peer_id.clone();
        let my_name2    = node_name.clone();
        let state2      = Arc::clone(&state);
        tokio::spawn(async move {
            while let Ok((stream, addr)) = listener.accept().await {
                info!("GUI connected from {}", addr);
                let cmd_tx  = cmd_tx2.clone();
                let mut brx = btx2.subscribe();
                let pid     = my_id2.clone();
                let name    = my_name2.clone();
                let st      = Arc::clone(&state2);
                tokio::spawn(async move {
                    handle_ws_client(stream, cmd_tx, &mut brx, pid, name, st).await;
                });
            }
        });
    }

    let mut cmd_rx: mpsc::UnboundedReceiver<GuiCommand> = cmd_rx;
    // peer_id → (file_name → transfer state)
    let mut transfers: HashMap<PeerId, HashMap<String, FileTransferState>> = HashMap::new();

    // ── Main loop ─────────────────────────────────────────────────────────────
    loop {
        tokio::select! {

            // ── GUI command ───────────────────────────────────────────────────
            Some(cmd) = cmd_rx.recv() => {
                match cmd {

                    // ── Set sync folder ──────────────────────────────────────
                    GuiCommand::SetFolder { path } => {
                        let p = PathBuf::from(&path);
                        if !p.exists() {
                            if let Err(e) = fs::create_dir_all(&p) {
                                let _ = event_tx.send(GuiEvent::Log {
                                    level: "ERROR".into(),
                                    message: format!("Cannot create folder: {e}"),
                                });
                                continue;
                            }
                        }
                        match fs::canonicalize(&p) {
                            Err(e) => {
                                let _ = event_tx.send(GuiEvent::Log {
                                    level: "ERROR".into(),
                                    message: format!("Bad path: {e}"),
                                });
                            }
                            Ok(abs) => {
                                // List the folder contents and send to GUI
                                match storage::list_folder(&abs).await {
                                    Ok(files) => {
                                        let listing: Vec<GuiFileInfo> = files.iter().map(|f| GuiFileInfo {
                                            name: f.file_name.clone(), size: f.file_size, chunks: f.total_chunks,
                                        }).collect();
                                        let count = listing.len();
                                        let _ = event_tx.send(GuiEvent::FolderListing { files: listing });
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "OK".into(),
                                            message: format!("Sync folder set: {} ({} file(s))", abs.display(), count),
                                        });
                                    }
                                    Err(e) => {
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "WARN".into(),
                                            message: format!("Folder set but listing failed: {e}"),
                                        });
                                    }
                                }

                                // Save path in shared state
                                let connected: Vec<PeerId> = {
                                    let mut st = state.lock().await;
                                    st.sync_path = Some(abs);
                                    st.connected_peers.iter().cloned().collect()
                                };

                                // ─── KEY FIX ───────────────────────────────
                                // Announce to every connected peer that we now have a folder.
                                // They will auto-request our manifest.
                                // Also, immediately request their manifests in case they
                                // already set their folder before we connected.
                                let name = node_name.clone();
                                for peer in connected {
                                    let pid_str = peer.to_string();
                                    // Tell them we have files
                                    swarm.behaviour_mut().rr.send_request(
                                        &peer,
                                        SyncMessage::FolderAnnouncement { node_name: name.clone() },
                                    );
                                    // Ask for their files too
                                    swarm.behaviour_mut().rr.send_request(
                                        &peer,
                                        SyncMessage::ManifestRequest,
                                    );
                                    let _ = event_tx.send(GuiEvent::Log {
                                        level: "INFO".into(),
                                        message: format!("Announced folder to {} and requested their manifest", short_id(&pid_str)),
                                    });
                                }
                            }
                        }
                    }

                    // ── Manual dial ──────────────────────────────────────────
                    GuiCommand::DialPeer { peer_id, addr } => {
                        let addr_str = addr.or_else(|| {
                            state.try_lock().ok()
                                .and_then(|s| s.known_addrs.get(&peer_id).cloned())
                        });
                        match addr_str {
                            None => {
                                let _ = event_tx.send(GuiEvent::Log {
                                    level: "WARN".into(),
                                    message: format!("No address for peer {}", short_id(&peer_id)),
                                });
                            }
                            Some(a) => match a.parse::<Multiaddr>() {
                                Err(e) => {
                                    let _ = event_tx.send(GuiEvent::Log {
                                        level: "ERROR".into(),
                                        message: format!("Invalid multiaddr: {e}"),
                                    });
                                }
                                Ok(ma) => {
                                    let _ = event_tx.send(GuiEvent::Log {
                                        level: "INFO".into(),
                                        message: format!("Dialing {} …", short_id(&peer_id)),
                                    });
                                    if let Err(e) = swarm.dial(ma) {
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "ERROR".into(),
                                            message: format!("Dial error: {e}"),
                                        });
                                    }
                                }
                            }
                        }
                    }

                    // ── Manual sync request ──────────────────────────────────
                    GuiCommand::RequestSync { peer_id } => {
                        if let Ok(pid) = peer_id.parse::<PeerId>() {
                            let _ = event_tx.send(GuiEvent::Log {
                                level: "INFO".into(),
                                message: format!("Requesting manifest from {} …", short_id(&peer_id)),
                            });
                            swarm.behaviour_mut().rr.send_request(&pid, SyncMessage::ManifestRequest);
                        }
                    }

                    // ── Disconnect ───────────────────────────────────────────
                    GuiCommand::Disconnect { peer_id } => {
                        if let Ok(pid) = peer_id.parse::<PeerId>() {
                            let _ = swarm.disconnect_peer_id(pid);
                        }
                    }
                }
            }

            // ── Swarm event ───────────────────────────────────────────────────
            event = swarm.select_next_some() => {
                match event {

                    // ── mDNS: discovered ─────────────────────────────────────
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(
                        mdns::Event::Discovered(list)
                    )) => {
                        for (peer_id, addr) in list {
                            let pid_str  = peer_id.to_string();
                            let addr_str = addr.to_string();
                            {
                                let mut st = state.lock().await;
                                st.known_addrs.insert(pid_str.clone(), addr_str.clone());
                            }
                            let display_name = {
                                let st = state.lock().await;
                                st.peer_names.get(&pid_str).cloned()
                                    .unwrap_or_else(|| format!("Node-{}", short_id(&pid_str)))
                            };
                            info!("mDNS: {} at {}", pid_str, addr_str);
                            let _ = event_tx.send(GuiEvent::PeerDiscovered {
                                peer_id:   pid_str.clone(),
                                addr:      addr_str,
                                node_name: display_name,
                            });
                        }
                    }

                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(
                        mdns::Event::Expired(list)
                    )) => {
                        for (peer_id, _) in list {
                            state.lock().await.known_addrs.remove(&peer_id.to_string());
                        }
                    }

                    // ── Connection established ────────────────────────────────
                    // NOTE: We do NOT auto-request manifest here.
                    // The correct trigger is SetFolder on either side.
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        let pid_str = peer_id.to_string();
                        {
                            let mut st = state.lock().await;
                            st.connected_peers.insert(peer_id);
                        }
                        info!("Connected to {}", pid_str);
                        let display_name = {
                            let st = state.lock().await;
                            st.peer_names.get(&pid_str).cloned()
                                .unwrap_or_else(|| format!("Node-{}", short_id(&pid_str)))
                        };
                        let _ = event_tx.send(GuiEvent::PeerConnected {
                            peer_id:   pid_str.clone(),
                            node_name: display_name.clone(),
                        });
                        let _ = event_tx.send(GuiEvent::Log {
                            level: "OK".into(),
                            message: format!("Connected to {}", display_name),
                        });

                        // If WE already have a folder set, announce it immediately
                        // and request their manifest (they may have set theirs already too)
                        let (have_folder, name) = {
                            let st = state.lock().await;
                            (st.sync_path.is_some(), st.node_name.clone())
                        };
                        if have_folder {
                            swarm.behaviour_mut().rr.send_request(
                                &peer_id,
                                SyncMessage::FolderAnnouncement { node_name: name },
                            );
                            swarm.behaviour_mut().rr.send_request(
                                &peer_id,
                                SyncMessage::ManifestRequest,
                            );
                            let _ = event_tx.send(GuiEvent::Log {
                                level: "INFO".into(),
                                message: format!("Folder already set — announced to {} and requesting their manifest", short_id(&pid_str)),
                            });
                        }
                    }

                    // ── Connection closed ─────────────────────────────────────
                    SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                        let pid_str = peer_id.to_string();
                        {
                            let mut st = state.lock().await;
                            st.connected_peers.remove(&peer_id);
                        }
                        let reason = cause.map(|e| e.to_string()).unwrap_or_default();
                        warn!("Closed: {} — {}", pid_str, reason);
                        let _ = event_tx.send(GuiEvent::PeerDisconnected { peer_id: pid_str.clone() });
                        let _ = event_tx.send(GuiEvent::Log {
                            level: "WARN".into(),
                            message: format!("Disconnected from {} ({})", short_id(&pid_str), reason),
                        });
                    }

                    // ── Request-Response ──────────────────────────────────────
                    SwarmEvent::Behaviour(MyBehaviourEvent::Rr(
                        request_response::Event::Message { peer, message }
                    )) => {
                        let pid_str = peer.to_string();

                        match message {

                            // ── We are the UPLOADER ───────────────────────────
                            request_response::Message::Request { channel, request, .. } => {
                                match request {

                                    // Peer told us they set their folder →
                                    // auto-request their manifest if we have a folder
                                    SyncMessage::FolderAnnouncement { node_name: peer_name } => {
                                        // Store peer's name
                                        {
                                            let mut st = state.lock().await;
                                            st.peer_names.insert(pid_str.clone(), peer_name.clone());
                                        }
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "INFO".into(),
                                            message: format!("{peer_name} announced their folder — requesting their manifest …"),
                                        });
                                        // Must send a response (even empty) to close the RR channel
                                        let _ = swarm.behaviour_mut().rr.send_response(channel, SyncMessage::Empty);

                                        // Now send back our own announcement if we have a folder
                                        let (have_folder, my_name) = {
                                            let st = state.lock().await;
                                            (st.sync_path.is_some(), st.node_name.clone())
                                        };
                                        // Always request their manifest
                                        swarm.behaviour_mut().rr.send_request(
                                            &peer,
                                            SyncMessage::ManifestRequest,
                                        );
                                        if have_folder {
                                            swarm.behaviour_mut().rr.send_request(
                                                &peer,
                                                SyncMessage::FolderAnnouncement { node_name: my_name },
                                            );
                                        }
                                    }

                                    // Peer wants our manifest
                                    SyncMessage::ManifestRequest => {
                                        let (path, my_name) = {
                                            let st = state.lock().await;
                                            (st.sync_path.clone(), st.node_name.clone())
                                        };
                                        match path {
                                            None => {
                                                let _ = event_tx.send(GuiEvent::Log {
                                                    level: "INFO".into(),
                                                    message: format!("{} requested manifest — we have no folder yet", short_id(&pid_str)),
                                                });
                                                let _ = swarm.behaviour_mut().rr.send_response(
                                                    channel,
                                                    SyncMessage::Empty,
                                                );
                                            }
                                            Some(ref p) => {
                                                let _ = event_tx.send(GuiEvent::Log {
                                                    level: "INFO".into(),
                                                    message: format!("{} requested our manifest", short_id(&pid_str)),
                                                });
                                                match storage::get_manifest(p, &my_name).await {
                                                    Ok(resp) => { let _ = swarm.behaviour_mut().rr.send_response(channel, resp); }
                                                    Err(e) => {
                                                        let _ = swarm.behaviour_mut().rr.send_response(
                                                            channel,
                                                            SyncMessage::Error { message: e.to_string() },
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Peer wants one chunk
                                    SyncMessage::ChunkRequest { ref file_name, chunk_index } => {
                                        let path = state.lock().await.sync_path.clone();
                                        match path {
                                            None => {
                                                let _ = swarm.behaviour_mut().rr.send_response(
                                                    channel,
                                                    SyncMessage::Error { message: "No sync folder".into() },
                                                );
                                            }
                                            Some(ref p) => {
                                                match storage::get_chunk(p, file_name, chunk_index).await {
                                                    Ok(resp) => {
                                                        let _ = event_tx.send(GuiEvent::Log {
                                                            level: "INFO".into(),
                                                            message: format!("→ {file_name} chunk {chunk_index} to {}", short_id(&pid_str)),
                                                        });
                                                        let _ = swarm.behaviour_mut().rr.send_response(channel, resp);
                                                    }
                                                    Err(e) => {
                                                        let _ = swarm.behaviour_mut().rr.send_response(
                                                            channel,
                                                            SyncMessage::Error { message: e.to_string() },
                                                        );
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    // Receiver confirmed a file arrived
                                    SyncMessage::TransferComplete { ref file_name } => {
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "OK".into(),
                                            message: format!("{} confirmed receipt of {file_name}", short_id(&pid_str)),
                                        });
                                        let _ = swarm.behaviour_mut().rr.send_response(channel, SyncMessage::Empty);
                                    }

                                    _ => {
                                        let _ = swarm.behaviour_mut().rr.send_response(
                                            channel,
                                            SyncMessage::Error { message: "Unexpected request".into() },
                                        );
                                    }
                                }
                            }

                            // ── We are the DOWNLOADER ─────────────────────────
                            request_response::Message::Response { response, .. } => {
                                match response {

                                    // Got the file list from the remote peer
                                    SyncMessage::Manifest { node_name: peer_name, ref files } => {
                                        // Learn their name
                                        {
                                            let mut st = state.lock().await;
                                            st.peer_names.insert(pid_str.clone(), peer_name.clone());
                                        }

                                        if files.is_empty() {
                                            let _ = event_tx.send(GuiEvent::Log {
                                                level: "INFO".into(),
                                                message: format!("{peer_name} has no files to sync"),
                                            });
                                            continue;
                                        }

                                        let sync_path = match state.lock().await.sync_path.clone() {
                                            Some(p) => p,
                                            None => {
                                                let _ = event_tx.send(GuiEvent::Log {
                                                    level: "WARN".into(),
                                                    message: "Received manifest but we have no sync folder — set one first!".into(),
                                                });
                                                continue;
                                            }
                                        };

                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "INFO".into(),
                                            message: format!("{peer_name} has {} file(s) — starting sync", files.len()),
                                        });

                                        let peer_transfers = transfers.entry(peer).or_insert_with(HashMap::new);

                                        for fe in files {
                                            let dest = sync_path.join(&fe.file_name);
                                            if dest.exists() {
                                                let _ = event_tx.send(GuiEvent::Log {
                                                    level: "INFO".into(),
                                                    message: format!("{} already exists — skipping", fe.file_name),
                                                });
                                                continue;
                                            }

                                            let _ = event_tx.send(GuiEvent::TransferStarted {
                                                peer_id:      pid_str.clone(),
                                                file_name:    fe.file_name.clone(),
                                                total_chunks: fe.total_chunks,
                                                file_size:    fe.file_size,
                                            });
                                            let _ = event_tx.send(GuiEvent::Log {
                                                level: "INFO".into(),
                                                message: format!(
                                                    "⬇  {} — {} chunks, {} KB",
                                                    fe.file_name, fe.total_chunks, fe.file_size / 1024
                                                ),
                                            });

                                            // Build transfer state
                                            let meta = storage::FileMetadata {
                                                file_name:    fe.file_name.clone(),
                                                total_chunks: fe.total_chunks,
                                                file_size:    fe.file_size,
                                                chunk_hashes: fe.chunk_hashes.clone(),
                                            };
                                            let mut ts = FileTransferState::new(sync_path.clone());
                                            ts.metadata = Some(meta);

                                            // Window of 2 — safe for hotspot, avoids stream overflow
                                            const WINDOW: usize = 2;
                                            let count = fe.total_chunks.min(WINDOW);
                                            for c in 0..count {
                                                swarm.behaviour_mut().rr.send_request(
                                                    &peer,
                                                    SyncMessage::ChunkRequest {
                                                        file_name:   fe.file_name.clone(),
                                                        chunk_index: c,
                                                    },
                                                );
                                            }
                                            ts.next_request = count;
                                            peer_transfers.insert(fe.file_name.clone(), ts);
                                        }
                                    }

                                    // Got one chunk
                                    SyncMessage::ChunkResponse { ref file_name, chunk_index, ref data, hash: _ } => {
                                        // Window of 2 — matches initial request count
                                        const WINDOW: usize = 2;

                                        let peer_transfers = transfers.entry(peer).or_insert_with(HashMap::new);
                                        let ts = match peer_transfers.get_mut(file_name) {
                                            Some(t) => t,
                                            None => {
                                                // State already cleaned up (file complete) — ignore stray chunks
                                                continue;
                                            }
                                        };

                                        // Verify against stored metadata hash
                                        let expected = ts.metadata.as_ref()
                                            .and_then(|m| m.chunk_hashes.get(chunk_index))
                                            .copied();
                                        let verified = expected.map(|h| storage::verify_chunk(data, &h)).unwrap_or(false);
                                        let total    = ts.metadata.as_ref().map(|m| m.total_chunks).unwrap_or(0);

                                        let _ = event_tx.send(GuiEvent::ChunkReceived {
                                            peer_id:      pid_str.clone(),
                                            file_name:    file_name.clone(),
                                            chunk_index,
                                            total_chunks: total,
                                            verified,
                                        });

                                        if !verified {
                                            let _ = event_tx.send(GuiEvent::Log {
                                                level: "ERROR".into(),
                                                message: format!("{file_name} chunk {chunk_index} hash mismatch — retrying"),
                                            });
                                            swarm.behaviour_mut().rr.send_request(
                                                &peer,
                                                SyncMessage::ChunkRequest { file_name: file_name.clone(), chunk_index },
                                            );
                                            continue;
                                        }

                                        // Store chunk
                                        ts.received_chunks.insert(chunk_index, data.clone());

                                        // Advance sliding window — request next unsent chunk
                                        if ts.next_request < total {
                                            swarm.behaviour_mut().rr.send_request(
                                                &peer,
                                                SyncMessage::ChunkRequest {
                                                    file_name:   file_name.clone(),
                                                    chunk_index: ts.next_request,
                                                },
                                            );
                                            ts.next_request += 1;
                                        }

                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "INFO".into(),
                                            message: format!("{file_name}  {}/{total}", chunk_index + 1),
                                        });

                                        // Check if this file is fully received
                                        if ts.received_chunks.len() == total {
                                            match storage::process_chunk(peer, chunk_index, data.clone(), ts).await {
                                                Ok(true) => {
                                                    let fname = file_name.clone();
                                                    let _ = event_tx.send(GuiEvent::TransferComplete {
                                                        peer_id:   pid_str.clone(),
                                                        file_name: fname.clone(),
                                                    });
                                                    let _ = event_tx.send(GuiEvent::Log {
                                                        level: "OK".into(),
                                                        message: format!("✅  {fname} saved to disk"),
                                                    });
                                                    // Notify sender
                                                    swarm.behaviour_mut().rr.send_request(
                                                        &peer,
                                                        SyncMessage::TransferComplete { file_name: fname.clone() },
                                                    );
                                                    // Remove state AFTER sending the notification,
                                                    // so no more chunk requests will be made for this file
                                                    peer_transfers.remove(&fname);
                                                }
                                                Ok(false) => {}
                                                Err(e) => {
                                                    error!("Reassembly error: {e}");
                                                    let _ = event_tx.send(GuiEvent::Log {
                                                        level: "ERROR".into(),
                                                        message: format!("Failed to write {file_name}: {e}"),
                                                    });
                                                }
                                            }
                                        }
                                    }

                                    // Remote has no files
                                    SyncMessage::Empty => {
                                        let _ = event_tx.send(GuiEvent::RemoteEmpty { peer_id: pid_str.clone() });
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "INFO".into(),
                                            message: format!("{} has no sync folder or empty folder", short_id(&pid_str)),
                                        });
                                    }

                                    SyncMessage::Error { message } => {
                                        let _ = event_tx.send(GuiEvent::PeerError {
                                            peer_id: pid_str.clone(),
                                            message: message.clone(),
                                        });
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "ERROR".into(),
                                            message: format!("Error from {}: {message}", short_id(&pid_str)),
                                        });
                                    }

                                    _ => { warn!("Unexpected response from {}", pid_str); }
                                }
                            }
                        }
                    }

                    // ── Dial error ────────────────────────────────────────────
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        let pid_str = peer_id.map(|p| p.to_string());
                        warn!("Dial failed {:?}: {}", pid_str, error);
                        let _ = event_tx.send(GuiEvent::DialFailed {
                            peer_id: pid_str,
                            error:   error.to_string(),
                        });
                    }

                    _ => {}
                }
            }

            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down…");
                break;
            }
        }
    }
    Ok(())
}

// ─── Minimal HTTP server ──────────────────────────────────────────────────────
async fn serve_http(mut stream: TcpStream, ws_port: u16) {
    let mut buf = [0u8; 512];
    let _ = stream.read(&mut buf).await;
    let html = GUI_HTML.replace("__WS_PORT__", &ws_port.to_string());
    let resp = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{}",
        html.len(), html
    );
    let _ = stream.write_all(resp.as_bytes()).await;
}

// ─── WebSocket handler ────────────────────────────────────────────────────────
async fn handle_ws_client(
    stream:     TcpStream,
    cmd_tx:     mpsc::UnboundedSender<GuiCommand>,
    brx:        &mut tokio::sync::broadcast::Receiver<String>,
    my_peer_id: String,
    my_name:    String,
    state:      Arc<Mutex<AppState>>,
) {
    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(_) => return,
    };
    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // Send full state snapshot to newly connected GUI
    if let Ok(json) = serde_json::to_string(&GuiEvent::Identity {
        peer_id:   my_peer_id.clone(),
        node_name: my_name.clone(),
    }) { let _ = ws_tx.send(Message::Text(json)).await; }

    {
        let st = state.lock().await;
        for (pid, addr) in &st.known_addrs {
            let name = st.peer_names.get(pid).cloned()
                .unwrap_or_else(|| format!("Node-{}", &pid.strip_prefix("12D3KooW").unwrap_or(pid)[..pid.len().min(8)]));
            if let Ok(json) = serde_json::to_string(&GuiEvent::PeerDiscovered {
                peer_id: pid.clone(), addr: addr.clone(), node_name: name,
            }) { let _ = ws_tx.send(Message::Text(json)).await; }
        }
        if let Some(ref path) = st.sync_path {
            if let Ok(files) = storage::list_folder(path).await {
                let listing: Vec<GuiFileInfo> = files.iter().map(|f| GuiFileInfo {
                    name: f.file_name.clone(), size: f.file_size, chunks: f.total_chunks,
                }).collect();
                if let Ok(json) = serde_json::to_string(&GuiEvent::FolderListing { files: listing }) {
                    let _ = ws_tx.send(Message::Text(json)).await;
                }
            }
            if let Ok(json) = serde_json::to_string(&GuiEvent::Log {
                level: "OK".into(),
                message: format!("Sync folder: {}", path.display()),
            }) { let _ = ws_tx.send(Message::Text(json)).await; }
        }
    }

    loop {
        tokio::select! {
            result = brx.recv() => {
                match result {
                    Ok(json) => { if ws_tx.send(Message::Text(json)).await.is_err() { break; } }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("GUI lagged, dropped {} events", n);
                    }
                    Err(_) => break,
                }
            }
            Some(Ok(msg)) = ws_rx.next() => {
                match msg {
                    Message::Text(text) => {
                        match serde_json::from_str::<GuiCommand>(&text) {
                            Ok(cmd) => { let _ = cmd_tx.send(cmd); }
                            Err(e)  => { error!("Bad GUI command '{}': {}", text, e); }
                        }
                    }
                    Message::Close(_) => break,
                    Message::Ping(d)  => { let _ = ws_tx.send(Message::Pong(d)).await; }
                    _ => {}
                }
            }
            else => break,
        }
    }
}
