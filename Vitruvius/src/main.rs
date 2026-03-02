// src/main.rs
mod network;
mod storage;

use anyhow::Result;
use futures_util::{SinkExt, StreamExt};
use libp2p::{Multiaddr, PeerId, mdns, request_response, swarm::SwarmEvent};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{error, info, warn};

// The GUI HTML is embedded at compile time from gui/vitruvius_gui.html.
// `cargo build` will fail with a clear error if the file is missing.
const GUI_HTML: &str = include_str!("../gui/vitruvius_gui.html");

use crate::network::{MyBehaviourEvent, SyncMessage};
use crate::storage::FileTransferState;

// ─── Messages FROM the GUI → backend ────────────────────────────────────────
#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum GuiCommand {
    /// Set the local sync folder path
    SetFolder { path: String },
    /// Dial a specific peer by ID (mDNS will have already found their addr,
    /// or we dial by multiaddr if provided)
    DialPeer { peer_id: String, addr: Option<String> },
    /// Request a sync (ask for metadata) from a connected peer
    RequestSync { peer_id: String },
    /// Disconnect from a peer
    Disconnect { peer_id: String },
}

// ─── Messages FROM the backend → GUI ────────────────────────────────────────
#[derive(Serialize, Debug, Clone)]
#[serde(tag = "type")]
enum GuiEvent {
    /// This node's own peer ID (sent once on startup)
    Identity { peer_id: String },
    /// A peer was discovered via mDNS
    PeerDiscovered { peer_id: String, addr: String },
    /// TCP connection established
    PeerConnected { peer_id: String },
    /// Connection dropped
    PeerDisconnected { peer_id: String },
    /// Outgoing dial failed
    DialFailed { peer_id: Option<String>, error: String },
    /// Received file metadata from a remote peer
    TransferStarted {
        peer_id: String,
        file_name: String,
        total_chunks: usize,
        file_size: u64,
    },
    /// A chunk was received and verified
    ChunkReceived {
        peer_id: String,
        chunk_index: usize,
        total_chunks: usize,
        verified: bool,
    },
    /// File fully reassembled
    TransferComplete { peer_id: String, file_name: String },
    /// Remote folder was empty
    RemoteEmpty { peer_id: String },
    /// Protocol-level error from a peer
    PeerError { peer_id: String, message: String },
    /// A chunk request was received (we're the sender side)
    ChunkSent { peer_id: String, chunk_index: usize },
    /// Free-form log line (mirrors tracing output)
    Log { level: String, message: String },
}

// Shared state visible to both the swarm task and the WS handler
struct AppState {
    /// Known peer addresses from mDNS (peer_id_str → multiaddr_str)
    known_addrs: HashMap<String, String>,
    /// Sync folder path (set by GUI)
    sync_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();
    info!("Starting Vitruvius...");

    // Channel: swarm task → WS broadcaster
    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<GuiEvent>();
    // Channel: WS handler → swarm task
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<GuiCommand>();

    let state = Arc::new(Mutex::new(AppState {
        known_addrs: HashMap::new(),
        sync_path: None,
    }));

    // ── Broadcast channel (swarm events → all connected GUI clients) ─────
    let (broadcast_tx, _) = tokio::sync::broadcast::channel::<String>(256);
    let broadcast_tx = Arc::new(broadcast_tx);

    // Forward events from the swarm mpsc → broadcast channel
    let btx_fwd = Arc::clone(&broadcast_tx);
    tokio::spawn(async move {
        while let Some(evt) = event_rx.recv().await {
            if let Ok(json) = serde_json::to_string(&evt) {
                let _ = btx_fwd.send(json);
            }
        }
    });

    // ── HTTP server on :9000 — serves the GUI HTML page ──────────────────
    let http_listener = TcpListener::bind("127.0.0.1:9000").await?;
    info!("GUI available at  →  http://127.0.0.1:9000");
    tokio::spawn(async move {
        while let Ok((stream, _)) = http_listener.accept().await {
            tokio::spawn(serve_http(stream));
        }
    });

    // ── Swarm setup ───────────────────────────────────────────────────────
    let mut swarm = crate::network::setup_network().await?;
    let my_peer_id = swarm.local_peer_id().to_string();

    // Also broadcast Identity once for any already-connected client
    let _ = event_tx.send(GuiEvent::Identity { peer_id: my_peer_id.clone() });

    // ── WebSocket server on :9001 — real-time events & commands ──────────
    let ws_listener = TcpListener::bind("127.0.0.1:9001").await?;
    info!("WebSocket backend at ws://127.0.0.1:9001");

    let cmd_tx_ws   = cmd_tx.clone();
    let btx_ws      = Arc::clone(&broadcast_tx);
    let my_id_ws    = my_peer_id.clone();
    let state_ws    = Arc::clone(&state);
    tokio::spawn(async move {
        while let Ok((stream, addr)) = ws_listener.accept().await {
            info!("GUI WS connected from {}", addr);
            let cmd_tx    = cmd_tx_ws.clone();
            let mut brx   = btx_ws.subscribe();
            let peer_id   = my_id_ws.clone();
            let st        = Arc::clone(&state_ws);
            tokio::spawn(async move {
                handle_ws_client(stream, cmd_tx, &mut brx, peer_id, st).await;
            });
        }
    });

    let mut cmd_rx: mpsc::UnboundedReceiver<GuiCommand> = cmd_rx;
    let mut transfer_states: HashMap<PeerId, FileTransferState> = HashMap::new();

    // ── Main event loop ───────────────────────────────────────────────────
    loop {
        tokio::select! {

            // ── GUI command ──────────────────────────────────────────────
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    GuiCommand::SetFolder { path } => {
                        let p = PathBuf::from(&path);
                        if !p.exists() {
                            if let Err(e) = fs::create_dir_all(&p) {
                                let _ = event_tx.send(GuiEvent::Log {
                                    level: "ERROR".into(),
                                    message: format!("Cannot create folder: {}", e),
                                });
                                continue;
                            }
                        }
                        match fs::canonicalize(&p) {
                            Ok(abs) => {
                                let _ = event_tx.send(GuiEvent::Log {
                                    level: "OK".into(),
                                    message: format!("Sync folder set: {}", abs.display()),
                                });
                                state.lock().await.sync_path = Some(abs);
                            }
                            Err(e) => {
                                let _ = event_tx.send(GuiEvent::Log {
                                    level: "ERROR".into(),
                                    message: format!("Bad path: {}", e),
                                });
                            }
                        }
                    }

                    GuiCommand::DialPeer { peer_id, addr } => {
                        // Use provided addr or fall back to mDNS cache
                        let addr_str = addr.or_else(|| {
                            state.try_lock().ok()
                                .and_then(|s| s.known_addrs.get(&peer_id).cloned())
                        });

                        if let Some(a) = addr_str {
                            match a.parse::<Multiaddr>() {
                                Ok(ma) => {
                                    let _ = event_tx.send(GuiEvent::Log {
                                        level: "INFO".into(),
                                        message: format!("Dialing {} at {}", &peer_id[..14], a),
                                    });
                                    if let Err(e) = swarm.dial(ma) {
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "ERROR".into(),
                                            message: format!("Dial error: {}", e),
                                        });
                                    }
                                }
                                Err(e) => {
                                    let _ = event_tx.send(GuiEvent::Log {
                                        level: "ERROR".into(),
                                        message: format!("Invalid multiaddr: {}", e),
                                    });
                                }
                            }
                        } else {
                            let _ = event_tx.send(GuiEvent::Log {
                                level: "WARN".into(),
                                message: format!("No address known for peer {}", &peer_id[..14.min(peer_id.len())]),
                            });
                        }
                    }

                    GuiCommand::RequestSync { peer_id } => {
                        if let Ok(pid) = peer_id.parse::<PeerId>() {
                            let _ = event_tx.send(GuiEvent::Log {
                                level: "INFO".into(),
                                message: format!("Requesting metadata from {}…", &peer_id[..14.min(peer_id.len())]),
                            });
                            swarm.behaviour_mut().rr.send_request(
                                &pid,
                                SyncMessage::Request { file_name: "MANIFEST_REQ".into() },
                            );
                        }
                    }

                    GuiCommand::Disconnect { peer_id } => {
                        if let Ok(pid) = peer_id.parse::<PeerId>() {
                            let _ = swarm.disconnect_peer_id(pid);
                            let _ = event_tx.send(GuiEvent::Log {
                                level: "WARN".into(),
                                message: format!("Disconnected from {}", &peer_id[..14.min(peer_id.len())]),
                            });
                        }
                    }
                }
            }

            // ── Swarm event ───────────────────────────────────────────────
            event = swarm.select_next_some() => {
                match event {

                    // mDNS discovery
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, addr) in list {
                            let pid_str = peer_id.to_string();
                            let addr_str = addr.to_string();
                            state.lock().await.known_addrs.insert(pid_str.clone(), addr_str.clone());
                            info!("Discovered peer: {} at {}", pid_str, addr_str);
                            let _ = event_tx.send(GuiEvent::PeerDiscovered {
                                peer_id: pid_str.clone(),
                                addr:    addr_str,
                            });
                            let _ = event_tx.send(GuiEvent::Log {
                                level: "INFO".into(),
                                message: format!("mDNS: discovered {}", &pid_str[..14.min(pid_str.len())]),
                            });
                        }
                    }

                    // mDNS peer expired
                    SwarmEvent::Behaviour(MyBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                        for (peer_id, _) in list {
                            let pid_str = peer_id.to_string();
                            state.lock().await.known_addrs.remove(&pid_str);
                        }
                    }

                    // Connection established
                    SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                        let pid_str = peer_id.to_string();
                        info!("Connected to {}", pid_str);
                        let _ = event_tx.send(GuiEvent::PeerConnected { peer_id: pid_str.clone() });
                        let _ = event_tx.send(GuiEvent::Log {
                            level: "OK".into(),
                            message: format!("Connection established: {}", &pid_str[..14.min(pid_str.len())]),
                        });
                    }

                    // Connection closed
                    SwarmEvent::ConnectionClosed { peer_id, .. } => {
                        let pid_str = peer_id.to_string();
                        let _ = event_tx.send(GuiEvent::PeerDisconnected { peer_id: pid_str.clone() });
                        let _ = event_tx.send(GuiEvent::Log {
                            level: "WARN".into(),
                            message: format!("Connection closed: {}", &pid_str[..14.min(pid_str.len())]),
                        });
                    }

                    // Request-Response messages
                    SwarmEvent::Behaviour(MyBehaviourEvent::Rr(
                        request_response::Event::Message { peer, message }
                    )) => {
                        let pid_str = peer.to_string();
                        match message {

                            // ── We are the SENDER (serving files) ───────
                            request_response::Message::Request { channel, request, .. } => {
                                let sync_path = state.lock().await.sync_path.clone();
                                let sync_path = match sync_path {
                                    Some(p) => p,
                                    None => {
                                        let _ = swarm.behaviour_mut().rr.send_response(
                                            channel,
                                            SyncMessage::Error { message: "No sync folder configured".into() },
                                        );
                                        continue;
                                    }
                                };

                                match request {
                                    SyncMessage::Request { .. } => {
                                        info!("Received metadata request from {}", pid_str);
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "INFO".into(),
                                            message: format!("Serving metadata to {}…", &pid_str[..14.min(pid_str.len())]),
                                        });
                                        match crate::storage::get_file_metadata(&sync_path).await {
                                            Ok(resp) => { let _ = swarm.behaviour_mut().rr.send_response(channel, resp); }
                                            Err(e)   => {
                                                let _ = swarm.behaviour_mut().rr.send_response(
                                                    channel,
                                                    SyncMessage::Error { message: e.to_string() },
                                                );
                                            }
                                        }
                                    }

                                    SyncMessage::ChunkRequest { chunk_index } => {
                                        match crate::storage::get_chunk(&sync_path, chunk_index).await {
                                            Ok(resp) => {
                                                let _ = event_tx.send(GuiEvent::ChunkSent {
                                                    peer_id: pid_str.clone(),
                                                    chunk_index,
                                                });
                                                let _ = event_tx.send(GuiEvent::Log {
                                                    level: "INFO".into(),
                                                    message: format!("Sent chunk {} to {}", chunk_index, &pid_str[..14.min(pid_str.len())]),
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

                                    _ => { warn!("Unexpected request type from {}", pid_str); }
                                }
                            }

                            // ── We are the RECEIVER (downloading) ───────
                            request_response::Message::Response { response, .. } => {
                                match response {
                                    SyncMessage::Metadata { file_name, total_chunks, file_size, chunk_hashes } => {
                                        info!("Received metadata: '{}' ({} chunks)", file_name, total_chunks);
                                        let _ = event_tx.send(GuiEvent::TransferStarted {
                                            peer_id: pid_str.clone(),
                                            file_name: file_name.clone(),
                                            total_chunks,
                                            file_size,
                                        });
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "OK".into(),
                                            message: format!("Starting transfer: {} ({} chunks, {} bytes)", file_name, total_chunks, file_size),
                                        });

                                        let sync_path = match state.lock().await.sync_path.clone() {
                                            Some(p) => p,
                                            None => {
                                                let _ = event_tx.send(GuiEvent::Log {
                                                    level: "ERROR".into(),
                                                    message: "Cannot receive: sync folder not set".into(),
                                                });
                                                continue;
                                            }
                                        };

                                        let metadata = crate::storage::FileMetadata {
                                            file_name,
                                            total_chunks,
                                            file_size,
                                            chunk_hashes,
                                        };
                                        let n = metadata.total_chunks;
                                        let mut ts = FileTransferState::new(sync_path);
                                        ts.metadata = Some(metadata);
                                        transfer_states.insert(peer, ts);

                                        // Request chunks with a sliding window (8 in-flight)
                                        let window = 8.min(n);
                                        for i in 0..window {
                                            swarm.behaviour_mut().rr.send_request(
                                                &peer,
                                                SyncMessage::ChunkRequest { chunk_index: i },
                                            );
                                        }
                                    }

                                    SyncMessage::ChunkResponse { chunk_index, data, hash } => {
                                        if let Some(ts) = transfer_states.get_mut(&peer) {
                                            // Verify against stored metadata hash, not sender-provided hash
                                            let expected_hash = ts.metadata.as_ref()
                                                .and_then(|m| m.chunk_hashes.get(chunk_index))
                                                .copied();

                                            let verified = expected_hash
                                                .map(|h| crate::storage::verify_chunk(&data, &h))
                                                .unwrap_or(false);

                                            let total = ts.metadata.as_ref().map(|m| m.total_chunks).unwrap_or(0);

                                            let _ = event_tx.send(GuiEvent::ChunkReceived {
                                                peer_id: pid_str.clone(),
                                                chunk_index,
                                                total_chunks: total,
                                                verified,
                                            });

                                            if !verified {
                                                let _ = event_tx.send(GuiEvent::Log {
                                                    level: "ERROR".into(),
                                                    message: format!("Chunk {} FAILED verification!", chunk_index),
                                                });
                                                continue;
                                            }

                                            let _ = event_tx.send(GuiEvent::Log {
                                                level: "INFO".into(),
                                                message: format!("Chunk {}/{} verified ✓", chunk_index + 1, total),
                                            });

                                            match crate::storage::process_received_chunk(
                                                peer,
                                                chunk_index,
                                                data,
                                                hash,
                                                ts,
                                            ).await {
                                                Ok(complete) => {
                                                    if complete {
                                                        let fname = ts.metadata.as_ref()
                                                            .map(|m| m.file_name.clone())
                                                            .unwrap_or_default();
                                                        let _ = event_tx.send(GuiEvent::TransferComplete {
                                                            peer_id: pid_str.clone(),
                                                            file_name: fname.clone(),
                                                        });
                                                        let _ = event_tx.send(GuiEvent::Log {
                                                            level: "OK".into(),
                                                            message: format!("✅ Transfer complete: {}", fname),
                                                        });
                                                        // Notify sender
                                                        swarm.behaviour_mut().rr.send_request(
                                                            &peer,
                                                            SyncMessage::TransferComplete,
                                                        );
                                                    } else {
                                                        // Request the next chunk outside the window
                                                        let window = 8;
                                                        let next = chunk_index + window;
                                                        if next < total {
                                                            swarm.behaviour_mut().rr.send_request(
                                                                &peer,
                                                                SyncMessage::ChunkRequest { chunk_index: next },
                                                            );
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    error!("Chunk processing error: {}", e);
                                                    let _ = event_tx.send(GuiEvent::Log {
                                                        level: "ERROR".into(),
                                                        message: format!("Chunk {} processing failed: {}", chunk_index, e),
                                                    });
                                                }
                                            }
                                        }
                                    }

                                    SyncMessage::Empty => {
                                        let _ = event_tx.send(GuiEvent::RemoteEmpty { peer_id: pid_str.clone() });
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "WARN".into(),
                                            message: format!("Remote folder is empty ({})", &pid_str[..14.min(pid_str.len())]),
                                        });
                                    }

                                    SyncMessage::Error { message } => {
                                        let _ = event_tx.send(GuiEvent::PeerError {
                                            peer_id: pid_str.clone(),
                                            message: message.clone(),
                                        });
                                        let _ = event_tx.send(GuiEvent::Log {
                                            level: "ERROR".into(),
                                            message: format!("Error from {}: {}", &pid_str[..14.min(pid_str.len())], message),
                                        });
                                    }

                                    _ => { warn!("Unexpected response type"); }
                                }
                            }
                        }
                    }

                    // Outgoing connection failed
                    SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                        let pid_str = peer_id.map(|p| p.to_string());
                        let msg = format!("Dial failed {:?}: {}", pid_str, error);
                        warn!("{}", msg);
                        let _ = event_tx.send(GuiEvent::DialFailed {
                            peer_id: pid_str,
                            error: error.to_string(),
                        });
                        let _ = event_tx.send(GuiEvent::Log { level: "ERROR".into(), message: msg });
                    }

                    _ => {}
                }
            }

            // Ctrl+C
            _ = tokio::signal::ctrl_c() => {
                info!("Shutting down…");
                break;
            }
        }
    }

    Ok(())
}

// ─── Minimal HTTP server — serves GUI_HTML on GET / ─────────────────────────
async fn serve_http(mut stream: TcpStream) {
    // Read just enough to see the request line — we don't need to parse headers
    let mut buf = [0u8; 512];
    let _ = stream.read(&mut buf).await;

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n{}",
        GUI_HTML.len(),
        GUI_HTML
    );
    let _ = stream.write_all(response.as_bytes()).await;
}

// ─── WebSocket client handler ────────────────────────────────────────────────
// Sends Identity + all known peers immediately when a GUI connects, so a
// late-connecting (or reconnecting) client always gets full state.
async fn handle_ws_client(
    stream: TcpStream,
    cmd_tx: mpsc::UnboundedSender<GuiCommand>,
    brx: &mut tokio::sync::broadcast::Receiver<String>,
    my_peer_id: String,
    state: Arc<Mutex<AppState>>,
) {
    // Peek at the first bytes — if it looks like plain HTTP (from a stray
    // browser retry or the GUI's reconnect loop hitting the wrong port),
    // respond with a redirect to the HTTP port and close.
    let ws_stream = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(_) => {
            // Silently ignore — browser retries, favicon fetches, etc.
            return;
        }
    };

    let (mut ws_tx, mut ws_rx) = ws_stream.split();

    // ── Send full initial state so a late/reconnecting GUI catches up ────
    // 1. Our own identity
    if let Ok(json) = serde_json::to_string(&GuiEvent::Identity { peer_id: my_peer_id.clone() }) {
        let _ = ws_tx.send(Message::Text(json)).await;
    }

    // 2. All peers currently known from mDNS
    {
        let st = state.lock().await;
        for (pid, addr) in &st.known_addrs {
            if let Ok(json) = serde_json::to_string(&GuiEvent::PeerDiscovered {
                peer_id: pid.clone(),
                addr: addr.clone(),
            }) {
                let _ = ws_tx.send(Message::Text(json)).await;
            }
        }
        // 3. Sync folder, if set
        if let Some(ref path) = st.sync_path {
            if let Ok(json) = serde_json::to_string(&GuiEvent::Log {
                level: "OK".into(),
                message: format!("Sync folder: {}", path.display()),
            }) {
                let _ = ws_tx.send(Message::Text(json)).await;
            }
        }
    }

    // ── Normal event loop ─────────────────────────────────────────────────
    loop {
        tokio::select! {
            // Backend broadcast event → this GUI client
            result = brx.recv() => {
                match result {
                    Ok(json) => {
                        if ws_tx.send(Message::Text(json)).await.is_err() { break; }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        // Fell behind — skip lost messages, keep going
                        warn!("GUI WS lagged, dropped {} messages", n);
                    }
                    Err(_) => break,
                }
            }
            // GUI command → backend
            Some(Ok(msg)) = ws_rx.next() => {
                match msg {
                    Message::Text(text) => {
                        match serde_json::from_str::<GuiCommand>(&text) {
                            Ok(cmd) => { let _ = cmd_tx.send(cmd); }
                            Err(e)  => { error!("Bad GUI command: {} — {}", text, e); }
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
