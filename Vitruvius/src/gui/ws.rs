// src/gui/ws.rs
//
// WebSocket handler — one Tokio task per connected browser tab.
//
// On connect   : sends a full state snapshot so a freshly opened or
//                reconnecting GUI tab never misses current state.
// Receive loop : deserialises incoming JSON → GuiCommand → cmd_tx.
// Send loop    : receives backend broadcast events → forwards as JSON text.

use std::sync::Arc;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, mpsc};
use tokio_tungstenite::{accept_async, tungstenite::Message};
use tracing::{error, warn};

use crate::crypto;
use crate::state::{AppState, short_id};
use crate::storage;
use super::types::{GuiCommand, GuiEvent, GuiFileInfo};

pub async fn handle_client(
    stream:     TcpStream,
    cmd_tx:     mpsc::UnboundedSender<GuiCommand>,
    brx:        &mut tokio::sync::broadcast::Receiver<String>,
    my_peer_id: String,
    my_name:    String,
    state:      Arc<Mutex<AppState>>,
) {
    // Upgrade raw TCP → WebSocket; silently ignore anything that isn't a
    // proper WS handshake (browser retries, favicon requests, health checks…)
    let ws = match accept_async(stream).await {
        Ok(ws) => ws,
        Err(_) => return,
    };
    let (mut ws_tx, mut ws_rx) = ws.split();

    // ── Send state snapshot ───────────────────────────────────────────────────

    send(&mut ws_tx, &GuiEvent::Identity {
        peer_id:   my_peer_id.clone(),
        node_name: my_name.clone(),
    }).await;

    // ── Vault posture snapshot ────────────────────────────────────────────────
    {
        let st = state.lock().await;
        let fp = st
            .vault_key
            .as_ref()
            .map(|k| crypto::short_fingerprint(k))
            .unwrap_or_else(|| "—".to_string());
        let vault_mode = st.vault_mode;
        let encrypted_protocol = st.encrypted_protocol;
        drop(st);
        send(
            &mut ws_tx,
            &GuiEvent::VaultStatus {
                vault_mode,
                encrypted_protocol,
                key_fingerprint: fp,
            },
        )
        .await;
    }

    {
        let st = state.lock().await;

        // Every peer currently known from mDNS
        for (pid, addr) in &st.known_addrs {
            let name = st.peer_names.get(pid).cloned()
                .unwrap_or_else(|| format!("Node-{}", short_id(pid)));
            send(&mut ws_tx, &GuiEvent::PeerDiscovered {
                peer_id:   pid.clone(),
                addr:      addr.clone(),
                node_name: name,
            }).await;
        }

        // Current folder listing if a folder is set
        if let Some(ref path) = st.sync_path {
            if let Ok(files) = storage::list_folder(path).await {
                let listing = files.iter().map(|f| GuiFileInfo {
                    name:   f.file_name.clone(),
                    size:   f.file_size,
                    chunks: f.total_chunks,
                }).collect();
                send(&mut ws_tx, &GuiEvent::FolderListing { files: listing }).await;
            }
            send(&mut ws_tx, &GuiEvent::Log {
                level:   "OK".into(),
                message: format!("Sync folder: {}", path.display()),
            }).await;
        }
    }

    // ── Event loop ────────────────────────────────────────────────────────────

    loop {
        tokio::select! {
            // Backend broadcast event → this tab
            result = brx.recv() => {
                match result {
                    Ok(json) => {
                        if ws_tx.send(Message::Text(json)).await.is_err() { break; }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("GUI WS lagged, dropped {} events", n);
                    }
                    Err(_) => break,
                }
            }

            // Incoming message from the browser
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

// ─── Serialise and send one event; silently ignore send errors ────────────────
async fn send(
    ws_tx: &mut futures_util::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<TcpStream>,
        Message,
    >,
    event: &GuiEvent,
) {
    if let Ok(json) = serde_json::to_string(event) {
        let _ = ws_tx.send(Message::Text(json)).await;
    }
}
