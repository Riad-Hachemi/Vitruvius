# Vitruvius

A peer-to-peer file sync tool built in Rust. Nodes discover each other automatically on a local network via mDNS, then transfer files in verified 1MB chunks using BLAKE3 hashing. A browser-based GUI is served directly by the backend — no separate web server needed.

```
cargo run
# → open http://127.0.0.1:9000
```

---

## How it works

- **Discovery** — libp2p mDNS broadcasts find peers on the same LAN automatically. No IP addresses to type.
- **Transfer** — files are split into 1MB chunks. Each chunk is hashed with BLAKE3 and verified on arrival against the metadata the sender provided upfront (not the hash the sender claims per-chunk, which could be spoofed).
- **GUI** — the backend embeds the HTML at compile time and serves it over HTTP on port 9000. The GUI connects to the backend over WebSocket on port 9001 for real-time events.
- **Protocol** — libp2p request-response with CBOR encoding over TCP with Noise encryption and Yamux multiplexing.

---

## Project structure

```
Vitruvius/
├── Cargo.toml
├── src/
│   ├── main.rs        # WebSocket server, HTTP server, swarm event loop
│   ├── network.rs     # libp2p behaviour (mDNS + request-response)
│   └── storage.rs     # Chunking, hashing, chunk serving, reassembly
└── gui/
    └── vitruvius_gui.html   # Single-file browser GUI (embedded into binary)
```

---

## Requirements

- Rust toolchain (stable) — install from [rustup.rs](https://rustup.rs)
- Both nodes must be on the same local network for mDNS discovery

---

## Running

### Single node (wait for incoming connections)

```bash
cargo run
```

Open `http://127.0.0.1:9000` in your browser. Your node ID is shown at the top. Set a sync folder in the left panel.

### Two nodes on the same machine (for testing)

```bash
# Terminal 1 — Node A
cargo run

# Terminal 2 — Node B (different ports to avoid conflict)
cargo run -- --http-port 9002 --ws-port 9003
```

- Node A GUI: `http://127.0.0.1:9000`
- Node B GUI: `http://127.0.0.1:9002`

### Two nodes on different machines (LAN)

Just run `cargo run` on each machine. mDNS will discover them automatically within a few seconds — no manual peer IDs needed.

---

## CLI flags

| Flag | Default | Description |
|------|---------|-------------|
| `--http-port` | `9000` | Port to serve the GUI HTML page |
| `--ws-port` | `9001` | Port for the WebSocket connection between GUI and backend |

The libp2p TCP port is always assigned randomly by the OS (port 0) — it never conflicts.

---

## Using the GUI

1. **Set sync folder** — type a local path and click SET. The folder will be created if it doesn't exist. This is where files are read from (if you're the sender) and written to (if you're the receiver).

2. **Wait for discovery or dial manually** — peers on the same LAN appear automatically tagged `DISCOVERED`. Click DIAL on their card to connect. Or paste a peer's full ID into the Peer ID field and click DIAL (useful across subnets where mDNS doesn't reach).

3. **Request sync** — once a peer shows `CONNECTED`, click SYNC on their card. This requests the file metadata from them.

4. **Watch the transfer** — the Transfer tab shows a live chunk grid filling in block by block, current speed, ETA, and a verified chunk count. The log panel on the right streams every event in real time.

5. **Done** — when the transfer completes the file is written to your sync folder and appears in the Files tab.

---

## Checkpoint history

| Checkpoint | Description |
|------------|-------------|
| **CP-1** | Core P2P sync working. GUI served over HTTP from backend. Two-instance local testing via `--http-port` / `--ws-port` flags. Bug fixes: seek-based chunk reading, hash verified against metadata (not sender), sliding window of 8 concurrent chunk requests. |

---

## Known limitations / next steps

- Only syncs the first file found in the sync folder (no directory walking yet)
- No resume — if a transfer is interrupted it starts over
- Single sender per session — no multi-peer parallel downloads
- mDNS only works on the same LAN segment; cross-subnet requires manual peer ID + multiaddr

---

## License

MIT
