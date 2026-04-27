# Vitruvius

**Privacy-first decentralized file synchronization with zero-knowledge encryption**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Status: Active Development](https://img.shields.io/badge/status-active%20development-green.svg)]()

-----

## Who We Are

Vitruvius is built by a team of engineers who are deeply committed to **decentralization as a discipline** — not just as a technology trend, but as a foundational approach to building trustworthy, resilient systems.

We are forming a startup around this conviction. Our focus is building products, conducting research, and providing consultation in the field of decentralized technology — starting inside the University of Tlemcen and expanding outward. Vitruvius is our first proof of concept: a real, working system that demonstrates what decentralized architecture can achieve when applied to a problem people care about every day.

Our areas of work include:

- **Product development** — Building decentralized tools and infrastructure for privacy-conscious users and organizations
- **Research** — Advancing the academic understanding of distributed systems, cryptographic protocols, and P2P networking
- **Consultation** — Helping organizations understand and adopt decentralized architecture where it genuinely adds value

We believe the next generation of software should not require users to trust a central party with their data. Vitruvius is where that belief meets working code.

-----

## Overview

Vitruvius is a decentralized, peer-to-peer file synchronization platform built on a **zero-knowledge encryption model**. Unlike cloud sync solutions (Dropbox, Google Drive) or existing P2P tools (Syncthing), Vitruvius encrypts files **on the source device before transmission**, ensuring that no relay node, server, or third party can ever read your data.

Named after Leonardo da Vinci’s *Vitruvian Man* — a study of ideal proportion and balance — Vitruvius brings balance between **convenience and privacy**, giving you seamless file sync without sacrificing control over your data.

### Key Features

- ** Zero-Knowledge Encryption** — Chunks are encrypted client-side with ChaCha20-Poly1305 before leaving your device. Relay nodes see only opaque ciphertext — they cannot decrypt your files even if compromised.
- ** Fully Decentralized** — Built on libp2p for peer discovery and direct device-to-device sync. No central server to trust, attack, or shut down.
- ** Version History** — Content-addressed storage with BLAKE3 hashing preserves every file version and enables point-in-time recovery.
- ** Deduplication** — Identical content blocks are stored and transferred only once across all files, saving storage and bandwidth.
- ** Written in Rust** — Memory safety and performance guaranteed at compile time. No garbage collection, no data races, no undefined behavior.

-----

## Why Vitruvius?

|Feature                          |Dropbox|Google Drive|Syncthing|**Vitruvius**|
|---------------------------------|-------|------------|---------|-------------|
|Zero-Knowledge Encryption        |✗      |✗           |✗        |**✓**        |
|Decentralized (No Central Server)|✗      |✗           |✓        |**✓**        |
|Works Offline / LAN-only         |✗      |✗           |✓        |**✓**        |
|Content-Addressed Version History|✗      |✗           |✗        |**✓**        |
|Automatic Deduplication          |✗      |✗           |✗        |**✓**        |
|Free & Open Source               |✗      |✗           |✓        |**✓**        |

**The critical difference:** Syncthing encrypts *in transit*. Vitruvius encrypts *before transit*. The data is encrypted on your device before it touches the network. A compromised relay node or a man-in-the-middle sees nothing but ciphertext it cannot decrypt.

-----

## Quick Start

### Prerequisites

- Rust 1.75 or later
- Cargo (comes with Rust)

### Installation

```bash
# Clone the repository
git clone https://github.com/XXNOUR/Vitruvius.git
cd Vitruvius

# Build from source
cargo build --release

# Run Vitruvius
./target/release/vitruvius
```

### Running with Encryption (Recommended)

```bash
# Step 1 — Generate a transport key once on any machine
./target/release/vitruvius --generate-key vitruvius.key

# Step 2 — Copy vitruvius.key to all peer machines

# Step 3 — Start each peer with the shared key
#         (vault mode + encrypted protocol are ON by default)
./target/release/vitruvius --key-path vitruvius.key
```

On first run, a separate **at-rest vault key** is auto-generated at
`~/.vitruvius/vault.key` (mode `0o600`). Files inside the sync folder are
stored as opaque `*.vit` blobs — even an attacker with full disk access
cannot read them without that key.

### CLI Options

```
--key-path                 <file>  Load the 32-byte transport key (peer-to-peer)
--generate-key             <file>  Generate a new random key file and exit
--vault-key                <file>  Override the at-rest vault key location
--no-vault                         Store files in plaintext on disk (legacy)
--no-encrypted-protocol            Send legacy plaintext-hash manifests on the wire
--http-port               <port>   GUI HTTP port (default: 9000)
--ws-port                 <port>   GUI WebSocket port (default: 9001)
--theme                   <name>   GUI theme

Subcommands:
  import <plaintext_dir>   Bulk-encrypt an existing directory into the sync folder
  export <name> <dest>     Decrypt a single *.vit file out to plaintext
```

### Zero-Knowledge Guarantees (v0.2)

Vitruvius v0.2 hardens the prototype into a defensible zero-knowledge build
across three planes:

| Plane          | Guarantee                                                                                                  |
|----------------|------------------------------------------------------------------------------------------------------------|
| **In transit** | Manifest is encrypted (CBOR-then-AEAD); chunk hashes on the wire are **blinded** per-key; filenames are replaced by opaque 16-byte `file_id`s. A passive observer learns only file count and approximate sizes. |
| **In memory**  | Keys are wrapped in a `SecretKey` newtype with `Zeroize` + `ZeroizeOnDrop`. Every chunk uses ChaCha20-Poly1305 with **per-chunk AAD** (`vitv02-chunk\0\0\0\0 ‖ file_id ‖ chunk_idx`). The global-key fallback in `key_for_peer` is gone — there is no implicit trust path. |
| **At rest**    | The default storage backend is the `*.vit` vault format: 40-byte header (magic ‖ file UUID ‖ chunk count ‖ original size ‖ reserved), then per-chunk `[plaintext-hash 32B][len u32][12B nonce ‖ ct ‖ 16B tag]`, AAD-bound to the file UUID and chunk index. |

The GUI exposes the posture live via the **VAULT / PROTO / key:…** pill in the
header, and ships a **Decrypt File** command (`GuiCommand::DecryptFile`) for
on-demand export of any `*.vit` blob to plaintext.

#### Threat model in plain English

| Vitruvius **does** stop                                                  | Vitruvius **does not** stop                                       |
|--------------------------------------------------------------------------|-------------------------------------------------------------------|
| Network eavesdropper learning filenames, hashes, or content              | A compromised endpoint with the running process & loaded keys     |
| Disk forensics on a stolen laptop (without the vault key)                | Theft of *both* `vitruvius.key` and `~/.vitruvius/vault.key`      |
| Tampering — every chunk is AEAD-authenticated end-to-end and at-rest     | Traffic-analysis side channels (file count / total size)          |
| Cross-file nonce confusion — AAD binds each ciphertext to its `file_id`  | Coercion of a trusted peer (TOFU is trust-on-first-use, not zero-trust) |

-----

## How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Device A                                                   │
│  ┌─────────────┐    ┌──────────────┐   ┌───────────────┐   │
│  │ File Watcher│───▶│  Chunk &     │──▶│   Encrypt     │   │
│  │  (notify)   │    │  Hash(BLAKE3)│   │ (ChaCha20)    │   │
│  └─────────────┘    └──────────────┘   └───────┬───────┘   │
│                                                 │           │
│                        Only ciphertext          ▼           │
│                        leaves this device  ┌────────────┐   │
│                                            │   libp2p   │   │
│                                            │  Network   │   │
│                                            └─────┬──────┘   │
└──────────────────────────────────────────────────┼──────────┘
                                                   │
                        [ ciphertext only ]        │
                                                   │
┌──────────────────────────────────────────────────┼──────────┐
│  Device B                                        ▼          │
│                                            ┌────────────┐   │
│                                            │   libp2p   │   │
│                                            │  Network   │   │
│                                            └─────┬──────┘   │
│                                                  │          │
│  ┌─────────────┐    ┌──────────────┐   ┌────────▼───────┐  │
│  │ Reconstruct │◀───│Verify(BLAKE3)│◀──│    Decrypt     │  │
│  │    File     │    │  plaintext   │   │  (ChaCha20)    │  │
│  └─────────────┘    └──────────────┘   └────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Encryption ordering matters:** The chunk hash in the manifest is computed from plaintext. The receiver decrypts first, then verifies the hash. This means integrity verification is always against the original content, and deduplication works correctly across all files regardless of the encryption nonce used.

### Core Components

1. **File Watcher** (`notify` crate) — Detects filesystem changes in real time, debounced to avoid spamming peers during large writes
1. **Chunker** — Splits files into 512 KB blocks, computes BLAKE3 hashes per block for integrity and deduplication
1. **Encryption Layer** — ChaCha20-Poly1305 authenticated encryption per chunk, random nonce per encryption, plaintext never leaves the device
1. **Download Scheduler** — Two-level queue (active + pending) capped at 3 concurrent files × 4 chunks in-flight = 12 streams, well within libp2p’s limits
1. **P2P Network** — libp2p with mDNS for LAN discovery, request-response protocol for manifest and chunk exchange
1. **Version Store** — Content-addressed block storage enabling full file history and point-in-time recovery

-----

## Security Model

### What Vitruvius protects against

- **Network eavesdropping** — All chunk data is ChaCha20-Poly1305 encrypted before transmission. A packet capture reveals nothing.
- **Compromised relay** — Relay nodes forward ciphertext they cannot decrypt. Even a malicious relay cannot read your files.
- **Data tampering** — Poly1305 authentication tags detect any modification to encrypted chunks. BLAKE3 hashes verify plaintext integrity after decryption. Any tampered chunk is detected and re-requested.

### What Vitruvius does not protect against

- **Compromised endpoint** — If an attacker has OS-level access to a peer’s machine, they can read files on disk. Files are stored as plaintext locally; encryption applies to transit only.
- **Key theft** — If the shared key file is stolen, an attacker can decrypt captured traffic. Protect the key file like a password.
- **Key distribution** — The current model requires manually copying a key file to every peer. Automated key exchange (TOFU / Diffie-Hellman) is on the roadmap.

### Cryptographic primitives

|Primitive           |Algorithm        |Purpose                                                  |
|--------------------|-----------------|---------------------------------------------------------|
|Symmetric encryption|ChaCha20-Poly1305|Authenticated chunk encryption                           |
|Hashing             |BLAKE3           |Content addressing, integrity verification, deduplication|
|P2P identity        |Ed25519 (libp2p) |Peer identity and transport security                     |

-----

## Development Roadmap

|Phase                       |Status       |Deliverables                                                                                            |
|----------------------------|-------------|--------------------------------------------------------------------------------------------------------|
|**Phase 1: Foundation**     | Complete   |P2P node setup, mDNS peer discovery, direct LAN file transfer                                           |
|**Phase 2: Sync Engine**    | Complete   |File watching, change detection, chunking, delta sync, deduplication                                    |
|**Phase 3: Encryption**     | Complete   |ChaCha20-Poly1305 per-chunk encryption, key management, nonce correctness, encryption mismatch detection|
|**Phase 4: Key Exchange**   | In Progress|SSH-style TOFU key exchange — no manual key copying                                                     |
|**Phase 5: Version History**| Planned    |Content-addressed block store, version index, point-in-time recovery                                    |
|**Phase 6: Polish & Demo**  | Planned    |Terminal UI (ratatui), end-to-end testing, thesis documentation                                         |

-----

## Technology Stack

|Component         |Technology                             |Purpose                                               |
|------------------|---------------------------------------|------------------------------------------------------|
|**Language**      |Rust 1.75+                             |Memory safety, performance, cryptographic reliability |
|**P2P Networking**|libp2p                                 |Peer discovery (mDNS), NAT traversal, relay, transport|
|**Encryption**    |ChaCha20-Poly1305                      |Authenticated per-chunk encryption                    |
|**Hashing**       |BLAKE3                                 |Content addressing, integrity verification            |
|**File Watching** |notify                                 |Real-time filesystem change detection                 |
|**Serialization** |serde + cbor                           |Binary peer protocol                                  |
|**UI**            |Browser (WebSocket) + ratatui (planned)|GUI and terminal interface                            |

-----

## Target Use Cases

Vitruvius is built for individuals and organizations that handle sensitive data and cannot afford to trust a third-party cloud provider:

- **Legal firms** syncing confidential case files across offices
- **Medical practices** sharing patient records between locations
- **Accounting offices** handling sensitive financial data
- **Research teams** syncing unpublished work without exposing it to cloud providers
- **Privacy-conscious individuals** who want full control over their personal data

-----

## Project Context

Vitruvius is being developed as a **Bachelor thesis project** at the University of Tlemcen, Faculty of Science & Technology, with three parallel objectives:

1. **Academic** — Demonstrate applied understanding of distributed systems, cryptographic protocol design, and systems programming in Rust
1. **Technical** — Build a working prototype that proves zero-knowledge P2P file sync is feasible, correct, and usable
1. **Commercial** — Lay the foundation for a decentralization-focused startup, validated through the University of Tlemcen incubation program

-----

## Team

|Member                       |Role                                                                                                             |
|-----------------------------|-----------------------------------------------------------------------------------------------------------------|
|**Guilal Mohammed Nour**     |Network & Sync Layer — peer discovery, connection management, transfer protocol, download scheduler              |
|**Hachemi Mohammed Ali Riad**|Storage & Encryption Layer — file watching, ChaCha20 encryption, BLAKE3 integrity, version history, deduplication|

**Supervisor:** TBA  
**Institution:** University of Tlemcen, Faculty of Science & Technology  
**Program:** Bachelor of Computer Science, Year 3

-----

## Security Notice

 Vitruvius is **pre-alpha software** under active development. It has not been audited by professional cryptographers and should not be used for production data or any scenario where data loss or security compromise would have serious consequences.

The encryption primitives are well-established (ChaCha20-Poly1305 via the `chacha20poly1305` crate, BLAKE3 via the `blake3` crate), but the overall protocol, key management strategy, and peer authentication model have not been independently verified.

**Use at your own risk during the development phase.**

-----

## Contributing

This is currently a student research project and not yet open for external contributions. Once the prototype is complete and the thesis is submitted, we plan to open the project to the community.

If you are interested in following the development, open an issue or star the repository.

-----

## License

MIT License — see <LICENSE> for details.

-----

## Acknowledgments

- [Syncthing](https://syncthing.net/) — for proving P2P sync can be done right
- [libp2p](https://libp2p.io/) — for the P2P networking foundation
- [Tahoe-LAFS](https://tahoe-lafs.org/) — for the original zero-knowledge storage model
- University of Tlemcen incubation program — for supporting student entrepreneurship

-----

<p align="center">
  <i>Named after the Vitruvian Man — Leonardo's study of proportion, balance, and the harmony between structure and freedom.</i>
</p>