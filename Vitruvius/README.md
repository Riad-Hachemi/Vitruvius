# Vitruvius
=======

**Privacy-first decentralized file synchronization with zero-knowledge encryption**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Status: Development](https://img.shields.io/badge/status-in%20development-yellow.svg)]()

---

## Overview

Vitruvius is a decentralized, peer-to-peer file synchronization platform built on a **zero-knowledge encryption model**. Unlike cloud sync solutions (Dropbox, Google Drive) or existing P2P tools (Syncthing), Vitruvius encrypts files **on the source device before transmission**, ensuring that no relay node, server, or third party can ever read your data.

Named after Leonardo da Vinci's *Vitruvian Man* — a study of ideal proportion and balance — Vitruvius brings balance between **convenience and privacy**, giving you seamless file sync without sacrificing control over your data.

### Key Features

- **🔐 Zero-Knowledge Encryption** — Files are encrypted client-side with ChaCha20-Poly1305 before leaving your device. Sync nodes see only opaque ciphertext.
- **🌐 Fully Decentralized** — Built on libp2p for peer discovery and direct device-to-device sync. No central server to trust or compromise.
- **📜 Version History** — Content-addressed storage with BLAKE3 hashing preserves every file version and enables point-in-time recovery.
- **♻️ Deduplication** — Identical content blocks are stored only once across all files, saving storage and bandwidth.
- **🦀 Written in Rust** — Memory safety and performance guaranteed at compile time, with no garbage collection overhead.

---

## Why Vitruvius?

| Feature | Dropbox | Google Drive | Syncthing | **Vitruvius** |
|---------|---------|--------------|-----------|---------------|
| Zero-Knowledge Encryption | ✗ | ✗ | ✗ | **✓** |
| Decentralized (No Central Server) | ✗ | ✗ | ✓ | **✓** |
| Works Offline / LAN-only | ✗ | ✗ | ✓ | **✓** |
| Content-Addressed Version History | ✗ | ✗ | ✗ | **✓** |
| Automatic Deduplication | ✗ | ✗ | ✗ | **✓** |
| Free & Open Source | ✗ | ✗ | ✓ | **✓** |

**The Difference:** Syncthing encrypts *in transit*. Vitruvius encrypts *before transit*. This means even a compromised relay cannot decrypt your files.

---

## Quick Start

> ⚠️ **Note:** Vitruvius is currently in active development as a final-year university project. The first working prototype is expected by **April 2025**.

### Prerequisites

- Rust 1.75 or later
- libp2p (installed via Cargo)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/vitruvius.git
cd vitruvius

# Build from source
cargo build --release

# Run Vitruvius
./target/release/vitruvius
```

---

## How It Works

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Device A                                                   │
│  ┌─────────────┐    ┌──────────────┐   ┌───────────────┐   │
│  │ File Watcher│───▶│  Encryption  │──▶│ Chunk & Hash  │   │
│  │  (notify)   │    │ (ChaCha20)   │   │   (BLAKE3)    │   │
│  └─────────────┘    └──────────────┘   └───────┬───────┘   │
│                                                 │           │
│                                                 ▼           │
│                                        ┌────────────────┐   │
│                                        │  libp2p P2P    │   │
│                                        │    Network     │   │
│                                        └────────┬───────┘   │
└─────────────────────────────────────────────────┼───────────┘
                                                  │
                          Encrypted Blocks Only  │
                                                  │
┌─────────────────────────────────────────────────┼───────────┐
│  Device B                                       ▼           │
│                                        ┌────────────────┐   │
│                                        │  libp2p P2P    │   │
│                                        │    Network     │   │
│                                        └────────┬───────┘   │
│                                                 │           │
│  ┌─────────────┐    ┌──────────────┐   ┌───────▼───────┐   │
│  │   Decrypt   │◀───│   Verify     │◀──│ Receive Blocks│   │
│  │ (ChaCha20)  │    │  (BLAKE3)    │   │               │   │
│  └──────┬──────┘    └──────────────┘   └───────────────┘   │
│         │                                                   │
│         ▼                                                   │
│  ┌─────────────┐                                           │
│  │ Reconstruct │                                           │
│  │    File     │                                           │
│  └─────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

1. **File Watcher** (`notify` crate) — Detects file system changes in real time
2. **Encryption Layer** — ChaCha20-Poly1305 authenticated encryption per file block
3. **Content Addressing** — BLAKE3 hashing for integrity verification and deduplication
4. **P2P Network** — libp2p for peer discovery, NAT traversal, and encrypted transport
5. **Version Store** — Content-addressed block storage enabling full file history

---

## Development Roadmap

This project is being developed over **10 weeks** as part of a Computer Science Bachelor thesis at the University of Tlemcen, Algeria.

| Phase | Timeline | Deliverables |
|-------|----------|--------------|
| **Phase 1: Foundation** | Weeks 1–2 | P2P node setup, direct peer connections, basic file transfer on LAN |
| **Phase 2: Sync Engine** | Weeks 3–4 | File watching, change detection, chunking, delta sync |
| **Phase 3: Encryption** | Weeks 5–6 | Client-side encryption layer, key management, ciphertext-only relay |
| **Phase 4: Version History** | Weeks 7–8 | Content-addressed storage, version index, block deduplication |
| **Phase 5: Polish & Demo** | Weeks 9–10 | Terminal UI, end-to-end testing, documentation, presentation |

**Current Status:** Phase 1 (Foundation) ✅ In Progress

---

## Technology Stack

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Language** | Rust | Memory safety, performance, cryptographic reliability |
| **P2P Networking** | libp2p | Peer discovery, NAT traversal, relay, transport |
| **Encryption** | ChaCha20-Poly1305 | Authenticated encryption of file blocks |
| **Hashing** | BLAKE3 | Content addressing, integrity verification |
| **File Watching** | notify | Real-time file system change detection |
| **Serialization** | serde + bincode | Efficient binary peer protocol |
| **UI** | ratatui | Terminal user interface |

---

## Target Use Cases

Vitruvius is designed for individuals and organizations that handle sensitive data and cannot afford to trust third-party cloud providers:

- **Legal firms** syncing confidential case files
- **Medical practices** sharing patient records across locations
- **Accounting offices** handling sensitive financial data
- **Creative agencies** syncing large media files without cloud storage fees
- **Privacy-conscious individuals** who want control over their personal data

---

## Project Goals

This is a **final-year Bachelor project** with three core objectives:

1. **Academic** — Demonstrate understanding of distributed systems, cryptography, and systems programming in Rust
2. **Technical** — Build a working prototype that proves zero-knowledge file sync is feasible and usable
3. **Commercial** — Validate the concept with real users and explore incubation through the University of Tlemcen's entrepreneurship program

---

## Team

- **Guilal Mohammed Nour** — Network & Sync Layer (peer discovery, connection management, transfer protocol)
- **Hachemi Mohammed Ali Riad** — Storage & Encryption Layer (file watching, encryption, version history, deduplication)

**Supervisor:** TBA  
**Institution:** University of Tlemcen, Faculty of Science & Technology  
**Program:** Bachelor of Computer Science, Year 3  
**Timeline:** February – April 2025  

---

## Contributing

This is currently a **student research project** and not yet open for external contributions. Once the prototype is complete and the thesis is submitted, we plan to open the project to the community.

If you're interested in following the development or have feedback, feel free to open an issue or star the repository.

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## Security Notice

⚠️ **Vitruvius is pre-alpha software under active development.** It has not been audited by professional cryptographers and should **not** be used for production data or any scenario where data loss or security compromise would have serious consequences.

The encryption implementation uses well-established libraries (ChaCha20-Poly1305 via Rust's `chacha20poly1305` crate), but the overall protocol and key management strategy have not been independently verified.

**Use at your own risk during the development phase.**

---

## Acknowledgments

- Inspired by [Syncthing](https://syncthing.net/) for showing that P2P sync can be done right
- Built on the shoulders of [libp2p](https://libp2p.io/) for rock-solid P2P networking
- Motivated by the need for truly private file sync in an era of increasing cloud surveillance
- Supported by the **University of Tlemcen** incubation program

---

## Contact

For questions, feedback, or collaboration inquiries:

- **Project Repository:** [github.com/yourusername/vitruvius](https://github.com/yourusername/vitruvius)
- **Email:** [your-email@example.com]
- **University:** University of Tlemcen, Department of Computer Science

---

<p align="center">
  <i>Named after the Vitruvian Man — a study of proportion, balance, and the harmony between structure and freedom.</i>
</p>
>>>>>>> master
