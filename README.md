# Vitruvius
A peer-to-peer file sync tool built in Rust. Nodes discover each other automatically on a local network via mDNS, then transfer files in verified 1MB chunks using BLAKE3 hashing. A browser-based GUI is served directly by the backend, no separate web server needed.
