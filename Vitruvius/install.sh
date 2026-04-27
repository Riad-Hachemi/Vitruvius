#!/usr/bin/env bash
set -euo pipefail

GITHUB="https://github.com/XXNOUR/Vitruvius"
DOWNLOAD_URL="${GITHUB}/releases/download/v0.1.0-alpha/vitruvius-linux-x86_64"
INSTALL_PATH="/usr/local/bin/vitruvius"
SERVICE_NAME="vitruvius"
HTTP_PORT=9000
WS_PORT=9001

GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; BOLD='\033[1m'; NC='\033[0m'
info()    { echo -e "${BLUE}[Vitruvius]${NC} $1"; }
success() { echo -e "${GREEN}[Vitruvius]${NC} $1"; }
error()   { echo -e "${RED}[Vitruvius]${NC} $1"; exit 1; }

echo -e "\n${BOLD}  Vitruvius — P2P LAN File Sync${NC}"
echo -e "  No cloud. No account. Just sync.\n"

# ── Requirements ──────────────────────────────────────────────────────────────
command -v curl >/dev/null 2>&1 || error "curl is required. Install it and retry."

ARCH=$(uname -m)
[ "$ARCH" = "x86_64" ] || error "Only x86_64 is supported right now. Your arch: $ARCH"

# ── Download ──────────────────────────────────────────────────────────────────
info "Downloading Vitruvius (static binary, no dependencies)..."
TMP=$(mktemp)
curl -fsSL --progress-bar "$DOWNLOAD_URL" -o "$TMP"
chmod +x "$TMP"

# Sanity check — make sure it's actually an ELF binary
file "$TMP" | grep -q "ELF" || error "Downloaded file doesn't look like a Linux binary. Check the release URL."

# ── Install ───────────────────────────────────────────────────────────────────
info "Installing to $INSTALL_PATH..."
if [ -w "$(dirname "$INSTALL_PATH")" ]; then
  mv "$TMP" "$INSTALL_PATH"
else
  sudo mv "$TMP" "$INSTALL_PATH"
fi

# ── Autostart — systemd (most distros) ───────────────────────────────────────
if command -v systemctl >/dev/null 2>&1 && systemctl --user status >/dev/null 2>&1; then
  info "Setting up systemd user service..."
  SERVICE_DIR="${HOME}/.config/systemd/user"
  mkdir -p "$SERVICE_DIR"

  cat > "${SERVICE_DIR}/${SERVICE_NAME}.service" << EOF
[Unit]
Description=Vitruvius P2P Sync Daemon
After=network.target

[Service]
ExecStart=${INSTALL_PATH} --http-port ${HTTP_PORT} --ws-port ${WS_PORT}
Restart=on-failure
RestartSec=5
Environment=RUST_LOG=warn

[Install]
WantedBy=default.target
EOF

  systemctl --user daemon-reload
  systemctl --user enable "$SERVICE_NAME" --now
  AUTOSTART="systemd service enabled — starts on login"
else
  info "systemd not available — skipping autostart setup."
  info "Run manually with: vitruvius"
  AUTOSTART="run manually with: vitruvius"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
sleep 1
success "Vitruvius installed!"
echo ""
echo -e "  ${BOLD}Open your browser:${NC} http://localhost:${HTTP_PORT}"
echo -e "  Autostart: ${AUTOSTART}"
echo ""
echo -e "  ${BLUE}systemctl --user status vitruvius${NC}   # check status"
echo -e "  ${BLUE}journalctl --user -u vitruvius -f${NC}   # live logs"
echo ""
xdg-open "http://localhost:${HTTP_PORT}" 2>/dev/null || true
