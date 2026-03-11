#!/usr/bin/env bash
# OpenClaw Security Auditor — one-line installer
# Usage: curl -fsSL https://raw.githubusercontent.com/openclaw-security/openclaw-security-auditor/main/install.sh | bash

set -euo pipefail

REPO="openclaw-security/openclaw-security-auditor"
BINARY_NAME="openclaw-security-auditor"
INSTALL_DIR="${INSTALL_DIR:-$HOME/.local/bin}"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── Detect OS / arch ─────────────────────────────────────────────────────────
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)   PLATFORM="linux" ;;
  Darwin)  PLATFORM="macos" ;;
  *)       PLATFORM="unknown" ;;
esac

case "$ARCH" in
  x86_64 | amd64) ARCH="x64" ;;
  arm64 | aarch64) ARCH="arm64" ;;
  *) ARCH="x64" ;;
esac

# ── Check prerequisites ───────────────────────────────────────────────────────
check_cmd() { command -v "$1" &>/dev/null; }

if check_cmd node; then
  NODE_VERSION=$(node --version | sed 's/v//' | cut -d. -f1)
  if [[ "$NODE_VERSION" -lt 18 ]]; then
    error "Node.js 18+ is required. Found: $(node --version). Please upgrade."
  fi
  info "Node.js $(node --version) detected"
else
  error "Node.js 18+ is required but not found. Install it from https://nodejs.org"
fi

# ── Install via npm (preferred) ───────────────────────────────────────────────
if check_cmd npm; then
  info "Installing via npm..."
  npm install -g openclaw-security-auditor
  info "Installation complete. Run: $BINARY_NAME --help"
  exit 0
fi

# ── Fallback: download pre-built bundle from GitHub Releases ─────────────────
info "npm not found — falling back to GitHub Releases download"

if ! check_cmd curl && ! check_cmd wget; then
  error "curl or wget is required for installation."
fi

# Get latest release tag
LATEST_TAG=""
if check_cmd curl; then
  LATEST_TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
elif check_cmd wget; then
  LATEST_TAG=$(wget -qO- "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' | sed 's/.*"tag_name": *"\([^"]*\)".*/\1/')
fi

if [[ -z "$LATEST_TAG" ]]; then
  error "Could not determine latest release tag. Check your internet connection."
fi

info "Latest release: $LATEST_TAG"

ASSET_NAME="${BINARY_NAME}-${PLATFORM}-${ARCH}.js"
DOWNLOAD_URL="https://github.com/${REPO}/releases/download/${LATEST_TAG}/${ASSET_NAME}"
TMP_FILE="$(mktemp /tmp/openclaw-auditor-XXXXXX.js)"

info "Downloading $ASSET_NAME..."
if check_cmd curl; then
  curl -fsSL "$DOWNLOAD_URL" -o "$TMP_FILE"
elif check_cmd wget; then
  wget -qO "$TMP_FILE" "$DOWNLOAD_URL"
fi

# ── Install to INSTALL_DIR ────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR"
TARGET="$INSTALL_DIR/$BINARY_NAME"

cat > "$TARGET" <<EOF
#!/usr/bin/env node
$(cat "$TMP_FILE")
EOF
chmod +x "$TARGET"
rm -f "$TMP_FILE"

# ── PATH check ────────────────────────────────────────────────────────────────
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
  warn "$INSTALL_DIR is not in your PATH."
  warn "Add the following to your shell profile (~/.bashrc, ~/.zshrc, etc.):"
  warn "  export PATH=\"\$HOME/.local/bin:\$PATH\""
fi

info "Installed to: $TARGET"
info "Run: $BINARY_NAME --help"
info ""
info "Quick start:"
info "  $BINARY_NAME --full"
info "  $BINARY_NAME --check-cve \$(openclaw --version 2>/dev/null || echo '1.0.0')"
