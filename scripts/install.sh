#!/usr/bin/env sh
# Warden installer for Linux and macOS.
#   curl -fsSL https://raw.githubusercontent.com/ForrestLasiter/warden/main/scripts/install.sh | sh
#
# Downloads the latest release binary for your platform and installs it to
# ~/.local/bin (override with WARDEN_BIN_DIR).
set -eu

REPO="ForrestLasiter/warden"
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) ASSET="warden-linux-x64" ;;
      aarch64|arm64) ASSET="warden-linux-arm64" ;;
      *) echo "No prebuilt Linux binary for '$ARCH' yet. Install from source: https://github.com/$REPO#install-dev" >&2; exit 1 ;;
    esac ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64) ASSET="warden-macos-arm64" ;;
      *) echo "Only Apple Silicon binaries are published. On Intel Macs, install from source: https://github.com/$REPO#install-dev" >&2; exit 1 ;;
    esac ;;
  *)
    echo "Unsupported OS: $OS. Install from source: https://github.com/$REPO#install-dev" >&2; exit 1 ;;
esac

BIN_DIR="${WARDEN_BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BIN_DIR"
TARGET="$BIN_DIR/warden"
URL="https://github.com/$REPO/releases/latest/download/$ASSET"

echo "Downloading $ASSET from the latest release..."
if command -v curl >/dev/null 2>&1; then
  curl -fSL "$URL" -o "$TARGET"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$TARGET" "$URL"
else
  echo "Need curl or wget to download." >&2; exit 1
fi

chmod +x "$TARGET"
echo "Installed Warden to $TARGET"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Note: $BIN_DIR is not on your PATH. Add it, e.g.:"
     echo "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile" ;;
esac

echo
"$TARGET" version || true
echo "Run 'warden --help' to get started."
