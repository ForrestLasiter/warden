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
BASE="https://github.com/$REPO/releases/latest/download"

_fetch() {  # url dest
  if command -v curl >/dev/null 2>&1; then curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else echo "Need curl or wget to download." >&2; exit 1; fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "Downloading $ASSET from the latest release..."
_fetch "$BASE/$ASSET" "$TMP/$ASSET"

# Verify against the published SHA256SUMS before installing.
if _fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" 2>/dev/null; then
  expected="$(grep " $ASSET\$" "$TMP/SHA256SUMS" | awk '{print $1}')"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$TMP/$ASSET" | awk '{print $1}')"
  else
    actual="$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')"
  fi
  if [ -z "$expected" ]; then
    echo "Warning: no checksum listed for $ASSET; proceeding unverified." >&2
  elif [ "$expected" != "$actual" ]; then
    echo "Checksum verification FAILED for $ASSET (expected $expected, got $actual)." >&2
    exit 1
  else
    echo "Checksum verified."
  fi
else
  echo "Warning: could not fetch SHA256SUMS; proceeding unverified." >&2
fi

mv "$TMP/$ASSET" "$TARGET"
chmod +x "$TARGET"
echo "Installed Warden to $TARGET"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Note: $BIN_DIR is not on your PATH. Add it, e.g.:"
     echo "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile" ;;
esac

# Create a double-clickable launcher that opens the dashboard.
if [ "$OS" = "Linux" ]; then
  apps="$HOME/.local/share/applications"
  mkdir -p "$apps"
  cat > "$apps/warden.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=Warden
Comment=Open the Warden malware scanner dashboard
Exec=$TARGET gui
Terminal=true
Categories=Security;Utility;
DESKTOP
  chmod +x "$apps/warden.desktop"
  if [ -d "$HOME/Desktop" ]; then
    cp "$apps/warden.desktop" "$HOME/Desktop/warden.desktop"
    chmod +x "$HOME/Desktop/warden.desktop"
    # GNOME needs the desktop file marked trusted before it'll launch on click.
    command -v gio >/dev/null 2>&1 && gio set "$HOME/Desktop/warden.desktop" metadata::trusted true 2>/dev/null || true
  fi
  echo "Created a 'Warden' application entry (also on your Desktop)."
elif [ "$OS" = "Darwin" ] && [ -d "$HOME/Desktop" ]; then
  launcher="$HOME/Desktop/Warden.command"
  printf '#!/bin/sh\nexec "%s" gui\n' "$TARGET" > "$launcher"
  chmod +x "$launcher"
  echo "Created 'Warden.command' on your Desktop - double-click it to open the dashboard."
fi

echo
"$TARGET" version || true
echo
echo "Double-click the 'Warden' launcher to open the dashboard, or run"
echo "'warden --help' in a terminal for the command line."
