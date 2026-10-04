#!/usr/bin/env sh
# Warden installer for Linux and macOS.
#
#   curl -fsSL https://raw.githubusercontent.com/ForrestLasiter/warden/main/scripts/install.sh | sh
#
# Options (pass with:  ... | sh -s -- <options>):
#   --install-dir DIR   install the binary here (default ~/.local/bin)
#   --version TAG        install a specific release tag (default: latest)
#   --no-shortcuts       don't create desktop/application launchers
#   --no-path            don't suggest adding the install dir to PATH
#   --allow-unverified   proceed even if checksums can't be fetched (NOT advised)
#   --uninstall          remove Warden, its launchers, and quarantine note
#   -h, --help           show this help
#
# Safety: the download is checksum-verified against the release's SHA256SUMS
# BEFORE anything is installed. If verification can't be performed the install
# FAILS CLOSED unless --allow-unverified is given. The existing install is never
# touched until a new binary is verified (safe rollback).
set -eu

REPO="ForrestLasiter/warden"

ALLOW_UNVERIFIED=0
NO_SHORTCUTS=0
NO_PATH=0
ACTION=install
VERSION=latest
BIN_DIR="${WARDEN_BIN_DIR:-$HOME/.local/bin}"

_help() { sed -n '2,20p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; }

while [ $# -gt 0 ]; do
  case "$1" in
    --allow-unverified) ALLOW_UNVERIFIED=1 ;;
    --no-shortcuts) NO_SHORTCUTS=1 ;;
    --no-path) NO_PATH=1 ;;
    --uninstall) ACTION=uninstall ;;
    --install-dir) shift; BIN_DIR="${1:?--install-dir needs a path}" ;;
    --install-dir=*) BIN_DIR="${1#*=}" ;;
    --version) shift; VERSION="${1:?--version needs a tag}" ;;
    --version=*) VERSION="${1#*=}" ;;
    -h|--help) _help; exit 0 ;;
    *) echo "Unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

OS="$(uname -s)"
ARCH="$(uname -m)"
TARGET="$BIN_DIR/warden"

# --- uninstall --------------------------------------------------------------
if [ "$ACTION" = "uninstall" ]; then
  if rm -f "$TARGET"; then echo "Removed $TARGET"; fi
  rm -f "$HOME/.local/share/applications/warden.desktop" \
        "$HOME/Desktop/warden.desktop" "$HOME/Desktop/Warden.command" 2>/dev/null || true
  echo "Removed Warden launchers."
  echo "Your scan history / quarantine in ~/.warden was left untouched."
  echo "If you added $BIN_DIR to your PATH, remove that line from your shell profile."
  exit 0
fi

# --- select asset -----------------------------------------------------------
case "$OS" in
  Linux)
    case "$ARCH" in
      x86_64|amd64) ASSET="warden-linux-x64" ;;
      aarch64|arm64) ASSET="warden-linux-arm64" ;;
      *) echo "No prebuilt Linux binary for '$ARCH'. Build from source: https://github.com/$REPO#install-dev" >&2; exit 1 ;;
    esac ;;
  Darwin)
    case "$ARCH" in
      arm64|aarch64) ASSET="warden-macos-arm64" ;;
      x86_64) echo "Only Apple Silicon binaries are published. On Intel Macs, build from source: https://github.com/$REPO#install-dev" >&2; exit 1 ;;
      *) echo "Unsupported macOS arch '$ARCH'." >&2; exit 1 ;;
    esac ;;
  *)
    echo "Unsupported OS: $OS. Build from source: https://github.com/$REPO#install-dev" >&2; exit 1 ;;
esac

if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/$REPO/releases/latest/download"
else
  BASE="https://github.com/$REPO/releases/download/$VERSION"
fi

_fetch() {  # url dest  -> returns non-zero on failure
  if command -v curl >/dev/null 2>&1; then curl -fSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then wget -qO "$2" "$1"
  else echo "Need curl or wget to download." >&2; exit 1; fi
}

mkdir -p "$BIN_DIR"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "Downloading $ASSET ($VERSION)..."
_fetch "$BASE/$ASSET" "$TMP/$ASSET" || { echo "Download failed." >&2; exit 1; }

# --- verify (fail closed) ---------------------------------------------------
verify_fatal() {  # msg
  if [ "$ALLOW_UNVERIFIED" -eq 1 ]; then
    echo "WARNING: $1 (continuing because --allow-unverified was given)." >&2
  else
    echo "ERROR: $1" >&2
    echo "Refusing to install unverified. Re-run with --allow-unverified to override." >&2
    exit 1
  fi
}

if _fetch "$BASE/SHA256SUMS" "$TMP/SHA256SUMS" 2>/dev/null; then
  expected="$(grep " $ASSET\$" "$TMP/SHA256SUMS" | awk '{print $1}')"
  if command -v sha256sum >/dev/null 2>&1; then
    actual="$(sha256sum "$TMP/$ASSET" | awk '{print $1}')"
  elif command -v shasum >/dev/null 2>&1; then
    actual="$(shasum -a 256 "$TMP/$ASSET" | awk '{print $1}')"
  else
    actual=""
    verify_fatal "no sha256 tool (sha256sum/shasum) available to verify the download"
  fi
  if [ -z "$expected" ]; then
    verify_fatal "SHA256SUMS does not list $ASSET"
  elif [ -n "$actual" ] && [ "$expected" != "$actual" ]; then
    # A positive mismatch is ALWAYS fatal - never overridable.
    echo "ERROR: checksum MISMATCH for $ASSET (expected $expected, got $actual)." >&2
    echo "The download may be corrupt or tampered with. Aborting." >&2
    exit 1
  elif [ -n "$actual" ]; then
    echo "Checksum verified."
  fi
else
  verify_fatal "could not download SHA256SUMS to verify the binary"
fi

# --- install (atomic move; existing install untouched until now) ------------
mv "$TMP/$ASSET" "$TARGET"
chmod +x "$TARGET"
echo "Installed Warden to $TARGET"

if [ "$NO_PATH" -eq 0 ]; then
  case ":$PATH:" in
    *":$BIN_DIR:"*) ;;
    *) echo "Note: $BIN_DIR is not on your PATH. Add it, e.g.:"
       echo "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.profile" ;;
  esac
fi

# --- double-clickable launcher ----------------------------------------------
if [ "$NO_SHORTCUTS" -eq 0 ]; then
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
      if command -v gio >/dev/null 2>&1; then
        gio set "$HOME/Desktop/warden.desktop" metadata::trusted true 2>/dev/null || true
      fi
    fi
    echo "Created a 'Warden' application entry (also on your Desktop)."
  elif [ "$OS" = "Darwin" ] && [ -d "$HOME/Desktop" ]; then
    launcher="$HOME/Desktop/Warden.command"
    printf '#!/bin/sh\nexec "%s" gui\n' "$TARGET" > "$launcher"
    chmod +x "$launcher"
    echo "Created 'Warden.command' on your Desktop - double-click it to open the dashboard."
  fi
fi

echo
"$TARGET" version || true
echo
echo "Double-click the 'Warden' launcher to open the dashboard, or run"
echo "'warden --help' in a terminal for the command line."
