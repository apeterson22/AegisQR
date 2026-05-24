#!/bin/sh
set -eu

REPO="apeterson22/AegisQR"
VERSION="latest"
INSTALL_DIR="${HOME}/.local/opt/aegisqr"
BIN_DIR="${HOME}/.local/bin"
ARCHIVE=""
FORCE=0
SKIP_CHECKSUM=0

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Install a portable AegisQR CLI bundle from GitHub Releases or a local archive.

Options:
  --repo owner/name       GitHub repository to install from
  --version tag           Release tag to install (default: latest)
  --archive path-or-url   Install from a local archive or direct URL instead of GitHub Releases
  --install-dir path      Directory where the bundle will be extracted
  --bin-dir path          Directory that will receive an aegisqr symlink
  --force                 Replace an existing install directory
  --skip-checksum         Skip SHA256 verification for downloaded assets
  --help                  Show this help

Examples:
  ./packaging/install.sh
  ./packaging/install.sh --version v0.1.0
  ./packaging/install.sh --install-dir /media/USB/aegisqr --bin-dir /media/USB/bin
  ./packaging/install.sh --archive ./aegisqr-x86_64-unknown-linux-gnu.tar.gz --install-dir /tmp/aegisqr
EOF
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'error: required command not found: %s\n' "$1" >&2
    exit 1
  }
}

download() {
  url=$1
  out=$2
  if command -v curl >/dev/null 2>&1; then
    curl -L --fail --proto '=https' --tlsv1.2 -o "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -O "$out" "$url"
  else
    printf 'error: curl or wget is required to download release assets\n' >&2
    exit 1
  fi
}

sha256_check() {
  expected=$1
  file=$2
  if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$file" | awk '{print $1}')
  elif command -v shasum >/dev/null 2>&1; then
    actual=$(shasum -a 256 "$file" | awk '{print $1}')
  else
    printf 'error: sha256sum or shasum is required for checksum verification\n' >&2
    exit 1
  fi

  if [ "$actual" != "$expected" ]; then
    printf 'error: checksum mismatch for %s\n' "$file" >&2
    printf 'expected: %s\nactual:   %s\n' "$expected" "$actual" >&2
    exit 1
  fi
}

detect_target() {
  os=$(uname -s)
  arch=$(uname -m)

  case "$os" in
    Linux)
      case "$arch" in
        x86_64|amd64) printf '%s\n' "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) printf '%s\n' "aarch64-unknown-linux-gnu" ;;
        *) printf 'error: unsupported Linux architecture: %s\n' "$arch" >&2; exit 1 ;;
      esac
      ;;
    Darwin)
      case "$arch" in
        x86_64) printf '%s\n' "x86_64-apple-darwin" ;;
        arm64) printf '%s\n' "aarch64-apple-darwin" ;;
        *) printf 'error: unsupported macOS architecture: %s\n' "$arch" >&2; exit 1 ;;
      esac
      ;;
    *)
      printf 'error: install.sh supports Linux and macOS. Use install.ps1 on Windows.\n' >&2
      exit 1
      ;;
  esac
}

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)
      REPO=$2
      shift 2
      ;;
    --version)
      VERSION=$2
      shift 2
      ;;
    --archive)
      ARCHIVE=$2
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR=$2
      shift 2
      ;;
    --bin-dir)
      BIN_DIR=$2
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --skip-checksum)
      SKIP_CHECKSUM=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

need_cmd tar
need_cmd mkdir
need_cmd rm
need_cmd cp
need_cmd ln

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT HUP INT TERM

if [ -n "$ARCHIVE" ]; then
  ASSET_NAME=$(basename "$ARCHIVE")
  ASSET_PATH="$TMPDIR/$ASSET_NAME"
  case "$ARCHIVE" in
    http://*|https://*)
      download "$ARCHIVE" "$ASSET_PATH"
      ;;
    *)
      cp "$ARCHIVE" "$ASSET_PATH"
      ;;
  esac
else
  TARGET=$(detect_target)
  ASSET_NAME="aegisqr-${TARGET}.tar.gz"
  if [ "$VERSION" = "latest" ]; then
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
  else
    BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"
  fi
  ASSET_PATH="$TMPDIR/$ASSET_NAME"
  CHECKSUMS_PATH="$TMPDIR/SHA256SUMS"
  download "${BASE_URL}/${ASSET_NAME}" "$ASSET_PATH"
  if [ "$SKIP_CHECKSUM" -eq 0 ]; then
    download "${BASE_URL}/SHA256SUMS" "$CHECKSUMS_PATH"
    EXPECTED=$(awk -v asset="$ASSET_NAME" '$2 == asset { print $1 }' "$CHECKSUMS_PATH")
    if [ -z "$EXPECTED" ]; then
      printf 'error: did not find checksum entry for %s\n' "$ASSET_NAME" >&2
      exit 1
    fi
    sha256_check "$EXPECTED" "$ASSET_PATH"
  fi
fi

EXTRACT_DIR="$TMPDIR/extract"
mkdir -p "$EXTRACT_DIR"
tar -xzf "$ASSET_PATH" -C "$EXTRACT_DIR"

TOP_LEVEL_COUNT=$(find "$EXTRACT_DIR" -mindepth 1 -maxdepth 1 | awk 'END { print NR + 0 }')
if [ "$TOP_LEVEL_COUNT" -ne 1 ]; then
  printf 'error: expected exactly one top-level archive entry, found %s\n' "$TOP_LEVEL_COUNT" >&2
  exit 1
fi

BUNDLE_DIR=$(find "$EXTRACT_DIR" -mindepth 1 -maxdepth 1 -type d -name 'aegisqr-*')
if [ -z "$BUNDLE_DIR" ]; then
  printf 'error: expected extracted bundle directory named aegisqr-*\n' >&2
  exit 1
fi

if [ -e "$INSTALL_DIR" ] && [ "$FORCE" -ne 1 ]; then
  printf 'error: install directory already exists: %s (use --force to replace it)\n' "$INSTALL_DIR" >&2
  exit 1
fi

rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"
cp -R "$BUNDLE_DIR"/. "$INSTALL_DIR"/

if [ -n "$BIN_DIR" ]; then
  mkdir -p "$BIN_DIR"
  ln -sfn "$INSTALL_DIR/aegisqr" "$BIN_DIR/aegisqr"
fi

printf 'Installed AegisQR to %s\n' "$INSTALL_DIR"
if [ -n "$BIN_DIR" ]; then
  printf 'Linked aegisqr into %s\n' "$BIN_DIR"
fi
