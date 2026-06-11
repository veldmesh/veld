#!/bin/sh
# Veld install script — https://github.com/veldmesh/veld
# Usage: curl -fsSL https://get.veldmesh.io/install.sh | sh
#
# What this script does:
#   1. Detects OS and CPU architecture
#   2. Downloads the latest release archive from GitHub
#   3. Installs binaries to /usr/local/bin/
#   4. Applies setcap CAP_NET_ADMIN to veld-daemon (Linux)
#   5. Optionally installs systemd units and creates the veld system user
#
# Supported platforms: linux/amd64, linux/arm64, linux/armv7, linux/armv6,
#                      linux/mips, linux/mipsle, darwin/amd64, darwin/arm64
#
# The script is intentionally POSIX sh (not bash) to run on busybox (OpenWrt).

set -e

GITHUB_REPO="veldmesh/veld"
INSTALL_DIR="/usr/local/bin"
API_URL="https://api.github.com/repos/${GITHUB_REPO}/releases/latest"

# ── helpers ───────────────────────────────────────────────────────────────────

die()  { printf 'error: %s\n' "$1" >&2; exit 1; }
info() { printf '  %s\n' "$1"; }
need() { command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"; }

# ── platform detection ────────────────────────────────────────────────────────

detect_os() {
    case "$(uname -s)" in
        Linux)  echo "linux"  ;;
        Darwin) echo "darwin" ;;
        *)      die "unsupported OS: $(uname -s)" ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)    echo "amd64"  ;;
        aarch64|arm64)   echo "arm64"  ;;
        armv7*|armv7l)   echo "arm_v7" ;;
        armv6*|armv6l)   echo "arm_v6" ;;
        mips)            echo "mips"   ;;
        mipsel|mipsle)   echo "mipsle" ;;
        *)               die "unsupported architecture: $(uname -m)" ;;
    esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
PLATFORM="${OS}_${ARCH}"

# ── privilege check ───────────────────────────────────────────────────────────

if [ "$(id -u)" -ne 0 ]; then
    die "this script must be run as root (try: sudo sh install.sh)"
fi

# ── dependency check ──────────────────────────────────────────────────────────

need curl
need tar
need install

# ── resolve latest version ────────────────────────────────────────────────────

printf '\nFetching latest release info...\n'
VERSION=$(curl -fsSL "$API_URL" | grep '"tag_name"' | head -1 | cut -d'"' -f4)
[ -n "$VERSION" ] || die "could not determine latest release version"

TARBALL="veld-${VERSION}-${PLATFORM}.tar.gz"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}/${TARBALL}"

printf 'Installing Veld %s on %s/%s\n\n' "$VERSION" "$OS" "$ARCH"

# ── download and install ──────────────────────────────────────────────────────

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${TARBALL}..."
curl -fsSL --progress-bar -o "${TMPDIR}/${TARBALL}" "$DOWNLOAD_URL"

info "Extracting..."
tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

for bin in veld-daemon veld-coord veld; do
    info "Installing ${bin} -> ${INSTALL_DIR}/${bin}"
    install -m 0755 "${TMPDIR}/${bin}" "${INSTALL_DIR}/${bin}"
done

# ── Linux-specific setup ──────────────────────────────────────────────────────

if [ "$OS" = "linux" ]; then
    # Apply CAP_NET_ADMIN so the daemon can manage TUN without running as root.
    if command -v setcap >/dev/null 2>&1; then
        info "Setting cap_net_admin on veld-daemon..."
        setcap 'cap_net_admin+ep' "${INSTALL_DIR}/veld-daemon"
    else
        info "setcap not found — veld-daemon will require root or sudo"
    fi

    # Create a dedicated system user for the daemon.
    if ! id veld >/dev/null 2>&1; then
        info "Creating system user 'veld'..."
        useradd --system --no-create-home --shell /sbin/nologin veld 2>/dev/null \
            || adduser -S -H -s /sbin/nologin veld 2>/dev/null \
            || info "  (could not create user — run daemon as root or set up manually)"
    fi

    # Install systemd units if systemd is running.
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
        for unit in veld-coord.service veld-daemon.service; do
            src="${SCRIPT_DIR}/${unit}"
            dst="/etc/systemd/system/${unit}"
            if [ -f "$src" ] && [ ! -f "$dst" ]; then
                info "Installing ${unit}..."
                install -m 0644 "$src" "$dst"
            fi
        done

        systemctl daemon-reload
        info "systemd units installed. Enable with:"
        info "  sudo systemctl enable --now veld-daemon"
    fi

    # Create default config directory.
    mkdir -p /etc/veld
    chmod 0750 /etc/veld
fi

# ── finish ────────────────────────────────────────────────────────────────────

printf '\nDone! Veld %s installed to %s\n\n' "$VERSION" "$INSTALL_DIR"
printf 'Quick start:\n'
printf '  veld login           # authenticate with the coord server\n'
printf '  veld up              # start the VPN\n'
printf '  veld status          # check connection\n'
printf '\n'
