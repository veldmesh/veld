#!/bin/sh
# Veld install script — https://github.com/veldmesh/veld
# Usage: curl -fsSL https://get.veldmesh.io/install.sh | sh
#
# What this script does:
#   1. Detects OS and CPU architecture
#   2. Downloads the latest release archive from GitHub and verifies it
#      against the release's checksums.txt
#   3. Installs binaries to /usr/local/bin/
#   4. Creates the veld system user and, on Linux, lets only root and the
#      veld group run veld-daemon, with CAP_NET_ADMIN
#   5. Optionally installs systemd units
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
# The tag goes into a URL and file names: accept only a plain version.
printf '%s' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$' \
    || die "unexpected release tag: $VERSION"

TARBALL="veld-${VERSION}-${PLATFORM}.tar.gz"
RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${VERSION}"
DOWNLOAD_URL="${RELEASE_URL}/${TARBALL}"

if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    die "required tool not found: sha256sum or shasum"
fi

printf 'Installing Veld %s on %s/%s\n\n' "$VERSION" "$OS" "$ARCH"

# ── download and install ──────────────────────────────────────────────────────

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

info "Downloading ${TARBALL}..."
curl -fsSL --progress-bar -o "${TMPDIR}/${TARBALL}" "$DOWNLOAD_URL"

info "Verifying checksum..."
curl -fsSL -o "${TMPDIR}/checksums.txt" "${RELEASE_URL}/checksums.txt" \
    || die "could not download checksums.txt"
WANT=$(awk -v f="$TARBALL" '$2 == f || $2 == "*" f { print $1 }' "${TMPDIR}/checksums.txt")
[ -n "$WANT" ] || die "${TARBALL} is not listed in checksums.txt"
GOT=$(sha256 "${TMPDIR}/${TARBALL}")
[ "$GOT" = "$WANT" ] || die "checksum mismatch for ${TARBALL}"

info "Extracting..."
tar -xzf "${TMPDIR}/${TARBALL}" -C "$TMPDIR"

for bin in veld-daemon veld-coord veld; do
    info "Installing ${bin} -> ${INSTALL_DIR}/${bin}"
    install -m 0755 "${TMPDIR}/${bin}" "${INSTALL_DIR}/${bin}"
done

# ── Linux-specific setup ──────────────────────────────────────────────────────

if [ "$OS" = "linux" ]; then
    # Create a dedicated system user for the daemon.
    if ! id veld >/dev/null 2>&1; then
        info "Creating system user 'veld'..."
        useradd --system --user-group --no-create-home --shell /sbin/nologin veld 2>/dev/null \
            || adduser -S -H -G veld -s /sbin/nologin veld 2>/dev/null \
            || { addgroup -S veld 2>/dev/null && adduser -S -H -G veld -s /sbin/nologin veld 2>/dev/null; } \
            || info "  (could not create user — run daemon as root or set up manually)"
    fi

    # CAP_NET_ADMIN lets veld-daemon manage TUN devices and routes, so a
    # user who can run it can reroute all of this host's traffic. File
    # capabilities apply to whoever runs the binary: grant them only once
    # the binary is restricted to root and the veld group. The systemd unit
    # grants the capability itself and does not need this.
    if VELD_GROUP=$(id -gn veld 2>/dev/null); then
        chown "root:${VELD_GROUP}" "${INSTALL_DIR}/veld-daemon"
        chmod 0750 "${INSTALL_DIR}/veld-daemon"
        if command -v setcap >/dev/null 2>&1; then
            info "Setting cap_net_admin on veld-daemon (root and group ${VELD_GROUP} only)..."
            setcap 'cap_net_admin+ep' "${INSTALL_DIR}/veld-daemon"
            info "  Add trusted users to it with: usermod -aG ${VELD_GROUP} <user>"
        fi
    else
        setcap -r "${INSTALL_DIR}/veld-daemon" 2>/dev/null || true
        info "No veld user — veld-daemon will require root or sudo"
    fi

    # Install systemd units if systemd is running. The unit files are only
    # taken from next to this script; when it is piped into sh there is no
    # such directory (and the current directory must not be trusted).
    SCRIPT_DIR=""
    if [ -f "$0" ]; then
        SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    fi
    if [ -n "$SCRIPT_DIR" ] && command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
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
    if [ -n "${VELD_GROUP:-}" ]; then
        chgrp "$VELD_GROUP" /etc/veld
    fi
fi

# ── finish ────────────────────────────────────────────────────────────────────

printf '\nDone! Veld %s installed to %s\n\n' "$VERSION" "$INSTALL_DIR"
printf 'Quick start:\n'
printf '  veld login           # authenticate with the coord server\n'
printf '  veld up              # start the VPN\n'
printf '  veld status          # check connection\n'
printf '\n'
