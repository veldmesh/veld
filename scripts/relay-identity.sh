#!/bin/sh
# veld-relay identity provisioning — https://github.com/veldmesh/veld
#
# Generates (or loads) the veld-relay identity keystore at
# /etc/veld/relay-identity.json, owned by the dedicated veld-relay user with
# mode 0600, and prints the relay's X25519 public key to stdout.
#
# Idempotent: if the keystore already exists it is loaded — never rotated —
# and the same public key is printed. Safe to re-run at any time.
#
# Usage:
#   sudo make relay-identity        (from a source checkout)
#   sudo scripts/relay-identity.sh
#
# Why this exists: peers pin the relay's X25519 key (coord.relay_x25519) and
# address (coord.relay_addr) in their own configs — the coord server does not
# distribute them. The identity must be provisioned before the systemd
# service first starts: deploy/veld-relay.service runs as the unprivileged
# veld-relay user and expects a readable keystore to already exist.
#
# See docs/RELAY.md for the full deployment guide.

set -e

IDENTITY_FILE="/etc/veld/relay-identity.json"
RELAY_USER="veld-relay"
RELAY_GROUP="veld-relay"

die()  { printf 'error: %s\n' "$1" >&2; exit 1; }
info() { printf '  %s\n' "$1"; }

[ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo make relay-identity)"

# Locate the veld-relay binary: an installed release first, then a local
# build. Override with VELD_RELAY_BIN if needed.
RELAY_BIN="${VELD_RELAY_BIN:-}"
if [ -z "$RELAY_BIN" ]; then
    if [ -x /usr/local/bin/veld-relay ]; then
        RELAY_BIN=/usr/local/bin/veld-relay
    elif [ -x ./bin/veld-relay ]; then
        RELAY_BIN=./bin/veld-relay
    elif command -v veld-relay >/dev/null 2>&1; then
        RELAY_BIN="$(command -v veld-relay)"
    else
        die "veld-relay binary not found — install it to /usr/local/bin/ or run 'make veld-relay'"
    fi
fi

# Dedicated unprivileged user for the service (User= in veld-relay.service).
if ! id "$RELAY_USER" >/dev/null 2>&1; then
    info "Creating system user '$RELAY_USER'..."
    useradd --system --no-create-home --shell /sbin/nologin "$RELAY_USER" 2>/dev/null \
        || adduser -S -H -s /sbin/nologin "$RELAY_USER" 2>/dev/null \
        || die "could not create system user '$RELAY_USER' — create it manually and re-run"
fi

mkdir -p /etc/veld
# The service user must be able to traverse /etc/veld to reach its keystore
# (install.sh leaves the dir 0750 root:root, which would block it). Private
# material is protected by the 0600 file mode, as in /etc/ssh.
chmod 0755 /etc/veld

if [ -f "$IDENTITY_FILE" ]; then
    info "Loading existing identity at $IDENTITY_FILE"
else
    info "Generating new identity at $IDENTITY_FILE"
fi

# -gen-identity is idempotent: loads an existing keystore or creates one,
# prints the base64 X25519 public key, and exits.
PUBKEY="$("$RELAY_BIN" -gen-identity -identity "$IDENTITY_FILE")" \
    || die "veld-relay -gen-identity failed — is $RELAY_BIN a current build?"

chown "$RELAY_USER:$RELAY_GROUP" "$IDENTITY_FILE" 2>/dev/null \
    || chown "$RELAY_USER" "$IDENTITY_FILE"
chmod 0600 "$IDENTITY_FILE"

printf '\n'
printf 'Relay identity:  %s (owner %s, mode 0600)\n' "$IDENTITY_FILE" "$RELAY_USER"
printf 'Relay X25519 public key (set as coord.relay_x25519 on peers):\n'
printf '%s\n' "$PUBKEY"
printf '\n'
info "Share this key plus the relay's public address (host:port of -listen) with the peers that should use it."
info "Then: sudo systemctl enable --now veld-relay  (see docs/RELAY.md)"
