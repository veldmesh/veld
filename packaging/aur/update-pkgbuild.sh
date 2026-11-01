#!/bin/sh
# Rewrites the AUR PKGBUILD for one release: pkgver, pkgrel and both
# sha256sums arrays, taken from the release's checksums.txt.
#
# Usage: update-pkgbuild.sh <version-without-v> <checksums.txt> [PKGBUILD]
#
#   version        e.g. 0.2.0 (the release tag without the leading "v")
#   checksums.txt  sha256sum output, one "<sha256>  <filename>" per line
#   PKGBUILD       optional; defaults to the PKGBUILD next to this script
#
# If a .SRCINFO already exists next to the PKGBUILD it is regenerated with
# makepkg. It is never created here.
set -eu

die() {
    printf 'update-pkgbuild.sh: error: %s\n' "$*" >&2
    exit 1
}

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    die "usage: $0 <version-without-v> <checksums.txt> [PKGBUILD]"
fi

version=$1
sums=$2

case $version in
    [0-9]*) ;;
    *) die "invalid version '$version' (expected e.g. 0.2.0, without a leading v)" ;;
esac
case $version in
    *[!0-9A-Za-z._+]*)
        die "invalid version '$version' (pkgver allows only letters, digits, '.', '_' and '+'; no '-')" ;;
esac

script_dir=$(cd "$(dirname "$0")" && pwd)
pkgbuild=${3:-$script_dir/PKGBUILD}
pkgdir=$(dirname "$pkgbuild")

[ -f "$sums" ] || die "checksums file not found: $sums"
[ -f "$pkgbuild" ] || die "PKGBUILD not found: $pkgbuild"

# Sets $result to the sha256 of the given archive name, or dies.
# Accepts text-mode ("hash  name") and binary-mode ("hash *name") lines.
# Not run in a subshell, so die() stops the whole script.
lookup() {
    matches=$(awk -v want="$1" '
        { f = $2; sub(/^\*/, "", f); if (f == want) print $1 }' "$sums")
    count=$(printf '%s\n' "$matches" | grep -c . || true)
    case $count in
        0) die "no checksum for '$1' in $sums" ;;
        1) ;;
        *) die "more than one checksum for '$1' in $sums" ;;
    esac
    result=$(printf '%s\n' "$matches" | tr 'A-F' 'a-f')
    if [ "${#result}" -ne 64 ]; then
        die "checksum for '$1' is not 64 characters: '$result'"
    fi
    case $result in
        *[!0-9a-f]*) die "checksum for '$1' is not hex: '$result'" ;;
    esac
}

lookup "veld-v${version}-linux_amd64.tar.gz"
sha_x86_64=$result
lookup "veld-v${version}-linux_arm64.tar.gz"
sha_aarch64=$result

for key in '^pkgver=' '^pkgrel=' '^sha256sums_x86_64=' '^sha256sums_aarch64='; do
    grep -q "$key" "$pkgbuild" || die "no line matching $key in $pkgbuild"
done

tmp="$pkgbuild.new.$$"
trap 'rm -f "$tmp"' EXIT
sed \
    -e "s/^pkgver=.*/pkgver=$version/" \
    -e "s/^pkgrel=.*/pkgrel=1/" \
    -e "s/^sha256sums_x86_64=.*/sha256sums_x86_64=('$sha_x86_64')/" \
    -e "s/^sha256sums_aarch64=.*/sha256sums_aarch64=('$sha_aarch64')/" \
    "$pkgbuild" > "$tmp"
mv "$tmp" "$pkgbuild"

srcinfo="$pkgdir/.SRCINFO"
if [ -f "$srcinfo" ]; then
    command -v makepkg >/dev/null 2>&1 \
        || die ".SRCINFO exists but makepkg is not installed; cannot regenerate $srcinfo"
    (cd "$pkgdir" && makepkg --printsrcinfo > "$srcinfo.new") \
        || { rm -f "$srcinfo.new"; die "makepkg --printsrcinfo failed in $pkgdir"; }
    mv "$srcinfo.new" "$srcinfo"
fi

printf 'updated %s: pkgver=%s pkgrel=1 x86_64=%s aarch64=%s\n' \
    "$pkgbuild" "$version" "$sha_x86_64" "$sha_aarch64"
