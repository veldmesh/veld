#!/bin/sh
# Prints the GitHub release notes for one tag as Markdown: an optional
# Highlights paragraph taken from the annotated tag's message, then one line
# per commit since the previous tag, grouped by its conventional-commit type.
#
# Usage: release-notes.sh <tag> [previous-tag]
#
#   tag           e.g. v0.3.0 (must exist; annotate it with `git tag -a` to
#                 add a Highlights paragraph)
#   previous-tag  optional; defaults to the newest v* tag before <tag> (for a
#                 final release, the newest final one: pre-release tags such
#                 as v0.3.0-rc1 are skipped, so the notes cover the whole
#                 cycle). With no previous tag every commit up to <tag> is
#                 listed.
#
# Only commit subjects are used. feat/perf go under Features, fix under Fixes,
# sec/security (or a subject starting with "Security") under Security, any
# other subject under Other changes. Dependency bumps ("Bump ..." and any
# "<type>(deps):" commit) and ci/chore/build/test/style/refactor/docs/revert
# commits are left out. A "!" after the type marks the line as breaking.
#
# Needs the full history and the real tag objects (actions/checkout with
# fetch-depth: 0, then `git fetch --force --tags`).
set -eu

die() {
    printf 'release-notes.sh: error: %s\n' "$*" >&2
    exit 1
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
    die "usage: release-notes.sh <tag> [previous-tag]"
fi

tag=$1
git rev-parse -q --verify "refs/tags/$tag" >/dev/null || die "no such tag: $tag"

if [ "$#" -eq 2 ]; then
    prev=$2
    git rev-parse -q --verify "refs/tags/$prev" >/dev/null || die "no such tag: $prev"
else
    case $tag in
    *-*) prev=$(git describe --tags --abbrev=0 --match 'v*' "$tag^" 2>/dev/null || true) ;;
    *) prev=$(git describe --tags --abbrev=0 --match 'v*' --exclude '*-*' "$tag^" 2>/dev/null || true) ;;
    esac
fi

if [ "$(git cat-file -t "refs/tags/$tag")" = tag ]; then
    highlights=$(git tag -l --format='%(contents:subject)%0a%0a%(contents:body)' "$tag" |
        sed '/^-----BEGIN PGP SIGNATURE-----$/,$d; /^-----BEGIN SSH SIGNATURE-----$/,$d')
    # A bare "v0.3.0" message says nothing; skip it.
    if [ -n "$(printf '%s' "$highlights" | tr -d '[:space:]')" ] &&
        [ "$(printf '%s' "$highlights" | tr -d '[:space:]')" != "$tag" ]; then
        printf '## Highlights\n\n%s\n\n' "$highlights"
    fi
fi

if [ -n "$prev" ]; then
    range="$prev..$tag"
else
    range=$tag
fi

git log --no-merges --format='%s' "$range" | awk '
{
    s = $0
    if (s ~ /^Bump / || s ~ /^[A-Za-z]+\(deps\)!?: /) next
    type = ""; rest = s; breaking = 0
    if (match(s, /^[A-Za-z]+(\([^)]*\))?!?: /)) {
        type = tolower(substr(s, 1, RLENGTH))
        sub(/[(!:].*/, "", type)
        breaking = substr(s, 1, RLENGTH) ~ /!: $/
        rest = substr(s, RLENGTH + 1)
    }
    if (type ~ /^(ci|chore|build|test|tests|style|refactor|docs|revert)$/) next
    if (type == "feat" || type == "perf") g = 1
    else if (type == "fix") g = 2
    else if (type == "sec" || type == "security") g = 3
    else {
        rest = s
        g = (tolower(s) ~ /^security/) ? 3 : 4
    }
    rest = toupper(substr(rest, 1, 1)) substr(rest, 2)
    if (breaking) rest = "**Breaking:** " rest
    lines[g] = lines[g] "- " rest "\n"
}
END {
    title[1] = "Features"; title[2] = "Fixes"; title[3] = "Security"; title[4] = "Other changes"
    for (g = 1; g <= 4; g++)
        if (g in lines) printf "## %s\n\n%s\n", title[g], lines[g]
}'

if [ -n "$prev" ]; then
    printf '**Full Changelog**: https://github.com/%s/compare/%s...%s\n' \
        "${GITHUB_REPOSITORY:-veldmesh/veld}" "$prev" "$tag"
fi
