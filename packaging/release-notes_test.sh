#!/bin/sh
# Tests release-notes.sh against a throwaway repository.
#
# Usage: release-notes_test.sh
set -eu

script=$(cd "$(dirname "$0")" && pwd)/release-notes.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

fail() {
    printf 'FAIL: %s\n--- output ---\n%s\n' "$1" "$out" >&2
    exit 1
}
has() { printf '%s\n' "$out" | grep -qxF -- "$1" || fail "missing line: $1"; }
lacks() { if printf '%s\n' "$out" | grep -qF -- "$1"; then fail "unexpected: $1"; fi; }

git init -q
git config user.name test
git config user.email test@example.com
commit() { git commit -q --allow-empty -m "$1"; }

commit "feat: first release"
git tag -a v1.0.0 -m v1.0.0
commit "feat(route): restore displaced routes (#46)"
commit "perf: faster lookups"
commit "fix: keep freed addresses last"
commit "feat!: drop the old config format"
commit "security: tighten coord auth"
commit "Security hardening: session crypto (#31)"
commit "coexist: correct the route advice (#45)"
commit "Bump actions/checkout from 4 to 7 (#29)"
commit "fix(deps): correct dependabot rule"
commit "ci: add a job"
commit "docs: fix a typo"
commit "chore: tidy"
commit "test(acl): more cases"
git tag -a v1.1.0 -m "Routes come back.

Second paragraph."
commit "fix: after the tag"
git tag v1.2.0
git tag -a v1.3.0 -m v1.3.0
commit "feat: in the release candidate"
git tag -a v1.4.0-rc1 -m v1.4.0-rc1
commit "fix: after the release candidate"
git tag -a v1.4.0 -m v1.4.0

out=$(sh "$script" v1.1.0)
has "## Highlights"
has "Routes come back."
has "Second paragraph."
has "## Features"
has "- Restore displaced routes (#46)"
has "- Faster lookups"
has "- **Breaking:** Drop the old config format"
has "## Fixes"
has "- Keep freed addresses last"
has "## Security"
has "- Tighten coord auth"
has "- Security hardening: session crypto (#31)"
has "## Other changes"
has "- Coexist: correct the route advice (#45)"
has "**Full Changelog**: https://github.com/veldmesh/veld/compare/v1.0.0...v1.1.0"
lacks "First release"
lacks "After the tag"
lacks "Bump"
lacks "dependabot"
lacks "Add a job"
lacks "Fix a typo"
lacks "Tidy"
lacks "More cases"

# The section order is fixed.
order=$(printf '%s\n' "$out" | grep '^## ' | tr '\n' '|')
[ "$order" = "## Highlights|## Features|## Fixes|## Security|## Other changes|" ] || fail "section order: $order"

# A lightweight tag has no Highlights; neither has a message that is just the tag name.
out=$(sh "$script" v1.2.0)
lacks "## Highlights"
has "- After the tag"
has "**Full Changelog**: https://github.com/veldmesh/veld/compare/v1.1.0...v1.2.0"
out=$(sh "$script" v1.3.0 v1.1.0)
lacks "## Highlights"
has "- After the tag"

# The first tag lists everything up to it and has no compare link.
out=$(sh "$script" v1.0.0)
has "- First release"
lacks "Full Changelog"

# Sections with no commits are left out.
out=$(sh "$script" v1.3.0 v1.2.0)
lacks "## Features"
lacks "## Fixes"

# A pre-release counts from the previous tag; the final release skips
# pre-release tags and covers the whole cycle.
out=$(sh "$script" v1.4.0-rc1)
has "- In the release candidate"
has "**Full Changelog**: https://github.com/veldmesh/veld/compare/v1.3.0...v1.4.0-rc1"
out=$(sh "$script" v1.4.0)
has "- In the release candidate"
has "- After the release candidate"
has "**Full Changelog**: https://github.com/veldmesh/veld/compare/v1.3.0...v1.4.0"

# GITHUB_REPOSITORY picks the compare link's repository.
out=$(GITHUB_REPOSITORY=example/fork sh "$script" v1.2.0)
has "**Full Changelog**: https://github.com/example/fork/compare/v1.1.0...v1.2.0"

# Unknown tags are errors.
if sh "$script" v9.9.9 2>/dev/null; then out=""; fail "accepted an unknown tag"; fi
if sh "$script" v1.1.0 v9.9.9 2>/dev/null; then out=""; fail "accepted an unknown previous tag"; fi

echo "release-notes.sh: all tests passed"
