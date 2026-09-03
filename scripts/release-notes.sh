#!/usr/bin/env bash
# Prints the CHANGELOG.md section for one version (written by changesets),
# for use as GitHub release notes: scripts/release-notes.sh 0.2.0
set -euo pipefail
VERSION="${1:?version}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
awk -v v="## $VERSION" '
  $0 == v { on = 1; next }
  on && /^## / { exit }
  on { print }
' "$ROOT/CHANGELOG.md" | sed -e '1{/^$/d;}' -e '${/^$/d;}'
