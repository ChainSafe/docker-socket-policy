#!/usr/bin/env bash
# Prints the newest strict vX.Y.Z tag merged into REF (default HEAD), or nothing if
# there is none. Fails if git fails. Rules: docs/release-versioning.md
set -euo pipefail

REF=${1:-HEAD}

tags=$(git tag --list --merged "$REF" --sort=-v:refname)
printf '%s\n' "$tags" | grep -E -m1 '^v[0-9]+\.[0-9]+\.[0-9]+$' || true
