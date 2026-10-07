#!/usr/bin/env bash
# Prints a breaking-changes section for the release notes, or nothing if there are none.
# Usage: git log -z --format=%B <tag>..HEAD | release-notes.sh
# A commit is breaking by the `breaking` row of docs/release-versioning.md.
set -euo pipefail

BREAKING_SUBJECT='^[a-z]+(\([^)]*\))?!:'
FOOTER='^BREAKING[ -]CHANGE:'

entries=""
while IFS= read -r -d '' msg || [ -n "$msg" ]; do
	subject=${msg%%$'\n'*}
	footers=$(grep -E "$FOOTER" <<<"$msg" || true)
	if [[ $subject =~ $BREAKING_SUBJECT ]] || [ -n "$footers" ]; then
		entries+="- $subject"$'\n'
		if [ -n "$footers" ]; then
			entries+=$(sed -E -e "s/$FOOTER[[:space:]]*/  - /" <<<"$footers")$'\n'
		fi
	fi
done

if [ -n "$entries" ]; then
	printf '## ⚠️ Breaking changes\n\n%s' "$entries"
fi
