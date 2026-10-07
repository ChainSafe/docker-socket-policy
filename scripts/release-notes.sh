#!/usr/bin/env bash
# Prints a breaking-changes section for the release notes, or nothing if there are none.
# Usage: git log -z --format=%B <tag>..HEAD | release-notes.sh
# A commit is breaking by the `breaking` row of docs/release-versioning.md.
set -euo pipefail

BREAKING_SUBJECT='^[A-Za-z]+(\([^)]*\))?!:'
FOOTER='^BREAKING[ -]CHANGE:'
TOKEN='^[A-Za-z-]+: '

# footers MSG — prints each BREAKING CHANGE footer as a "  - " bullet. A footer runs until
# a blank line, the next footer token line, or the end of the message.
footers() {
	local line text in_footer=0 started=0
	while IFS= read -r line; do
		line=${line%$'\r'}
		if [[ $line =~ $FOOTER ]]; then
			in_footer=1
			started=0
			text=${line#BREAKING?CHANGE:}
		elif [ "$in_footer" -eq 1 ] && [ -n "$line" ] && ! [[ $line =~ $TOKEN ]]; then
			text=$line
		else
			in_footer=0
			continue
		fi
		text=${text#"${text%%[![:space:]]*}"}
		[ -n "$text" ] || continue
		if [ "$started" -eq 0 ]; then
			echo "  - $text"
			started=1
		else
			echo "    $text"
		fi
	done <<<"$1"
}

entries=""
while IFS= read -r -d '' msg || [ -n "$msg" ]; do
	subject=${msg%%$'\n'*}
	subject=${subject%$'\r'}
	if [[ $subject =~ $BREAKING_SUBJECT ]] || grep -Eq "$FOOTER" <<<"$msg"; then
		entries+="- $subject"$'\n'
		body=$(footers "$msg")
		if [ -n "$body" ]; then
			entries+="$body"$'\n'
		fi
	fi
done

if [ -n "$entries" ]; then
	printf '## ⚠️ Breaking changes\n\n%s' "$entries"
fi
