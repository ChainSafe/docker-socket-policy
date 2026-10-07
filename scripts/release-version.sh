#!/usr/bin/env bash
# Derives the next release version from the commit messages since the latest tag.
# Usage: git log -z --format=%B <tag>..HEAD | release-version.sh <tag-or-empty>
# Prints bump=<major|minor|patch|release-as> and tag=vX.Y.Z. Rules: docs/release-versioning.md.
set -euo pipefail

SEMVER='^v?([0-9]+)\.([0-9]+)\.([0-9]+)$'
BREAKING_SUBJECT='^[a-z]+(\([^)]*\))?!:'
FEATURE_SUBJECT='^feat(\([^)]*\))?:'

die() {
	echo "release-version: $*" >&2
	exit 1
}

latest=${1:-v0.0.0}
[[ $latest =~ $SEMVER ]] || die "latest tag '$latest' is not vX.Y.Z"
major=$((10#${BASH_REMATCH[1]}))
minor=$((10#${BASH_REMATCH[2]}))
patch=$((10#${BASH_REMATCH[3]}))

# 0 = patch, 1 = minor, 2 = major (breaking)
level=0
release_as=""
release_as_found=0

while IFS= read -r -d '' msg || [ -n "$msg" ]; do
	subject=${msg%%$'\n'*}
	if [[ $subject =~ $BREAKING_SUBJECT ]] || grep -Eq '^BREAKING[ -]CHANGE:' <<<"$msg"; then
		level=2
	elif [[ $subject =~ $FEATURE_SUBJECT ]] && [ "$level" -lt 1 ]; then
		level=1
	fi
	# Input is newest first, so the first message with a Release-As line decides.
	if [ "$release_as_found" -eq 0 ]; then
		line=$(grep -i '^release-as:' <<<"$msg" | tail -n 1 || true)
		if [ -n "$line" ]; then
			release_as_found=1
			release_as=$(sed -e 's/^[^:]*://' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' <<<"$line")
		fi
	fi
done

if [ "$release_as_found" -eq 1 ]; then
	[[ $release_as =~ $SEMVER ]] || die "Release-As value '$release_as' is not vX.Y.Z"
	ra_major=$((10#${BASH_REMATCH[1]}))
	ra_minor=$((10#${BASH_REMATCH[2]}))
	ra_patch=$((10#${BASH_REMATCH[3]}))
	if [ "$ra_major" -gt "$major" ] ||
		{ [ "$ra_major" -eq "$major" ] && [ "$ra_minor" -gt "$minor" ]; } ||
		{ [ "$ra_major" -eq "$major" ] && [ "$ra_minor" -eq "$minor" ] && [ "$ra_patch" -gt "$patch" ]; }; then
		echo "bump=release-as"
		echo "tag=v$ra_major.$ra_minor.$ra_patch"
		exit 0
	fi
	die "Release-As v$ra_major.$ra_minor.$ra_patch is not greater than the latest tag v$major.$minor.$patch"
fi

if [ "$level" -eq 2 ] && [ "$major" -ge 1 ]; then
	echo "bump=major"
	echo "tag=v$((major + 1)).0.0"
elif [ "$level" -ge 1 ]; then
	echo "bump=minor"
	echo "tag=v$major.$((minor + 1)).0"
else
	echo "bump=patch"
	echo "tag=v$major.$minor.$((patch + 1))"
fi
