#!/usr/bin/env bash
# Tests for release-version.sh and release-notes.sh. The rules are defined in
# docs/release-versioning.md; case names match the rows of its rule table.
# Plain bash, portable to macOS /bin/bash 3.2.
set -u

DIR=$(cd "$(dirname "$0")" && pwd)
VERSION_SCRIPT="$DIR/release-version.sh"
NOTES_SCRIPT="$DIR/release-notes.sh"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/release-version-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

passed=0
failed=0

pass() {
	passed=$((passed + 1))
	echo "PASS: $1"
}

fail() {
	failed=$((failed + 1))
	echo "FAIL: $1 ($2)"
}

# feed MSG... — write each message NUL-terminated, newest first; no args = empty range.
feed() {
	if [ $# -gt 0 ]; then
		printf '%s\0' "$@"
	fi
}

# run SCRIPT ARG MSG... — runs SCRIPT with ARG, stdin from MSG...; sets rc, out, err.
run() {
	local script=$1 arg=$2
	shift 2
	feed "$@" >"$TMP/in"
	bash "$script" "$arg" <"$TMP/in" >"$TMP/out" 2>"$TMP/err"
	rc=$?
	out=$(cat "$TMP/out")
	err=$(cat "$TMP/err")
}

# expect NAME LATEST BUMP TAG MSG... — script exits 0 and prints exactly bump=BUMP and tag=TAG.
expect() {
	local name=$1 latest=$2 bump=$3 tag=$4
	shift 4
	if [ ! -f "$VERSION_SCRIPT" ]; then
		fail "$name" "want bump=$bump tag=$tag, got script not found: $VERSION_SCRIPT"
		return
	fi
	run "$VERSION_SCRIPT" "$latest" "$@"
	local want
	want=$(printf 'bump=%s\ntag=%s' "$bump" "$tag")
	if [ "$rc" -ne 0 ]; then
		fail "$name" "want bump=$bump tag=$tag, got exit $rc: $err"
	elif [ "$out" != "$want" ]; then
		fail "$name" "want $(echo "$want" | tr '\n' ' '), got $(echo "$out" | tr '\n' ' ')"
	else
		pass "$name"
	fi
}

# expect_error NAME LATEST MSG... — script exits non-zero and explains why on stderr.
expect_error() {
	local name=$1 latest=$2
	shift 2
	if [ ! -f "$VERSION_SCRIPT" ]; then
		fail "$name" "want non-zero exit with stderr message, got script not found: $VERSION_SCRIPT"
		return
	fi
	run "$VERSION_SCRIPT" "$latest" "$@"
	if [ "$rc" -eq 0 ]; then
		fail "$name" "want non-zero exit, got exit 0: $(echo "$out" | tr '\n' ' ')"
	elif [ -z "$err" ]; then
		fail "$name" "want a message on stderr, got exit $rc with empty stderr"
	else
		pass "$name"
	fi
}

# expect_notes NAME NEEDLE... -- MSG... — notes exit 0 and contain every NEEDLE.
expect_notes() {
	local name=$1
	shift
	local needles=()
	while [ $# -gt 0 ] && [ "$1" != "--" ]; do
		needles[${#needles[@]}]=$1
		shift
	done
	shift
	if [ ! -f "$NOTES_SCRIPT" ]; then
		fail "$name" "want breaking-changes section, got script not found: $NOTES_SCRIPT"
		return
	fi
	run "$NOTES_SCRIPT" "" "$@"
	if [ "$rc" -ne 0 ]; then
		fail "$name" "want exit 0, got exit $rc: $err"
		return
	fi
	local n
	for n in "${needles[@]}"; do
		case "$out" in
		*"$n"*) ;;
		*)
			fail "$name" "want output containing '$n', got '$out'"
			return
			;;
		esac
	done
	pass "$name"
}

# expect_no_notes NAME MSG... — notes exit 0 and print nothing.
expect_no_notes() {
	local name=$1
	shift
	if [ ! -f "$NOTES_SCRIPT" ]; then
		fail "$name" "want empty output, got script not found: $NOTES_SCRIPT"
		return
	fi
	run "$NOTES_SCRIPT" "" "$@"
	if [ "$rc" -ne 0 ]; then
		fail "$name" "want exit 0, got exit $rc: $err"
	elif [ -n "$out" ]; then
		fail "$name" "want empty output, got '$out'"
	else
		pass "$name"
	fi
}

NL=$'\n'

# ─── other ───────────────────────────────────────────
expect other v0.2.25 patch v0.2.26 "fix: x"
expect other/non-conventional v0.2.25 patch v0.2.26 "Update README"
expect other/docs-chore-test v0.2.25 patch v0.2.26 "docs: a" "chore: b" "test: c" "spec: d" "ci: e"
expect other/empty-range v0.2.25 patch v0.2.26

# ─── feature ─────────────────────────────────────────
expect feature v0.2.25 minor v0.3.0 "feat: x"
expect feature/scoped v0.2.25 minor v0.3.0 "feat(ts): x"
expect feature/body-bullet-under-fix v0.2.25 patch v0.2.26 "fix: x (#1)${NL}${NL}* feat: x${NL}* fix: y"
expect feature/mid-line v0.2.25 patch v0.2.26 "fix: handle feat: prefix"
expect feature/highest-wins v0.2.25 minor v0.3.0 "fix: a" "feat: b" "docs: c"
expect feature/above-1.0 v1.4.2 minor v1.5.0 "feat: x"

# ─── breaking ────────────────────────────────────────
expect breaking v0.2.25 minor v0.3.0 "fix!: x"
expect breaking/scoped-feat v0.2.25 minor v0.3.0 "feat(rs)!: x"
expect breaking/footer-under-fix v0.2.25 minor v0.3.0 "fix: x${NL}${NL}BREAKING CHANGE: y is gone"
expect breaking/hyphen-footer v0.2.25 minor v0.3.0 "fix: x${NL}${NL}BREAKING-CHANGE: y is gone"
expect breaking/footer-mid-line v0.2.25 patch v0.2.26 "fix: x${NL}${NL}This is not a BREAKING CHANGE: y"
expect breaking/above-1.0 v1.4.2 major v2.0.0 "fix!: x"
expect breaking/highest-wins v1.4.2 major v2.0.0 "fix: a" "fix!: b" "feat: c"

# ─── no-tag ──────────────────────────────────────────
expect no-tag "" patch v0.0.1 "fix: x"
expect no-tag/feature "" minor v0.1.0 "feat: x"

# ─── release-as ──────────────────────────────────────
expect release-as v0.2.26 release-as v0.3.0 "fix: x${NL}${NL}Release-As: v0.3.0"
expect release-as/lowercase-no-v v0.2.26 release-as v0.3.0 "fix: x${NL}${NL}release-as: 0.3.0"
expect release-as/whitespace v0.2.26 release-as v0.3.0 "fix: x${NL}${NL}Release-As:    v0.3.0   "
expect release-as/overrides-breaking v0.2.26 release-as v0.3.0 "fix!: x${NL}${NL}Release-As: v0.3.0"
expect release-as/numeric-compare v0.9.3 release-as v0.10.0 "fix: x${NL}${NL}Release-As: v0.10.0"
expect_error release-as/not-greater v0.2.26 "fix: x${NL}${NL}Release-As: v0.2.26"
expect_error release-as/malformed v0.2.26 "fix: x${NL}${NL}Release-As: 0.3"
expect release-as/newest-wins v0.2.26 release-as v0.4.0 \
	"fix: b${NL}${NL}Release-As: v0.4.0" \
	"fix: a${NL}${NL}Release-As: v0.3.0"
expect release-as/newest-wins-in-message v0.2.26 release-as v0.4.0 \
	"fix: a${NL}${NL}Release-As: v0.3.0${NL}Release-As: v0.4.0"
expect release-as/recovery v0.2.26 release-as v0.3.0 \
	"fix: b${NL}${NL}Release-As: v0.3.0" \
	"fix: a${NL}${NL}Release-As: 0.3"
expect_error release-as/newest-malformed v0.2.26 \
	"fix: b${NL}${NL}Release-As: 0.3" \
	"fix: a${NL}${NL}Release-As: v0.3.0"

# ─── notes ───────────────────────────────────────────
expect_notes notes/breaking \
	"Breaking changes" "fix: x" "y is gone" -- \
	"docs: a" "fix: x${NL}${NL}BREAKING CHANGE: y is gone" "feat: b"
expect_notes notes/breaking-subject \
	"Breaking changes" "feat(rs)!: drop z" -- \
	"feat(rs)!: drop z"
expect_no_notes notes/none "fix: a" "feat: b${NL}${NL}* feat!: bullet only"
expect_no_notes notes/empty-range

echo
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
