#!/usr/bin/env bash
# Tests for release-latest-tag.sh: the newest strict vX.Y.Z tag merged into a ref.
# Plain bash, portable to macOS /bin/bash 3.2.
set -u

DIR=$(cd "$(dirname "$0")" && pwd)
SCRIPT="$DIR/release-latest-tag.sh"

TMP=$(mktemp -d "${TMPDIR:-/tmp}/release-latest-tag-test.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

# Keep the user's and the system's git config (tag.sort, versionsort.suffix, signing,
# init.defaultBranch) out of the throwaway repos and out of the script under test.
export GIT_CONFIG_NOSYSTEM=1
export GIT_CONFIG_GLOBAL=/dev/null
# Never walk up from $TMP into an enclosing repo.
export GIT_CEILING_DIRECTORIES="$TMP"

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

# unrunnable — prints why the script cannot be run, or nothing. Checked up front so a
# missing script never counts as the non-zero exit the failure case is looking for.
unrunnable() {
	if [ ! -f "$SCRIPT" ]; then
		echo "script not found: $SCRIPT"
	elif [ ! -x "$SCRIPT" ]; then
		echo "script not executable: $SCRIPT"
	fi
}

# gitc ARGS... — git with a fixed identity and no signing or hooks, so it runs in CI.
gitc() {
	git -c user.name=t -c user.email=t@t -c commit.gpgSign=false -c tag.gpgSign=false \
		-c core.hooksPath=/dev/null "$@"
}

# mkrepo NAME — creates an empty repo on branch main and prints its path.
mkrepo() {
	local repo="$TMP/$1"
	gitc init -q "$repo" && gitc -C "$repo" symbolic-ref HEAD refs/heads/main && echo "$repo"
}

# commit_tag REPO TAG... — makes an empty commit in REPO and puts every TAG on it.
commit_tag() {
	local repo=$1 t
	shift
	gitc -C "$repo" commit -q --allow-empty -m "c" || return 1
	for t in "$@"; do
		gitc -C "$repo" tag "$t" || return 1
	done
}

# run DIR ARGS... — runs the script (directly, so the executable bit and shebang are
# exercised) from DIR; sets rc, out, err.
run() {
	local dir=$1
	shift
	(cd "$dir" && "$SCRIPT" "$@") >"$TMP/out" 2>"$TMP/err"
	rc=$?
	out=$(cat "$TMP/out")
	err=$(cat "$TMP/err")
}

# expect NAME WANT DIR ARGS... — exits 0 and prints exactly WANT (empty = nothing).
expect() {
	local name=$1 want=$2 dir=$3 why
	shift 3
	why=$(unrunnable)
	if [ -n "$why" ]; then
		fail "$name" "want '$want', got $why"
		return
	fi
	run "$dir" "$@"
	if [ "$rc" -ne 0 ]; then
		fail "$name" "want '$want', got exit $rc: $err"
	elif [ "$out" != "$want" ]; then
		fail "$name" "want '$want', got '$out'"
	else
		pass "$name"
	fi
}

# setup_failed NAME — records a case whose throwaway repo could not be built.
setup_failed() {
	fail "$1" "want a throwaway git repo, got git failure"
}

# ─── no-tags ─────────────────────────────────────────
if r=$(mkrepo no-tags) && commit_tag "$r"; then
	expect no-tags "" "$r"
else
	setup_failed no-tags
fi

# ─── strict-only ─────────────────────────────────────
if r=$(mkrepo strict-only) && commit_tag "$r" v1.0.0-rc1 vfoo 1.2.3; then
	expect strict-only "" "$r"
else
	setup_failed strict-only
fi

# ─── version-sort ────────────────────────────────────
if r=$(mkrepo version-sort) && commit_tag "$r" v0.2.0 v0.10.0 v0.9.1; then
	expect version-sort v0.10.0 "$r"
else
	setup_failed version-sort
fi

# ─── ignores-prerelease ──────────────────────────────
if r=$(mkrepo ignores-prerelease) && commit_tag "$r" v0.3.0 && commit_tag "$r" v0.4.0-rc1; then
	expect ignores-prerelease v0.3.0 "$r"
else
	setup_failed ignores-prerelease
fi

# ─── merged-only ─────────────────────────────────────
if r=$(mkrepo merged-only) && commit_tag "$r" v0.1.0 &&
	gitc -C "$r" checkout -q -b side && commit_tag "$r" v9.9.9 &&
	gitc -C "$r" checkout -q main; then
	expect merged-only v0.1.0 "$r"
else
	setup_failed merged-only
fi

# ─── explicit-ref ────────────────────────────────────
# HEAD (main) sees only v0.1.0; the side branch also has v9.9.9.
if r=$(mkrepo explicit-ref) && commit_tag "$r" v0.1.0 &&
	gitc -C "$r" checkout -q -b side && commit_tag "$r" v9.9.9 &&
	gitc -C "$r" checkout -q main && commit_tag "$r" v0.2.0; then
	expect explicit-ref/side v9.9.9 "$r" side
	expect explicit-ref/older-tag v0.1.0 "$r" v0.1.0
else
	setup_failed explicit-ref
fi

# ─── git-failure ─────────────────────────────────────
# Outside any repo: git fails, so the script must fail rather than print nothing.
why=$(unrunnable)
if [ -n "$why" ]; then
	fail git-failure "want non-zero exit, got $why"
elif ! mkdir "$TMP/not-a-repo"; then
	fail git-failure "want an empty directory, got mkdir failure"
else
	GIT_DIR="$TMP/nonexistent" run "$TMP/not-a-repo"
	if [ "$rc" -eq 0 ]; then
		fail git-failure "want non-zero exit, got exit 0: '$out'"
	elif [ -n "$out" ]; then
		fail git-failure "want empty stdout, got '$out'"
	else
		pass git-failure
	fi
fi

# ─── bad-ref ─────────────────────────────────────────
# A REF that does not resolve: git fails, so the script must fail rather than print nothing.
if r=$(mkrepo bad-ref) && commit_tag "$r" v0.1.0; then
	run "$r" nonexistent-ref
	if [ -n "$(unrunnable)" ]; then
		fail bad-ref "want non-zero exit, got $(unrunnable)"
	elif [ "$rc" -eq 0 ]; then
		fail bad-ref "want non-zero exit, got exit 0: '$out'"
	elif [ -n "$out" ]; then
		fail bad-ref "want empty stdout, got '$out'"
	else
		pass bad-ref
	fi
else
	setup_failed bad-ref
fi

echo
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
