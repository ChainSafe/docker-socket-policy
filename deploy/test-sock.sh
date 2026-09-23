#!/bin/sh
# Integration tests for docker-socket-policy with Unix socket group permissions.
# Tests that the proxy correctly handles group-restricted Docker sockets.
# proxy-granted runs with GID 2001 (in dockertest group) → should work
# proxy-denied runs with GID 3001 (not in dockertest group) → should fail with 403

set -e

PASS=0
FAIL=0

# Each proxy listens on its own Unix socket in the shared volume. The host part
# of the URL is ignored when curl is given --unix-socket, but must still parse.
GRANTED_SOCK="${PROXY_GRANTED_SOCK:-/sock/granted.sock}"
DENIED_SOCK="${PROXY_DENIED_SOCK:-/sock/denied.sock}"
URL="http://localhost"

# busybox wget cannot speak to a Unix socket, so the helpers below need curl.
# It is baked into Dockerfile.test rather than installed here, so a run does
# not depend on the Alpine CDN being reachable.
if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl is missing from the test image (see deploy/Dockerfile.test)"
  exit 1
fi

# Bound every request; curl has no default overall timeout.
TIMEOUT="--max-time 10 --connect-timeout 2"

# Both helpers take the target socket as their first argument, since this
# suite talks to two proxies with deliberately different socket permissions.
# curl exits non-zero when it cannot connect at all, which under `set -e` would
# abort the run instead of reporting a failed assertion, so connection failures
# are normalised to the synthetic status 000. This matters more here than in
# test.sh: the wait loops below poll sockets that do not exist yet.
# curl still prints %{http_code} when it exits non-zero, so the fallback only
# applies when it produced nothing at all.
get_status() {
  out=$(curl -s -o /dev/null -w '%{http_code}' $TIMEOUT --unix-socket "$1" "$2" 2>/dev/null || true)
  echo "${out:-000}"
}
post_json() {
  out=$(curl -s -o /dev/null -w '%{http_code}' $TIMEOUT --unix-socket "$1" \
    -X POST -H "Content-Type: application/json" -d "$2" "$3" 2>/dev/null || true)
  echo "${out:-000}"
}

check() {
  desc="$1"
  expected="$2"
  actual="$3"
  if [ "$actual" = "$expected" ]; then
    echo "  PASS: $desc"
    PASS=$((PASS+1))
  else
    echo "  FAIL: $desc (expected $expected, got $actual)"
    FAIL=$((FAIL+1))
  fi
}

echo ""
echo "=================================================="
echo "  Socket permissions integration tests"
echo "=================================================="
echo ""

# ─── Wait for proxies to be ready ──────────────────────

# proxy-granted needs the socat socket to be ready; poll _ping until 200
echo "Waiting for proxy-granted at $GRANTED_SOCK..."
i=0
while [ $i -lt 30 ]; do
  S=$(get_status "$GRANTED_SOCK" "$URL/_ping")
  if [ "$S" = "200" ]; then
    echo "proxy-granted ready."
    break
  fi
  printf "."
  sleep 1
  i=$((i + 1))
done
if [ $i -eq 30 ]; then
  echo ""
  # Fail here rather than letting every assertion come back 000, which reads
  # as a policy bug when the real cause is that the proxy never started.
  if [ ! -S "$GRANTED_SOCK" ]; then
    echo "ERROR: proxy-granted never created $GRANTED_SOCK — it failed to bind"
  else
    echo "ERROR: proxy-granted is listening but not answering after 30s"
  fi
  exit 1
fi

# proxy-denied: it listens fine but cannot reach the Docker socket, so it can
# never return 200. Wait for the listening socket itself to accept a request,
# whatever status that request comes back with.
echo "Waiting for proxy-denied at $DENIED_SOCK..."
i=0
while [ $i -lt 15 ]; do
  if [ "$(get_status "$DENIED_SOCK" "$URL/_ping")" != "000" ]; then
    echo "proxy-denied ready."
    break
  fi
  printf "."
  sleep 1
  i=$((i + 1))
done
if [ $i -eq 15 ]; then
  echo ""
  if [ ! -S "$DENIED_SOCK" ]; then
    echo "ERROR: proxy-denied never created $DENIED_SOCK — it failed to bind"
  else
    echo "ERROR: proxy-denied is listening but not answering after 15s"
  fi
  exit 1
fi
echo ""

# ─── proxy-granted: should work ───────────────────────

echo "--- proxy-granted (GID 2001, has group access) ---"

S=$(get_status "$GRANTED_SOCK" "$URL/_ping")
check "GET /_ping -> 200" "200" "$S"

S=$(get_status "$GRANTED_SOCK" "$URL/version")
check "GET /version -> 200" "200" "$S"

S=$(get_status "$GRANTED_SOCK" "$URL/containers/json")
check "GET /containers/json -> 200" "200" "$S"

# Allowed image create passes through to Docker (daemon returns 404, not 403)
S=$(post_json "$GRANTED_SOCK" '{"Image":"chainsafe/lodestar:beacon","Cmd":["--rcConfig","/data/config.yml"]}' "$URL/containers/create")
if [ "$S" = "201" ] || [ "$S" = "404" ]; then
  echo "  PASS: create container -> $S (not 403)"
  PASS=$((PASS+1))
else
  echo "  FAIL: create container (expected 201|404, got $S)"
  FAIL=$((FAIL+1))
fi

# ─── proxy-denied: should return 403 ──────────────────

echo ""
echo "--- proxy-denied (GID 3001, no group access) ---"

# The proxy starts and listens, but cannot connect to the Docker socket.
# Permission denied on the Unix socket returns 403 Forbidden.
S=$(get_status "$DENIED_SOCK" "$URL/_ping")
check "GET /_ping -> 403 (permission denied on socket)" "403" "$S"

S=$(get_status "$DENIED_SOCK" "$URL/version")
check "GET /version -> 403" "403" "$S"

S=$(get_status "$DENIED_SOCK" "$URL/containers/json")
check "GET /containers/json -> 403" "403" "$S"

S=$(post_json "$DENIED_SOCK" '{"Image":"chainsafe/lodestar:beacon","Cmd":["--rcConfig","/data/config.yml"]}' "$URL/containers/create")
check "POST /containers/create -> 403" "403" "$S"

# ─── Summary ──────────────────────────────────────────

echo ""
echo "============================================"
if [ "$FAIL" -eq 0 ]; then
  echo "  ALL $PASS TESTS PASSED"
else
  echo "  $PASS PASSED, $FAIL FAILED"
fi
echo "============================================"
exit "$FAIL"
