#!/bin/sh
# Integration tests for docker-socket-policy with Unix socket group permissions.
# Tests that the proxy correctly handles group-restricted Docker sockets.
# proxy-granted runs with GID 2001 (in dockertest group) → should work
# proxy-denied runs with GID 3001 (not in dockertest group) → should fail with 403

set -e

PASS=0
FAIL=0
GRANTED="${PROXY_GRANTED:-http://proxy-granted:2375}"
DENIED="${PROXY_DENIED:-http://proxy-denied:2375}"

get_status() {
  wget -qO /dev/null -S "$1" 2>&1 | grep -o 'HTTP/[0-9.]* [0-9]*' | tail -1 | awk '{print $2}'
}
post_json() {
  wget -qO /dev/null -S --post-data="$1" --header="Content-Type: application/json" "$2" 2>&1 | grep -o 'HTTP/[0-9.]* [0-9]*' | tail -1 | awk '{print $2}'
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
echo "Waiting for proxy-granted at $GRANTED..."
i=0
while [ $i -lt 30 ]; do
  S=$(get_status "$GRANTED/_ping")
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
  echo "WARNING: proxy-granted not ready after 30s"
fi

# proxy-denied: just verify TCP port is open (will always return 403 on requests)
host="${DENIED#http://}"
echo "Waiting for proxy-denied at $DENIED..."
i=0
while [ $i -lt 15 ]; do
  if nc -z "${host%:*}" "${host#*:}" 2>/dev/null; then
    echo "proxy-denied ready."
    break
  fi
  printf "."
  sleep 1
  i=$((i + 1))
done
if [ $i -eq 15 ]; then
  echo ""
  echo "WARNING: proxy-denied not responding after 15s"
fi
echo ""

# ─── proxy-granted: should work ───────────────────────

echo "--- proxy-granted (GID 2001, has group access) ---"

S=$(get_status "$GRANTED/_ping")
check "GET /_ping -> 200" "200" "$S"

S=$(get_status "$GRANTED/version")
check "GET /version -> 200" "200" "$S"

S=$(get_status "$GRANTED/containers/json")
check "GET /containers/json -> 200" "200" "$S"

# Allowed image create passes through to Docker (daemon returns 404, not 403)
S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Cmd":["--rcConfig","/data/config.yml"]}' "$GRANTED/containers/create")
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
S=$(get_status "$DENIED/_ping")
check "GET /_ping -> 403 (permission denied on socket)" "403" "$S"

S=$(get_status "$DENIED/version")
check "GET /version -> 403" "403" "$S"

S=$(get_status "$DENIED/containers/json")
check "GET /containers/json -> 403" "403" "$S"

S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Cmd":["--rcConfig","/data/config.yml"]}' "$DENIED/containers/create")
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
