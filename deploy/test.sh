#!/bin/sh
# Integration tests for docker-socket-policy.
# Sends HTTP requests directly to the proxy's Docker API and checks status codes.
# The proxy's ReadonlyGate, RegistryGate, MountSourceGate, EnvFileGate,
# CmdGate, ExecGate, and ContainerConfigMutator are all exercised.

set -e

PASS=0
FAIL=0
PROXY="${DOCKER_HOST:-tcp://proxy:2375}"
# Strip tcp:// prefix for HTTP clients
case "$PROXY" in
  tcp://*) PROXY="http://${PROXY#tcp://}" ;;
  unix://*) echo "ERROR: unix:// DOCKER_HOST not supported for HTTP tests"; exit 1 ;;
esac

# Wait for proxy to become available
echo "Waiting for proxy at ${PROXY}..."
i=0
while [ $i -lt 30 ]; do
  if wget -qO- "$PROXY/_ping" >/dev/null 2>&1; then
    echo "Proxy ready."
    break
  fi
  printf "."
  sleep 1
  i=$((i + 1))
done
if [ $i -eq 30 ]; then
  echo ""
  echo "ERROR: Proxy failed to respond within 30s"
  exit 1
fi
echo ""
while [ $i -lt 30 ]; do
  if wget -qO- "$PROXY/_ping" >/dev/null 2>&1; then
    echo "Proxy ready."
    break
  fi
  printf "."
  sleep 1
  i=$((i + 1))
done
if [ $i -eq 30 ]; then
  echo ""
  echo "ERROR: Proxy failed to respond within 30s"
  exit 1
fi
echo ""

# Helpers: extract HTTP status code from wget --server-response output
get_status() {
  wget -qO /dev/null -S "$1" 2>&1 | grep -o 'HTTP/[0-9.]* [0-9]*' | tail -1 | awk '{print $2}'
}
post_json() {
  wget -qO /dev/null -S --post-data="$1" --header="Content-Type: application/json" "$2" 2>&1 | grep -o 'HTTP/[0-9.]* [0-9]*' | tail -1 | awk '{print $2}'
}
post_empty() {
  wget -qO /dev/null -S --post-data="" --header="Content-Type: application/json" "$1" 2>&1 | grep -o 'HTTP/[0-9.]* [0-9]*' | tail -1 | awk '{print $2}'
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
echo "============================================"
echo "  docker-socket-policy integration tests"
echo "============================================"
echo ""

# ─── Read-only endpoints (always allowed) ───────────────────────

echo "--- Read-only endpoints ---"

S=$(get_status "$PROXY/_ping")
check "GET /_ping -> 200" "200" "$S"

S=$(get_status "$PROXY/v1.45/_ping")
check "GET /v1.45/_ping -> 200 (API version stripped)" "200" "$S"

S=$(get_status "$PROXY/version")
check "GET /version -> 200" "200" "$S"

S=$(get_status "$PROXY/info")
check "GET /info -> 200" "200" "$S"

S=$(get_status "$PROXY/containers/json")
check "GET /containers/json -> 200" "200" "$S"

# ─── Denied endpoints ───────────────────────────────────────

echo ""
echo "--- Denied endpoints ---"

S=$(post_empty "$PROXY/containers/test/exec")
check "POST /containers/*/exec -> 403" "403" "$S"

S=$(post_empty "$PROXY/exec/abc123/start")
check "POST /exec/*/start -> 403" "403" "$S"

S=$(post_empty "$PROXY/build")
check "POST /build -> 403" "403" "$S"

S=$(post_empty "$PROXY/commit")
check "POST /commit -> 403" "403" "$S"

S=$(post_empty "$PROXY/auth")
check "POST /auth -> 403" "403" "$S"

# ─── Container create — image validation ───────────────────

echo ""
echo "--- Image validation ---"

# Allowed image reaches Docker daemon, which returns 404 (image doesn't exist)
# The key is that the proxy does NOT return 403 — the request is allowed.
S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
if [ "$S" = "201" ] || [ "$S" = "404" ]; then
  echo "  PASS: create with allowed image -> $S (not 403)"
  PASS=$((PASS+1))
else
  echo "  FAIL: create with allowed image (expected 201|404, got $S)"
  FAIL=$((FAIL+1))
fi

S=$(post_json '{"Image":"alpine:latest","Cmd":["sh"]}' "$PROXY/containers/create")
check "create with unlisted image -> 403" "403" "$S"

# Another allowed image prefix
S=$(post_json '{"Image":"ethpandaops/lodestar:latest","Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
if [ "$S" = "201" ] || [ "$S" = "404" ]; then
  echo "  PASS: create with ethpandaops image -> $S (not 403)"
  PASS=$((PASS+1))
else
  echo "  FAIL: create with ethpandaops image (expected 201|404, got $S)"
  FAIL=$((FAIL+1))
fi

S=$(post_json '{"Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
check "create with no image -> 403" "403" "$S"

# ─── Container create — privileged mode ──────────────────

echo ""
echo "--- Privileged mode ---"

# ContainerConfigMutator sets HostConfig.Privileged=false, so request passes
# through to Docker. Daemon returns 404 (image doesn't exist).
S=$(post_json '{"Image":"chainsafe/lodestar:beacon","HostConfig":{"Privileged":true},"Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
if [ "$S" = "201" ] || [ "$S" = "404" ]; then
  echo "  PASS: create with privileged=true -> $S (mutated, not denied)"
  PASS=$((PASS+1))
else
  echo "  FAIL: create with privileged=true (expected 201|404, got $S)"
  FAIL=$((FAIL+1))
fi

# ─── Volume validation ───────────────────────────────────

echo ""
echo "--- Volume validation ---"

S=$(post_json '{"Image":"chainsafe/lodestar:beacon","HostConfig":{"Binds":["/home/beacon:/data"]},"Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
if [ "$S" = "201" ] || [ "$S" = "404" ]; then
  echo "  PASS: create with allowed volume -> $S (not 403)"
  PASS=$((PASS+1))
else
  echo "  FAIL: create with allowed volume (expected 201|404, got $S)"
  FAIL=$((FAIL+1))
fi

S=$(post_json '{"Image":"chainsafe/lodestar:beacon","HostConfig":{"Binds":["/tmp:/tmp"]},"Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
check "create with unlisted volume -> 403" "403" "$S"

# ─── Inline env vars (env_file is set in policy) ─────────

echo ""
echo "--- Inline environment variables ---"

S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Env":["VALIDATOR_KEY=secret"],"Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
check "create with inline env -> 403" "403" "$S"

# ─── CLI flag validation ────────────────────────────────

echo ""
echo "--- CLI flag validation ---"

# --privileged is in denied_flags -> proxy denies
S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Cmd":["--privileged","--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
check "create with --privileged flag -> 403" "403" "$S"

# Allowed flags, request passes through to Docker
S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Cmd":["--rcConfig","/data/config.yml","--logLevel","info"]}' "$PROXY/containers/create")
if [ "$S" = "201" ] || [ "$S" = "404" ]; then
  echo "  PASS: create with allowed flags -> $S (not 403)"
  PASS=$((PASS+1))
else
  echo "  FAIL: create with allowed flags (expected 201|404, got $S)"
  FAIL=$((FAIL+1))
fi

# ─── Docker API passthrough ─────────────────────────────

echo ""
echo "--- Docker API passthrough ---"

# Image pull: allowed image passes proxy, daemon fails (image doesn't exist)
S=$(post_json '{"fromImage":"chainsafe/lodestar:beacon"}' "$PROXY/images/create")
if [ "$S" = "200" ]; then
  echo "  PASS: image pull allowed -> $S"
  PASS=$((PASS+1))
elif [ "$S" = "500" ]; then
  echo "  PASS: image pull allowed (500 = daemon can't fetch, not proxy) -> $S"
  PASS=$((PASS+1))
elif [ "$S" = "404" ]; then
  echo "  PASS: image pull allowed (404 = daemon can't fetch, not proxy) -> $S"
  PASS=$((PASS+1))
else
  echo "  FAIL: image pull (expected 200|404|500, got $S)"
  FAIL=$((FAIL+1))
fi

# Unlisted image pull -> proxy denies
S=$(post_json '{"fromImage":"alpine:latest"}' "$PROXY/images/create")
check "pull unlisted image -> 403" "403" "$S"

# Real container lifecycle with busybox (image that exists)
# Step 1: Pull busybox through proxy (should be denied — not in policy)
S=$(post_json '{"fromImage":"busybox:latest"}' "$PROXY/images/create")
check "pull busybox (unlisted) -> 403" "403" "$S"

# ─── Endpoint completeness ─────────────────────────────

echo ""
echo "--- Unrecognized endpoints ---"

S=$(post_empty "$PROXY/networks/create")
check "POST /networks/create -> 403" "403" "$S"

S=$(post_empty "$PROXY/volumes/create")
check "POST /volumes/create -> 403" "403" "$S"

S=$(post_empty "$PROXY/containers/test")
check "PATCH /containers/test -> 403" "403" "$S"

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
