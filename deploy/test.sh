#!/bin/sh
# Integration tests for docker-socket-policy.
# Sends HTTP requests directly to the proxy's Docker API and checks status codes,
# and the deny message on every expected proxy 403.
# The proxy's RegistryGate, MountSourceGate, EnvFileGate, CmdGate, and
# ContainerConfigMutator are all exercised; exec and attach are denied by the
# router, protocol upgrades by the handler (#76), non-read methods on the read
# endpoints by the router and CONNECT by the handler (#78), and every write on a
# second proxy run with --readonly (#75).

set -e

PASS=0
FAIL=0

# The proxy listens on a Unix socket only, shared with this container through
# a volume. The host part of the URL is ignored when curl is given
# --unix-socket, but it still has to be present for the URL to parse.
PROXY_SOCK="${PROXY_SOCK:-/sock/proxy.sock}"
PROXY="http://localhost"

# busybox wget cannot speak to a Unix socket, so the helpers below need curl.
# It is baked into Dockerfile.test rather than installed here, so a run does
# not depend on the Alpine CDN being reachable.
if ! command -v curl >/dev/null 2>&1; then
  echo "ERROR: curl is missing from the test image (see deploy/Dockerfile.test)"
  exit 1
fi

# Bound every request. curl has no default overall timeout, so without this a
# proxy that accepts the connection and then never answers would hang the run
# instead of failing it — and the readiness counter below would never advance.
TIMEOUT="--max-time 10 --connect-timeout 2"

# The --readonly proxy (#75) serves the same config on its own socket.
PROXY_RO_SOCK="${PROXY_RO_SOCK:-/sock/readonly.sock}"

# Wait for a proxy to create and serve its socket.
wait_for_sock() {
  echo "Waiting for proxy at $1..."
  i=0
  while [ $i -lt 30 ]; do
    if curl -sf $TIMEOUT --unix-socket "$1" "$PROXY/_ping" >/dev/null 2>&1; then
      echo "Proxy ready."
      break
    fi
    printf "."
    sleep 1
    i=$((i + 1))
  done
  if [ $i -eq 30 ]; then
    echo ""
    echo "ERROR: Proxy at $1 failed to respond within 30s"
    exit 1
  fi
  echo ""
}
wait_for_sock "$PROXY_SOCK"
wait_for_sock "$PROXY_RO_SOCK"

# Helpers: report the HTTP status code of a request sent over the Unix socket.
# curl exits non-zero when it cannot connect at all, which under `set -e` would
# abort the run instead of reporting a failed assertion, so connection failures
# are normalised to the synthetic status 000.
# curl still prints %{http_code} when it exits non-zero, so the fallback only
# applies when it produced nothing at all. Overwriting unconditionally would
# discard a real status on a mid-response error and report it as 000.
# The response body goes to $BODY for check_denied. It is truncated first, so a
# request that gets no body cannot pass on the previous request's body.
BODY=$(mktemp)
trap 'rm -f "$BODY"' EXIT
get_status() {
  : >"$BODY"
  out=$(curl -s -o "$BODY" -w '%{http_code}' $TIMEOUT --unix-socket "$PROXY_SOCK" "$1" 2>/dev/null || true)
  echo "${out:-000}"
}
post_json() {
  : >"$BODY"
  out=$(curl -s -o "$BODY" -w '%{http_code}' $TIMEOUT --unix-socket "$PROXY_SOCK" \
    -X POST -H "Content-Type: application/json" -d "$1" "$2" 2>/dev/null || true)
  echo "${out:-000}"
}
post_empty() {
  : >"$BODY"
  out=$(curl -s -o "$BODY" -w '%{http_code}' $TIMEOUT --unix-socket "$PROXY_SOCK" \
    -X POST -H "Content-Type: application/json" -d "" "$1" 2>/dev/null || true)
  echo "${out:-000}"
}
delete_status() {
  : >"$BODY"
  out=$(curl -s -o "$BODY" -w '%{http_code}' $TIMEOUT --unix-socket "$PROXY_SOCK" \
    -X DELETE "$1" 2>/dev/null || true)
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

# check_denied DESC ACTUAL_STATUS BODY_FILE WANT_SUBSTRING [WANT_SUBSTRING...]
# Passes only on a 403 whose body contains one of the WANT_SUBSTRINGs, so a
# 403 from the daemon (or a different proxy deny) cannot pass for the one the
# check is about. The proxy's body is its plain-text deny message.
check_denied() {
  desc="$1"
  actual="$2"
  body_file="$3"
  shift 3
  if [ "$actual" = "403" ]; then
    for want in "$@"; do
      if grep -qF -- "$want" "$body_file"; then
        echo "  PASS: $desc"
        PASS=$((PASS+1))
        return 0
      fi
    done
  fi
  echo "  FAIL: $desc (expected 403 with \"$*\", got $actual: $(head -c 200 "$body_file"))"
  FAIL=$((FAIL+1))
}

echo ""
echo "============================================"
echo "  docker-socket-policy integration tests"
echo "============================================"
echo ""

# ─── Transport: Unix socket only ────────────────────────────────

# Regression guard. Every other assertion in this file goes over the Unix
# socket and would pass just as happily if the proxy were also serving TCP,
# so without this nothing here would notice a TCP listener coming back.
echo "--- Transport ---"

# Assert the specific failure rather than "curl failed somehow": exit 7 is
# connection refused, which proves the host resolved and nothing accepted on
# 2375. Treating any non-zero exit as success would also pass when the name
# does not resolve (exit 6), which proves nothing at all.
# `|| rc=$?` keeps set -e from aborting here: this curl is expected to fail,
# and a bare failing command would terminate the script before rc is read.
rc=0
curl -s -o /dev/null --max-time 3 --connect-timeout 2 \
  "http://${PROXY_HOST:-proxy}:2375/_ping" 2>/dev/null || rc=$?
case "$rc" in
  0)
    echo "  FAIL: proxy answered on TCP 2375 (it must listen on a Unix socket only)"
    FAIL=$((FAIL+1))
    ;;
  7)
    echo "  PASS: no TCP listener on 2375 (connection refused)"
    PASS=$((PASS+1))
    ;;
  *)
    echo "  FAIL: inconclusive TCP probe of ${PROXY_HOST:-proxy}:2375 (curl exit $rc);"
    echo "        expected 7 (connection refused). Exit 6 means the name did not"
    echo "        resolve, so this assertion would prove nothing."
    FAIL=$((FAIL+1))
    ;;
esac

# ─── Read-only endpoints (GET and HEAD allowed, #78) ────────────

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
check_denied "POST /containers/*/exec -> 403" "$S" "$BODY" 'exec is not allowed'

S=$(post_empty "$PROXY/exec/abc123/start")
check_denied "POST /exec/*/start -> 403" "$S" "$BODY" 'exec is not allowed'

S=$(post_empty "$PROXY/build")
check_denied "POST /build -> 403" "$S" "$BODY" 'build is not allowed'

S=$(post_empty "$PROXY/commit")
check_denied "POST /commit -> 403" "$S" "$BODY" 'commit is not allowed'

S=$(post_empty "$PROXY/auth")
check_denied "POST /auth -> 403" "$S" "$BODY" 'auth endpoint is not allowed'

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
check_denied "create with unlisted image -> 403" "$S" "$BODY" 'image alpine:latest not allowed by any policy'

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
check_denied "create with no image -> 403" "$S" "$BODY" 'image field is required'

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
check_denied "create with unlisted volume -> 403" "$S" "$BODY" 'volume mount "/tmp" is not in the whitelist'

# ─── Inline env vars (env_file is set in policy) ─────────

echo ""
echo "--- Inline environment variables ---"

S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Env":["VALIDATOR_KEY=secret"],"Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
check_denied "create with inline env -> 403" "$S" "$BODY" 'inline environment variables are not allowed for service'

# ─── CLI flag validation ────────────────────────────────

echo ""
echo "--- CLI flag validation ---"

# --privileged is in denied_flags -> proxy denies
S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Cmd":["--privileged","--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
check_denied "create with --privileged flag -> 403" "$S" "$BODY" 'flag "--privileged" is denied for service'

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
check_denied "pull unlisted image -> 403" "$S" "$BODY" 'image alpine:latest not allowed by any policy'

# Real container lifecycle with busybox (image that exists)
# Step 1: Pull busybox through proxy (should be denied — not in policy)
S=$(post_json '{"fromImage":"busybox:latest"}' "$PROXY/images/create")
check_denied "pull busybox (unlisted) -> 403" "$S" "$BODY" 'image busybox:latest not allowed by any policy'

# ─── Endpoint completeness ─────────────────────────────

echo ""
echo "--- Unrecognized endpoints ---"

S=$(post_empty "$PROXY/networks/create")
check_denied "POST /networks/create -> 403" "$S" "$BODY" 'endpoint POST /networks/create is not allowed'

S=$(post_empty "$PROXY/volumes/create")
check_denied "POST /volumes/create -> 403" "$S" "$BODY" 'endpoint POST /volumes/create is not allowed'

S=$(post_empty "$PROXY/containers/test")
check_denied "POST /containers/test -> 403 (no action segment)" "$S" "$BODY" 'endpoint POST /containers/test is not allowed'

# Reserved path segments (#24). /containers/json is the list endpoint, not a
# container called "json". Treating it as a container name sent the request
# down the lifecycle path, where an unknown container is allowed through, so Go
# allowed this while Rust and TypeScript denied it.
S=$(delete_status "$PROXY/containers/json")
check_denied "DELETE /containers/json -> 403 (reserved, not a container)" "$S" "$BODY" 'endpoint DELETE /containers/json is not allowed'

S=$(delete_status "$PROXY/containers/create")
check_denied "DELETE /containers/create -> 403 (reserved, not a container)" "$S" "$BODY" 'endpoint DELETE /containers/create is not allowed'

# Listing must still work: it reaches the GET/HEAD passthrough instead.
S=$(get_status "$PROXY/containers/json")
check "GET /containers/json -> 200 (still the list endpoint)" "200" "$S"

# Empty name segment (#48). /containers/ and /containers//start carry no
# container name. Treating "" as a name sent the request down the lifecycle
# path, where an unknown container is allowed through, so Rust forwarded these
# while Go and TypeScript denied them.
S=$(delete_status "$PROXY/containers/")
check_denied "DELETE /containers/ -> 403 (empty name, not a container)" "$S" "$BODY" 'endpoint DELETE /containers/ is not allowed'

S=$(post_empty "$PROXY/containers//start")
check_denied "POST /containers//start -> 403 (empty name, not a container)" "$S" "$BODY" 'empty path segment not allowed'

# Dotted API-version prefix (#52). The Docker CLI versions every request
# (/v1.45/containers/...). The proxy must strip the prefix and route the rest
# like the unversioned path: a lifecycle call reaches the daemon (404, no such
# container — not a proxy 403), and a reserved segment is still denied.
# TypeScript only stripped undotted prefixes, so these fell to the default deny.
S=$(post_empty "$PROXY/v1.45/containers/no-such-container/start")
check "POST /v1.45/containers/*/start -> 404 (daemon answered, not proxy 403)" "404" "$S"

S=$(delete_status "$PROXY/v1.45/containers/json")
check_denied "DELETE /v1.45/containers/json -> 403 (reserved survives version strip)" "$S" "$BODY" 'endpoint DELETE /containers/json is not allowed'

# #57: /volumes/ is not an API-version prefix. The daemon would run a volume
# removal; the proxy must not classify it as a container delete.
S=$(delete_status "$PROXY/volumes/containers/no-such-container")
check_denied "DELETE /volumes/containers/no-such-container -> 403 (not a version prefix)" "$S" "$BODY" 'endpoint DELETE /volumes/containers/no-such-container is not allowed'

# #52: versioned create, the `docker run` path. Mirrors the unversioned
# allowed-image create above: the daemon answers 201, or 404 when the image is
# not present locally — anything but a proxy 403.
S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/v1.45/containers/create")
if [ "$S" = "201" ] || [ "$S" = "404" ]; then
  echo "  PASS: POST /v1.45/containers/create with allowed image -> $S (not 403)"
  PASS=$((PASS+1))
else
  echo "  FAIL: POST /v1.45/containers/create with allowed image (expected 201|404, got $S)"
  FAIL=$((FAIL+1))
fi

# #53: percent-encoded paths. The daemon decodes the path before it routes,
# so the proxy and the daemon could read the same request differently; any %
# in the path is denied. curl sends the path as written (it does not decode
# %XX, and there are no dot segments to squash). The query string is never
# inspected: an encoded filter, as `docker ps --filter` sends, still passes.
S=$(delete_status "$PROXY/containers/no-such%20x")
check_denied "DELETE /containers/no-such%20x -> 403 (percent-encoded path)" "$S" "$BODY" 'percent-encoded path not allowed'

S=$(delete_status "$PROXY/containers/%2F")
check_denied "DELETE /containers/%2F -> 403 (percent-encoded path)" "$S" "$BODY" 'percent-encoded path not allowed'

# The handler tests prove the query reaches the daemon unchanged; this check
# proves an encoded query is not denied.
S=$(get_status "$PROXY/v1.45/containers/json?filters=%7B%22status%22%3A%5B%22running%22%5D%7D")
check "GET /v1.45/containers/json?filters=<encoded> -> 200 (query not inspected)" "200" "$S"

# #49: exec and create are matched on whole path segments. Exec is denied for
# every method under /containers/<name>/exec and /exec/, GET included (exec
# inspect leaks command lines). A name that only starts with exec reaches the
# daemon (404, no such container — not a proxy 403). A create path with extra
# segments is not the create endpoint, even with an allowed image.
S=$(delete_status "$PROXY/containers/no-such/exec")
check_denied "DELETE /containers/*/exec -> 403 (exec subpath, any method)" "$S" "$BODY" 'exec is not allowed'

S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/containers/create/extra")
check_denied "POST /containers/create/extra -> 403 (not the create endpoint)" "$S" "$BODY" 'endpoint POST /containers/create/extra is not allowed'

S=$(post_empty "$PROXY/containers/exec-nosuch/start")
check "POST /containers/exec-nosuch/start -> 404 (daemon answered, not proxy 403)" "404" "$S"

S=$(get_status "$PROXY/exec/0000000000000000000000000000000000000000000000000000000000000000/json")
check_denied "GET /exec/*/json -> 403 (exec inspect denied)" "$S" "$BODY" 'exec is not allowed'

# #55: an empty interior segment is denied for every method. Before #55 the
# empty first segment of //exec/... hid the exec namespace and the GET
# passthrough forwarded it. --path-as-is stops curl from collapsing the //.
: >"$BODY"
S=$(curl -s -o "$BODY" -w '%{http_code}' $TIMEOUT --path-as-is --unix-socket "$PROXY_SOCK" \
  "$PROXY//exec/0000000000000000000000000000000000000000000000000000000000000000/json" 2>/dev/null || true)
S="${S:-000}"
check_denied "GET //exec/*/json -> 403 (empty segment)" "$S" "$BODY" 'empty path segment not allowed'

# #55: an absolute-form request target. Before #55 the TypeScript router saw
# the raw target, whose first segment is "http:", and forwarded exec inspect;
# the daemon answered 404 for this unknown ID (200 with the command line for a
# real one). Go and Rust route on the parsed path, /exec/..., and deny it as
# exec; TypeScript routes the raw target and denies its "//" as an empty
# segment. Either proxy deny passes; a daemon 403 does not.
: >"$BODY"
S=$(curl -s -o "$BODY" -w '%{http_code}' $TIMEOUT --unix-socket "$PROXY_SOCK" \
  --request-target "http://docker/exec/0000000000000000000000000000000000000000000000000000000000000000/json" \
  "$PROXY/" 2>/dev/null || true)
S="${S:-000}"
check_denied "GET http://docker/exec/*/json -> 403 (absolute-form target)" "$S" "$BODY" \
  'exec is not allowed' 'empty path segment not allowed'

# #76: attach is denied by the router for every method, and any protocol
# upgrade is refused by the handler before routing. Before #76 a websocket
# attach went through the GET passthrough and Go relayed the daemon's 101,
# handing the caller the container's stdin. The target is this test
# container (its hostname is its short ID), so on a proxy without the fix the
# daemon answers 101, not 404. curl does not speak websocket over http://, so
# it reports the status and waits for the body until --max-time.
upgrade_get() {
  : >"$BODY"
  out=$(curl -s -o "$BODY" -w '%{http_code}' $TIMEOUT --unix-socket "$PROXY_SOCK" \
    -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' "$1" 2>/dev/null || true)
  echo "${out:-000}"
}

S=$(upgrade_get "$PROXY/containers/$(hostname)/attach/ws?stdin=1&stream=1")
check_denied "GET /containers/*/attach/ws with Upgrade: websocket -> 403 (upgrade refused)" "$S" "$BODY" 'protocol upgrade not allowed'

S=$(get_status "$PROXY/containers/no-such-container/attach/ws")
check_denied "GET /containers/*/attach/ws -> 403 (attach denied)" "$S" "$BODY" 'attach is not allowed'

S=$(upgrade_get "$PROXY/_ping")
check_denied "GET /_ping with Upgrade: websocket -> 403 (upgrade refused)" "$S" "$BODY" 'protocol upgrade not allowed'

# #78: the read endpoints admit only GET and HEAD. Before #78 an early router
# clause allowed /_ping, /version, /info and /events… for every method, so the
# daemon answered POST /_ping. CONNECT is refused by the handler before
# routing; before #78 the TypeScript proxy dropped it with no response.
# method_status METHOD URL [CURL_ARGS...]
method_status() {
  : >"$BODY"
  m="$1"
  u="$2"
  shift 2
  out=$(curl -s -o "$BODY" -w '%{http_code}' $TIMEOUT --unix-socket "$PROXY_SOCK" \
    -X "$m" "$@" "$u" 2>/dev/null || true)
  echo "${out:-000}"
}

S=$(method_status POST "$PROXY/_ping")
check_denied "POST /_ping -> 403 (read endpoint, GET/HEAD only)" "$S" "$BODY" 'endpoint POST /_ping is not allowed'

S=$(method_status DELETE "$PROXY/version")
check_denied "DELETE /version -> 403 (read endpoint, GET/HEAD only)" "$S" "$BODY" 'endpoint DELETE /version is not allowed'

S=$(method_status OPTIONS "$PROXY/_ping")
check_denied "OPTIONS /_ping -> 403 (CORS preflight denied)" "$S" "$BODY" 'endpoint OPTIONS /_ping is not allowed'

S=$(method_status CONNECT "$PROXY/_ping")
check_denied "CONNECT /_ping -> 403 (CONNECT refused)" "$S" "$BODY" 'CONNECT is not allowed'

S=$(method_status CONNECT "$PROXY/" --request-target localhost:80)
check_denied "CONNECT localhost:80 -> 403 (CONNECT refused, authority form)" "$S" "$BODY" 'CONNECT is not allowed'

S=$(method_status HEAD "$PROXY/_ping" -I)
check "HEAD /_ping -> 200" "200" "$S"

S=$(get_status "$PROXY/events?since=1&until=2")
check "GET /events (bounded) -> 200" "200" "$S"

# ─── Read-only mode (#75) ────────────────────────────────

# The same config behind --readonly. Every request whose method is not GET or
# HEAD is denied by the router. Before #75 the flag only reached the gate
# chain, which runs on create alone, so these reached the daemon (a 404 for
# the unknown container below, i.e. a leak, not a proxy 403).
echo ""
echo "--- Read-only mode ---"

# The request helpers read PROXY_SOCK, so this switches every check below to
# the read-only proxy. Keep this section last.
PROXY_SOCK="$PROXY_RO_SOCK"

S=$(get_status "$PROXY/_ping")
check "GET /_ping -> 200 (read-only)" "200" "$S"

S=$(post_empty "$PROXY/containers/no-such-container/stop")
check_denied "POST /containers/*/stop -> 403 (read-only)" "$S" "$BODY" 'read-only mode: POST requests are not allowed'

S=$(delete_status "$PROXY/containers/no-such-container")
check_denied "DELETE /containers/* -> 403 (read-only)" "$S" "$BODY" 'read-only mode: DELETE requests are not allowed'

S=$(post_json '{"Image":"chainsafe/lodestar:beacon","Cmd":["--rcConfig","/data/config.yml"]}' "$PROXY/containers/create")
check_denied "POST /containers/create with allowed image -> 403 (read-only)" "$S" "$BODY" 'read-only mode: POST requests are not allowed'

S=$(post_empty "$PROXY/images/create?fromImage=chainsafe/lodestar&tag=beacon")
check_denied "POST /images/create?fromImage=chainsafe/lodestar -> 403 (read-only)" "$S" "$BODY" 'read-only mode: POST requests are not allowed'

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
