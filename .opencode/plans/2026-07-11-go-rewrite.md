# Go Rewrite Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Rewrite the Go implementation from scratch — remove `uuid` dependency, consolidate `internal/types` into `internal/proxy`, streamline body parsing, add graceful shutdown, use `slog` for structured logging, add comprehensive test coverage, upgrade to Go 1.22.

**Architecture:** Single entry point (`main.go`), four internal packages (`proxy`, `middleware`, `policy`, `audit`), one external dependency (`gopkg.in/yaml.v3` for YAML config parsing — unavoidable, not deprecated). The `proxy` package owns routing, handler, and transport. The `middleware` package owns the Gate/Mutator chain. The `policy` package owns YAML loading and types. The `audit` package owns JSON audit logging.

**Tech Stack:** Go 1.22, stdlib (`net/http`, `encoding/json`, `log/slog`, `crypto/rand`, `flag`), one dep: `gopkg.in/yaml.v3` (YAML parsing).

---

### Project Structure

```
├── main.go                           # CLI entry point with graceful shutdown
├── internal/
│   ├── proxy/
│   │   ├── router.go                 # Route matching + Action/RouteResult types
│   │   ├── router_test.go            # Route tests (carried forward from old)
│   │   ├── handler.go                # HTTP handler (ServeHTTP)
│   │   ├── handler_test.go           # Handler tests — NEW
│   │   ├── transport.go              # Reverse proxy to Docker socket
│   │   └── transport_test.go         # Transport tests (carried forward)
│   ├── middleware/
│   │   ├── chain.go                  # Gate/Mutator interfaces + Chain
│   │   ├── exec.go                   # ExecGate
│   │   ├── readonly.go               # ReadonlyGate
│   │   ├── registry.go               # RegistryGate
│   │   ├── mountsource.go            # MountSourceGate
│   │   ├── envfile.go                # EnvFileGate
│   │   ├── cmd.go                    # CmdGate
│   │   ├── containerconfig.go        # ContainerConfigMutator
│   │   └── chain_test.go             # Middleware tests — NEW
│   ├── policy/
│   │   ├── types.go                  # Policy, ContainerConfig, Volume, FlagRule
│   │   ├── manager.go                # Load YAML, lookup by name/image
│   │   └── manager_test.go           # Manager tests — NEW
│   └── audit/
│       └── audit.go                  # JSON file audit logger
```

### Files eliminated

- `internal/types/types.go` — Action enum + RouteResult folded into `internal/proxy/router.go`
- `internal/policy/marshal.go` — no longer needed (body marshaling lives in handler)
- `internal/policy/policy.go` — renamed to `internal/policy/types.go` (types only)
- `github.com/google/uuid` — removed, replaced with `crypto/rand` 16-byte hex

### Files unchanged

- `config/` — policy YAML files (identical format)
- `deploy/` — shell integration tests + docker-compose
- `spec/` — Quint formal spec (unchanged)
- `opencode.json` — MCP/agent config
- `Makefile` — targets unchanged

---

### Task 1: Scaffold new project

**Files:**
- Modify: `go.mod` (replace with Go 1.22, yaml.v3 only dep)
- Remove: `go.sum` (will regenerate), all old `internal/` code
- Create: `internal/policy/types.go`
- Create: `internal/policy/manager.go` (stub)
- Create: `internal/proxy/router.go` (stub with Action/RouteResult)
- Create: `internal/middleware/chain.go` (stub with Gate/Mutator)
- Create: `internal/audit/audit.go` (stub)
- Create: `main.go` (scaffold with graceful shutdown)

**go.mod:**
```
module github.com/ChainSafe/docker-socket-policy
go 1.22
require gopkg.in/yaml.v3 v3.0.1
```

- [ ] **Step 1: Wipe old internal/ and go.sum, create directory structure**
- [ ] **Step 2: Write `go.mod`, `go.sum`** via `go mod tidy`
- [ ] **Step 3: Write `internal/policy/types.go`** — Policy, ContainerConfig, Volume, FlagRule structs with yaml tags, plus `MarshalBody()` helper
- [ ] **Step 4: Write `internal/policy/manager.go`** — Manager struct, `NewManager`, `Get`, `GetByImage`, `List`, `extractImageName`, `loadPolicy` with YAML unmarshal
- [ ] **Step 5: Write `internal/audit/audit.go`** — Logger with JSON file output, `Allow`/`Deny`/`Close`
- [ ] **Step 6: Write `internal/middleware/chain.go`** — Gate/Mutator interfaces, Chain struct, stub Execute
- [ ] **Step 7: Write `internal/proxy/router.go`** — Action enum, RouteResult struct, Router stub
- [ ] **Step 8: Write `main.go`** — CLI flags, wire everything, `signal.NotifyContext` graceful shutdown
- [ ] **Step 9: Run `go mod tidy && go build ./...`** — verify zero yaml.v3 dependency compiles
- [ ] **Step 10: Commit**

---

### Task 2: Policy Manager (full implementation + tests)

**Files:**
- Rewrite: `internal/policy/manager.go` (full YAML loading + validation)
- Create: `internal/policy/manager_test.go`

**Logic (same as old):**
- `NewManager(configDir)`: walk dir, load `.yaml`/`.yml`, validate `service_name` and `allowed_image_prefixes` required
- `Get(serviceName)`: exact lookup in `policiesByName`
- `GetByImage(imageRef)`: `extractImageName` (split on `:` or `@`), `strings.HasPrefix` check against each policy's `AllowedImagePrefixes`
- `List()`: return all service names

**Tests:**
- `TestNewManager_LoadsValidPolicies`
- `TestNewManager_RejectsMissingServiceName`
- `TestNewManager_RejectsEmptyPrefixes`
- `TestGetByImage_Match`
- `TestGetByImage_NoMatch`
- `TestGetByImage_PrefixMatch`

- [ ] **Step 1: Write `internal/policy/manager_test.go`** — 6+ tests (RED first)
- [ ] **Step 2: Run tests to confirm they fail** — `go test ./internal/policy/... -v` → FAIL (expected)
- [ ] **Step 3: Write `internal/policy/manager.go`** — full implementation (GREEN)
- [ ] **Step 4: Run tests to confirm they pass** — `go test ./internal/policy/... -v` → PASS
- [ ] **Step 5: Run `go vet ./internal/policy/...`** — PASS
- [ ] **Step 6: Commit**

---

### Task 3: Router (full implementation + tests)

**Files:**
- Rewrite: `internal/proxy/router.go` — full `Route()` logic
- Carry forward: `internal/proxy/router_test.go` (same tests, update imports)

**Logic (same as old):**
- `Route(method, path, body)`: strip API version, route by path patterns
- Read-only: `/ping`, `/version`, `/info`, `/events`, GET containers
- Deny: `/auth`, exec, `/build`, `/commit`, rename, update
- Container create: `routeCreate(body)` → parse JSON, get image, lookup policy
- Container lifecycle: `routeByContainerName` (start/stop/restart/kill/wait/pause/unpause)
- Image pull: `routeImagePull(body)`
- Default: deny with reason

**Tests (carried forward from old):**
- `TestRouterDenyAuth`, `TestRouterAllowPing`, `TestRouterAllowVersion`, `TestRouterDenyExec`, `TestRouterDenyBuild`
- `TestRouterCreateContainerValidImage`, `TestRouterCreateContainerDeniedImage`
- `TestRouterContainerLifecycle` (covers all lifecycle verbs)
- `TestRouterDefaultDeny`, `TestRouterAllowInfo`, `TestRouterAllowEvents`

**Note:** The new `Route` signature changes from `(method, path string, body []byte)` to `(method, path string, body map[string]interface{})` because the handler now parses JSON before calling Route. Tests must construct bodies as Go map literals, not JSON strings:

```go
// Old style (no longer valid):
// body := []byte(`{"Image": "chainsafe/lodestar:next"}`)

// New style:
body := map[string]interface{}{
    "Image": "chainsafe/lodestar:next",
    "HostConfig": map[string]interface{}{},
}
```

- [ ] **Step 1: Write `internal/proxy/router_test.go`** — carried forward from old, converted to map literals (RED first)
- [ ] **Step 2: Run tests to confirm they fail** — `go test ./internal/proxy/... -run TestRouter -v` → FAIL (expected)
- [ ] **Step 3: Write full `internal/proxy/router.go`** — full implementation (GREEN)
- [ ] **Step 4: Run tests to confirm they pass** — `go test ./internal/proxy/... -run TestRouter -v` → PASS
- [ ] **Step 5: Commit**

---

### Task 4: Middleware chain + all gates and mutators

**Files:**
- Rewrite: `internal/middleware/chain.go` — full Chain with proper ordering
- Create: `internal/middleware/exec.go`
- Create: `internal/middleware/readonly.go`
- Create: `internal/middleware/registry.go`
- Create: `internal/middleware/mountsource.go`
- Create: `internal/middleware/envfile.go`
- Create: `internal/middleware/cmd.go`
- Create: `internal/middleware/containerconfig.go`
- Create: `internal/middleware/chain_test.go`

**Note:** The `Chain.Execute` signature changes from `(r, *types.RouteResult)` to `(r, *policy.Policy, map[string]interface{})` — gates receive the policy and parsed body directly.

**Gate implementations (same logic as old, each file ~20-100 lines):**
- **ExecGate**: reject paths containing `/exec` with POST
- **ReadonlyGate**: reject POST/PUT/DELETE/PATCH
- **RegistryGate**: `splitImageRef` → `isAllowedPrefix` + tag/digest regex validation
- **MountSourceGate**: check `HostConfig.Binds` + `Volumes` against policy whitelist
- **EnvFileGate**: reject inline `Env` when `EnvFile != ""`, strip empty `Env`
- **CmdGate**: `safeCharset` regex, allowed/denied flags, value pattern validation
- **ContainerConfigMutator**: override `NetworkMode`, `RestartPolicy`, `SecurityOpt`, `User`, `LogConfig`; always set `Privileged=false`

**New tests (15+ test functions):**
- Each gate tested in isolation (allow + deny cases)
- Pattern validation and digest format tests for RegistryGate
- Bind string parsing tests for MountSourceGate
- Inline env var rejection for EnvFileGate
- Denied/allowed/value-pattern tests for CmdGate
- Mutator verification for ContainerConfigMutator
- Chain ordering test (mutator runs before gate)

- [ ] **Step 1: Write `chain_test.go`** — all gate tests (RED first), 15+ test functions
- [ ] **Step 2: Run tests to confirm they fail** — `go test ./internal/middleware/... -v` → FAIL (expected)
- [ ] **Step 3–9: Write each gate/mutator file + full `chain.go`** — write minimal implementation per test (one per step, each ~20-100 lines), re-run tests after each
- [ ] **Step 10: Run final `go test ./internal/middleware/... -v`** — PASS
- [ ] **Step 11: Commit**

---

### Task 5: Handler + Transport + graceful shutdown

**Files:**
- Create: `internal/proxy/handler.go`
- Rewrite: `internal/proxy/transport.go` (copy from old)
- Carry forward: `internal/proxy/transport_test.go` (from old)
- Create: `internal/proxy/handler_test.go`
- Rewrite: `main.go` (final version)

**Handler flow:**
1. `generateRequestID()` — 16 random bytes via `crypto/rand`, fmt as hex
2. `io.ReadAll(r.Body)` → body bytes
3. JSON unmarshal → `map[string]interface{}`
4. `router.Route(method, path, bodyJSON)` → `RouteResult`
5. If deny: 403 + audit + slog warn; return
6. If create: `chain.Execute(r, policy, bodyJSON)` → run mutators then gates
7. If chain denies: 403 + audit; return
8. Set modified body on request
9. `transport.ServeHTTP(w, r)` — forward to Docker
10. slog.Info + audit.Allow

**Transport:** Identical to old `transport.go` — `httputil.ReverseProxy` with Unix/TCP dialer

**Graceful shutdown:**
- `signal.NotifyContext(ctx, SIGTERM, SIGINT)` — single signal handler
- Both listeners started in goroutines
- On signal: `http.Server.Shutdown(ctx)` with 30s timeout
- Clean exit

**Handler tests:**
- `TestHandler_DeniesRoute` — mock chain, verify 403
- `TestHandler_CreateContainerValid` — full chain, verify forward
- `TestHandler_CreateContainerDenied` — gate rejects, verify 403

- [ ] **Step 1: Write `internal/proxy/handler_test.go`** — including these test cases:
  - `TestHandler_DeniesRoute` — route denies, expect 403
  - `TestHandler_CreateContainerValid` — full chain, verify forward
  - `TestHandler_CreateContainerDenied` — gate rejects, verify 403
  - `TestHandler_BodyReadError` — simulate broken connection, expect 400
  - `TestHandler_EmptyBody` — no body, routes correctly
  - `TestHandler_NonJSONBody` — non-JSON body passthrough for read-only endpoints
  - `TestHandler_ContentLengthPreserved` — after mutation, ContentLength matches modified body
- [ ] **Step 2: Run handler tests to confirm they fail** — `go test ./internal/proxy/... -run TestHandler -v` → FAIL (expected)
- [ ] **Step 3: Write `internal/proxy/transport.go`** — copy from old
- [ ] **Step 4: Write `internal/proxy/handler.go`** — implementation (GREEN)
- [ ] **Step 5: Write `main.go`** — final version with graceful shutdown
- [ ] **Step 6: Run handler tests to confirm they pass** — `go test ./internal/proxy/... -run TestHandler -v` → PASS
- [ ] **Step 7: Run `go test ./... -v -count=1`** — all tests PASS
- [ ] **Step 8: Run `go vet ./...`** — clean
- [ ] **Step 9: Run `go build -o /dev/null .`** — builds clean
- [ ] **Step 10: Commit**

---

### Task 6: Update Dockerfile

**Files:**
- Modify: `Dockerfile`

**Changes:**
- `golang:1.21-alpine` → `golang:1.22-alpine`
- All other lines unchanged

- [ ] **Step 1: Update `Dockerfile`**
- [ ] **Step 2: Commit**

---

### Task 7: Final verification

- [ ] **Step 1: `go test ./... -v -count=1`** — PASS (25+ tests)
- [ ] **Step 2: `go vet ./...`** — PASS
- [ ] **Step 3: `make verify`** — PASS (Quint spec unchanged, invariants hold)
- [ ] **Step 4: `go build -o /dev/null .`** — PASS

### Commands reference

```bash
go mod tidy                          # Download yaml.v3, update go.sum
go test ./... -v -count=1            # All unit tests
go vet ./...                         # Static analysis
go build -o /dev/null .              # Verify build
make verify                          # Quint simulation
```

### Rollback

If a task breaks the build or tests:
1. Check `go vet` output for unused imports, shadowed variables
2. Fix the specific file and re-test
3. If stuck on middleware wiring, verify `Chain.Execute` signature matches handler call site
4. The router test and transport test are well-covered — if they pass, the core logic is correct
