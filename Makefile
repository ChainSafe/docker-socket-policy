BINARY_NAME ?= docker-socket-policy
OUTPUT_DIR ?= .
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
QUINT ?= $(shell command -v quint 2>/dev/null || echo node $$HOME/.hermes/node/lib/node_modules/@informalsystems/quint/dist/src/cli.js)
SPEC ?= spec/docker_socket_policy.qnt

.PHONY: build clean test lint verify typecheck validate
.PHONY: build-go test-go lint-go build-rs test-rs build-ts test-ts

# ─── Go ──────────────────────────────────────────────

build-go:
	cd go && go build -ldflags="-X main.Version=$(VERSION)" -o ../$(OUTPUT_DIR)/$(BINARY_NAME) .

test-go:
	cd go && go test ./... -count=1

lint-go:
	cd go && go vet ./...

# ─── Rust ────────────────────────────────────────────

build-rs:
	cd rs && cargo build --release

test-rs:
	cd rs && cargo test

lint-rs:
	cd rs && cargo check

# ─── Rust release binary location
RS_BINARY = rs/target/release/docker-socket-policy

# ─── TypeScript ──────────────────────────────────────

build-ts:
	cd ts && npm run build

test-ts:
	cd ts && npm run build && node --test dist/*.test.js

lint-ts:
	cd ts && npm run typecheck

# ─── Aggregate targets ───────────────────────────────

build-all: build-go build-rs build-ts
test-all: test-go test-rs test-ts
lint-all: lint-go lint-rs lint-ts

# ─── Legacy aliases (default to Go) ──────────────────

build: build-go
test: test-go
lint: lint-go

clean:
	rm -f $(BINARY_NAME) go/$(BINARY_NAME)
	cd rs && cargo clean 2>/dev/null; true
	rm -rf ts/dist ts/node_modules

# ─── Shared (Quint) ──────────────────────────────────

typecheck:
	$(QUINT) typecheck $(SPEC)

verify:
	$(QUINT) run --max-steps=100 --invariants allInvariants $(SPEC)

verify-ts:
	$(QUINT) run --max-steps=50 --invariants allInvariants --backend typescript $(SPEC)

# ─── Integration tests ───────────────────────────────

test-integration:
	docker compose -f deploy/docker-compose.yml down --remove-orphans -v 2>/dev/null; \
	docker compose -f deploy/docker-compose.yml run --rm test; \
	rc=$$?; \
	docker compose -f deploy/docker-compose.yml down --remove-orphans -v; \
	exit $$rc

test-integration-tcp:
	docker compose -f deploy/docker-compose.tcp.yml down --remove-orphans -v 2>/dev/null; \
	docker compose -f deploy/docker-compose.tcp.yml run --rm test; \
	rc=$$?; \
	docker compose -f deploy/docker-compose.tcp.yml down --remove-orphans -v; \
	exit $$rc

test-integration-sock:
	docker compose -f deploy/docker-compose.sock.yml down --remove-orphans -v 2>/dev/null; \
	docker compose -f deploy/docker-compose.sock.yml run --rm test; \
	rc=$$?; \
	docker compose -f deploy/docker-compose.sock.yml down --remove-orphans -v; \
	exit $$rc

validate: typecheck verify lint-go test-go
