BINARY_NAME ?= docker-socket-policy
OUTPUT_DIR ?= .
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
QUINT ?= $(shell command -v quint 2>/dev/null || echo node $$HOME/.hermes/node/lib/node_modules/@informalsystems/quint/dist/src/cli.js)
SPEC ?= spec/docker_socket_policy.qnt
LISTENER_SPEC ?= spec/listener.qnt
ROUTER_SPEC ?= spec/router.qnt
BACKEND ?=

.PHONY: build clean test lint verify typecheck test-spec validate ci-verify release-verify test-release
.PHONY: build-go test-go lint-go build-rs test-rs lint-rs build-ts test-ts lint-ts build-all test-all lint-all fmt-go fmt-rs fmt-ts fmt-all hooks

# ─── Go ──────────────────────────────────────────────

build-go:
	cd go && go build -ldflags="-X main.Version=$(VERSION)" -o ../$(OUTPUT_DIR)/$(BINARY_NAME) .

test-go:
	cd go && go test ./... -count=1

lint-go:
	cd go && out=$$(gofmt -l . 2>&1); test -z "$$out" || { echo "gofmt needed (run make fmt-go):"; echo "$$out"; exit 1; }
	cd go && go vet ./...

fmt-go:
	cd go && gofmt -w .

# ─── Rust ────────────────────────────────────────────

build-rs:
	cd rs && cargo build --release

test-rs:
	cd rs && cargo test

lint-rs:
	cd rs && cargo fmt --check && cargo check

fmt-rs:
	cd rs && cargo fmt

# ─── Rust release binary location
RS_BINARY = rs/target/release/docker-socket-policy

# ─── TypeScript ──────────────────────────────────────

build-ts:
	cd ts && npm run build

test-ts:
	cd ts && npm run build && node --test dist/*.test.js

lint-ts:
	cd ts && npm run typecheck && npm run format:check

fmt-ts:
	@test -x ts/node_modules/.bin/prettier || { echo "prettier not installed: run npm ci in ts/"; exit 1; }
	cd ts && node_modules/.bin/prettier --write src

# ─── Aggregate targets ───────────────────────────────

build-all: build-go build-rs build-ts
test-all: test-go test-rs test-ts
lint-all: lint-go lint-rs lint-ts
fmt-all: fmt-go fmt-rs fmt-ts

hooks:
	git config core.hooksPath .githooks
	@echo "git hooks active: core.hooksPath=.githooks (pre-commit, pre-push)"

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
	$(QUINT) typecheck $(LISTENER_SPEC)
	$(QUINT) typecheck $(ROUTER_SPEC)

verify:
	if [ -n "$(BACKEND)" ]; then \
		$(QUINT) run $(SPEC) --max-steps=100 --invariants allInvariants --backend $(BACKEND) && \
		$(QUINT) run $(LISTENER_SPEC) --main=listener_locked --max-steps=30 --invariant allListenerInvariants --backend $(BACKEND); \
	else \
		$(QUINT) run $(SPEC) --max-steps=100 --invariants allInvariants && \
		$(QUINT) run $(LISTENER_SPEC) --main=listener_locked --max-steps=30 --invariant allListenerInvariants; \
	fi

test-spec:
	$(QUINT) test $(LISTENER_SPEC) --main=listener_locked
	$(QUINT) test $(LISTENER_SPEC) --main=listener_unlocked
	$(QUINT) test $(ROUTER_SPEC) --main=router
	$(QUINT) test $(ROUTER_SPEC) --main=router_pre48
	$(QUINT) test $(ROUTER_SPEC) --main=router_pre53

verify-ts:
	$(QUINT) run $(SPEC) --max-steps=50 --invariants allInvariants --backend typescript

ci-verify:
	$(MAKE) typecheck
	$(MAKE) test-spec
	$(MAKE) verify BACKEND=typescript
	$(MAKE) test-all
	$(MAKE) test-integration
	$(MAKE) verify-reproducible-all

release-verify:
	$(MAKE) typecheck
	$(MAKE) test-spec
	$(MAKE) verify BACKEND=rust
	$(MAKE) test-all
	$(MAKE) test-integration
	$(MAKE) verify-reproducible-all

# ─── Integration tests ───────────────────────────────

IMPL ?= go

test-integration:
	IMPL=$(IMPL) docker compose -f deploy/docker-compose.yml down --remove-orphans -v 2>/dev/null; \
	IMPL=$(IMPL) docker compose -f deploy/docker-compose.yml run --build --rm test; \
	rc=$$?; \
	IMPL=$(IMPL) docker compose -f deploy/docker-compose.yml down --remove-orphans -v; \
	exit $$rc

test-integration-rs:
	$(MAKE) test-integration IMPL=rs

test-integration-ts:
	$(MAKE) test-integration IMPL=ts

# Unix-socket provisioning tests. The proxy both listens and connects over
# Unix sockets only — TCP would bypass user/group socket ownership, which is
# the security model this target exercises: proxy-granted is in the socket's
# group and succeeds, proxy-denied is not and gets 403. Not run in CI (uses
# group-restricted socket setup); run locally per IMPL.
test-integration-sock:
	IMPL=$(IMPL) docker compose -f deploy/docker-compose.sock.yml down --remove-orphans -v 2>/dev/null; \
	IMPL=$(IMPL) docker compose -f deploy/docker-compose.sock.yml run --build --rm test; \
	rc=$$?; \
	IMPL=$(IMPL) docker compose -f deploy/docker-compose.sock.yml down --remove-orphans -v; \
	exit $$rc

test-integration-sock-rs:
	$(MAKE) test-integration-sock IMPL=rs

test-integration-sock-ts:
	$(MAKE) test-integration-sock IMPL=ts

validate: typecheck verify lint-go test-go

# ─── Release scripts ─────────────────────────────────

test-release:
	bash scripts/release-version_test.sh
	bash scripts/release-latest-tag_test.sh

# ─── Reproducible build verification ─────────────────

.PHONY: verify-reproducible-go verify-reproducible-rs verify-reproducible-ts verify-reproducible-all

verify-reproducible-go:
	docker build --no-cache --platform linux/amd64 \
	  --build-arg VERSION=$(VERSION) \
	  --output type=local,dest=/tmp/repro-go-a \
	  -f go/Dockerfile go/
	docker build --no-cache --platform linux/amd64 \
	  --build-arg VERSION=$(VERSION) \
	  --output type=local,dest=/tmp/repro-go-b \
	  -f go/Dockerfile go/
	cmp /tmp/repro-go-a/docker-socket-policy /tmp/repro-go-b/docker-socket-policy \
	  && echo "Go: REPRODUCIBLE ✓" && rm -rf /tmp/repro-go-a /tmp/repro-go-b

verify-reproducible-rs:
	docker build --no-cache --platform linux/amd64 \
	  --output type=local,dest=/tmp/repro-rs-a \
	  -f rs/Dockerfile rs/
	docker build --no-cache --platform linux/amd64 \
	  --output type=local,dest=/tmp/repro-rs-b \
	  -f rs/Dockerfile rs/
	cmp /tmp/repro-rs-a/docker-socket-policy /tmp/repro-rs-b/docker-socket-policy \
	  && echo "Rust: REPRODUCIBLE ✓" && rm -rf /tmp/repro-rs-a /tmp/repro-rs-b

verify-reproducible-ts:
	docker build --no-cache --platform linux/amd64 \
	  --output type=local,dest=/tmp/repro-ts-a \
	  -f ts/Dockerfile ts/
	docker build --no-cache --platform linux/amd64 \
	  --output type=local,dest=/tmp/repro-ts-b \
	  -f ts/Dockerfile ts/
	cmp /tmp/repro-ts-a/app/dist/index.js /tmp/repro-ts-b/app/dist/index.js \
	  && echo "TypeScript: REPRODUCIBLE ✓" && rm -rf /tmp/repro-ts-a /tmp/repro-ts-b

verify-reproducible-all: verify-reproducible-go verify-reproducible-rs verify-reproducible-ts
