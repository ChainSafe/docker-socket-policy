BINARY_NAME ?= docker-socket-policy
OUTPUT_DIR ?= .
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
QUINT ?= $(shell command -v quint 2>/dev/null || echo node $$HOME/.hermes/node/lib/node_modules/@informalsystems/quint/dist/src/cli.js)
SPEC ?= spec/docker_socket_policy.qnt

.PHONY: build clean test lint verify typecheck validate

build:
	go build -ldflags="-X main.Version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME) .

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -f $(BINARY_NAME)

typecheck:
	$(QUINT) typecheck $(SPEC)

verify:
	$(QUINT) run --max-steps=100 --invariants allInvariants --backend rust $(SPEC)

verify-ts:
	$(QUINT) run --max-steps=50 --invariants allInvariants --backend typescript $(SPEC)

validate: typecheck verify lint test
