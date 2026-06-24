BINARY_NAME ?= docker-socket-policy
OUTPUT_DIR ?= .
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build clean test lint

build:
	go build -ldflags="-X main.Version=$(VERSION)" -o $(OUTPUT_DIR)/$(BINARY_NAME) .

test:
	go test ./...

lint:
	go vet ./...

clean:
	rm -f $(BINARY_NAME)
