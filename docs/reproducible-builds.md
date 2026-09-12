# Reproducible Builds Verification

This document describes how to verify that docker-socket-policy builds are reproducible and how to verify SBOMs and signatures. docker-socket-policy is built for multiple architectures: **amd64** and **arm64**.

## Prerequisites

- Docker (with buildx support)
- Cosign (`brew install cosign` or [install guide](https://docs.sigstore.dev/cosign/installation/))
- Syft (`brew install syft` or [install guide](https://github.com/anchore/syft#installation))

## Quick Start: Verify Reproducibility

Run two independent no-cache builds and compare byte-for-byte:

```bash
# Go
make verify-reproducible-go

# Rust
make verify-reproducible-rs

# TypeScript
make verify-reproducible-ts

# All three
make verify-reproducible-all
```

Each target builds twice with `--no-cache` and uses `cmp` to confirm bit-identical output. If any pair differs, the build is not reproducible.

## Verify a Single Build Step by Step

### Build and Verify amd64 Binary

```bash
# Build Go binary for amd64
docker build --no-cache --platform linux/amd64 \
  --build-arg VERSION=$(git describe --tags --always --dirty) \
  --output type=local,dest=/tmp/build-amd64 \
  -f go/Dockerfile go/

# Check the binary
file /tmp/build-amd64/docker-socket-policy
# Expected: ELF 64-bit LSB executable, x86-64, statically linked

# Generate SBOM
syft scan /tmp/build-amd64/docker-socket-policy -o spdx-json > docker-socket-policy-amd64.spdx.json
syft scan /tmp/build-amd64/docker-socket-policy -o cyclonedx-json > docker-socket-policy-amd64.cyclonedx.json
```

### Build and Verify arm64 Binary

```bash
# Build Go binary for arm64
docker build --no-cache --platform linux/arm64 \
  --build-arg VERSION=$(git describe --tags --always --dirty) \
  --output type=local,dest=/tmp/build-arm64 \
  -f go/Dockerfile go/

# Check the binary
file /tmp/build-arm64/docker-socket-policy
# Expected: ELF 64-bit LSB executable, ARM aarch64, statically linked

# Generate SBOM
syft scan /tmp/build-arm64/docker-socket-policy -o spdx-json > docker-socket-policy-arm64.spdx.json
syft scan /tmp/build-arm64/docker-socket-policy -o cyclonedx-json > docker-socket-policy-arm64.cyclonedx.json
```

## Verify SBOMs from a Release

Binary artifacts are available for both amd64 and arm64:

```bash
# Download SBOMs from a release
gh release download v0.1.0 --pattern "*.spdx.json"
gh release download v0.1.0 --pattern "*.cyclonedx.json"

# Available binaries: docker-socket-policy-{go,rs,ts}-linux-{amd64,arm64}
ls -la docker-socket-policy-*-linux-*

# Inspect SBOM (covers all architectures in the release)
cat docker-socket-policy-go.spdx.json | jq '.packages[].name'
```

## Verify Docker Image Signatures

Docker images are published as **multi-arch manifest indexes** that automatically select the correct architecture (amd64 or arm64) when pulling:

```bash
# Verify Cosign signature on multi-arch image (verifies entire manifest index)
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/chainsafe/docker-socket-policy-go:<version>

# Pull for specific architecture (if you need to override auto-detection)
docker pull --platform linux/amd64 ghcr.io/chainsafe/docker-socket-policy-go:<version>
docker pull --platform linux/arm64 ghcr.io/chainsafe/docker-socket-policy-go:<version>
```

## Verify SBOMs Attached to Docker Images

SBOMs are attached to the multi-arch manifest index, covering all architectures:

```bash
# List attestations on the multi-arch image (covers amd64 and arm64)
cosign verify-attestation \
  --type spdx \
  ghcr.io/chainsafe/docker-socket-policy-go:<version>

# Download and inspect attestation
cosign download attestation \
  --type spdx \
  ghcr.io/chainsafe/docker-socket-policy-go:<version> \
  | jq '.payload | @base64d | fromjson'

# If you need the SBOM for a specific architecture image, download from release artifacts
# Example: docker-socket-policy-go-linux-arm64.spdx.json
```

## Build from Source

### Go
```bash
cd go
go build -trimpath -buildvcs=false \
  -ldflags="-s -w -buildid= -X main.Version=$(git describe --tags --always --dirty)" \
  -o docker-socket-policy .
```

### Rust
```bash
cd rs
cargo build --release --frozen
# Binary at rs/target/release/docker-socket-policy
```

### TypeScript
```bash
cd ts
npm ci --ignore-scripts
npm run build
# Output at ts/dist/
```

## StageX Digest Update Process

StageX images are updated by release. To update pinned digests:

1. Check the current StageX digest files:
   - Pallets: `https://codeberg.org/stagex/stagex/raw/branch/main/digests/pallet.txt`
   - Core: `https://codeberg.org/stagex/stagex/raw/branch/main/digests/core.txt`

2. Look up the current digest for each image:
   ```bash
   curl -s "https://codeberg.org/stagex/stagex/raw/branch/main/digests/pallet.txt" \
     | awk '$2 == "pallet-go" { print $1 }'
   ```

3. Update `FROM` lines in Dockerfiles with the new digest.

4. Run `make verify-reproducible-all` to confirm builds still work.
