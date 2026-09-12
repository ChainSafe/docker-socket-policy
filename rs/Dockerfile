FROM stagex/pallet-rust@sha256:59d4d0c9e232a05ecb99348f7216b521af1b914a430059dbdb9130018f2afde1 AS build

ENV SOURCE_DATE_EPOCH=1
ENV CARGO_TARGET_DIR=/target
ENV CARGO_INCREMENTAL=0
ENV RUSTFLAGS="-C codegen-units=1 -C target-feature=+crt-static -C strip=symbols --remap-path-prefix=/app=. --remap-path-prefix=/target=target"

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo fetch --locked --target "$(uname -m)-unknown-linux-musl" 2>/dev/null || true

COPY src/ src/

RUN --network=none /bin/bash << 'EOFBUILD'
set -e
echo "[DEBUG] TARGETPLATFORM=${TARGETPLATFORM}"
echo "[DEBUG] uname -m=$(uname -m)"
platform="${TARGETPLATFORM}"
if [ -z "$platform" ]; then
  case "$(uname -m)" in
    x86_64)  platform="linux/amd64" ;;
    aarch64) platform="linux/arm64" ;;
    *) echo "Unsupported native architecture: $(uname -m)"; exit 1 ;;
  esac
fi
echo "[DEBUG] Detected platform=$platform"
case "$platform" in
  linux/amd64)  triple="x86_64-unknown-linux-musl" ;;
  linux/arm64)  triple="aarch64-unknown-linux-musl" ;;
  *) echo "Unsupported platform: $platform"; exit 1 ;;
esac
cargo build --frozen --release --target "$triple"
install -Dm755 "/target/$triple/release/docker-socket-policy" /docker-socket-policy
EOFBUILD

FROM scratch AS run
COPY --from=build /docker-socket-policy /docker-socket-policy
USER 65532:65532
ENTRYPOINT ["/docker-socket-policy"]
