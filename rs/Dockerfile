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

RUN --network=none <<-'EOF'
  # Detect target platform: TARGETPLATFORM is set by buildx, fallback to native arch for docker build
  if [ -n "${TARGETPLATFORM}" ]; then
    platform="${TARGETPLATFORM}"
  else
    # Native build: detect machine architecture
    machine_arch=$(uname -m)
    case "${machine_arch}" in
      x86_64)  platform="linux/amd64" ;;
      aarch64) platform="linux/arm64" ;;
      *) echo "Unsupported native architecture: ${machine_arch}"; exit 1 ;;
    esac
  fi
  
  # Map platform to Rust target triple
  case "${platform}" in
    linux/amd64)  triple="x86_64-unknown-linux-musl" ;;
    linux/arm64)  triple="aarch64-unknown-linux-musl" ;;
    *) echo "Unsupported platform: ${platform}"; exit 1 ;;
  esac
  
  cargo build --frozen --release --target "${triple}"
  install -Dm755 "/target/${triple}/release/docker-socket-policy" /docker-socket-policy
EOF

FROM scratch AS run
COPY --from=build /docker-socket-policy /docker-socket-policy
USER 65532:65532
ENTRYPOINT ["/docker-socket-policy"]
