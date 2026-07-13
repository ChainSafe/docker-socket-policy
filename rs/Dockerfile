FROM --platform=linux/amd64 stagex/pallet-rust@sha256:59d4d0c9e232a05ecb99348f7216b521af1b914a430059dbdb9130018f2afde1 AS build

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
  set -eux
  triple="$(uname -m)-unknown-linux-musl"
  cargo build --frozen --release --target "${triple}"
  install -Dm755 "/target/${triple}/release/docker-socket-policy" /docker-socket-policy
EOF

FROM --platform=linux/amd64 scratch AS run
COPY --from=build /docker-socket-policy /docker-socket-policy
USER 65532:65532
ENTRYPOINT ["/docker-socket-policy"]
