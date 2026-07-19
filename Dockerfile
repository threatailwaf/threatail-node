# Multi-stage build for the Threatail node.
# Produces a statically linked musl binary in a minimal Alpine image.
#
#   docker build -t threatail-node .
#   docker run -d -p 80:80 -p 443:443 \
#     -v /etc/threatail:/etc/threatail:ro \
#     -v threatail-data:/var/lib/threatail \
#     threatail-node

FROM rust:1.97-alpine AS builder

RUN apk add --no-cache musl-dev pkgconfig

WORKDIR /build

# Cache dependencies separately from source: this layer is only invalidated
# when the manifests change, which keeps rebuilds fast during development.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release 2>/dev/null || true \
    && rm -rf src

COPY src ./src
COPY ml ./ml

# Touch main.rs so cargo does not reuse the dummy build above.
RUN touch src/main.rs && cargo build --release && strip target/release/threatail-node


FROM alpine:3.20

# Root certificates are required for TLS to backends, ACME and cloud mode.
RUN apk add --no-cache ca-certificates && update-ca-certificates

# Run unprivileged. Ports 80 and 443 are published by the container runtime,
# so the process itself does not need to bind privileged ports as root.
RUN addgroup -S threatail && adduser -S -G threatail threatail \
    && mkdir -p /var/lib/threatail /etc/threatail \
    && chown -R threatail:threatail /var/lib/threatail

COPY --from=builder /build/target/release/threatail-node /usr/local/bin/threatail-node

USER threatail

# 80 = HTTP (and ACME challenges), 443 = HTTPS.
EXPOSE 80 443

# Config is read from /etc/threatail/config.json unless a path is given.
ENTRYPOINT ["/usr/local/bin/threatail-node"]
