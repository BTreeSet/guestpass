# syntax=docker/dockerfile:1

# ---- Stage 1: build the embedded frontend ----------------------------------
FROM node:24-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run verify

# ---- Stage 2: build the Rust binary ----------------------------------------
FROM rust:1.97-slim-bookworm AS backend
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Cache dependency compilation against the manifests alone.
COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && mkdir -p frontend/dist && echo "<!doctype html>" > frontend/dist/index.html \
    && GUESTPASS_SKIP_FRONTEND_BUILD=1 cargo build --release --locked || true
RUN rm -rf src

COPY src ./src
COPY --from=frontend /app/frontend/dist ./frontend/dist
ENV GUESTPASS_SKIP_FRONTEND_BUILD=1
RUN cargo build --release --locked

# ---- Stage 3: fetch cloudflared --------------------------------------------
# Pinned by version and verified by checksum. Never downloaded at runtime:
# that would make startup depend on the network and make the binary mutable.
FROM debian:bookworm-slim AS connector
ARG TARGETARCH
ARG CLOUDFLARED_VERSION=2026.7.1
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN curl -fsSL -o /cloudflared \
      "https://github.com/cloudflare/cloudflared/releases/download/${CLOUDFLARED_VERSION}/cloudflared-linux-${TARGETARCH}" \
    && chmod +x /cloudflared

# ---- Stage 4: runtime ------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=backend /app/target/release/guestpass /usr/local/bin/guestpass
COPY --from=connector /cloudflared /usr/local/bin/cloudflared

# No host port is published: the only route in is the outbound tunnel.
USER nonroot
ENTRYPOINT ["/usr/local/bin/guestpass"]
CMD ["serve"]
