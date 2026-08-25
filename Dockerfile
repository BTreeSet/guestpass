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

# Cache dependency compilation against the manifests alone. The xtask member
# is CI-only and never compiled here, but cargo needs its manifest and a target
# file to resolve the workspace.
COPY Cargo.toml Cargo.lock rust-toolchain.toml build.rs ./
COPY xtask/Cargo.toml xtask/Cargo.toml
RUN mkdir -p src xtask/src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && echo "fn main() {}" > xtask/src/main.rs \
    && mkdir -p frontend/dist && echo "<!doctype html>" > frontend/dist/index.html \
    && GUESTPASS_SKIP_FRONTEND_BUILD=1 cargo build --release --locked -p guestpass || true
RUN rm -rf src

COPY src ./src
COPY --from=frontend /app/frontend/dist ./frontend/dist
ENV GUESTPASS_SKIP_FRONTEND_BUILD=1
RUN cargo build --release --locked -p guestpass

# ---- Stage 3: fetch cloudflared --------------------------------------------
# Always the latest release, resolved at build time: an outdated connector is
# a liability, and Cloudflare supports only recent versions. Never downloaded
# at runtime: that would make startup depend on the network and the binary
# mutable. The `releases/latest` redirect names the version; resolving it once
# and downloading by that name keeps the recorded version and the fetched
# binary consistent even if a release lands mid-build. The resolved version is
# recorded in the image and logged at startup.
FROM debian:bookworm-slim AS connector
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN latest=$(curl -fsSLo /dev/null -w '%{url_effective}' \
      "https://github.com/cloudflare/cloudflared/releases/latest") \
    && version="${latest##*/}" \
    && case "$version" in [0-9][0-9][0-9][0-9].*) ;; *) echo "unexpected version: $version" >&2; exit 1 ;; esac \
    && printf '%s\n' "$version" > /cloudflared.version \
    && curl -fsSL -o /cloudflared \
      "https://github.com/cloudflare/cloudflared/releases/download/${version}/cloudflared-linux-${TARGETARCH}" \
    && chmod +x /cloudflared

# The runtime stage has no shell, so the socket directory is assembled here.
RUN mkdir -p /runtree && ln -s /dev/shm/guestpass /runtree/guestpass

# ---- Stage 4: runtime ------------------------------------------------------
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=backend /app/target/release/guestpass /usr/local/bin/guestpass
COPY --from=connector /cloudflared /usr/local/bin/cloudflared
COPY --from=connector /cloudflared.version /etc/cloudflared.version

# No port is published and none is opened: guestpass listens on a UNIX socket at
# /run/guestpass/guest.sock, which cloudflared reaches inside this container.
# That directory is a symlink to /dev/shm/guestpass, the one tmpfs every OCI
# runtime mounts, so a read-only rootfs holds the socket with no mount flag.
COPY --from=connector /runtree /run
USER nonroot
ENTRYPOINT ["/usr/local/bin/guestpass"]
CMD ["serve"]

# Build metadata. The registry and the Supervisor read these; the program does
# not. The values that change per build arrive as arguments; the values that
# describe the project are written here, so a build outside CI still produces a
# labelled image.
ARG BUILD_ARCH="amd64"
ARG BUILD_DATE
ARG BUILD_REF
ARG BUILD_REPOSITORY="BTreeSet/guestpass"
ARG BUILD_VERSION="dev"

LABEL \
    io.hass.name="guestpass" \
    io.hass.description="Give a visitor a QR code that turns on one light, from anywhere, without exposing Home Assistant." \
    io.hass.arch="${BUILD_ARCH}" \
    io.hass.type="addon" \
    io.hass.version="${BUILD_VERSION}" \
    maintainer="Joe Fang <guestpass@oss.joefang.org>" \
    org.opencontainers.image.title="guestpass" \
    org.opencontainers.image.description="Give a visitor a QR code that turns on one light, from anywhere, without exposing Home Assistant." \
    org.opencontainers.image.vendor="BTreeSet" \
    org.opencontainers.image.authors="Joe Fang <guestpass@oss.joefang.org>" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.url="https://github.com/${BUILD_REPOSITORY}" \
    org.opencontainers.image.source="https://github.com/${BUILD_REPOSITORY}" \
    org.opencontainers.image.documentation="https://github.com/${BUILD_REPOSITORY}/blob/main/README.md" \
    org.opencontainers.image.created="${BUILD_DATE}" \
    org.opencontainers.image.revision="${BUILD_REF}" \
    org.opencontainers.image.version="${BUILD_VERSION}"
