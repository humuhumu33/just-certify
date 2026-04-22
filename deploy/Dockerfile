# syntax=docker/dockerfile:1.6
#
# Single-image build for the just-certify service. The image bundles:
#   * `sem-ipld-service` — the HTTP binary.
#   * `ipfs` (Kubo 0.30.0) — the block-store sidecar, pinned.
#   * `start.sh` — boots Kubo, waits for its RPC, then exec's the service.
#
# The UOR foundation path dependency is resolved by cloning UOR-Framework
# into `/UOR-Framework` during the build stage. Each crate's Cargo.toml
# references `../../../../UOR-Framework/foundation`, which — from
# `/build/crates/<crate>/Cargo.toml` — resolves to `/UOR-Framework/foundation`.

# ─── Build stage ────────────────────────────────────────────────────────────
FROM rust:1.81-bookworm AS build

# Clone UOR-Framework first so the path dependency resolves during
# `cargo build`. The clone is pinned to the main branch — if you want
# a specific commit, pass `--build-arg UOR_FOUNDATION_REF=<sha>`.
ARG UOR_FOUNDATION_REF=main
RUN git clone --depth=1 --branch ${UOR_FOUNDATION_REF} \
    https://github.com/uor-foundation/UOR-Framework.git /UOR-Framework \
 || git clone --depth=1 https://github.com/uor-foundation/UOR-Framework.git /UOR-Framework

WORKDIR /build
COPY . /build

# Release build of just the service binary. Workspace `lto = "thin"`
# from the root Cargo.toml keeps size reasonable.
RUN cargo build --release --bin sem-ipld-service \
 && strip target/release/sem-ipld-service

# ─── Runtime stage ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl wget tini \
 && rm -rf /var/lib/apt/lists/*

# Kubo 0.30.0 — pinned to the version sem-ipld-service is tested
# against. Upgrades must go through a new image tag, not a silent
# base-image bump.
ARG KUBO_VERSION=v0.30.0
RUN wget -q "https://dist.ipfs.tech/kubo/${KUBO_VERSION}/kubo_${KUBO_VERSION}_linux-amd64.tar.gz" \
      -O /tmp/kubo.tgz \
 && tar xzf /tmp/kubo.tgz -C /tmp \
 && install -m 0755 /tmp/kubo/ipfs /usr/local/bin/ipfs \
 && rm -rf /tmp/kubo /tmp/kubo.tgz

COPY --from=build /build/target/release/sem-ipld-service /usr/local/bin/sem-ipld-service
COPY deploy/start.sh /usr/local/bin/start.sh
RUN chmod +x /usr/local/bin/start.sh

# /data is mounted as a Railway volume at runtime (VOLUME keyword is banned).
ENV IPFS_PATH=/data/ipfs

# Service defaults — override via platform secrets / `docker run -e`.
ENV SEM_IPLD_STORE=kubo
ENV SEM_IPLD_IPFS_API_URL=http://127.0.0.1:5001
ENV SEM_IPLD_BIND=0.0.0.0:8787
ENV SEM_IPLD_LRU_CAPACITY=10000

EXPOSE 8787

# `tini` as PID 1 gives us correct signal forwarding to both Kubo and
# the service under SIGTERM — important for graceful shutdown on
# Railway / platform rolling deploys.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/usr/local/bin/start.sh"]
