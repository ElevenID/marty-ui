# syntax=docker/dockerfile:1.7
FROM rust:1.95-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder
WORKDIR /build/rust
COPY rust /build/rust
RUN --mount=type=cache,id=marty-cargo-registry,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,id=marty-cargo-git,target=/usr/local/cargo/git,sharing=locked \
    cargo build --locked --release -p marty-canvas-sandbox \
    && cp target/release/marty-canvas-sandbox /tmp/marty-canvas-sandbox

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin marty
COPY --from=builder /tmp/marty-canvas-sandbox /usr/local/bin/marty-canvas-sandbox
USER 10001:10001
EXPOSE 8017
HEALTHCHECK --interval=10s --timeout=5s --retries=3 CMD curl -fsS http://localhost:8017/health || exit 1
ENTRYPOINT ["/usr/local/bin/marty-canvas-sandbox"]
