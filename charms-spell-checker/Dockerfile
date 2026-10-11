# Reproducible RISC-V builds of the charms-spell-checker and charms-proof-wrapper guests.
#
# The toolchain image is ghcr.io/charmsdev/charms/guest-builder (linux/amd64 and
# linux/arm64). Docker on Apple Silicon pulls the arm64 image.
#
# Build from the repository root:
#   docker build -f charms-spell-checker/Dockerfile -t charms-guests .

ARG GUEST_BUILDER=ghcr.io/charmsdev/charms/guest-builder:latest
FROM ${GUEST_BUILDER} AS build

WORKDIR /src
COPY . .
RUN cd charms-spell-checker \
    && cargo prove build --locked --output-directory=/out \
    && test -s /out/charms-spell-checker \
    && cargo run --release --manifest-path /src/charms-proof-wrapper/vk/Cargo.toml -- \
        /out/charms-spell-checker /src/charms-proof-wrapper/src/lib.rs \
    && cp /src/charms-proof-wrapper/src/lib.rs /out/charms-proof-wrapper-lib.rs \
    && cd /src \
    && cargo prove build --locked -p charms-proof-wrapper --output-directory=/out \
    && test -s /out/charms-proof-wrapper \
    && rm -rf /src/target /src/charms-spell-checker/target /src/charms-proof-wrapper/vk/target

FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends file \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/charms-spell-checker /opt/charms-spell-checker
COPY --from=build /out/charms-proof-wrapper /opt/charms-proof-wrapper
COPY --from=build /out/charms-proof-wrapper-lib.rs /opt/charms-proof-wrapper-lib.rs
CMD ["sh", "-c", "file /opt/charms-spell-checker /opt/charms-proof-wrapper"]
