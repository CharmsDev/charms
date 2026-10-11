# Reproducible RISC-V builds of the charms-spell-checker and charms-proof-wrapper guests.
#
# GUEST_BUILDER is the toolchain image, published for linux/amd64 and linux/arm64.
# Pass it by digest. The `latest` and `sha-<commit>` tags move when that image is
# rebuilt, which changes the guest ELFs and the protocol verification keys.
#
#   docker build -f charms-spell-checker/Dockerfile \
#     --build-arg GUEST_BUILDER=ghcr.io/charmsdev/charms/guest-builder@sha256:<digest> \
#     -t charms-guests .

ARG GUEST_BUILDER
FROM ${GUEST_BUILDER} AS build

WORKDIR /src
COPY . .
RUN cd charms-spell-checker \
    && cargo prove build --locked --output-directory=/out \
    && test -s /out/charms-spell-checker \
    && cargo run --release --locked --manifest-path /src/charms-proof-wrapper/vk/Cargo.toml -- \
        checker \
        /out/charms-spell-checker \
        /src/charms-proof-wrapper/src/lib.rs \
        /out/charms-spell-checker-vk.bin \
    && test -s /out/charms-spell-checker-vk.bin \
    && cp /src/charms-proof-wrapper/src/lib.rs /out/charms-proof-wrapper-lib.rs \
    && cd /src \
    && cargo prove build --locked -p charms-proof-wrapper --output-directory=/out \
    && test -s /out/charms-proof-wrapper \
    && cargo run --release --locked --manifest-path /src/charms-proof-wrapper/vk/Cargo.toml -- \
        wrapper \
        /out/charms-proof-wrapper \
        /src/charms-lib/src/lib.rs \
        /out/charms-proof-wrapper-vk.bin \
    && test -s /out/charms-proof-wrapper-vk.bin \
    && cp /src/charms-lib/src/lib.rs /out/charms-lib.rs \
    && rm -rf /src/target /src/charms-spell-checker/target /src/charms-proof-wrapper/vk/target

FROM ubuntu:24.04
RUN apt-get update \
    && apt-get install -y --no-install-recommends file \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/charms-spell-checker /opt/charms-spell-checker
COPY --from=build /out/charms-proof-wrapper /opt/charms-proof-wrapper
COPY --from=build /out/charms-spell-checker-vk.bin /opt/charms-spell-checker-vk.bin
COPY --from=build /out/charms-proof-wrapper-vk.bin /opt/charms-proof-wrapper-vk.bin
COPY --from=build /out/charms-proof-wrapper-lib.rs /opt/charms-proof-wrapper-lib.rs
COPY --from=build /out/charms-lib.rs /opt/charms-lib.rs
CMD ["sh", "-c", "file /opt/charms-spell-checker /opt/charms-proof-wrapper"]
