# Reproducible RISC-V builds of the charms-spell-checker and charms-proof-wrapper guests.
#
# Build from the repository root:
#   container build -f charms-spell-checker/Dockerfile -t charms-guests .
#
# SP1 6.8.1 matches sp1-zkvm. Ubuntu's clang and the RISC-V gcc from
# `sp1up --c-toolchain` compile blst and secp256k1 for the spell checker.

FROM ubuntu:24.04 AS build

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/root/.sp1/bin:${PATH}

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        cmake \
        curl \
        git \
        libssl-dev \
        libprotobuf-dev \
        pkg-config \
        protobuf-compiler \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

# Host toolchain matches rust-toolchain.toml. `cargo prove` compiles the guest
# with the succinct toolchain installed next.
RUN curl --proto '=https' --tlsv1.2 --retry 10 --retry-connrefused -fsSL https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain 1.96 --profile minimal

RUN curl -fsSL https://sp1up.succinct.xyz | bash \
    && sp1up -v 6.8.1 -c \
    && rustup toolchain list \
    && cargo prove --version

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
