# Toolchain for reproducible RISC-V builds of the zkVM guests.
#
# Published for linux/amd64 and linux/arm64 on pushes to the guest-builder branch:
#   ghcr.io/charmsdev/charms/guest-builder
#
# SP1 6.8.1 matches sp1-zkvm. Ubuntu's clang and the RISC-V gcc from
# `sp1up --c-toolchain` compile blst and secp256k1 for the spell checker.
#
# Build locally (Docker picks the host architecture):
#   docker build -f charms-spell-checker/guest-builder.Dockerfile -t ghcr.io/charmsdev/charms/guest-builder .

FROM ubuntu:24.04

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
    && cargo prove --version \
    && riscv64-unknown-elf-gcc --version

WORKDIR /src
