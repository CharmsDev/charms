`charms-spell-checker` is not a spelling checker: it's a validator for spells.

It runs in a zkVM to produce recursive proofs of correctness for spells — metadata on transactions that
specifies what charms are created in the transaction outputs.

### Building

The zkVM toolchain is a separate image, `ghcr.io/charmsdev/charms/guest-builder`.
It carries Rust 1.96, SP1 6.8.1, and the RISC-V C compiler for `blst` and `secp256k1`.
Pushes to the `guest-builder` branch publish `linux/amd64` and `linux/arm64`, so Docker
on Apple Silicon pulls a native image.

Build both guest ELFs from the repository root. `GUEST_BUILDER` is required. Pass a published
image by digest — `docker buildx imagetools inspect ghcr.io/charmsdev/charms/guest-builder:latest`
prints the current one — so a later toolchain rebuild keeps these ELFs and verification keys stable:

```sh
docker build -f charms-spell-checker/Dockerfile \
  --build-arg GUEST_BUILDER=ghcr.io/charmsdev/charms/guest-builder@sha256:<digest> \
  -t charms-guests .
```

An image built from `guest-builder.Dockerfile` is passed the same way, by its local name.

`charms-spell-checker` validates spells. `charms-proof-wrapper` verifies that proof and is the program proved as a
Groth16 SNARK. The image derives `SPELL_CHECKER_VK` from the spell-checker ELF and writes it into the wrapper before
that guest is compiled. It also writes both serialized SP1 verifying keys, and writes the wrapper key into
`charms-lib` as `SPELL_VK`. Copy the ELFs into `src/bin`, where the host crate embeds them, and copy the keys and
sources back with them. `Prover::new` checks those cached keys against the constants:

```sh
docker run --rm --entrypoint cat charms-guests /opt/charms-spell-checker > src/bin/charms-spell-checker
docker run --rm --entrypoint cat charms-guests /opt/charms-proof-wrapper > src/bin/charms-proof-wrapper
docker run --rm --entrypoint cat charms-guests /opt/charms-spell-checker-vk.bin > src/bin/charms-spell-checker-vk.bin
docker run --rm --entrypoint cat charms-guests /opt/charms-proof-wrapper-vk.bin > src/bin/charms-proof-wrapper-vk.bin
docker run --rm --entrypoint cat charms-guests /opt/charms-proof-wrapper-lib.rs > charms-proof-wrapper/src/lib.rs
docker run --rm --entrypoint cat charms-guests /opt/charms-lib.rs > charms-lib/src/lib.rs
chmod +x src/bin/charms-spell-checker src/bin/charms-proof-wrapper
```

`docker run --rm charms-guests` prints the type of each ELF.
