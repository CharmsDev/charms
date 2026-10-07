`charms-spell-checker` is not a spelling checker: it's a validator for spells.

It runs in a zkVM to produce recursive proofs of correctness for spells — metadata on transactions that
specifies what charms are created in the transaction outputs.

### Building

From the repository root, build both guest ELFs in Linux:

```sh
docker build -f charms-spell-checker/Dockerfile -t charms-guests .
```

`charms-spell-checker` validates spells. `charms-proof-wrapper` verifies that proof and is the program proved as a
Groth16 SNARK. The image derives `SPELL_CHECKER_VK` from the spell-checker ELF and writes it into the wrapper before
that guest is compiled. Copy the ELFs into `src/bin`, where the host crate embeds them, and copy the updated key back
into the wrapper source:

```sh
docker run --rm --entrypoint cat charms-guests /opt/charms-spell-checker > src/bin/charms-spell-checker
docker run --rm --entrypoint cat charms-guests /opt/charms-proof-wrapper > src/bin/charms-proof-wrapper
docker run --rm --entrypoint cat charms-guests /opt/charms-proof-wrapper-lib.rs > charms-proof-wrapper/src/lib.rs
chmod +x src/bin/charms-spell-checker src/bin/charms-proof-wrapper
```

`docker run --rm charms-guests` prints the type of each ELF.
