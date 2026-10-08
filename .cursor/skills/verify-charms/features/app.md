# Sign a versioned app

A user creates a Charms app, reads its verification key, and for a versioned app generates a BIP-340 key, signs the Wasm binary, and verifies that signature. The verification key of a simple app is the SHA-256 of the Wasm file. The verification key of a versioned app is the SHA-256 of the signing public key.

## Sub-features

- `app-new` creates a new app crate from the Charms template.
- `app-build` compiles the app to `wasm32-wasip1` and prints the `.wasm` path.
- `app-vk-wasm` prints the simple-app verification key of a Wasm file.
- `app-keygen` writes a new signing key file and refuses to overwrite it.
- `app-vk-pubkey` prints the versioned-app verification key of that key file.
- `app-sign` writes a signature over the Wasm bytes.
- `app-verify` accepts that signature and rejects a changed binary.

## How to get to it (user POV)

- Run `charms app new <name>` in the directory that should contain the new app.
- From the app crate, run `charms app build`.
- Run `charms app vk [PATH] [--pubkey <FILE>]`.
- Run `charms app keygen [--out <FILE>]`.
- Run `charms app sign [--key <FILE>] [--bin <FILE>] [--out <FILE>]`.
- Run `charms app verify [--bin <FILE>] [--sig <FILE>]`.

## Driving it with control-charms

Preconditions:

- `control-charms doctor` prints `ready: yes`.
- The work directory is `/tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID` and does not contain `app-key.json` or `app.wasm`.
- `app new` and `app build` need network access to GitHub, `cargo-generate`, and the `wasm32-wasip1` target. The sign and verify steps below use a Wasm file written in the work directory so they do not clone the template. Do not treat that file as a built app contract.

- **Wasm file.** Write a minimal Wasm module into the work directory. Run `python3 -c 'import os; open("/tmp/charms-verify-work/"+os.environ["CHARMS_VERIFY_RUN_ID"]+"/app.wasm","wb").write(bytes.fromhex("0061736d01000000010401600000030201000503010001071302066d656d6f72790200065f737461727400000a040102000b"))'`. The file exists and is 50 bytes.
- **Simple verification key.** Hash that file. Run `control-charms cli --feature app --evidence app-vk-wasm -- app vk /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm`. Exit code `0` and stdout is `87799c1b578e1ef444797b90bd09efe88f1af0b1810d578f9ccf03df9b1de499`.
- **Generate a key.** Write the key only in the work directory. Run `control-charms cli --feature app --evidence app-keygen -- app keygen --out /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app-key.json`. Exit code `0`. Stderr contains `wrote app signing keypair to /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app-key.json`. The file mode is `0600`. Do not copy the file into evidence.
- **Versioned verification key.** Read the key back through the CLI. Run `control-charms cli --feature app --evidence app-vk-pubkey -- app vk --pubkey /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app-key.json`. Exit code `0`. Stdout is 64 hex characters and differs from `87799c1b578e1ef444797b90bd09efe88f1af0b1810d578f9ccf03df9b1de499`. Confirm the file agrees by running `python3 -c 'import json,os; print(json.load(open("/tmp/charms-verify-work/"+os.environ["CHARMS_VERIFY_RUN_ID"]+"/app-key.json"))["vk"])'`. That line equals the stdout. Do not print `secret_key`.
- **Sign.** Sign the Wasm file. Run `control-charms cli --feature app --evidence app-sign -- app sign --key /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app-key.json --bin /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm --out /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm.sig.yaml`. Exit code `0`. Stderr contains `signed wasm module; wrote app signature to /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm.sig.yaml`. The signature file's only key equals the stdout of `app-vk-pubkey`.
- **Verify.** Check the signature. Run `control-charms cli --feature app --evidence app-verify -- app verify --bin /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm --sig /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm.sig.yaml`. Exit code `0`. Stderr contains `signature verified for /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm`.
- **Reject a changed binary.** Change one byte of `app.wasm`, then run `control-charms cli --feature app --evidence app-verify-tamper -- app verify --bin /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm --sig /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app.wasm.sig.yaml`. Exit code is non-zero and stderr contains `signature verification failed`.
- **Reject overwrite.** Run `control-charms cli --feature app --evidence app-keygen-overwrite -- app keygen --out /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/app-key.json`. Exit code is non-zero and stderr contains `refusing to overwrite existing keypair`.
- **Create from the template.** Run `control-charms cli --feature app --evidence app-new --timeout 600 -- app new verify-token`. Exit code `0` and `/tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/verify-token/Cargo.toml` exists. Skip this entry when GitHub or `cargo-generate` is unavailable and report that precondition. Do not report `app-sign` as a substitute.
- **Build.** After `app-new`, run `control-charms cli --cwd /tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/verify-token --feature app --evidence app-build --timeout 600 -- app build`. Exit code `0` and stdout is the path of the built `.wasm` file. Do not run `app build` in the Charms repository root or in the work directory itself.
- **Proof.** Keep `app-vk-wasm.txt`, `app-vk-pubkey.txt`, and `app-verify.txt`. They show the simple-app hash, the versioned-app key, and `signature verified`. They do not contain `secret_key`.

## Gotchas

- `app keygen` without `--out` writes `.charms/app-key.json` in the current directory and refuses to overwrite it. The harness current directory is the work directory; still pass `--out`.
- The key file contains `secret_key`. Evidence may record the `vk` from `charms app vk --pubkey`. It must not contain the secret.
- `app vk <PATH>` hashes the Wasm bytes. `app vk --pubkey <FILE>` hashes the signing public key. They are different keys. Passing both flags fails with `pass at most one of <PATH> or --pubkey`.
- `app sign` and `app verify` hash the file bytes. They do not execute the module. The 50-byte module above is not a Charms app contract.
- `app new` clones `https://github.com/CharmsDev/charms-app` and installs `cargo-generate` when it is missing. It creates `./<name>` in the current directory.
- `app build` runs `cargo build --locked --release --target=wasm32-wasip1` in the current crate and prints the `.wasm` path on stdout. If `.charms/app-key.json` exists, it also writes `<wasm>.sig.yaml`.
- Verification-key hex from `app vk` has no `0x` prefix. `charms spell vk` does prefix `0x`.
