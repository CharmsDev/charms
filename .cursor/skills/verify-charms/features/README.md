# Charms CLI verification map

This directory is the maintained source for verifying the user-facing behavior of the `charms` CLI. Read the index before driving the app, then use the matching feature file as the recipe.

## Baseline preconditions

- Build with `control-charms launch`, which runs `cargo build --profile=test --bin charms` and produces `target/test/charms`.
- Set `CHARMS_VERIFY_RUN_ID` to a unique id and keep it for launch, doctor, every drive, and cleanup.
- Set `CHARMS_VERIFY_REPO` to the repository root.
- The disposable work directory is `/tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID`. The harness uses it as the process working directory.
- Put `control-charms` on `PATH` (`.cursor/skills/verify-charms/scripts/control-charms`).
- Run `control-charms doctor` and require `ready: yes`, the test-profile binary, and `version: charms 16.0.0` (or the current `[workspace.package] version` if that line has changed).
- Never drive a binary this run did not build, and never run mutating commands in the repository root.

## Driving conventions

- Start every recipe from the baseline state unless its preconditions say otherwise.
- Treat every command as literal. Keep quoted names and flags unchanged.
- Run terminal actions through `control-charms cli -- <charms-args>`.
- The harness exits with the charms exit code. A recipe that expects rejection still leaves a transcript.
- Do not remove proof artifacts during cleanup. Cleanup deletes the work directory and this run's tmux sessions only.

## Proof and skip reporting

- Capture the user action and the resulting state, not only the exit code.
- CLI proof includes the command, stdout, stderr, and exit code in `/tmp/charms-verify-evidence/$CHARMS_VERIFY_RUN_ID/<name>.txt`.
- Mutation proof includes a second user-facing read of the written value, without copying secret key material into the evidence.
- Record the feature ID and entry point used with every artifact (`--feature` and `--evidence`).
- Report an unreachable path with the attempted command and the unmet precondition.
- Do not report a skipped entry point as verified through a different path.
- `--mock`, `--payload`, and an Ethereum placeholder are not a network proof. A real proof uses the SP1 network path in [Prove a spell](./spell-prove.md). If `NETWORK_PRIVATE_KEY` is unset, record that the proof did not run.

## Feature entry contract

Each feature file starts with an H1 title and one paragraph describing the user-visible behavior. It then uses exactly four H2 sections in this order.

1. `Sub-features` lists short IDs with one line for each behavior.
2. `How to get to it (user POV)` lists every user entry point.
3. `Driving it with control-charms` starts with `Preconditions:` and uses labeled bullets that pair each user action with an exact command and observable result.
4. `Gotchas` lists traps that can waste or invalidate a verification run.

Keep implementation details out of the map. Name only user paths, stable handles, required state, commands, and observable proof.

## Features

- [Derive a destination](./dest.md) covers Bitcoin, Cardano, and Ethereum address encoding, Cardano app proxies, and rejected selector combinations.
- [Sign a versioned app](./app.md) covers app creation, the simple-app verification key, key generation, signing, verification, and a rejected overwrite.
- [Check a spell](./spell-check.md) covers a local contract check with no proof, and a spell that is missing inputs.
- [Prove a spell](./spell-prove.md) covers the spell verification key, a payload that does not call the API, an Ethereum placeholder with an empty proof, and a later SP1 network proof.
- [Show a spell](./show-spell.md) covers extracting a spell from a Bitcoin transaction and the no-spell result.
