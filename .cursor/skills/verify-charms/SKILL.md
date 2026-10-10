---
name: verify-charms
description: "Drive the Charms CLI (charms) the way a user does: build the test-profile binary, run spell, app, tx, and util commands in an isolated terminal, and capture transcripts. Use to prove CLI behavior in this repo. The prover HTTP server and the Ethereum Foundry contracts are separate surfaces and are not what this skill drives."
---

# Verify Charms

Charms is a Rust CLI for programmable assets on Bitcoin, Cardano, and Ethereum. The user-facing surface this skill drives is the `charms` binary. Two other surfaces exist and are out of this harness: the prover HTTP server (`charms server`, `GET /ready`, `POST /spells/prove`) and the Foundry contracts in `ethereum/` (`forge test`). `charms wallet list` shells out to `bitcoin-cli` and is not an isolated check.

The CLI is short-lived. Launch builds the binary once. Each drive runs in its own tmux session, with a disposable work directory. Proof transcripts stay under `/tmp/charms-verify-evidence/$CHARMS_VERIFY_RUN_ID/` and cleanup does not delete them.

## Launch

From the repository root (the directory that contains `Cargo.toml`):

```bash
export CHARMS_VERIFY_RUN_ID="<unique-id>"
export CHARMS_VERIFY_REPO="<repository-root>"
.cursor/skills/verify-charms/scripts/control-charms launch
```

`CHARMS_VERIFY_RUN_ID` must match `[A-Za-z0-9._-]+`. `protoc` must be on `PATH` before that build. `sp1-prover-types` compiles protobufs and fails with `Could not find protoc` when it is missing. The image workflow installs protoc 34.x; protoc 3.21 is enough for this crate. Check with `protoc --version`.

Launch runs the repo build with `CARGO_TARGET_DIR` set to `<repository-root>/target`:

```bash
cargo build --profile=test --bin charms
```

That profile is the one in `Cargo.toml` (`opt-level = 3`, LTO off). Cargo writes this built-in profile to `target/debug`, not `target/test`. The harness sets `CARGO_TARGET_DIR` on that command, so an ambient `CARGO_TARGET_DIR` cannot send the binary somewhere else. Launch records `<repository-root>/target/debug/charms` and ignores `CHARMS_BIN`. Launch is finished when that command exits 0 and that file is executable. There is no server to wait for.

Launch also creates:

- work: `/tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID/`
- evidence: `/tmp/charms-verify-evidence/$CHARMS_VERIFY_RUN_ID/`
- state: `/tmp/charms-verify-state/$CHARMS_VERIFY_RUN_ID/instance`

Those directories, and the parents `/tmp/charms-verify-work`, `/tmp/charms-verify-state`, and `/tmp/charms-verify-evidence`, are created mode `0700` and owned by the current user. A `CHARMS_VERIFY_WORK`, `CHARMS_VERIFY_STATE`, or `CHARMS_VERIFY_EVIDENCE` path may add directories under that root, such as `/tmp/charms-verify-work/group/run`. Launch creates each missing parent mode `0700` and checks it. If one of them already exists and is a symlink, is not owned by this user, or is writable by group or other, launch stops before it writes state, runners, or evidence. State, runners, and evidence files are created with `O_NOFOLLOW`, so a precreated `instance` symlink is not opened and its target is not truncated.

Do not start a second `cargo build` against the same checkout at the same time. Two runs may share the already-built binary if they use different run ids, work directories, and tmux sessions.

This launch does not pass `--features prover`, so the binary is not an SP1 prover. `charms spell prove` on Bitcoin or Cardano, without `--payload`, posts to `CHARMS_PROVE_API_URL` (default `https://v15.charms.dev/spells/prove`). Building `charms-prover` and proving on the SP1 network is the later path in `features/spell-prove.md`.

The default logger filter is `off` (`RUST_LOG` unset). Do not wait for an info log line to decide that a command finished. Readiness for a drive is `control-charms doctor`.

Teardown is `control-charms cleanup` in [Cleanup](#cleanup).

## Doctor

Run this before every drive, and again whenever a command looks wrong:

```bash
.cursor/skills/verify-charms/scripts/control-charms doctor
```

Doctor is read-only. It uses the binary, work directory, and evidence directory recorded at launch. It does not read `CHARMS_BIN`. It exits 0 only when all of these are true:

- state for `CHARMS_VERIFY_RUN_ID` exists
- the recorded binary is executable and `--version` prints `charms <version>`, where `<version>` is `[workspace.package] version` in `Cargo.toml` (currently `16.0.0`)
- the work directory exists, is the one launch created, and is not inside the repository
- the evidence directory exists

Stdout looks like:

```text
run_id: <id>
repo: <repository-root>
binary: <repository-root>/target/debug/charms
version: charms 16.0.0
work: /tmp/charms-verify-work/<id>
evidence: /tmp/charms-verify-evidence/<id>
ready: yes
```

Doctor does not prove that the binary includes uncommitted Rust edits. After changing Rust code, run launch again. Doctor does not print environment variables. `NETWORK_PRIVATE_KEY` stays in the environment and never appears in doctor output, transcripts, the repo, or a pull request.

`control-charms cli` runs doctor before it drives. If doctor fails, it does not send the command.

## Drive

Put the harness on `PATH` or call it by the path under `.cursor/skills/verify-charms/scripts/`. Read `features/README.md`, then the feature file. Run one command at a time:

```bash
control-charms cli --feature <feature-id> --evidence <name> -- <charms-args>
```

The harness starts a tmux session named `charms-verify-$CHARMS_VERIFY_RUN_ID-<name>`, with working directory `/tmp/charms-verify-work/$CHARMS_VERIFY_RUN_ID`, and runs the binary launch recorded with `<charms-args>`. Pass `--bin <path>` to drive a different binary for that command. `--bin` must resolve to an executable file under `<repo>/target/`; `charms-prover` is the network-proof binary. `--version` must print `charms <version>` or `charms-prover <version>`. Setting `CHARMS_BIN` on `doctor` or `cli` does not change the binary. The runner unsets `CHARMS_PROVE_API_URL`, `APP_SP1_PROVER`, `SPELL_SP1_PROVER`, `NETWORK_PRIVATE_KEY`, `NETWORK_RPC_URL`, `RUST_LOG`, and `RUST_LOGGER`, then exports only the ones that are set in the caller. A value left on an existing tmux server is not kept when the caller left the variable unset. The harness never writes `NETWORK_PRIVATE_KEY` into the evidence files or the pane.

The runner writes the process exit code to a new file in the work directory after the process exits, then prints the captured output into the tmux pane. The harness reads the code from that file. It saves `<name>.pane.txt` only after the pane shows the completion line that follows that output. Text in the pane, including an argument that contains `CHARMS_VERIFY_EXIT:`, is not completion. The same `--evidence` name can be driven again. The new transcript replaces the previous one. The harness exits with the charms process exit code after writing the transcript. A rejection check expects a non-zero exit; the transcript is still written. Default timeout is 60 seconds (`--timeout` seconds). On timeout the harness kills that session, then writes `<name>.txt`, `<name>.stdout`, `<name>.stderr`, `<name>.exit` (`timeout`), and `<name>.pane.txt` from the redirected output. `--cwd` must resolve to the work directory or a subdirectory of it; `app build` uses it so the session is inside the app crate rather than the Charms repository.

Do not run the binary in the repository root. `charms app keygen` with no `--out` writes `.charms/app-key.json` in the current directory. The harness current directory is the work directory.

Stable command handles, not tab order:

- `charms spell check`, `charms spell prove`, `charms spell vk`
- `charms tx show-spell`, `charms tx build`
- `charms app new`, `charms app build`, `charms app vk`, `charms app keygen`, `charms app sign`, `charms app verify`
- `charms util dest`

`charms --help` and `<command> --help` are the user-facing flag list. Prefer the flags named in the feature file.

Other surfaces, not driven by `control-charms cli`:

- Prover server: `charms server --ip 127.0.0.1 --port <free-port>`. Ready when `curl -sf http://127.0.0.1:<port>/ready` prints `OK`. The info line `Server running on 127.0.0.1:<port>` is emitted only if that target is enabled in `RUST_LOG`. Record the pid and kill that pid on teardown. Two servers cannot share a port. The default CLI still calls the hosted prove URL unless `CHARMS_PROVE_API_URL` points at this server.
- Ethereum contracts: from `ethereum/`, `forge test`. That is a chain-contract suite, not a CLI transcript.

## Evidence

Write proof under `/tmp/charms-verify-evidence/$CHARMS_VERIFY_RUN_ID/`. Cleanup never removes that tree.

For each `control-charms cli` invocation the harness writes:

- `<name>.txt` — feature id, run id, binary, argv, exit code, stdout, stderr
- `<name>.stdout`, `<name>.stderr`, `<name>.exit`
- `<name>.pane.txt` — tmux pane (lines may wrap; assert on `<name>.stdout` and `<name>.txt`)

Save doctor with:

```bash
control-charms doctor | tee "$CHARMS_VERIFY_EVIDENCE/doctor.txt"
```

(`CHARMS_VERIFY_EVIDENCE` defaults to `/tmp/charms-verify-evidence/$CHARMS_VERIFY_RUN_ID` when unset; the harness uses that default. `tee` needs the directory launch created, or set the variable to the same path.)

Proof standard:

- Drive the CLI command a user runs. Do not call library functions, test-only setters, or `cargo test` as the proof.
- Capture the command and the resulting state. An exit code alone is not enough.
- Check side effects outside the transcript: files the command writes, and a second CLI view of the same result (for example `app vk` after `app keygen`, or the same `util dest` flags agreeing).
- Do not copy `secret_key` from an app key file into evidence. Record the verification key printed by `charms app vk --pubkey`.
- `--mock` skips proof generation. `--payload` prints the prove request and does not submit it. `--chain ethereum` on `spell prove` prints a placeholder whose proof field is empty. None of those are a Groth16 proof. Confirm the skip by the transcript (empty proof, no HTTP dependency), not by the flag name alone.
- A real SP1 proof is the network path in `features/spell-prove.md`. If `NETWORK_PRIVATE_KEY` is unset, say the proof did not run.

## Cleanup

```bash
.cursor/skills/verify-charms/scripts/control-charms cleanup
```

Cleanup kills only tmux sessions this run recorded (`charms-verify-$CHARMS_VERIFY_RUN_ID-*`). It canonicalizes the work, state, and evidence paths, refuses any path that does not resolve under `/tmp/charms-verify-work/`, `/tmp/charms-verify-state/`, or `/tmp/charms-verify-evidence/`, then deletes the work directory and the state directory. It refuses to delete a work or state directory that is a symlink, is not owned by this user, or is writable by group or other. It does not delete `/tmp/charms-verify-evidence/$CHARMS_VERIFY_RUN_ID/`. It does not kill by process name. Run it after a failed launch or drive as well, so a broken attempt does not leave a session or a work directory. After cleanup, the evidence path must still exist.

## Helpers

The harness is `.cursor/skills/verify-charms/scripts/control-charms` (executable).

```bash
control-charms launch
control-charms doctor
control-charms cli --feature dest --evidence dest-ethereum -- util dest --addr 0x0102030405060708090a0b0c0d0e0f1011121314 --chain ethereum
control-charms cleanup
```

`cli` flags before `--` are `--feature`, `--evidence`, `--timeout`, `--cwd`, and `--bin`. `--cwd` must resolve to the work directory or a subdirectory of it. `--bin` must resolve under the repository `target/` directory. Everything after `--` is the charms argv, without the binary name.
