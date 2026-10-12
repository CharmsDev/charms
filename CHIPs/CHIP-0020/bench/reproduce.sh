#!/usr/bin/env bash
# Rebuild the CHIP-0020 quorum-check measurement from helios tag 0.11.1.
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d "${TMPDIR:-/tmp}/chip-0020-bench.XXXXXX")"
echo "work $work"

git clone --depth 1 --branch 0.11.1 https://github.com/a16z/helios.git "$work/helios"
git -C "$work/helios" apply "$root/helios-0.11.1-wasm32.patch"
cp -a "$root/helios-agg-wasm" "$work/helios-agg-wasm"
cp -a "$root/agg-runner" "$work/agg-runner"

cargo +1.96 build --release --target wasm32-unknown-unknown --manifest-path "$work/helios-agg-wasm/Cargo.toml"
wasm="$work/helios-agg-wasm/target/wasm32-unknown-unknown/release/helios_agg_wasm.wasm"
echo "wasm_bytes $(wc -c < "$wasm")"

cargo +1.96 build --release --manifest-path "$work/agg-runner/Cargo.toml"
SKIP_NATIVE=1 "$work/agg-runner/target/release/agg_runner" "$wasm"
