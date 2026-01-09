# charms-lib

## Prerequisites

Install LLVM, Rust Wasm target support and wasm-bindgen CLI:

```sh
brew install llvm
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli
```

Make sure LLVM is in your path:

```sh
export PATH="/opt/homebrew/opt/llvm/bin:$PATH"
```

## Building

In this directory:

```sh
cargo build --release --features wasm --target wasm32-unknown-unknown

wasm-bindgen --out-dir target/wasm-bindgen-nodejs --target nodejs ../target/wasm32-unknown-unknown/release/charms_lib.wasm
```

## Testing

In this directory:

```sh
node test/extractAndVerifySpell.node.test.js
```

## Packaging for NPM

Make sure `wasm-pack` is installed:

```bash
cargo install wasm-pack
```

Pack charms-lib for NPM:

```bash
wasm-pack build --release --features wasm
```

The NPM package will be in `./pkg` dir.
