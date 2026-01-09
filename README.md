![Charms](.github/logo-charms.png)

---
[![crates.io](https://img.shields.io/crates/v/charms)](https://crates.io/crates/charms)

`charms` is a library, CLI tool and web API for programmable tokens and NFTs on top of Bitcoin.

_Charms_ are bundles of tokens, NFTs and arbitrary app state, enchanting Bitcoin UTXOs, that can be used to build
**apps** directly on Bitcoin.

For example: Charms NFTs have state, so it's easy to create a token managed by an NFT: the token's remaining unminted
supply is stored in the NFT state, and you can only mint the token when updating the NFT state accordingly (in the same
transaction).

Charms are created using _spells_ — special messages added to Bitcoin transactions, manifesting creation and
**transformation** of charms.

## Get Started

Install Charms CLI:

```sh
export CARGO_TARGET_DIR=$(mktemp -d)/target
cargo install --locked charms
```

Create your first app (your own token on Bitcoin):

```sh
charms app new my-token
cd ./my-token
ls -l
```

Now head on to [docs.charms.dev](https://docs.charms.dev) to learn more!

## Documentation

Concepts and guides: [docs.charms.dev](https://docs.charms.dev)

Charms CLI:

```sh
charms --help
```

## Inspiration

Charms are inspired by [Runes](https://docs.ordinals.com/runes.html) — a way to create tokens on top of Bitcoin. Charms
are, in a way, a generalization of Runes.

The main difference is that Charms are programmable (and composable).

---
©️2026 Charms Inc.
