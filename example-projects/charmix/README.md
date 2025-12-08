This is a [Charms](https://charms.dev) app.

It is a simple fungible token managed by a reference NFT. The NFT has a state that specifies the remaining total supply
of the tokens available to mint. If you control the NFT, you can mint new tokens.

NOTE: you may need to install Wasm WASI P1 support:

```sh
rustup target add wasm32-wasip1
```

Build with:

```sh
app_bins=$(charms app build)
```

The resulting Wasm binary will show up at `./target/wasm32-wasip1/release/panoramix-charm.wasm`.

Get the verification key for the app with:

```sh
charms app vk
```

Test the app with a simple NFT mint example:

```sh
export app_vk=$(charms app vk)

# set to a UTXO you're spending (you can see what you have by running `b listunspent`)
export in_utxo_0="d8fa4cdade7ac3dff64047dc73b58591ebe638579881b200d4fea68fc84521f0:0"

export app_id=$(echo -n "${in_utxo_0}" | sha256sum | cut -d' ' -f1)
export addr_0="tb1p3w06fgh64axkj3uphn4t258ehweccm367vkdhkvz8qzdagjctm8qaw2xyv"

prev_txs=02000000000101a3a4c09a03f771e863517b8169ad6c08784d419e6421015e8c360db5231871eb0200000000fdffffff024331070000000000160014555a971f96c15bd5ef181a140138e3d3c960d6e1204e0000000000002251207c4bb238ab772a2000906f3958ca5f15d3a80d563f17eb4123c5b7c135b128dc0140e3d5a2a8c658ea8a47de425f1d45e429fbd84e68d9f3c7ff9cd36f1968260fa558fe15c39ac2c0096fe076b707625e1ae129e642a53081b177294251b002ddf600000000

cat ./spells/mint-nft.yaml | envsubst | charms spell check --prev-txs=${prev_txs} --app-bins=${app_bins} 
```
