`charms-spell-checker` is not a spelling checker: it's a validator for spells.

It runs in a zkVM to produce recursive proofs of correctness for spells — metadata on transactions that
specifies what charms are created in the transaction outputs.

### Building

```sh
cargo prove build --locked --output-directory=../src/bin
```
