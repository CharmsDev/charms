# Concepts

Shared domain vocabulary for this project — entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then accretes as ce-compound and ce-compound-refresh process learnings; direct edits are fine. Glossary only, not a spec or catch-all.

## Spell

### Spell
The description of how charms move in one transaction. On Bitcoin and Cardano, the copy stored on the chain omits the input list, because the transaction already names its inputs. Checking a proof puts that input list back onto the spell before accepting it. A proved Ethereum spell is stored with its inputs.

### Charm
App state attached to one output. A spell's outputs carry charms. The app that owns a charm decides whether that transformation is allowed.

### Scrolls output
A Bitcoin output the Scrolls signer can spend. The signer derives that key from the creating transaction's first input and the output index. A spell may treat an output as Scrolls-controlled only when that signer has signed the output's script together with that same first input.

A replacement that spends the same first input keeps the key. It keeps the signature when the script map is unchanged. The signature is not bound to the creating transaction's own id. When the creating transaction is a coinbase, the spend path uses a zero transaction id and the block height in place of the coinbase input's output index. The spell's own input list does not perform that substitution.
