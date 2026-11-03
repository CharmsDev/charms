use anyhow::{Context, anyhow, bail};
use candid::{CandidType, Decode, Encode, Principal};
use charms_client::{
    NormalizedSpell, SignedScrollOutputs, ensure_no_coinbase_scroll_outputs, tx::Chain,
};
use charms_data::UtxoId;
use ic_agent::Agent;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const SCROLLS_BITCOIN_V15_CANISTER_ID: &str = "rpgc6-oqaaa-aaaak-qy3uq-cai";

/// Mirror of the canister's [`Addresses`](scrolls_bitcoin::Addresses) result —
/// declared locally so we don't pull the canister crate into the host build.
#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
struct CanisterAddresses {
    script_pubkeys: BTreeMap<u32, String>,
    signature: String,
}

/// If `spell.tx.scrolls` is non-empty and the spell is on Bitcoin, call the
/// `scrolls_bitcoin_v15` canister to fetch the signed `scriptPubKey` map and
/// write each `scriptPubKey` into `spell.tx.coins[i].dest` so the Bitcoin
/// transaction we ultimately build pays the canister-controlled scripts.
///
/// Returns `None` if there's no scrolls work to do (no scroll outputs, not
/// Bitcoin, or spell-without-inputs — which is a malformed case that the
/// downstream validator will reject anyway).
pub async fn fill_scroll_outputs(
    spell: &mut NormalizedSpell,
    chain: Chain,
) -> anyhow::Result<Option<SignedScrollOutputs>> {
    if chain != Chain::Bitcoin {
        return Ok(None);
    }
    ensure_no_coinbase_scroll_outputs(spell)?;
    let Some(scrolls) = spell.tx.scrolls.as_ref().filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    let Some(tx_in_0) = spell.tx.ins.as_ref().and_then(|ins| ins.first()).cloned() else {
        return Ok(None);
    };
    let out_is: Vec<u32> = scrolls.iter().copied().collect();

    let signed = call_canister_addresses(&tx_in_0, out_is).await?;

    let coins =
        spell.tx.coins.as_mut().ok_or_else(|| {
            anyhow!("Bitcoin spell with Scrolls outputs must have `tx.coins` set")
        })?;
    let coins_len = coins.len();
    for (&i, spk_hex) in &signed.script_pubkeys {
        let coin = coins.get_mut(i as usize).ok_or_else(|| {
            anyhow!(
                "tx.scrolls references output #{} but tx.coins only has {} entries",
                i,
                coins_len
            )
        })?;
        let spk = hex::decode(spk_hex)
            .with_context(|| format!("decoding scriptPubKey hex for output #{}", i))?;
        coin.dest = spk;
    }
    Ok(Some(signed))
}

async fn call_canister_addresses(
    tx_in_0: &UtxoId,
    out_is: Vec<u32>,
) -> anyhow::Result<SignedScrollOutputs> {
    let agent = Agent::builder()
        .with_url("https://ic0.app")
        .build()
        .context("Failed to create ICP agent")?;

    let canister_id = Principal::from_text(SCROLLS_BITCOIN_V15_CANISTER_ID)
        .context("Failed to parse scrolls_bitcoin_v15 canister ID")?;

    let args = Encode!(&tx_in_0.to_string(), &out_is)
        .context("Failed to encode Candid arguments for addresses()")?;

    let response = agent
        .update(&canister_id, "addresses")
        .with_arg(args)
        .call_and_wait()
        .await
        .context("Failed to call scrolls_bitcoin_v15.addresses")?;

    let inner = Decode!(&response, Result<CanisterAddresses, String>)
        .context("Failed to decode addresses() response")?;
    let canister_result = match inner {
        Ok(a) => a,
        Err(e) => bail!("scrolls_bitcoin_v15.addresses returned error: {}", e),
    };

    Ok(SignedScrollOutputs {
        script_pubkeys: canister_result.script_pubkeys,
        signature: canister_result.signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use charms_data::{TxId, UtxoId};
    use std::collections::BTreeSet;

    #[tokio::test]
    async fn fill_scroll_outputs_rejects_a_coinbase_before_calling_the_canister() {
        let mut spell = NormalizedSpell::default();
        spell.tx.scrolls = Some(BTreeSet::from([0]));
        spell.tx.ins = Some(vec![UtxoId(TxId([0; 32]), u32::MAX)]);
        let err = fill_scroll_outputs(&mut spell, Chain::Bitcoin)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("coinbase transactions cannot create Scrolls outputs"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn fill_scroll_outputs_allows_a_coinbase_without_scroll_outputs() {
        let mut spell = NormalizedSpell::default();
        spell.tx.ins = Some(vec![UtxoId(TxId([0; 32]), u32::MAX)]);
        let signed = fill_scroll_outputs(&mut spell, Chain::Bitcoin)
            .await
            .unwrap();
        assert!(signed.is_none());
    }
}
