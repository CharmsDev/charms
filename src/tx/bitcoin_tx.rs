use crate::{
    spell,
    spell::CharmsFee,
};
use anyhow::bail;
use bitcoin::{
    self, Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Txid,
    Transaction, TxIn, TxOut, Weight,
    absolute::LockTime,
    hashes::Hash,
    script::PushBytesBuf,
    transaction::Version,
};
use charms_client::{
    NormalizedSpell, NormalizedTransaction,
    bitcoin_tx::BitcoinTx,
    tx::{Chain, Tx},
};
use charms_data::{TxId, UtxoId};
use std::{collections::BTreeMap, str::FromStr};

const DUST_LIMIT: Amount = Amount::from_sat(300);

/// Adds spell data to a Bitcoin transaction via OP_RETURN output.
///
/// # Arguments
/// * `tx` - Base (unsigned) transaction to add the spell data to
/// * `spell_data` - Raw byte data of the spell to commit
/// * `funding_out_point` - UTXO to fund the transaction
/// * `funding_output_value` - Value of the funding UTXO in sats
/// * `change_pubkey` - Script pubkey for change output
/// * `fee_rate` - Fee rate to calculate transaction fees
/// * `prev_txs` - Map of previous transactions referenced by the spell
/// * `charms_fee_pubkey` - Optional script pubkey for charms fee output
/// * `charms_fee` - Amount of charms fee to pay
///
/// # Returns
/// Returns a single transaction with spell data in OP_RETURN output (before change output).
pub fn add_spell(
    tx: Transaction,
    spell_data: &[u8],
    funding_out_point: OutPoint,
    funding_output_value: Amount,
    change_pubkey: ScriptBuf,
    fee_rate: FeeRate,
    prev_txs: &BTreeMap<TxId, Tx>,
    charms_fee_pubkey: Option<ScriptBuf>,
    charms_fee: Amount,
) -> anyhow::Result<Vec<Transaction>> {
    let mut tx = tx;

    // Add funding input
    tx.input.push(TxIn {
        previous_output: funding_out_point,
        script_sig: Default::default(),
        sequence: Default::default(),
        witness: Default::default(),
    });

    // Add charms fee output if needed
    if let Some(charms_fee_pubkey) = charms_fee_pubkey {
        let existing_fee_amount: Amount = tx
            .output
            .iter()
            .filter(|txout| txout.script_pubkey == charms_fee_pubkey)
            .map(|txout| txout.value)
            .sum();

        if existing_fee_amount < charms_fee {
            let additional_fee = charms_fee - existing_fee_amount + DUST_LIMIT;
            tx.output.push(TxOut {
                value: additional_fee,
                script_pubkey: charms_fee_pubkey,
            });
        }
    }

    // Add OP_RETURN output with spell data
    let push_bytes = PushBytesBuf::try_from(spell_data.to_vec())
        .map_err(|_| anyhow::anyhow!("spell data too large for OP_RETURN"))?;
    let op_return_script = ScriptBuf::new_op_return(&push_bytes);
    tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: op_return_script,
    });

    // Calculate change amount
    let change_amount = compute_change_amount(
        fee_rate,
        spell_data.len(),
        &tx,
        prev_txs,
        funding_output_value,
    );

    // Add change output if above dust limit
    if change_amount >= Amount::from_sat(546) {
        tx.output.push(TxOut {
            value: change_amount,
            script_pubkey: change_pubkey,
        });
    }

    Ok(vec![tx])
}

/// Calculate change amount for the transaction with OP_RETURN output.
fn compute_change_amount(
    fee_rate: FeeRate,
    _spell_data_len: usize,
    tx: &Transaction,
    prev_txs: &BTreeMap<TxId, Tx>,
    funding_output_value: Amount,
) -> Amount {
    // OP_RETURN output is already included in tx.output
    let change_output_weight = Weight::from_wu(172);
    let signatures_weight = Weight::from_wu(65) * tx.input.len() as u64;

    let total_tx_weight = tx.weight()
        + signatures_weight
        + change_output_weight;

    let fee = fee_rate.fee_wu(total_tx_weight).unwrap();

    // Calculate total input amount: sum of spell inputs (excluding last funding input) + funding
    let spell_inputs_amount = if tx.input.len() > 1 {
        let mut tx_without_funding = tx.clone();
        tx_without_funding.input.pop(); // Remove funding input
        tx_total_amount_in(prev_txs, &tx_without_funding)
    } else {
        Amount::ZERO
    };
    let tx_amount_in = spell_inputs_amount + funding_output_value;
    let tx_amount_out = tx.output.iter().map(|tx_out| tx_out.value).sum::<Amount>();

    tx_amount_in - tx_amount_out - fee
}

pub fn tx_total_amount_in(prev_txs: &BTreeMap<TxId, Tx>, tx: &Transaction) -> Amount {
    tx.input
        .iter()
        .map(|tx_in| (tx_in.previous_output.txid, tx_in.previous_output.vout))
        .map(|(tx_id, i)| {
            let txid = TxId(tx_id.to_byte_array());
            let Tx::Bitcoin(tx) = prev_txs[&txid].clone() else {
                unreachable!()
            };
            tx.inner().output[i as usize].value
        })
        .sum::<Amount>()
}

pub fn tx_total_amount_out(tx: &Transaction) -> Amount {
    tx.output.iter().map(|tx_out| tx_out.value).sum::<Amount>()
}

pub fn tx_output(tx: &NormalizedTransaction) -> anyhow::Result<Vec<TxOut>> {
    let tx_outputs = (tx.coins.as_ref().expect("coins should be provided"))
        .iter()
        .map(|u| {
            let value = Amount::from_sat(u.amount);
            let script_pubkey = ScriptBuf::from_bytes(u.dest.to_vec());
            Ok(TxOut {
                value,
                script_pubkey,
            })
        })
        .collect::<anyhow::Result<_>>()?;
    Ok(tx_outputs)
}

pub fn tx_input(ins: &[UtxoId]) -> Vec<TxIn> {
    ins.iter()
        .map(|utxo_id| TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array(utxo_id.0.0),
                vout: utxo_id.1,
            },
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        })
        .collect()
}

pub fn from_spell(spell: &NormalizedSpell) -> anyhow::Result<BitcoinTx> {
    let input = tx_input(&spell.tx.ins.as_ref().expect("inputs are expected"));
    let output = tx_output(&spell.tx)?;

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output,
    };
    Ok(BitcoinTx::Simple(tx))
}

pub fn make_transactions(
    spell: &NormalizedSpell,
    funding_utxo: UtxoId,
    funding_utxo_value: u64,
    change_address: &String,
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
    spell_data: &[u8],
    fee_rate: f64,
    charms_fee: Option<CharmsFee>,
    total_cycles: u64,
) -> anyhow::Result<Vec<Tx>> {
    let change_address = bitcoin::Address::from_str(&change_address)?;

    let network = match &change_address {
        a if a.is_valid_for_network(Network::Bitcoin) => Network::Bitcoin.to_core_arg(),
        a if a.is_valid_for_network(Network::Testnet4) => Network::Testnet4.to_core_arg(),
        a if a.is_valid_for_network(Network::Regtest) => Network::Regtest.to_core_arg(),
        _ => bail!("Invalid change address: {:?}", change_address),
    };

    let funding_utxo = OutPoint::new(Txid::from_byte_array(funding_utxo.0.0), funding_utxo.1);

    // Parse change address into ScriptPubkey
    let change_address_checked = change_address.assume_checked();

    let change_pubkey = change_address_checked.script_pubkey();

    let charms_fee_pubkey = charms_fee
        .as_ref()
        .and_then(|charms_fee| charms_fee.fee_address(&Chain::Bitcoin, network))
        .and_then(|fee_address| {
            Address::from_str(fee_address)
                .ok()
                .map(|a| a.assume_checked().script_pubkey())
        });

    // Calculate fee
    let charms_fee = spell::get_charms_fee(&charms_fee, total_cycles);

    // Parse fee rate
    let fee_rate = FeeRate::from_sat_per_kwu((fee_rate * 250.0) as u64);

    let tx = from_spell(spell)?;
    let BitcoinTx::Simple(tx) = tx else {
        bail!("expected simple transaction")
    };

    // Call the add_spell function
    let transactions = add_spell(
        tx,
        spell_data,
        funding_utxo,
        Amount::from_sat(funding_utxo_value),
        change_pubkey,
        fee_rate,
        &prev_txs_by_id,
        charms_fee_pubkey,
        charms_fee,
    )?;
    Ok(transactions
        .into_iter()
        .map(|tx| Tx::Bitcoin(BitcoinTx::Simple(tx)))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{ScriptBuf, Txid, absolute::LockTime, transaction::Version};
    use std::collections::BTreeMap;

    #[test]
    fn test_add_spell_op_return() {
        let dummy_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let spell_data = b"spell";
        let funding_out_point = OutPoint {
            txid: Txid::all_zeros(),
            vout: 0,
        };
        let funding_value = Amount::from_sat(10000);
        let change_pubkey = ScriptBuf::new();
        let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
        let prev_txs = BTreeMap::new();
        let charms_fee_pubkey = None;
        let charms_fee = Amount::ZERO;

        let txs = add_spell(
            dummy_tx,
            spell_data,
            funding_out_point,
            funding_value,
            change_pubkey,
            fee_rate,
            &prev_txs,
            charms_fee_pubkey,
            charms_fee,
        )
        .unwrap();

        // Should only return one transaction now
        assert_eq!(txs.len(), 1);

        let spell_tx = &txs[0];

        // Find OP_RETURN output
        let op_return_output = spell_tx.output.iter()
            .find(|out| out.script_pubkey.is_op_return());

        assert!(op_return_output.is_some());
        assert_eq!(op_return_output.unwrap().value, Amount::ZERO);
    }
}
