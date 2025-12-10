use crate::{
    script::{control_block, data_script, taproot_spend_info},
    spell,
    spell::CharmsFee,
};
use anyhow::bail;
use bitcoin::{
    self, Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Txid, Weight, Witness, XOnlyPublicKey,
    absolute::LockTime,
    hashes::Hash,
    key::Secp256k1,
    secp256k1::{Keypair, Message, rand::thread_rng, schnorr},
    sighash::{Prevouts, SighashCache},
    taproot,
    taproot::LeafVersion,
    transaction::Version,
};
use charms_client::{
    NormalizedSpell, NormalizedTransaction,
    bitcoin_tx::BitcoinTx,
    tx::{Chain, Tx},
};
use charms_data::{TxId, UtxoId};
use std::{collections::BTreeMap, str::FromStr};

/// Adds spell data to a Bitcoin transaction by creating a committed spell output and spending it.
///
/// # Arguments
/// * `tx` - Base (unsigned) transaction to add the spell data to
/// * `spell_data` - Raw byte data of the spell to commit
/// * `funding_out_point` - UTXO to fund both the commit and spell transactions
/// * `funding_output_value` - Value of the funding UTXO in sats
/// * `change_pubkey` - Script pubkey for change output to be added to spell_tx
/// * `fee_rate` - Fee rate to calculate transaction fees
/// * `prev_txs` - Map of previous transactions referenced by the spell
/// * `charms_fee_pubkey` - Optional script pubkey for charms fee output
/// * `charms_fee` - Amount of charms fee to pay
///
/// # Returns
/// Returns a vector containing two transactions:
/// 1. `commit_tx` - Transaction that creates the committed spell Tapscript output
/// 2. `spell_tx` - Modified input `tx` with added spell input (with witness data) and change
///    output.
///
/// Both transactions need to be signed before broadcasting.
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
) -> Vec<Transaction> {
    let secp256k1 = Secp256k1::new();
    let keypair = Keypair::new(&secp256k1, &mut thread_rng());
    let (public_key, _) = XOnlyPublicKey::from_keypair(&keypair);

    let script = data_script(public_key, &spell_data);

    let commit_tx = create_commit_tx(
        funding_out_point,
        funding_output_value,
        public_key,
        &script,
        fee_rate,
    );
    let commit_txout = &commit_tx.output[0];

    let mut tx = tx;
    if let Some(charms_fee_pubkey) = charms_fee_pubkey {
        tx.output.push(TxOut {
            value: charms_fee,
            script_pubkey: charms_fee_pubkey,
        });
    }

    let script_len = script.len();
    let change_amount =
        compute_change_amount(fee_rate, script_len, &tx, prev_txs, commit_txout.value);

    modify_tx(
        &mut tx,
        commit_tx.compute_txid(),
        change_pubkey,
        change_amount,
    );
    let spell_input_idx = tx.input.len() - 1;

    let signature = create_tx_signature(keypair, &mut tx, spell_input_idx, &commit_txout, &script);

    append_witness_data(
        &mut tx.input[spell_input_idx].witness,
        public_key,
        script,
        signature,
    );

    dbg!((
        tx.input[0].witness.size(),
        tx.input[0].base_size(),
        tx.input[0].total_size()
    ));
    dbg!((
        script_len,
        tx.input[spell_input_idx].witness.size(),
        tx.input[spell_input_idx].base_size(),
        tx.input[spell_input_idx].total_size()
    ));
    dbg!(tx.output[tx.output.len() - 1].size());

    [commit_tx, tx].to_vec()
}

/// fee covering only the marginal cost of spending the committed spell output.
fn compute_change_amount(
    fee_rate: FeeRate,
    script_len: usize,
    tx: &Transaction,
    prev_txs: &BTreeMap<TxId, Tx>,
    commit_txout_value: Amount,
) -> Amount {
    let script_input_weight = Weight::from_wu(script_len as u64 + 268);
    let change_output_weight = Weight::from_wu(172);
    let signatures_weight = Weight::from_wu(66) * tx.input.len() as u64;

    let total_tx_weight = dbg!(tx.weight() + Weight::from_wu(2))
        + dbg!(signatures_weight)
        + dbg!(script_input_weight)
        + dbg!(change_output_weight);

    let fee = fee_rate.fee_wu(dbg!(total_tx_weight)).unwrap();

    let tx_amount_in = tx_total_amount_in(prev_txs, &tx);
    let tx_amount_out = tx.output.iter().map(|tx_out| tx_out.value).sum::<Amount>();

    commit_txout_value + tx_amount_in - tx_amount_out - fee
}

fn create_commit_tx(
    funding_out_point: OutPoint,
    funding_output_value: Amount,
    public_key: XOnlyPublicKey,
    script: &ScriptBuf,
    fee_rate: FeeRate,
) -> Transaction {
    let fee = fee_rate.fee_vb(111).unwrap(); // tx is 111 vbytes when spending a Taproot output

    let commit_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding_out_point,
            script_sig: Default::default(),
            sequence: Default::default(),
            witness: Default::default(),
        }],
        output: vec![TxOut {
            value: funding_output_value - fee,
            script_pubkey: ScriptBuf::new_p2tr_tweaked(
                taproot_spend_info(public_key, script.clone()).output_key(),
            ),
        }],
    };

    commit_tx
}

fn modify_tx(
    tx: &mut Transaction,
    commit_txid: Txid,
    change_script_pubkey: ScriptBuf,
    change_amount: Amount,
) {
    tx.input.push(TxIn {
        previous_output: OutPoint {
            txid: commit_txid,
            vout: 0,
        },
        script_sig: Default::default(),
        sequence: Default::default(),
        witness: Witness::new(),
    });

    // dust limit // TODO make a constant
    if change_amount >= Amount::from_sat(546) {
        tx.output.push(TxOut {
            value: change_amount,
            script_pubkey: change_script_pubkey,
        });
    }
}

fn create_tx_signature(
    keypair: Keypair,
    tx: &mut Transaction,
    input_index: usize,
    prev_out: &TxOut,
    script: &ScriptBuf,
) -> schnorr::Signature {
    let mut sighash_cache = SighashCache::new(tx);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::One(input_index, prev_out),
            TapLeafHash::from_script(script, LeafVersion::TapScript),
            TapSighashType::AllPlusAnyoneCanPay,
        )
        .unwrap();
    let secp256k1 = Secp256k1::new();
    let signature = secp256k1.sign_schnorr(
        &Message::from_digest_slice(sighash.as_ref())
            .expect("should be cryptographically secure hash"),
        &keypair,
    );

    signature
}

fn append_witness_data(
    witness: &mut Witness,
    public_key: XOnlyPublicKey,
    script: ScriptBuf,
    signature: schnorr::Signature,
) {
    witness.push(
        taproot::Signature {
            signature,
            sighash_type: TapSighashType::AllPlusAnyoneCanPay,
        }
        .to_vec(),
    );
    witness.push(script.clone());
    witness.push(control_block(public_key, script).serialize());
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
    );
    Ok(transactions
        .into_iter()
        .map(|tx| Tx::Bitcoin(BitcoinTx::Simple(tx)))
        .collect())
}
