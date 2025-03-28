use crate::{
    script::{control_block, data_script, taproot_spend_info},
    spell::{Input, Output, Spell},
    SPELL_VK,
};
use bitcoin::{
    self,
    absolute::LockTime,
    hashes::Hash,
    key::Secp256k1,
    secp256k1::{rand::thread_rng, schnorr, Keypair, Message},
    sighash::{Prevouts, SighashCache},
    taproot,
    taproot::LeafVersion,
    transaction::Version,
    Amount, FeeRate, OutPoint, ScriptBuf, TapLeafHash, TapSighashType, Transaction, TxIn, TxOut,
    Txid, Weight, Witness, XOnlyPublicKey,
};
use charms_client::NormalizedSpell;
use std::collections::BTreeMap;

/// `add_spell` adds `spell` to `tx`:
/// 1. it builds `commit_tx` transaction which creates a *committed spell* Tapscript output
/// 2. then appends an input spending the *committed spell* to `tx`, and adds a witness for it.
///
/// `fee_rate` is used to compute the amount of sats necessary to fund the commit and spell
/// transactions.
///
/// Return `[commit_tx, tx]`.
///
/// Both `commit_tx` and `tx` need to be signed.
pub fn add_spell(
    tx: Transaction,
    spell_data: &[u8],
    funding_out_point: OutPoint,
    funding_output_value: Amount,
    change_pubkey: ScriptBuf,
    fee_rate: FeeRate,
    prev_txs: &BTreeMap<Txid, Transaction>,
    charms_fee_pubkey: Option<ScriptBuf>,
    charms_fee: Amount,
) -> [Transaction; 2] {
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

    [commit_tx, tx]
}

/// fee covering only the marginal cost of spending the committed spell output.
fn compute_change_amount(
    fee_rate: FeeRate,
    script_len: usize,
    tx: &Transaction,
    prev_txs: &BTreeMap<Txid, Transaction>,
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

#[tracing::instrument(level = "debug", skip_all)]
pub fn norm_spell(tx: &Transaction) -> Option<NormalizedSpell> {
    charms_client::tx::extract_and_verify_spell(&tx, SPELL_VK)
        .map_err(|e| {
            tracing::debug!("spell verification failed: {:?}", e);
            e
        })
        .ok()
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn spell(tx: &Transaction) -> Option<Spell> {
    match norm_spell(tx) {
        Some(norm_spell) => Some(Spell::denormalized(&norm_spell)),
        None => None,
    }
}

pub fn txs_by_txid(prev_txs: Vec<Transaction>) -> BTreeMap<Txid, Transaction> {
    prev_txs
        .into_iter()
        .map(|prev_tx| (prev_tx.compute_txid(), prev_tx))
        .collect::<BTreeMap<_, _>>()
}

pub fn tx_total_amount_in(prev_txs: &BTreeMap<Txid, Transaction>, tx: &Transaction) -> Amount {
    tx.input
        .iter()
        .map(|tx_in| (tx_in.previous_output.txid, tx_in.previous_output.vout))
        .map(|(tx_id, i)| prev_txs[&tx_id].output[i as usize].value)
        .sum::<Amount>()
}

pub fn tx_total_amount_out(tx: &Transaction) -> Amount {
    tx.output.iter().map(|tx_out| tx_out.value).sum::<Amount>()
}

pub fn tx_output(outs: &[Output]) -> Vec<TxOut> {
    outs.iter()
        .map(|u| {
            let value = Amount::from_sat(u.sats.unwrap_or(1000)); // TODO make a constant
            let address = u
                .address
                .as_ref()
                .expect("address should be provided")
                .clone()
                .assume_checked();
            let script_pubkey = ScriptBuf::from(address.script_pubkey());
            TxOut {
                value,
                script_pubkey,
            }
        })
        .collect()
}

pub fn tx_input(ins: &[Input]) -> Vec<TxIn> {
    ins.iter()
        .map(|u| {
            let utxo_id = u.utxo_id.as_ref().unwrap();
            TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array(utxo_id.0 .0),
                    vout: utxo_id.1,
                },
                script_sig: Default::default(),
                sequence: Default::default(),
                witness: Default::default(),
            }
        })
        .collect()
}

pub fn from_spell(spell: &Spell) -> Transaction {
    let input = tx_input(&spell.ins);
    let output = tx_output(&spell.outs);

    let tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input,
        output,
    };
    tx
}
