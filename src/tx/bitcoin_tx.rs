use crate::{spell, spell::CharmsFee};
use anyhow::bail;
use bitcoin::consensus::encode::serialize;
use bitcoin::{
    self, Address, Amount, FeeRate, Network, OutPoint, PubkeyHash, Script, ScriptBuf, ScriptHash,
    Transaction, TxIn, TxOut, Txid, Weight, WitnessProgram, WitnessVersion, absolute::LockTime,
    hashes::Hash, opcodes::all::OP_RETURN, script::Builder, script::PushBytesBuf,
    transaction::Version,
};
use charms_client::{
    NormalizedSpell, NormalizedTransaction,
    bitcoin_tx::{BitcoinTx, LitecoinTx, SPELL_MARKER},
    tx::{Chain, Tx},
};
use charms_data::{TxId, UtxoId};
use std::{collections::BTreeMap, str::FromStr};

pub(crate) const DUST_LIMIT: Amount = Amount::from_sat(300);

const LTC_MAIN_PUBKEY_VERSION: u8 = 48;
const LTC_MAIN_SCRIPT_VERSIONS: [u8; 2] = [5, 50];
const LTC_TEST_PUBKEY_VERSION: u8 = 111;
const LTC_TEST_SCRIPT_VERSIONS: [u8; 2] = [196, 58];

const LITECOIN_DUST_RELAY_TX_FEE: u64 = 30_000;
const LITECOIN_WITNESS_INPUT_SIZE: u64 = 32 + 4 + 1 + (107 / 4) + 4;
const LITECOIN_LEGACY_INPUT_SIZE: u64 = 32 + 4 + 1 + 107 + 4;

struct LitecoinChainParams {
    fee_key: &'static str,
    hrp: &'static str,
    pubkey_version: u8,
    script_versions: &'static [u8],
}

const LITECOIN_CHAINS: [LitecoinChainParams; 3] = [
    LitecoinChainParams {
        fee_key: "main",
        hrp: "ltc",
        pubkey_version: LTC_MAIN_PUBKEY_VERSION,
        script_versions: &LTC_MAIN_SCRIPT_VERSIONS,
    },
    LitecoinChainParams {
        fee_key: "test",
        hrp: "tltc",
        pubkey_version: LTC_TEST_PUBKEY_VERSION,
        script_versions: &LTC_TEST_SCRIPT_VERSIONS,
    },
    LitecoinChainParams {
        fee_key: "regtest",
        hrp: "rltc",
        pubkey_version: LTC_TEST_PUBKEY_VERSION,
        script_versions: &LTC_TEST_SCRIPT_VERSIONS,
    },
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LitecoinAddress {
    pub(crate) script_pubkey: ScriptBuf,
    pub(crate) networks: Vec<&'static str>,
}

pub(crate) fn decode_litecoin_address(address: &str) -> anyhow::Result<LitecoinAddress> {
    if let Ok((hrp, version, program)) = bech32::segwit::decode(address) {
        return litecoin_witness_address(hrp, version, program);
    }
    litecoin_base58_address(address)
}

fn litecoin_witness_address(
    hrp: bech32::Hrp,
    version: bech32::Fe32,
    program: Vec<u8>,
) -> anyhow::Result<LitecoinAddress> {
    let networks: Vec<&'static str> = LITECOIN_CHAINS
        .iter()
        .filter(|chain| hrp == bech32::Hrp::parse(chain.hrp).expect("litecoin hrp"))
        .map(|chain| chain.fee_key)
        .collect();
    if networks.is_empty() {
        bail!("invalid Litecoin address");
    }
    let version = WitnessVersion::try_from(version.to_u8())?;
    let program = WitnessProgram::new(version, &program)?;
    Ok(LitecoinAddress {
        script_pubkey: ScriptBuf::new_witness_program(&program),
        networks,
    })
}

fn litecoin_base58_address(address: &str) -> anyhow::Result<LitecoinAddress> {
    let payload =
        base58ck::decode_check(address).map_err(|_| anyhow::anyhow!("invalid Litecoin address"))?;
    if payload.len() != 21 {
        bail!("invalid Litecoin address");
    }
    let (version, hash) = payload.split_first().expect("length checked");
    let hash: [u8; 20] = hash.try_into().expect("length checked");
    let mut script_pubkey = None;
    let mut networks = Vec::new();
    for chain in &LITECOIN_CHAINS {
        if *version == chain.pubkey_version {
            script_pubkey = Some(ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array(hash)));
            networks.push(chain.fee_key);
        } else if chain.script_versions.contains(version) {
            script_pubkey = Some(ScriptBuf::new_p2sh(&ScriptHash::from_byte_array(hash)));
            networks.push(chain.fee_key);
        }
    }
    let Some(script_pubkey) = script_pubkey else {
        bail!("invalid Litecoin address");
    };
    Ok(LitecoinAddress {
        script_pubkey,
        networks,
    })
}

pub(crate) fn litecoin_fee_key<'a>(networks: &'a [&'a str], mock: bool) -> anyhow::Result<&'a str> {
    if let [fee_key] = networks {
        if *fee_key == "regtest" && !mock {
            bail!("regtest change address requires mock");
        }
        return Ok(*fee_key);
    }
    if networks.len() == 2 && networks.contains(&"test") && networks.contains(&"regtest") {
        return Ok(if mock { "regtest" } else { "test" });
    }
    bail!("litecoin change address does not select one network");
}

pub(crate) fn ensure_litecoin_coin_dust(spell: &NormalizedSpell) -> anyhow::Result<()> {
    let coins = spell
        .tx
        .coins
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("coins must be present"))?;
    let scrolls = spell.tx.scrolls.clone().unwrap_or_default();
    for (i, coin) in coins.iter().enumerate() {
        if scrolls.contains(&(i as u32)) && coin.dest.is_empty() {
            continue;
        }
        let dust = litecoin_dust(Script::from_bytes(&coin.dest)).to_sat();
        if coin.amount < dust {
            bail!(
                "coins[{i}].amount {} is below the Litecoin dust limit {dust}",
                coin.amount
            );
        }
    }
    Ok(())
}

pub(crate) fn litecoin_dust(script: &Script) -> Amount {
    if script.is_op_return() {
        return Amount::ZERO;
    }
    let output_size = serialize(&TxOut {
        value: Amount::ZERO,
        script_pubkey: script.to_owned(),
    })
    .len() as u64;
    let input_size = if script.is_witness_program() {
        LITECOIN_WITNESS_INPUT_SIZE
    } else {
        LITECOIN_LEGACY_INPUT_SIZE
    };
    Amount::from_sat((output_size + input_size) * LITECOIN_DUST_RELAY_TX_FEE / 1000)
}

pub(crate) fn litecoin_output_script_ok(script: &Script) -> bool {
    if script.is_p2pkh() || script.is_p2sh() {
        return true;
    }
    let Some(version) = script.witness_version() else {
        return false;
    };
    WitnessProgram::new(version, &script.as_bytes()[2..]).is_ok()
}

pub(crate) fn prevout_amount(prev: &Tx, vout: u32) -> Option<Amount> {
    let outputs = match prev {
        Tx::Bitcoin(tx) => &tx.inner().output,
        Tx::Litecoin(tx) => &tx.inner().output,
        Tx::Cardano(_) | Tx::Ethereum(_) => return None,
    };
    outputs.get(vout as usize).map(|output| output.value)
}

/// Adds spell data to a Bitcoin transaction via OP_RETURN output.
///
/// # Arguments
/// * `tx` - Base (unsigned) transaction to add the spell data to (includes all spell inputs)
/// * `spell_data` - Raw byte data of the spell to commit
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
    change_pubkey: ScriptBuf,
    fee_rate: FeeRate,
    prev_txs: &BTreeMap<TxId, Tx>,
    charms_fee_pubkey: Option<ScriptBuf>,
    charms_fee: Amount,
    fee_dust: Amount,
    change_dust: Amount,
) -> anyhow::Result<Vec<Transaction>> {
    let mut tx = tx;

    // Add charms fee output if needed
    if let Some(charms_fee_pubkey) = charms_fee_pubkey {
        let existing_fee_amount: Amount = tx
            .output
            .iter()
            .filter(|txout| txout.script_pubkey == charms_fee_pubkey)
            .map(|txout| txout.value)
            .sum();

        if existing_fee_amount < charms_fee {
            let additional_fee = charms_fee - existing_fee_amount + fee_dust;
            tx.output.push(TxOut {
                value: additional_fee,
                script_pubkey: charms_fee_pubkey,
            });
        }
    }

    // Add OP_RETURN output with spell data (split into marker and payload pushes)
    let spell_marker = PushBytesBuf::try_from(SPELL_MARKER.to_vec())
        .map_err(|_| anyhow::anyhow!("failed to create spell marker"))?;
    let spell_payload = PushBytesBuf::try_from(spell_data.to_vec())
        .map_err(|_| anyhow::anyhow!("spell data too large for OP_RETURN"))?;

    let op_return_script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(&spell_marker)
        .push_slice(&spell_payload)
        .into_script();

    tx.output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: op_return_script,
    });

    // Calculate change amount from spell inputs
    let change_amount = compute_change_amount(fee_rate, &tx, prev_txs);

    // Add change output if above dust limit
    if change_amount >= change_dust {
        tx.output.push(TxOut {
            value: change_amount,
            script_pubkey: change_pubkey,
        });
    }

    Ok(vec![tx])
}

/// Calculate change amount for the transaction with OP_RETURN output.
/// All inputs are spell inputs - fees come from the difference between inputs and outputs.
fn compute_change_amount(
    fee_rate: FeeRate,
    tx: &Transaction,
    prev_txs: &BTreeMap<TxId, Tx>,
) -> Amount {
    // OP_RETURN output is already included in tx.output
    let change_output_weight = Weight::from_wu(172);
    let signatures_weight = Weight::from_wu(65) * tx.input.len() as u64;

    let total_tx_weight = tx.weight() + signatures_weight + change_output_weight;

    let fee = fee_rate.fee_wu(total_tx_weight).unwrap();

    // All inputs are spell inputs
    let tx_amount_in = tx_total_amount_in(prev_txs, tx);
    let tx_amount_out = tx.output.iter().map(|tx_out| tx_out.value).sum::<Amount>();

    tx_amount_in - tx_amount_out - fee
}

pub fn tx_total_amount_in(prev_txs: &BTreeMap<TxId, Tx>, tx: &Transaction) -> Amount {
    tx.input
        .iter()
        .map(|tx_in| (tx_in.previous_output.txid, tx_in.previous_output.vout))
        .map(|(tx_id, i)| {
            let txid = TxId(tx_id.to_byte_array());
            match prevout_amount(&prev_txs[&txid], i) {
                Some(value) => value,
                None => unreachable!(),
            }
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
    chain: Chain,
    spell: &NormalizedSpell,
    change_address: &String,
    prev_txs_by_id: &BTreeMap<TxId, Tx>,
    spell_data: &[u8],
    fee_rate: f64,
    charms_fee: Option<CharmsFee>,
    total_cycles: u64,
    mock: bool,
) -> anyhow::Result<Vec<Tx>> {
    let (change_pubkey, charms_fee_pubkey, fee_dust, change_dust) = match chain {
        Chain::Bitcoin => {
            let change_address = bitcoin::Address::from_str(change_address)?;

            let network = match &change_address {
                a if a.is_valid_for_network(Network::Bitcoin) => Network::Bitcoin.to_core_arg(),
                a if a.is_valid_for_network(Network::Testnet4) => Network::Testnet4.to_core_arg(),
                a if a.is_valid_for_network(Network::Regtest) => Network::Regtest.to_core_arg(),
                _ => bail!("Invalid change address: {:?}", change_address),
            };

            let change_pubkey = change_address.assume_checked().script_pubkey();

            let charms_fee_pubkey = charms_fee
                .as_ref()
                .and_then(|charms_fee| charms_fee.fee_address(&Chain::Bitcoin, network))
                .and_then(|fee_address| {
                    Address::from_str(fee_address)
                        .ok()
                        .map(|a| a.assume_checked().script_pubkey())
                });
            (change_pubkey, charms_fee_pubkey, DUST_LIMIT, DUST_LIMIT)
        }
        Chain::Litecoin => {
            ensure_litecoin_coin_dust(spell)?;
            let decoded = decode_litecoin_address(change_address)?;
            let fee_key = litecoin_fee_key(&decoded.networks, mock)
                .map_err(|_| anyhow::anyhow!("Invalid change address: {:?}", change_address))?;
            let change_pubkey = decoded.script_pubkey;
            let charms_fee_pubkey = match charms_fee
                .as_ref()
                .and_then(|fee| fee.fee_address(&Chain::Litecoin, fee_key))
            {
                Some(fee_address) => Some(decode_litecoin_address(fee_address)?.script_pubkey),
                None => None,
            };
            let fee_dust = charms_fee_pubkey
                .as_ref()
                .map(|script| litecoin_dust(script))
                .unwrap_or(Amount::ZERO);
            let change_dust = litecoin_dust(&change_pubkey);
            (change_pubkey, charms_fee_pubkey, fee_dust, change_dust)
        }
        Chain::Cardano | Chain::Ethereum => bail!("unsupported chain"),
    };

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
        change_pubkey,
        fee_rate,
        prev_txs_by_id,
        charms_fee_pubkey,
        charms_fee,
        fee_dust,
        change_dust,
    )?;
    Ok(transactions
        .into_iter()
        .map(|tx| match chain {
            Chain::Bitcoin => Tx::Bitcoin(BitcoinTx::Simple(tx)),
            Chain::Litecoin => Tx::Litecoin(LitecoinTx::new(tx)),
            Chain::Cardano | Chain::Ethereum => unreachable!(),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::opcodes::all::{OP_ENDIF, OP_IF, OP_PUSHBYTES_0};
    use bitcoin::script::Instruction;
    use bitcoin::{
        OutPoint, ScriptBuf, TxIn, Txid, WPubkeyHash, Witness, absolute::LockTime, hashes::Hash,
        transaction::Version,
    };
    use charms_client::bitcoin_tx::parse_spell_and_proof_from_op_return;
    use charms_client::tx::EnchantedTx;
    use charms_data::{NativeOutput, util};
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn test_add_spell_op_return() {
        // Create a previous transaction with an output that provides funding
        let prev_txid_bytes = [1u8; 32];
        let prev_txid = Txid::from_byte_array(prev_txid_bytes);
        let prev_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000), // 100k sats for fees
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut prev_txs: BTreeMap<TxId, Tx> = BTreeMap::new();
        prev_txs.insert(
            TxId(prev_txid_bytes),
            Tx::Bitcoin(BitcoinTx::Simple(prev_tx)),
        );

        // Create the spell transaction with one input referencing the prev tx
        let dummy_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: prev_txid,
                    vout: 0,
                },
                script_sig: Default::default(),
                sequence: Default::default(),
                witness: Default::default(),
            }],
            output: vec![],
        };

        let spell_data = b"spell";
        let change_pubkey = ScriptBuf::new();
        let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
        let charms_fee_pubkey = None;
        let charms_fee = Amount::ZERO;

        let txs = add_spell(
            dummy_tx,
            spell_data,
            change_pubkey,
            fee_rate,
            &prev_txs,
            charms_fee_pubkey,
            charms_fee,
            DUST_LIMIT,
            DUST_LIMIT,
        )
        .unwrap();

        // Should only return one transaction now
        assert_eq!(txs.len(), 1);

        let spell_tx = &txs[0];

        // Find OP_RETURN output
        let op_return_output = spell_tx
            .output
            .iter()
            .find(|out| out.script_pubkey.is_op_return());

        assert!(op_return_output.is_some());
        assert_eq!(op_return_output.unwrap().value, Amount::ZERO);
    }

    #[test]
    fn litecoin_spell_is_one_op_return() {
        let fee_address =
            bech32::segwit::encode_v0(bech32::Hrp::parse("ltc").unwrap(), &[0x11; 20]).unwrap();
        let mut change_payload = vec![LTC_MAIN_PUBKEY_VERSION];
        change_payload.extend_from_slice(&[0x22; 20]);
        let change_address = base58ck::encode_check(&change_payload);
        let fee_script = decode_litecoin_address(&fee_address).unwrap().script_pubkey;
        let change_script = decode_litecoin_address(&change_address)
            .unwrap()
            .script_pubkey;
        let witness_program =
            WitnessProgram::new(WitnessVersion::V1, &[0x44; 32]).expect("32-byte program");
        let long_witness = ScriptBuf::new_witness_program(&witness_program);
        let op_return = Builder::new().push_opcode(OP_RETURN).into_script();
        let witness_dust = litecoin_dust(&fee_script).to_sat();
        let legacy_dust = litecoin_dust(&change_script).to_sat();
        assert_eq!(fee_script.len(), 22);
        assert_eq!(long_witness.len(), 34);
        assert_eq!(witness_dust, 2940);
        assert_eq!(litecoin_dust(&long_witness).to_sat(), 3300);
        assert_eq!(legacy_dust, 5460);
        assert_eq!(litecoin_dust(&op_return).to_sat(), 0);
        assert_ne!(witness_dust, 300);
        assert_ne!(legacy_dust, 300);
        assert!(fee_script.is_witness_program());
        assert!(!change_script.is_witness_program());
        assert!(!change_script.is_op_return());
        let coin_script = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x33; 20]));
        assert_ne!(coin_script, fee_script);
        assert_ne!(coin_script, change_script);

        let spell_cbor = b"litecoin spell payload 9f3ac7e1-cbor".to_vec();
        let coin_sats = 50_000u64;
        let fee_sats = 1_000u64;
        let paid_input = coin_sats + fee_sats + witness_dust + legacy_dust;

        let kept = litecoin_spell_tx(
            paid_input,
            &change_address,
            &fee_address,
            &coin_script,
            coin_sats,
            fee_sats,
            &spell_cbor,
        );
        assert_eq!(kept.len(), 1);
        let json = serde_json::to_value(&kept).unwrap();
        assert!(
            json[0]
                .get("litecoin")
                .and_then(|value| value.as_str())
                .is_some()
        );
        let Tx::Litecoin(litecoin_tx) = &kept[0] else {
            panic!("litecoin tx");
        };
        assert!(!litecoin_tx.proven_final());
        let tx = litecoin_tx.inner();
        assert_eq!(tx.output.len(), 4);
        assert_eq!(
            tx.output
                .iter()
                .filter(|out| out.script_pubkey.is_op_return())
                .count(),
            1
        );
        assert_eq!(tx.output[0].script_pubkey, coin_script);
        assert_eq!(tx.output[0].value.to_sat(), coin_sats);
        assert_eq!(tx.output[1].script_pubkey, fee_script);
        assert_eq!(tx.output[1].value.to_sat(), fee_sats + witness_dust);
        assert_ne!(tx.output[1].value.to_sat(), fee_sats + 300);
        assert_eq!(tx.output[2].value, Amount::ZERO);
        assert_spell_op_return(&tx.output[2].script_pubkey, &spell_cbor);
        assert_eq!(tx.output[3].script_pubkey, change_script);
        assert_eq!(tx.output[3].value.to_sat(), legacy_dust);
        for output in tx
            .output
            .iter()
            .filter(|out| !out.script_pubkey.is_op_return())
        {
            let raw = serialize(output);
            assert!(
                !raw.windows(spell_cbor.len())
                    .any(|window| window == spell_cbor)
            );
        }

        let omitted = litecoin_spell_tx(
            paid_input - 1,
            &change_address,
            &fee_address,
            &coin_script,
            coin_sats,
            fee_sats,
            &spell_cbor,
        );
        let Tx::Litecoin(omitted_tx) = &omitted[0] else {
            panic!("litecoin tx");
        };
        let omitted_tx = omitted_tx.inner();
        assert_eq!(omitted_tx.output.len(), 3);
        assert_eq!(omitted_tx.output[0].script_pubkey, coin_script);
        assert_eq!(omitted_tx.output[1].script_pubkey, fee_script);
        assert_eq!(omitted_tx.output[1].value.to_sat(), fee_sats + witness_dust);
        assert_spell_op_return(&omitted_tx.output[2].script_pubkey, &spell_cbor);
        assert!(
            omitted_tx
                .output
                .iter()
                .all(|out| out.script_pubkey != change_script)
        );

        let mut doubled = tx.clone();
        doubled.output.push(tx.output[2].clone());
        let doubled_err = parse_spell_and_proof_from_op_return(&doubled).unwrap_err();
        assert!(
            doubled_err
                .to_string()
                .contains("expected exactly one spell OP_RETURN")
        );

        let witnessed = witness_only_spell();
        let extracted = witnessed
            .extract_and_verify_spell(&[9u8; 32], true)
            .unwrap_err();
        let parsed = parse_spell_and_proof_from_op_return(witnessed.inner()).unwrap_err();
        assert_eq!(extracted.to_string(), parsed.to_string());
        assert!(
            parsed
                .to_string()
                .contains("expected exactly one spell OP_RETURN")
        );

        fn assert_spell_op_return(script: &Script, payload: &[u8]) {
            let mut instructions = script.instructions();
            assert_eq!(
                instructions.next().unwrap().unwrap(),
                Instruction::Op(OP_RETURN)
            );
            match instructions.next().unwrap().unwrap() {
                Instruction::PushBytes(bytes) => assert_eq!(bytes.as_bytes(), b"spell"),
                other => panic!("spell marker: {other:?}"),
            }
            match instructions.next().unwrap().unwrap() {
                Instruction::PushBytes(bytes) => assert_eq!(bytes.as_bytes(), payload),
                other => panic!("spell payload: {other:?}"),
            }
            assert!(instructions.next().is_none());
        }

        fn litecoin_spell_tx(
            input_sats: u64,
            change_address: &str,
            fee_address: &str,
            coin_script: &ScriptBuf,
            coin_sats: u64,
            fee_sats: u64,
            spell_cbor: &[u8],
        ) -> Vec<Tx> {
            let prev = Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![],
                output: vec![TxOut {
                    value: Amount::from_sat(input_sats),
                    script_pubkey: ScriptBuf::new(),
                }],
            };
            let txid = prev.compute_txid().to_byte_array();
            let mut prev_txs = BTreeMap::new();
            prev_txs.insert(TxId(txid), Tx::Litecoin(LitecoinTx::new(prev)));
            let spell = NormalizedSpell {
                tx: NormalizedTransaction {
                    ins: Some(vec![UtxoId(TxId(txid), 0)]),
                    outs: vec![Default::default()],
                    coins: Some(vec![NativeOutput {
                        amount: coin_sats,
                        dest: coin_script.to_bytes(),
                        content: None,
                    }]),
                    ..Default::default()
                },
                ..Default::default()
            };
            let mut networks = BTreeMap::new();
            networks.insert("main".to_string(), fee_address.to_string());
            let mut fee_addresses = BTreeMap::new();
            fee_addresses.insert(Chain::Litecoin, networks);
            make_transactions(
                Chain::Litecoin,
                &spell,
                &change_address.to_string(),
                &prev_txs,
                spell_cbor,
                0.0,
                Some(CharmsFee {
                    fee_addresses,
                    fee_rate: 0,
                    fee_base: fee_sats,
                }),
                0,
                false,
            )
            .unwrap()
        }

        fn witness_only_spell() -> LitecoinTx {
            let spell_bytes = util::write(&(NormalizedSpell::default(), vec![1u8, 2, 3])).unwrap();
            let marker = PushBytesBuf::try_from(b"spell".to_vec()).unwrap();
            let payload = PushBytesBuf::try_from(spell_bytes).unwrap();
            let leaf = Builder::new()
                .push_opcode(OP_PUSHBYTES_0)
                .push_opcode(OP_IF)
                .push_slice(&marker)
                .push_slice(&payload)
                .push_opcode(OP_ENDIF)
                .into_script();
            let mut control = vec![0xc0];
            control.extend_from_slice(&[4u8; 32]);
            let witness = Witness::from_slice(&[leaf.as_bytes(), &control]);
            LitecoinTx::new(Transaction {
                version: Version::TWO,
                lock_time: LockTime::ZERO,
                input: vec![TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_byte_array([9u8; 32]),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness,
                }],
                output: vec![TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([5u8; 20])),
                }],
            })
        }
    }

    #[test]
    fn shared_prefix_p2pkh_selects_test_outside_mock_and_regtest_in_mock() {
        let mut payload = vec![LTC_TEST_PUBKEY_VERSION];
        payload.extend_from_slice(&[0x55; 20]);
        let change = base58ck::encode_check(&payload);
        let decoded = decode_litecoin_address(&change).unwrap();
        assert_eq!(litecoin_fee_key(&decoded.networks, false).unwrap(), "test");
        assert_eq!(
            litecoin_fee_key(&decoded.networks, true).unwrap(),
            "regtest"
        );

        let test_fee =
            bech32::segwit::encode_v0(bech32::Hrp::parse("tltc").unwrap(), &[0x11; 20]).unwrap();
        let regtest_fee =
            bech32::segwit::encode_v0(bech32::Hrp::parse("rltc").unwrap(), &[0x22; 20]).unwrap();
        let test_script = decode_litecoin_address(&test_fee).unwrap().script_pubkey;
        let regtest_script = decode_litecoin_address(&regtest_fee).unwrap().script_pubkey;
        let coin = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x33; 20]));
        let mut fees = BTreeMap::new();
        fees.insert("test".to_string(), test_fee);
        fees.insert("regtest".to_string(), regtest_fee);
        let outside =
            litecoin_built(&change, &coin, 2_940, 6_880, fees.clone(), 1_000, false).unwrap();
        let inside = litecoin_built(&change, &coin, 2_940, 6_880, fees, 1_000, true).unwrap();
        let outside_scripts = output_scripts(&outside);
        let inside_scripts = output_scripts(&inside);
        assert!(outside_scripts.contains(&test_script));
        assert!(!outside_scripts.contains(&regtest_script));
        assert!(inside_scripts.contains(&regtest_script));
        assert!(!inside_scripts.contains(&test_script));

        let tltc =
            bech32::segwit::encode_v0(bech32::Hrp::parse("tltc").unwrap(), &[0x66; 20]).unwrap();
        let rltc =
            bech32::segwit::encode_v0(bech32::Hrp::parse("rltc").unwrap(), &[0x66; 20]).unwrap();
        assert_eq!(
            litecoin_fee_key(&decode_litecoin_address(&tltc).unwrap().networks, false).unwrap(),
            "test"
        );
        assert_eq!(
            litecoin_fee_key(&decode_litecoin_address(&tltc).unwrap().networks, true).unwrap(),
            "test"
        );
        assert_eq!(
            litecoin_fee_key(&decode_litecoin_address(&rltc).unwrap().networks, true).unwrap(),
            "regtest"
        );
        assert!(
            litecoin_fee_key(&decode_litecoin_address(&rltc).unwrap().networks, false).is_err()
        );
    }

    #[test]
    fn litecoin_p2wpkh_coin_dust_rejects_300_and_accepts_2940() {
        let coin = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([0x33; 20]));
        let low = coin_spell(&coin, 300, None);
        assert!(
            ensure_litecoin_coin_dust(&low)
                .unwrap_err()
                .to_string()
                .contains("below the Litecoin dust limit")
        );
        ensure_litecoin_coin_dust(&coin_spell(&coin, 2_940, None)).unwrap();

        let mut payload = vec![LTC_MAIN_PUBKEY_VERSION];
        payload.extend_from_slice(&[0x22; 20]);
        let change = base58ck::encode_check(&payload);
        assert!(litecoin_built(&change, &coin, 300, 10_000, BTreeMap::new(), 0, false).is_err());
        assert!(litecoin_built(&change, &coin, 2_940, 2_940, BTreeMap::new(), 0, false).is_ok());

        let exempt = coin_spell(&coin, 0, Some(BTreeSet::from([0])));
        let mut exempt = exempt;
        exempt.tx.coins.as_mut().unwrap()[0].dest.clear();
        ensure_litecoin_coin_dust(&exempt).unwrap();
    }

    fn coin_spell(
        coin: &ScriptBuf,
        amount: u64,
        scrolls: Option<BTreeSet<u32>>,
    ) -> NormalizedSpell {
        NormalizedSpell {
            tx: NormalizedTransaction {
                ins: Some(vec![UtxoId(TxId([1; 32]), 0)]),
                outs: vec![Default::default()],
                coins: Some(vec![NativeOutput {
                    amount,
                    dest: coin.to_bytes(),
                    content: None,
                }]),
                scrolls,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn output_scripts(txs: &[Tx]) -> Vec<ScriptBuf> {
        let Tx::Litecoin(tx) = &txs[0] else {
            panic!("litecoin tx");
        };
        tx.inner()
            .output
            .iter()
            .map(|output| output.script_pubkey.clone())
            .collect()
    }

    fn litecoin_built(
        change: &str,
        coin: &ScriptBuf,
        coin_sats: u64,
        input_sats: u64,
        fees: BTreeMap<String, String>,
        fee_sats: u64,
        mock: bool,
    ) -> anyhow::Result<Vec<Tx>> {
        let prev = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(input_sats),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let txid = prev.compute_txid().to_byte_array();
        let mut prev_txs = BTreeMap::new();
        prev_txs.insert(TxId(txid), Tx::Litecoin(LitecoinTx::new(prev)));
        let spell = NormalizedSpell {
            tx: NormalizedTransaction {
                ins: Some(vec![UtxoId(TxId(txid), 0)]),
                outs: vec![Default::default()],
                coins: Some(vec![NativeOutput {
                    amount: coin_sats,
                    dest: coin.to_bytes(),
                    content: None,
                }]),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut fee_addresses = BTreeMap::new();
        fee_addresses.insert(Chain::Litecoin, fees);
        make_transactions(
            Chain::Litecoin,
            &spell,
            &change.to_string(),
            &prev_txs,
            b"spell-bytes",
            0.0,
            Some(CharmsFee {
                fee_addresses,
                fee_rate: 0,
                fee_base: fee_sats,
            }),
            0,
            mock,
        )
    }
}
