use crate::{NormalizedSpell, Proof, V7, charms, tx, tx::EnchantedTx};
use anyhow::{Context, anyhow, bail, ensure};
use charms_data::{App, Charms, Data, NFT, NativeOutput, TOKEN, TxId, UtxoId, util};
use cml_chain::{
    Deserialize, PolicyId, Serialize,
    assets::{AssetName, ClampedSub, MultiAsset},
    crypto::TransactionHash,
    plutus::{PlutusData, PlutusV3Script},
    transaction::{ConwayFormatTxOut, DatumOption, Transaction, TransactionOutput},
};
use hex_literal::hex;
use std::collections::BTreeMap;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CardanoTx(pub Transaction);

impl PartialEq for CardanoTx {
    fn eq(&self, other: &Self) -> bool {
        if std::ptr::eq(self, other) {
            return true;
        }
        self.0.to_canonical_cbor_bytes() == other.0.to_canonical_cbor_bytes()
    }
}

impl CardanoTx {
    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        Ok(Self(
            Transaction::from_cbor_bytes(&hex::decode(hex.as_bytes())?)
                .map_err(|e| anyhow!("{}", e))?,
        ))
    }
}

impl EnchantedTx for CardanoTx {
    fn extract_and_verify_spell(
        &self,
        spell_vk: &str,
        mock: bool,
    ) -> anyhow::Result<NormalizedSpell> {
        let tx = &self.0;

        let inputs = &tx.body.inputs;
        ensure!(inputs.len() > 0, "Transaction has no inputs");

        let outputs = &tx.body.outputs;
        ensure!(outputs.len() > 0, "Transaction has no outputs");

        let Some(spell_data) = outputs
            .iter()
            .rev()
            .take(2)
            .find_map(|output| match output {
                TransactionOutput::ConwayFormatTxOut(ConwayFormatTxOut {
                    datum_option:
                        Some(DatumOption::Datum {
                            datum:
                                PlutusData::Bytes {
                                    bytes: spell_data, ..
                                },
                            ..
                        }),
                    ..
                }) => Some(spell_data),
                _ => None,
            })
        else {
            bail!("Transaction has no spell output");
        };

        let (spell, proof): (NormalizedSpell, Proof) = util::read(spell_data.as_slice())
            .map_err(|e| anyhow!("could not parse spell and proof: {}", e))?;

        if !mock {
            ensure!(!spell.mock, "spell is a mock, but we are not in mock mode");
        }
        ensure!(
            &spell.tx.ins.is_none(),
            "spell must inherit inputs from the enchanted tx"
        );
        ensure!(
            spell.tx.outs.len() < outputs.len(),
            "spell tx outs mismatch"
        );

        let spell = spell_with_committed_ins_and_coins(spell, self);

        native_outs_comply(&spell, self)?;

        let spell_vk = tx::spell_vk(spell.version, spell_vk, spell.mock)?;

        let public_values = tx::to_serialized_pv(spell.version, &(spell_vk, &spell));

        tx::verify_snark_proof(&proof, &public_values, spell_vk, spell.version, spell.mock)?;

        Ok(spell)
    }

    fn tx_outs_len(&self) -> usize {
        self.0.body.outputs.len()
    }

    fn tx_id(&self) -> TxId {
        let transaction_hash = self.0.body.hash();
        tx_id(transaction_hash)
    }

    fn hex(&self) -> String {
        hex::encode(self.0.to_canonical_cbor_bytes())
    }

    fn spell_ins(&self) -> Vec<UtxoId> {
        self.0.body.inputs[..self.0.body.inputs.len() - 1] // exclude the funding input
            .iter()
            .map(|tx_in| {
                let tx_id = tx_id(tx_in.transaction_id);
                let index = tx_in.index as u32;

                UtxoId(tx_id, index)
            })
            .collect()
    }

    fn all_coin_outs(&self) -> Vec<NativeOutput> {
        (self.0.body.outputs)
            .iter()
            .map(|tx_out| NativeOutput {
                amount: tx_out.amount().coin.into(),
                dest: tx_out.address().to_raw_bytes(),
            })
            .collect()
    }
}

pub const MINT_SCRIPT: &[u8] = &hex!(
    "5859010100229800aba2aba1aab9eaab9dab9a9bae00248888896600264653001300700198039804000cc01c0092225980099b8748000c020dd500144c9289bae300a3009375400516401c30070013004375400f149a26cac80101"
);

pub fn policy_id(app: &App) -> anyhow::Result<(PolicyId, PlutusV3Script)> {
    let param_data = PlutusData::new_list(vec![PlutusData::new_bytes(app.vk.0.to_vec())]);
    let program = uplc::tx::apply_params_to_script(&param_data.to_cbor_bytes(), MINT_SCRIPT)
        .map_err(|e| anyhow!("error applying app.vk to Charms token policy: {}", e))?;
    let script = PlutusV3Script::new(program);
    let policy_id = script.hash();
    Ok((policy_id, script))
}

pub fn asset_name(app: &App) -> anyhow::Result<AssetName> {
    const FT_LABEL: &[u8] = &[0x00, 0x14, 0xdf, 0x10];
    const NFT_LABEL: &[u8] = &[0x00, 0x0d, 0xe1, 0x40];
    let label = match app.tag {
        TOKEN => FT_LABEL,
        NFT => NFT_LABEL,
        _ => unreachable!("unsupported tag: {}", app.tag),
    };
    Ok(AssetName::new([label, &app.identity.0[4..]].concat())
        .map_err(|e| anyhow!("error converting to Cardano AssetName: {}", e))?)
}

pub fn get_value(app: &App, data: &Data) -> anyhow::Result<u64> {
    match app.tag {
        TOKEN => Ok(data.value()?),
        NFT => Ok(1),
        _ => unreachable!("unsupported tag: {}", app.tag),
    }
}

pub fn multi_asset(charms: &Charms) -> anyhow::Result<MultiAsset> {
    let mut multi_asset = MultiAsset::new();
    let mut scripts = BTreeMap::new();
    for (app, data) in charms {
        if app.tag != TOKEN && app.tag != NFT {
            continue; // TODO figure what to do with other tags
        }
        let (policy_id, script) = policy_id(app)?;
        let asset_name = asset_name(app)?;
        let value = get_value(app, data)?;
        scripts.insert(policy_id, script);
        multi_asset.set(policy_id, asset_name, value);
    }
    Ok(multi_asset)
}

/// Native outputs contain CNTs representing Charms
fn native_outs_comply(spell: &NormalizedSpell, tx: &CardanoTx) -> anyhow::Result<()> {
    // for each spell output, check that the corresponding native output has CNTs corresponding to
    // charms in it
    for (i, (spell_out, native_out)) in spell
        .tx
        .outs
        .iter()
        .zip(tx.0.body.outputs.iter())
        .enumerate()
    {
        let tx_multi_asset = &native_out.amount().multiasset;
        let expected_multi_asset = multi_asset(&charms(spell, spell_out))?;

        let remainder = tx_multi_asset
            .checked_sub(&expected_multi_asset)
            .context(format!("Output {i} missing CNTs"))?;
        let unexpected = expected_multi_asset.clamped_sub(&remainder);
        ensure!(
            expected_multi_asset.clamped_sub(&remainder).is_empty(),
            "Output {i} has unexpected Charms CNTs: {unexpected:?}"
        );
    }
    Ok(())
}

fn spell_with_committed_ins_and_coins(spell: NormalizedSpell, tx: &CardanoTx) -> NormalizedSpell {
    let tx_ins: Vec<UtxoId> = tx.spell_ins();

    let mut spell = spell;
    spell.tx.ins = Some(tx_ins);

    if spell.version > V7 {
        let mut coins = tx.all_coin_outs();
        coins.truncate(spell.tx.outs.len());
        spell.tx.coins = Some(coins);
    }

    spell
}

pub fn tx_id(transaction_hash: TransactionHash) -> TxId {
    let mut txid: [u8; 32] = transaction_hash.into();
    txid.reverse(); // Charms use Bitcoin's reverse byte order for txids
    let tx_id = TxId(txid);
    tx_id
}

pub fn tx_hash(tx_id: TxId) -> TransactionHash {
    let mut txid_bytes = tx_id.0;
    txid_bytes.reverse(); // Charms use Bitcoin's reverse byte order for txids
    let tx_hash = txid_bytes.into();
    tx_hash
}
