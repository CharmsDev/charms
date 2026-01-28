use crate::{NormalizedSpell, Proof, V7, charms, tx, tx::EnchantedTx};
use anyhow::{anyhow, bail, ensure};
use charms_data::{App, Charms, Data, NFT, NativeOutput, TOKEN, TxId, UtxoId, util};
use cml_chain::{
    Deserialize, PolicyId, Serialize,
    assets::{AssetName, ClampedSub, MultiAsset},
    crypto::TransactionHash,
    plutus::{PlutusData, PlutusV3Script},
    transaction::{ConwayFormatTxOut, DatumOption, Transaction, TransactionOutput},
};
use hex_literal::hex;
use serde_with::serde_as;
use std::collections::BTreeMap;

serde_with::serde_conv!(
    TransactionHex,
    Transaction,
    |tx: &Transaction| hex::encode(tx.to_canonical_cbor_bytes()),
    |s: String| Transaction::from_cbor_bytes(&hex::decode(s.as_bytes())?)
        .map_err(|e| anyhow!("{}", e))
);

#[serde_as]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct CardanoTx(#[serde_as(as = "TransactionHex")] pub Transaction);

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

    fn proven_final(&self) -> bool {
        false
    }
}

/// This script is parameterized with app VK for every token, NFT or spending contract.
pub const CHARMS_APP_PROXY_SCRIPT: &[u8] = &hex!(
    "59024401010032229800aba2aba1aba0aab9faab9eaab9dab9a9bae0039bae0024888888889660033001300537540152259800800c530103d87a80008992cc004006266e9520003300a300b0024bd7044cc00c00c0050091805800a010918049805000cdc3a400091111991194c004c02cdd5000cc03c01e44464b30013008300f37540031325980099b87323322330020020012259800800c00e2646644b30013372201400515980099b8f00a0028800c01901544cc014014c06c0110151bae3014001375a602a002602e00280a8c8c8cc004004dd59806980a1baa300d3014375400844b3001001801c4c8cc896600266e4403000a2b30013371e0180051001803202c899802802980e002202c375c602a0026eacc058004c0600050160a5eb7bdb180520004800a264b3001300a301137540031323322330020020012259800800c528456600266ebc00cc050c0600062946266004004603200280990161bab30163017301730173017301730173017301730173013375400a66e952004330143374a90011980a180a98091baa0014bd7025eb822c8080c050c054c054c054c044dd5180518089baa0018b201e301330103754003164038600a6eb0c020c03cdd5000cc03c00d222259800980400244ca600201d375c005004400c6eb8c04cc040dd5002c56600266e1d200200489919914c0040426eb801200c8028c050004c050c054004c040dd5002c5900e201c1807180780118068021801801a29344d959003130011e581c1775920b2f415d295553835fb7d26d8186cff73d352c9e9b98cad2400001"
);

pub fn policy_id(app: &App) -> (PolicyId, PlutusV3Script) {
    let param_data = PlutusData::new_list(vec![PlutusData::new_bytes(app.vk.0.to_vec())]);
    let program =
        uplc::tx::apply_params_to_script(&param_data.to_cbor_bytes(), CHARMS_APP_PROXY_SCRIPT)
            .expect("app VK should successfully apply to the Charms app proxy script");
    let script = PlutusV3Script::from_cbor_bytes(&program)
        .expect("script should successfully deserialize from CBOR");
    let policy_id = script.hash();
    (policy_id, script)
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

pub fn multi_asset(
    charms: &Charms,
) -> anyhow::Result<(MultiAsset, BTreeMap<PolicyId, PlutusV3Script>)> {
    let mut multi_asset = MultiAsset::new();
    let mut scripts = BTreeMap::new();
    for (app, data) in charms {
        if app.tag != TOKEN && app.tag != NFT {
            continue; // TODO figure what to do with other tags
        }
        let (policy_id, script) = policy_id(app);
        let asset_name = asset_name(app)?;
        let value = get_value(app, data)?;
        scripts.insert(policy_id, script);
        multi_asset.set(policy_id, asset_name, value);
    }
    Ok((multi_asset, scripts))
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
        let present_all = &native_out.amount().multiasset;
        let (expected_charms, _) = multi_asset(&charms(spell, spell_out))?;

        let missing_charms = expected_charms.clamped_sub(&present_all);
        ensure!(
            missing_charms.is_empty(),
            format!("Output {i} missing Charms CNTs: {missing_charms:?}")
        );

        // now present_all >= expected_charms

        // might contain non-expected CNTs (we don't care) PLUS extra amounts of expected CNTs (bad)
        let extra_all = present_all.clamped_sub(&expected_charms);
        if extra_all.is_empty() {
            // present_all == expected_charms
            continue;
        }

        // Check if any of the extra tokens overlap with expected CNTs (indicating excess amounts)
        let extra_charms = {
            let mut extra_charms = MultiAsset::new();
            for (policy, assets) in expected_charms.iter() {
                for (asset_name, _) in assets.iter() {
                    if let Some(amount) = extra_all.get(policy, asset_name) {
                        extra_charms.set(*policy, asset_name.clone(), amount);
                    }
                }
            }
            extra_charms
        };
        ensure!(
            extra_charms.is_empty(),
            format!("Output {i} has excess amounts of expected Charms CNTs: {extra_charms:?}")
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

#[cfg(test)]
mod tests {
    use super::*;
    use charms_data::B32;
    use cml_core::serialization::RawBytesEncoding;
    use std::str::FromStr;
    use uplc::ast::{DeBruijn, Program};

    const UNPARAMETERIZED_MAIN_SCRIPT: &[u8] = &hex!(
        "5902210101002229800aba2aba1aba0aab9faab9eaab9dab9a9bae0039bae0024888888889660033001300537540152259800800c5300103d87a80008992cc004006266e9520003300a300b0024bd7044cc00c00c0050091805800a010918049805000cdc3a400091111991194c004c02cdd5000cc03c01e44464b30013008300f37540031325980099b87323322330020020012259800800c00e2646644b30013372201400515980099b8f00a0028800c01901544cc014014c06c0110151bae3014001375a602a002602e00280a8c8c8cc004004dd59806980a1baa300d3014375400844b3001001801c4c8cc896600266e4403000a2b30013371e0180051001803202c899802802980e002202c375c602a0026eacc058004c0600050160a5eb7bdb180520004800a264b3001300a301137540031323322330020020012259800800c528456600266ebc00cc050c0600062946266004004603200280990161bab30163017301730173017301730173017301730173013375400a66e952004330143374a90011980a180a98091baa0014bd7025eb822c8080c050c054c054c054c044dd5180518089baa0018b201e301330103754003164038600a6eb0c020c03cdd5000cc03c00d222259800980400244ca600201d375c005004400c6eb8c04cc040dd5002c56600266e1d200200489919914c0040426eb801200c8028c050004c050c054004c040dd5002c5900e201c1807180780118068021801801a29344d9590031"
    );
    const PROTOCOL_VERSION_NFT_POLICY_ID: &[u8] =
        &hex!("1775920b2f415d295553835fb7d26d8186cff73d352c9e9b98cad240");

    fn apply_policy_id_to_main_script(policy_id: PolicyId) -> Vec<u8> {
        let param_data =
            PlutusData::new_list(vec![PlutusData::new_bytes(policy_id.to_raw_bytes().into())]);
        let program_cbor = uplc::tx::apply_params_to_script(
            &param_data.to_cbor_bytes(),
            UNPARAMETERIZED_MAIN_SCRIPT,
        )
        .unwrap();
        program_cbor
    }

    #[test]
    fn charms_app_proxy_script() {
        let policy_id = PolicyId::from_raw_bytes(PROTOCOL_VERSION_NFT_POLICY_ID).unwrap();
        let applied_script_cbor = apply_policy_id_to_main_script(policy_id);
        // dbg!(hex::encode(&applied_script_cbor));
        assert_eq!(CHARMS_APP_PROXY_SCRIPT, &applied_script_cbor);

        let mut buffer = Vec::new();
        let program = Program::<DeBruijn>::from_cbor(CHARMS_APP_PROXY_SCRIPT, &mut buffer).unwrap();
        // eprintln!("{}", program.to_pretty());
        assert_eq!(583, program.to_cbor().unwrap().len());
    }

    #[test]
    fn charms_app_policy_id() {
        let app = App {
            tag: TOKEN,
            identity: B32::from_str(
                "3d7fe7e4cea6121947af73d70e5119bebd8aa5b7edfe74bfaf6e779a1847bd9b",
            )
            .unwrap(),
            vk: B32::from_str("c975d4e0c292fb95efbda5c13312d6ac1d8b5aeff7f0f1e5578645a2da70ff5f")
                .unwrap(),
        };
        let (policy_id, script) = policy_id(&app);
        dbg!(policy_id.to_hex());
        let app_script = script.to_cbor_bytes();

        let mut buffer = Vec::new();
        let program = Program::<DeBruijn>::from_cbor(&app_script, &mut buffer).unwrap();
        // eprintln!("{}", program.to_pretty());
        assert_eq!(622, program.to_cbor().unwrap().len());
    }
}
