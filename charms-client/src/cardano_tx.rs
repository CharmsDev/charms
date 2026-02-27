use crate::{NormalizedSpell, Proof, V10, beamed_out_to_hash, charms, tx, tx::EnchantedTx};
use anyhow::{anyhow, bail, ensure};
use charms_data::{App, Charms, Data, NFT, NativeOutput, TOKEN, TxId, UtxoId, util};
use cml_chain::{
    Deserialize, PolicyId, Serialize,
    address::Address,
    assets::{AssetName, ClampedSub, MultiAsset},
    certs::Credential,
    crypto::{Ed25519Signature, ScriptHash, TransactionHash, Vkey},
    plutus::{PlutusData, PlutusV3Script, RedeemerTag},
    transaction::{ConwayFormatTxOut, DatumOption, ScriptRef, Transaction, TransactionOutput},
};
use cml_core::serialization::RawBytesEncoding;
use hex_literal::hex;
use pallas_crypto::hash::Hasher;
use serde_with::serde_as;
use std::collections::BTreeMap;

/// Ed25519 public key used by Scrolls to certify Cardano transaction finality.
const FINALITY_VKEY: [u8; 32] =
    hex!("fa868875d46c5dd4da079f4e17e5f94d89b7b64f748275b7810f5ec9d9011bb9");

serde_with::serde_conv!(
    TransactionHex,
    Transaction,
    |tx: &Transaction| hex::encode(tx.to_cbor_bytes()),
    |s: String| Transaction::from_cbor_bytes(&hex::decode(s.as_bytes())?)
        .map_err(|e| anyhow!("{}", e))
);

serde_with::serde_conv!(
    SignatureHex,
    Ed25519Signature,
    |sig: &Ed25519Signature| sig.to_hex(),
    |s: String| Ed25519Signature::from_hex(&s).map_err(|e| anyhow!("{}", e))
);

#[serde_as]
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(untagged)]
pub enum CardanoTx {
    Simple(#[serde_as(as = "TransactionHex")] Transaction),
    WithFinalityProof {
        #[serde_as(as = "TransactionHex")]
        tx: Transaction,

        #[serde_as(as = "SignatureHex")]
        signature: Ed25519Signature,
    },
}

impl PartialEq for CardanoTx {
    fn eq(&self, other: &Self) -> bool {
        if std::ptr::eq(self, other) {
            return true;
        }
        self.inner().to_cbor_bytes() == other.inner().to_cbor_bytes()
    }
}

impl CardanoTx {
    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        Ok(Self::Simple(
            Transaction::from_cbor_bytes(&hex::decode(hex.as_bytes())?)
                .map_err(|e| anyhow!("{}", e))?,
        ))
    }

    pub fn inner(&self) -> &Transaction {
        match self {
            CardanoTx::Simple(tx) => tx,
            CardanoTx::WithFinalityProof { tx, .. } => tx,
        }
    }
}

impl EnchantedTx for CardanoTx {
    fn extract_and_verify_spell(
        &self,
        spell_vk: &str,
        mock: bool,
    ) -> anyhow::Result<NormalizedSpell> {
        let tx = self.inner();

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

        let permutation = extract_input_permutation(tx)?;
        let spell = spell_with_committed_ins_and_coins(spell, self, &permutation)?;

        native_outs_comply(&spell, self)?;

        let spell_vk = tx::spell_vk(spell.version, spell_vk, spell.mock)?;

        let public_values = tx::to_serialized_pv(spell.version, &(spell_vk, &spell));

        tx::verify_snark_proof(&proof, &public_values, spell_vk, spell.version, spell.mock)?;

        Ok(spell)
    }

    fn tx_outs_len(&self) -> usize {
        self.inner().body.outputs.len()
    }

    fn tx_id(&self) -> TxId {
        let transaction_hash = self.inner().body.hash();
        tx_id(transaction_hash)
    }

    fn hex(&self) -> String {
        hex::encode(self.inner().to_cbor_bytes())
    }

    fn spell_ins(&self) -> Vec<UtxoId> {
        self.inner()
            .body
            .inputs
            .iter()
            .map(|tx_in| {
                let tx_id = tx_id(tx_in.transaction_id);
                let index = tx_in.index as u32;

                UtxoId(tx_id, index)
            })
            .collect()
    }

    fn all_coin_outs(&self, spell: &NormalizedSpell) -> anyhow::Result<Vec<NativeOutput>> {
        let default_charms = Default::default();
        self.inner()
            .body
            .outputs
            .iter()
            .enumerate()
            .map(|(i, tx_out)| -> anyhow::Result<NativeOutput> {
                let spell_out = spell.tx.outs.get(i).unwrap_or(&default_charms);
                let beamed_out = beamed_out_to_hash(spell, i as u32).is_some();
                let ma_all = tx_out.amount().multiasset.clone();
                let (ma_charms, _) = multi_asset(&charms(spell, spell_out), beamed_out);
                let output_content = OutputContent {
                    multiasset: ma_all.checked_sub(&ma_charms)?,
                    datum: tx_out.datum(),
                    script_ref: tx_out.script_ref().cloned(),
                };
                Ok(NativeOutput {
                    amount: tx_out.amount().coin.into(),
                    dest: tx_out.address().to_raw_bytes(),
                    content: Some((&output_content).into()),
                })
            })
            .collect()
    }

    fn proven_final(&self) -> bool {
        match self {
            CardanoTx::Simple(_) => false,
            CardanoTx::WithFinalityProof { tx, signature } => {
                verify_finality_signature(tx, signature).is_ok()
            }
        }
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct OutputContent {
    pub multiasset: MultiAsset,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub datum: Option<DatumOption>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub script_ref: Option<ScriptRef>,
}

fn verify_finality_signature(tx: &Transaction, signature: &Ed25519Signature) -> anyhow::Result<()> {
    let vkey =
        Vkey::from_raw_bytes(&FINALITY_VKEY).map_err(|e| anyhow!("invalid finality vkey: {e}"))?;
    let tx_body_hash = tx.body.hash();
    ensure!(
        vkey.verify(tx_body_hash.to_raw_bytes(), signature),
        "finality signature verification failed"
    );
    Ok(())
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
    let policy_id = script_hash(&script);
    (policy_id, script)
}

pub fn proxy_script_hash(apps: &[&App]) -> (ScriptHash, PlutusV3Script) {
    let apps_hash = apps_hash(apps);

    let param_data = PlutusData::new_list(vec![PlutusData::new_bytes(apps_hash)]);
    let program =
        uplc::tx::apply_params_to_script(&param_data.to_cbor_bytes(), CHARMS_APP_PROXY_SCRIPT)
            .expect("app VK should successfully apply to the Charms app proxy script");
    let script = PlutusV3Script::from_cbor_bytes(&program)
        .expect("script should successfully deserialize from CBOR");
    let script_hash = script_hash(&script);
    (script_hash, script)
}

fn apps_hash(apps: &[&App]) -> Vec<u8> {
    let mut apps = apps.to_vec();
    apps.sort();
    let hasher = apps.iter().fold(Hasher::<256>::new(), |mut acc, &app| {
        acc.input(&util::write(app).expect("infallible"));
        acc
    });
    hasher.finalize().to_vec()
}

/// Compute the correct script hash for a PlutusV3 script.
/// The Cardano ledger expects: blake2b-224(0x03 || cbor_bytes)
/// where cbor_bytes includes the CBOR header (e.g., 59026b for a 619-byte script).
fn script_hash(script: &PlutusV3Script) -> ScriptHash {
    let cbor_bytes = script.to_cbor_bytes();
    let hash = Hasher::<224>::hash_tagged(&cbor_bytes, 0x03); // PlutusV3 namespace tag
    ScriptHash::from_raw_bytes(hash.as_ref()).expect("hash should be valid")
}

pub fn asset_name(app: &App) -> AssetName {
    const FT_LABEL: &[u8] = &[0x00, 0x14, 0xdf, 0x10];
    const NFT_LABEL: &[u8] = &[0x00, 0x0d, 0xe1, 0x40];
    let label = match app.tag {
        TOKEN => FT_LABEL,
        NFT => NFT_LABEL,
        _ => unreachable!("unsupported tag: {}", app.tag),
    };
    AssetName::new([label, &app.identity.0[4..]].concat())
        .expect(format!("error converting app to Cardano AssetName: {}", app).as_str())
}

pub fn get_value(app: &App, data: &Data) -> u64 {
    match app.tag {
        TOKEN => data.value().expect("numeric value expected"),
        NFT => 1,
        _ => unreachable!("unsupported tag: {}", app.tag),
    }
}

pub fn multi_asset(
    charms: &Charms,
    beamed_out: bool,
) -> (MultiAsset, BTreeMap<PolicyId, PlutusV3Script>) {
    let mut multi_asset = MultiAsset::new();
    let mut scripts = BTreeMap::new();
    if beamed_out {
        return (multi_asset, scripts);
    }
    for (app, data) in charms {
        if app.tag != TOKEN && app.tag != NFT {
            continue; // skip non-token charms
        }
        let (policy_id, script) = policy_id(app);
        let asset_name = asset_name(app);
        let value = get_value(app, data);
        scripts.insert(policy_id, script);
        multi_asset.set(policy_id, asset_name, value);
    }
    (multi_asset, scripts)
}

/// Native outputs contain CNTs representing Charms.
/// Native outputs with non-token Charms are at the Charms proxy script addresses.
fn native_outs_comply(spell: &NormalizedSpell, tx: &CardanoTx) -> anyhow::Result<()> {
    // for each spell output, check that the corresponding native output has CNTs corresponding to
    // charms in it
    for (i, (spell_out, native_out)) in (spell.tx.outs)
        .iter()
        .zip(tx.inner().body.outputs.iter())
        .enumerate()
    {
        let is_beamed_out = beamed_out_to_hash(spell, i as u32).is_some();

        let present_all = &native_out.amount().multiasset;
        let charms = charms(spell, spell_out);

        native_out_address_complies(&charms, native_out.address())?;

        let (expected_charms, _) = multi_asset(&charms, is_beamed_out);

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

fn native_out_address_complies(charms: &Charms, address: &Address) -> anyhow::Result<()> {
    let non_token_charms_apps = charms
        .keys()
        .filter(|&app| app.tag != TOKEN && app.tag != NFT)
        .collect::<Vec<_>>();
    let non_token_charms_present = !non_token_charms_apps.is_empty();

    let is_address_charms_proxy_script: bool =
        is_proxy_script_address(&non_token_charms_apps, address)?;

    ensure!(
        non_token_charms_present && is_address_charms_proxy_script
            || !non_token_charms_present && !is_address_charms_proxy_script
    );

    Ok(())
}

fn is_proxy_script_address(apps: &[&App], address: &Address) -> anyhow::Result<bool> {
    let (script_hash, _) = proxy_script_hash(apps);
    if let Credential::Script { hash, .. } = address
        .payment_cred()
        .ok_or(anyhow!("Address does not have payment credential"))?
    {
        return Ok(hash == &script_hash);
    }
    Ok(false)
}

fn spell_with_committed_ins_and_coins(
    spell: NormalizedSpell,
    tx: &CardanoTx,
    permutation: &[u32],
) -> anyhow::Result<NormalizedSpell> {
    let tx_ins: Vec<UtxoId> = tx.spell_ins();

    // Restore the original order using permutation
    let original_ins: Vec<UtxoId> = permutation
        .iter()
        .map(|&pos| tx_ins[pos as usize].clone())
        .collect();

    let mut spell = spell;
    spell.tx.ins = Some(original_ins);

    // this code is coming online with V10, so `spell.version > V7` holds
    let mut coins = tx.all_coin_outs(&spell)?;
    coins.truncate(spell.tx.outs.len());
    // `native_output.content` is available since V11
    if spell.version <= V10 {
        for native_output in &mut coins {
            native_output.content = None;
        }
    }
    spell.tx.coins = Some(coins);

    Ok(spell)
}

/// Extracts the input permutation from the withdraw-0 redeemer data.
fn extract_input_permutation(tx: &Transaction) -> anyhow::Result<Vec<u32>> {
    use cml_chain::plutus::Redeemers;

    let redeemers = tx
        .witness_set
        .redeemers
        .as_ref()
        .ok_or_else(|| anyhow!("Transaction has no redeemers"))?;

    match redeemers {
        Redeemers::ArrLegacyRedeemer {
            arr_legacy_redeemer,
            ..
        } => {
            for redeemer in arr_legacy_redeemer {
                if redeemer.tag == RedeemerTag::Reward {
                    if let PlutusData::Bytes { bytes, .. } = &redeemer.data {
                        return util::read(bytes.as_slice())
                            .map_err(|e| anyhow!("Failed to decode input permutation: {}", e));
                    }
                }
            }
        }
        Redeemers::MapRedeemerKeyToRedeemerVal {
            map_redeemer_key_to_redeemer_val,
            ..
        } => {
            for (key, val) in map_redeemer_key_to_redeemer_val.iter() {
                if key.tag == RedeemerTag::Reward {
                    if let PlutusData::Bytes { bytes, .. } = &val.data {
                        return util::read(bytes.as_slice())
                            .map_err(|e| anyhow!("Failed to decode input permutation: {}", e));
                    }
                }
            }
        }
    }
    bail!("Transaction has no withdraw redeemer with input permutation")
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
    fn test_flat_encoding_roundtrip() {
        // Test if round-tripping through uplc changes the flat encoding
        // Get the raw flat bytes from CHARMS_APP_PROXY_SCRIPT (skip CBOR header)
        // CBOR header is 590244 (3 bytes: 59 = bytes with 2-byte length, 0244 = 580)
        let original_flat = &CHARMS_APP_PROXY_SCRIPT[3..];
        eprintln!("Original flat length: {}", original_flat.len());
        eprintln!(
            "Original flat first 10 bytes: {}",
            hex::encode(&original_flat[..10])
        );

        // Parse from flat
        let program =
            Program::<DeBruijn>::from_flat(original_flat).expect("should parse from flat");
        eprintln!(
            "Parsed program version: {}.{}.{}",
            program.version.0, program.version.1, program.version.2
        );

        // Re-encode to flat
        let re_encoded = program.to_flat().expect("should encode to flat");
        eprintln!("Re-encoded flat length: {}", re_encoded.len());
        eprintln!(
            "Re-encoded flat first 10 bytes: {}",
            hex::encode(&re_encoded[..10])
        );

        // Compare
        eprintln!("Same encoding: {}", original_flat == re_encoded.as_slice());

        if original_flat != re_encoded.as_slice() {
            eprintln!("\nDifferences found!");
            for (i, (a, b)) in original_flat.iter().zip(re_encoded.iter()).enumerate() {
                if a != b {
                    eprintln!("  Byte {}: original={:02x}, re-encoded={:02x}", i, a, b);
                }
            }
            if original_flat.len() != re_encoded.len() {
                eprintln!(
                    "  Length differs: {} vs {}",
                    original_flat.len(),
                    re_encoded.len()
                );
            }
        }

        // The encoding should be stable - this would catch any issues with the flat encoding
        assert_eq!(
            original_flat,
            re_encoded.as_slice(),
            "Flat encoding changed after round-trip!"
        );
    }

    #[test]
    fn test_apply_params_encoding() {
        // Test what apply_params_to_script produces
        let app = App {
            tag: TOKEN,
            identity: B32::from_str(
                "3d7fe7e4cea6121947af73d70e5119bebd8aa5b7edfe74bfaf6e779a1847bd9b",
            )
            .unwrap(),
            vk: B32::from_str("c975d4e0c292fb95efbda5c13312d6ac1d8b5aeff7f0f1e5578645a2da70ff5f")
                .unwrap(),
        };

        let param_data = PlutusData::new_list(vec![PlutusData::new_bytes(app.vk.0.to_vec())]);
        eprintln!(
            "param_data CBOR: {}",
            hex::encode(param_data.to_cbor_bytes())
        );

        // Apply params
        let program_cbor =
            uplc::tx::apply_params_to_script(&param_data.to_cbor_bytes(), CHARMS_APP_PROXY_SCRIPT)
                .expect("apply_params_to_script should work");

        eprintln!("Result CBOR length: {}", program_cbor.len());
        eprintln!(
            "Result CBOR first 10 bytes: {}",
            hex::encode(&program_cbor[..10])
        );

        // Extract flat bytes (skip CBOR header)
        // The header could be 59 XX XX (3 bytes) for lengths up to 65535
        let flat_bytes = if program_cbor[0] == 0x59 {
            &program_cbor[3..]
        } else if program_cbor[0] == 0x58 {
            &program_cbor[2..]
        } else {
            panic!("Unexpected CBOR header: {:02x}", program_cbor[0]);
        };

        eprintln!("Flat bytes length: {}", flat_bytes.len());
        eprintln!("Flat bytes first 10: {}", hex::encode(&flat_bytes[..10]));

        // Parse the flat bytes
        let program = Program::<DeBruijn>::from_flat(flat_bytes).expect("should parse from flat");
        eprintln!(
            "Parsed program version: {}.{}.{}",
            program.version.0, program.version.1, program.version.2
        );
        eprintln!("Program pretty:\n{}", program.to_pretty());

        // Re-encode to flat and compare
        let re_encoded = program.to_flat().expect("should encode to flat");
        eprintln!("\nRe-encoded flat length: {}", re_encoded.len());
        eprintln!(
            "Re-encoded flat first 10: {}",
            hex::encode(&re_encoded[..10])
        );

        if flat_bytes != re_encoded.as_slice() {
            eprintln!("\nEncoding changed after round-trip!");
            for (i, (a, b)) in flat_bytes.iter().zip(re_encoded.iter()).enumerate() {
                if a != b {
                    eprintln!("  Byte {}: original={:02x}, re-encoded={:02x}", i, a, b);
                }
            }
        } else {
            eprintln!("\nEncoding is stable after round-trip");
        }
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

        // Check intermediate steps
        let param_data = PlutusData::new_list(vec![PlutusData::new_bytes(app.vk.0.to_vec())]);
        eprintln!(
            "param_data CBOR: {}",
            hex::encode(param_data.to_cbor_bytes())
        );

        let program_cbor =
            uplc::tx::apply_params_to_script(&param_data.to_cbor_bytes(), CHARMS_APP_PROXY_SCRIPT)
                .expect("apply_params_to_script should work");
        eprintln!("program_cbor length: {}", program_cbor.len());
        eprintln!(
            "program_cbor first 20 bytes: {}",
            hex::encode(&program_cbor[..20])
        );

        // Try to parse the CBOR output
        let mut buffer = Vec::new();
        let program = Program::<DeBruijn>::from_cbor(&program_cbor, &mut buffer)
            .expect("should parse from CBOR");
        eprintln!(
            "Parsed program version: {}.{}.{}",
            program.version.0, program.version.1, program.version.2
        );

        // Encode back to flat and compare
        let flat_bytes = program.to_flat().expect("should encode to flat");
        eprintln!("Flat encoding length: {}", flat_bytes.len());
        eprintln!(
            "Flat encoding first 20 bytes: {}",
            hex::encode(&flat_bytes[..20])
        );

        let (policy_id, script) = policy_id(&app);
        dbg!(policy_id.to_hex());

        // Check what's in script.inner
        eprintln!("script.inner length: {}", script.inner.len());
        eprintln!(
            "script.inner first 20 bytes: {}",
            hex::encode(&script.inner[..20])
        );
        eprintln!("script.inner == flat_bytes: {}", script.inner == flat_bytes);

        // Check if the first 3 bytes indicate the right version
        eprintln!(
            "UPLC version from inner: {}.{}.{}",
            script.inner[0], script.inner[1], script.inner[2]
        );

        let app_script = script.to_cbor_bytes();

        let mut buffer = Vec::new();
        let program = Program::<DeBruijn>::from_cbor(&app_script, &mut buffer).unwrap();
        // eprintln!("{}", program.to_pretty());
        assert_eq!(622, program.to_cbor().unwrap().len());
    }

    #[test]
    fn test_script_bytes() {
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
        eprintln!("policy_id: {}", policy_id.to_hex());
        eprintln!("script.inner length: {}", script.inner.len());
        eprintln!(
            "script.inner first 20 bytes: {}",
            hex::encode(&script.inner[..20])
        );
        eprintln!(
            "script.to_cbor_bytes length: {}",
            script.to_cbor_bytes().len()
        );
        eprintln!(
            "script.to_cbor_bytes first 20 bytes: {}",
            hex::encode(&script.to_cbor_bytes()[..20])
        );
        eprintln!(
            "script.to_raw_bytes length: {}",
            script.to_raw_bytes().len()
        );
        eprintln!(
            "script.to_raw_bytes first 20 bytes: {}",
            hex::encode(&script.to_raw_bytes()[..20])
        );

        // Also test SCROLLS_V10 reference script for comparison
        let scrolls_v10_cbor = hex::decode("58ca0101003229800aba2aba1aab9eaab9dab9a9bae0024888889660026464646644b30013370e900200144ca600200f375c60166018601860186018601860186018601860186018601860146ea8c02c01a6eb800976a300a3009375400715980099b874801800a2653001375a6016003300b300c0019bae0024889288c024dd5001c59007200e300637540026010004600e6010002600e00260086ea801e29344d95900213001225820aa75665a675fc5bcbaded7b8ae8d833b07d3559ab352db6c83efd361392840cb0001").unwrap();
        // Decode CBOR to get raw bytes (58ca is the CBOR header)
        let scrolls_raw = &scrolls_v10_cbor[2..]; // Skip 58ca header
        match Program::<DeBruijn>::from_flat(scrolls_raw) {
            Ok(program) => {
                eprintln!(
                    "SCROLLS_V10 parsed! version: {}.{}.{}",
                    program.version.0, program.version.1, program.version.2
                );
            }
            Err(e) => {
                eprintln!("SCROLLS_V10 failed to parse: {:?}", e);
            }
        }

        // Test the exact bytes extracted from a failing transaction
        let extracted_script = hex::decode("010100332229800aba2aba1aba0aab9faab9eaab9dab9a9bae0039bae0024888888889660033001300537540152259800800c5300103d87a80008992cc004006266e9520003300a300b0024bd7044cc00c00c0050091805800a010918049805000cdc3a400091111991194c004c02cdd5000cc03c01e44464b30013008300f37540031325980099b87323322330020020012259800800c00e2646644b30013372201400515980099b8f00a0028800c01901544cc014014c06c0110151bae3014001375a602a002602e00280a8c8c8cc004004dd59806980a1baa300d3014375400844b3001001801c4c8cc896600266e4403000a2b30013371e0180051001803202c899802802980e002202c375c602a0026eacc058004c0600050160a5eb7bdb180520004800a264b3001300a301137540031323322330020020012259800800c528456600266ebc00cc050c0600062946266004004603200280990161bab30163017301730173017301730173017301730173013375400a66e952004330143374a90011980a180a98091baa0014bd7025eb822c8080c050c054c054c054c044dd5180518089baa0018b201e301330103754003164038600a6eb0c020c03cdd5000cc03c00d222259800980400244ca600201d375c005004400c6eb8c04cc040dd5002c56600266e1d200200489919914c0040426eb801200c8028c050004c050c054004c040dd5002c5900e201c1807180780118068021801801a29344d959003130011e581c1775920b2f415d295553835fb7d26d8186cff73d352c9e9b98cad240004c01225820c975d4e0c292fb95efbda5c13312d6ac1d8b5aeff7f0f1e5578645a2da70ff5f0001").unwrap();
        match Program::<DeBruijn>::from_flat(&extracted_script) {
            Ok(program) => {
                eprintln!(
                    "Extracted script parsed! version: {}.{}.{}",
                    program.version.0, program.version.1, program.version.2
                );
            }
            Err(e) => {
                eprintln!("Extracted script failed to parse: {:?}", e);
            }
        }

        // Try to parse with uplc from flat encoding
        match Program::<DeBruijn>::from_flat(&script.inner) {
            Ok(program) => {
                eprintln!(
                    "Successfully parsed UPLC program from flat! version: {}.{}.{}",
                    program.version.0, program.version.1, program.version.2
                );
            }
            Err(e) => {
                eprintln!("Failed to parse UPLC program from flat: {:?}", e);
                // Try from cbor
                let mut buffer = Vec::new();
                match Program::<DeBruijn>::from_cbor(&script.to_cbor_bytes(), &mut buffer) {
                    Ok(program) => {
                        eprintln!(
                            "Successfully parsed UPLC program from CBOR! version: {}.{}.{}",
                            program.version.0, program.version.1, program.version.2
                        );
                    }
                    Err(e2) => {
                        eprintln!("Also failed to parse from CBOR: {:?}", e2);
                    }
                }
            }
        }
    }

    #[test]
    fn test_save_and_decode_scripts() {
        let app = App {
            tag: TOKEN,
            identity: B32::from_str(
                "3d7fe7e4cea6121947af73d70e5119bebd8aa5b7edfe74bfaf6e779a1847bd9b",
            )
            .unwrap(),
            vk: B32::from_str("c975d4e0c292fb95efbda5c13312d6ac1d8b5aeff7f0f1e5578645a2da70ff5f")
                .unwrap(),
        };
        let (_, script) = policy_id(&app);

        // Save our script flat bytes
        let our_flat = &script.inner;
        std::fs::write("/tmp/our_script_flat.hex", hex::encode(our_flat)).unwrap();
        eprintln!(
            "Saved our script to /tmp/our_script_flat.hex ({} bytes flat)",
            our_flat.len()
        );

        // Save SCROLLS_V10 flat bytes for comparison
        let scrolls_cbor = hex::decode("58ca0101003229800aba2aba1aab9eaab9dab9a9bae0024888889660026464646644b30013370e900200144ca600200f375c60166018601860186018601860186018601860186018601860146ea8c02c01a6eb800976a300a3009375400715980099b874801800a2653001375a6016003300b300c0019bae0024889288c024dd5001c59007200e300637540026010004600e6010002600e00260086ea801e29344d95900213001225820aa75665a675fc5bcbaded7b8ae8d833b07d3559ab352db6c83efd361392840cb0001").unwrap();
        let scrolls_flat = &scrolls_cbor[2..]; // Skip 58ca CBOR header
        std::fs::write("/tmp/scrolls_flat.hex", hex::encode(scrolls_flat)).unwrap();
        eprintln!(
            "Saved SCROLLS_V10 to /tmp/scrolls_flat.hex ({} bytes flat)",
            scrolls_flat.len()
        );

        // Also save the base script (CHARMS_APP_PROXY_SCRIPT) before param application
        let base_flat = &CHARMS_APP_PROXY_SCRIPT[3..]; // Skip 590244 CBOR header
        std::fs::write("/tmp/base_script_flat.hex", hex::encode(base_flat)).unwrap();
        eprintln!(
            "Saved base script to /tmp/base_script_flat.hex ({} bytes flat)",
            base_flat.len()
        );
    }

    #[test]
    fn test_script_hash_both_ways() {
        use pallas_crypto::hash::Hasher;

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
        assert_eq!(
            policy_id.to_hex(),
            "b8f72e95dee612df98ac5a90b7604f7815c2af07a6db209a5c70abe4"
        );

        // Method 1: Hash flat bytes with 0x03 prefix (what cml-chain does)
        let flat_bytes = &script.inner;
        let mut data1 = vec![0x03u8]; // PlutusV3 namespace
        data1.extend_from_slice(flat_bytes);
        let hash1 = Hasher::<224>::hash(&data1);

        // Method 2: Hash CBOR-wrapped bytes with 0x03 prefix
        let cbor_bytes = script.to_cbor_bytes();
        let mut data2 = vec![0x03u8]; // PlutusV3 namespace
        data2.extend_from_slice(&cbor_bytes);
        let hash2 = Hasher::<224>::hash(&data2);

        eprintln!("Policy ID:          {}", policy_id.to_hex());
        eprintln!("Hash of flat bytes: {}", hex::encode(hash1));
        eprintln!("Hash of CBOR bytes: {}", hex::encode(hash2));
        eprintln!(
            "Expected from cli:        b8f72e95dee612df98ac5a90b7604f7815c2af07a6db209a5c70abe4"
        );
        eprintln!("");
        eprintln!("Flat bytes length: {}", flat_bytes.len());
        eprintln!("CBOR bytes length: {}", cbor_bytes.len());
    }
}
