mod sorted_app_map;

pub mod prove;
pub mod prove_spell_tx;
pub mod request;
mod validate;

// Re-export public API to preserve existing `crate::spell::*` imports.
pub use prove::{MockProver, Prove, Prover};
pub use prove_spell_tx::{ProveSpellTx, ProveSpellTxImpl, committed_data_hash};
pub use request::{CharmsFee, FeeAddressForNetwork, ProveRequest};
pub use validate::{ensure_all_prev_txs_are_present, ensure_exact_app_binaries};

pub use charms_client::{
    BeamSource, CURRENT_VERSION, NormalizedCharms, NormalizedSpell, NormalizedTransaction, Proof,
    SpellProverInput, to_tx,
};

use anyhow::{Context, anyhow, ensure};
use bitcoin::{Amount, hashes::Hash};
use charms_client::{
    cardano_tx::OutputContent,
    tx::{Chain, Tx},
};
use charms_data::{App, Data, TxId, UtxoId};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::collections::BTreeMap;

/// CLI input format that wraps `NormalizedSpell` fields with additional private inputs
/// and beaming source data. Trivially decomposes into `NormalizedSpell` + extras.
#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpellInput {
    /// Protocol version.
    pub version: u32,
    /// Transaction data.
    pub tx: NormalizedTransaction,
    /// Maps all `App`s in the transaction to (potentially empty) public input data.
    /// Keys must be in sorted order in the input (human-readable formats).
    #[serde(
        serialize_with = "sorted_app_map::serialize",
        deserialize_with = "sorted_app_map::deserialize"
    )]
    pub app_public_inputs: BTreeMap<App, Data>,
    /// Is this a mock spell?
    #[serde(skip_serializing_if = "std::ops::Not::not", default)]
    pub mock: bool,

    /// Private inputs to the apps for this spell.
    #[serde(
        alias = "private_inputs",
        skip_serializing_if = "Option::is_none",
        default
    )]
    #[serde_as(as = "Option<BTreeMap<DisplayFromStr, _>>")]
    pub app_private_inputs: Option<BTreeMap<App, Data>>,

    /// Beaming source UTXOs, indexed by input position.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub beamed_from: Option<BTreeMap<usize, BeamSource>>,
}

impl SpellInput {
    /// Decompose into `NormalizedSpell`, private inputs, and beaming sources.
    pub fn into_parts(
        self,
    ) -> (
        NormalizedSpell,
        BTreeMap<App, Data>,
        BTreeMap<usize, BeamSource>,
    ) {
        let spell = NormalizedSpell {
            version: self.version,
            tx: self.tx,
            app_public_inputs: self.app_public_inputs,
            mock: self.mock,
        };
        let private_inputs = self.app_private_inputs.unwrap_or_default();
        let beamed_from = self.beamed_from.unwrap_or_default();
        (spell, private_inputs, beamed_from)
    }

    /// Create a `SpellInput` from a `NormalizedSpell` (for display, e.g. `tx show-spell`).
    pub fn from_normalized_spell(ns: &NormalizedSpell) -> Self {
        SpellInput {
            version: ns.version,
            tx: ns.tx.clone(),
            app_public_inputs: ns.app_public_inputs.clone(),
            mock: ns.mock,
            app_private_inputs: None,
            beamed_from: None,
        }
    }
}

/// Adjust `NativeOutput.content` fields in `spell_input.tx.coins` according to the target chain.
///
/// - **Cardano**: each non-`None` `content` is serialized to JSON, deserialized as
///   [`OutputContent`], and converted back to [`Data`] so that the CBOR representation matches the
///   canonical form produced by `charms_client::cardano_tx`.
/// - **Bitcoin**: every `content` field **must** be `None`; otherwise an error is returned.
pub fn adjust_coin_contents(
    mut spell_input: SpellInput,
    chain: Chain,
) -> anyhow::Result<SpellInput> {
    let Some(coins) = spell_input.tx.coins.as_mut() else {
        return Ok(spell_input);
    };

    for (i, coin) in coins.iter_mut().enumerate() {
        match chain {
            Chain::Bitcoin => {
                ensure!(
                    coin.content.is_none(),
                    "coins[{i}].content must be None for Bitcoin"
                );
            }
            Chain::Cardano => {
                if let Some(content) = coin.content.take() {
                    let json = serde_json::to_value(&content).with_context(|| {
                        format!("coins[{i}].content: failed to serialize to JSON")
                    })?;
                    let output_content: OutputContent =
                        serde_json::from_value(json).with_context(|| {
                            format!("coins[{i}].content: failed to parse as OutputContent")
                        })?;
                    coin.content = Some((&output_content).into());
                }
            }
        }
    }

    Ok(spell_input)
}

pub fn from_strings(prev_txs: &[String]) -> anyhow::Result<Vec<Tx>> {
    prev_txs
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|tx_hex| {
            Tx::try_from(tx_hex)
                .context("failed to convert from hex")
                .or_else(|_| serde_json::from_str(tx_hex).context("failed to convert from JSON"))
                .or_else(|_| serde_yaml::from_str(tx_hex).context("failed to convert from YAML"))
        })
        .collect()
}

pub fn get_charms_fee(charms_fee: &Option<CharmsFee>, total_cycles: u64) -> Amount {
    charms_fee
        .as_ref()
        .map(|charms_fee| {
            Amount::from_sat(total_cycles * charms_fee.fee_rate / 1000000 + charms_fee.fee_base)
        })
        .unwrap_or_default()
}

pub fn align_spell_to_tx(
    norm_spell: NormalizedSpell,
    tx: &bitcoin::Transaction,
) -> anyhow::Result<NormalizedSpell> {
    let mut norm_spell = norm_spell;
    let spell_ins = norm_spell.tx.ins.as_ref().ok_or(anyhow!("no inputs"))?;

    ensure!(
        spell_ins.len() <= tx.input.len(),
        "spell inputs exceed transaction inputs"
    );
    ensure!(
        norm_spell.tx.outs.len() <= tx.output.len(),
        "spell outputs exceed transaction outputs"
    );

    for i in 0..spell_ins.len() {
        let utxo_id = &spell_ins[i];
        let out_point = tx.input[i].previous_output;
        ensure!(
            utxo_id.0 == TxId(out_point.txid.to_byte_array()),
            "input {} txid mismatch: {} != {}",
            i,
            utxo_id.0,
            out_point.txid
        );
        ensure!(
            utxo_id.1 == out_point.vout,
            "input {} vout mismatch: {} != {}",
            i,
            utxo_id.1,
            out_point.vout
        );
    }

    for i in spell_ins.len()..tx.input.len() {
        let out_point = tx.input[i].previous_output;
        let utxo_id = UtxoId(TxId(out_point.txid.to_byte_array()), out_point.vout);
        norm_spell.tx.ins.get_or_insert_with(Vec::new).push(utxo_id);
    }

    Ok(norm_spell)
}

#[cfg(test)]
mod test {
    use super::*;
    use charms_client::{cardano_tx::CardanoTx, tx::EnchantedTx};

    #[test]
    fn txs_from_strings() {
        let b_tx_hex = "!bitcoin {tx: 0200000000010236c4d581d18b974562cf32e835c2c1e5d2590cd7c070e5ece35ebcb672216ae00000000000ffffffff36c4d581d18b974562cf32e835c2c1e5d2590cd7c070e5ece35ebcb672216ae00400000000ffffffff042302000000000000160014b9698eae2e61774bd88749e0f9b169acc50f99fb23020000000000001600144b1f883dd56c33fb7300dc27fc125eab88a462cf0000000000000000fd01036a057370656c6c4df70282a36776657273696f6e09627478a2646f75747382a1001a05f5e100a1001b00000001954fc4006b6265616d65645f6f757473a1009820189b18d30f18460718be1833181b18bc18a518b318ae18fa18bc18c9185b18b1185618c2185218e618a912182718d318cb18ac182a18b6184418ab189e716170705f7075626c69635f696e70757473a18361749820183d187f18e718e418ce18a6121819184718af187318d70e1851181918be18bd188a18a518b718ed18fe187418bf18af186e1877189a1818184718bd189b982018c9187518d418e018c2189218fb189518ef18bd18a518c118331218d618ac181d188b185a18ef18f718f018f118e518571886184518a218da187018ff185ff699010418a41859184c185909186c18de186e18ca18a818a618b81318201841185118df1827183718ad18ed18501866185418f1182f18e41861185c08182d185318da182418dc1883181a187918b018c6183c0f02185218c416186818c918a518c91865182118a618af18fc184018e218ba18f518cd181b1318dc18a0184d184a18e418da0b188c18c0184718691835185f18e018b218ce18ba189b18fe188118d918d4185b1845183b18e5188218b818f71865182f0218bb185318330e187518581819181909182d18cd18271898188b182f18d018571881183b18e218d818e918b4185418ed184c1832186e091218e1030918fd18e7187d187c0d1820187b18f5182118621834182818ff183b187c18c71867186b183818631876182618d918e218a018d918ad121893181d18f5181918a913184e183700171818182d189e18b118520418b1187718a318e818ea1882184118fd183818830e181a18b3184018cf18ab18d7185c18a218e3182e1825183718fb18a50b184718b6185b184e001866188e184c1898188518b518a8183e189618e0185d15186718c8185c18e3188618cf18f6189718b418d5184f186618df040d00183f18351855188918c1182b18c9181d18dc0418d31882186114181b188817181b185018e318d618ae1847182116186b18b618d8185f1877db0e000000000000160014542e0cd4e07fa3d919cf5aa5f8242612d4a3b3550247304402202bd582e27041fc7ae426853826e9c52cf8a5c8e5755026a6ba21892bdbcf51cb02201fef093148d7e5fa8ad7a10c8f953398db4a7efca4003d6a5c7cbbb58e468d84012103d5453d402d158c84de22dd20caf3cc1968178b5f674f5ec6d063d9fe8675fb27024730440220344cf2c2812b1c086c931bb6c1643bc91f33f4347011c594c37f54c4b23ea16a022049fad130880b7e88fc20e267cf151e23d32ed2669d94937e066658defea8c97b012103d5453d402d158c84de22dd20caf3cc1968178b5f674f5ec6d063d9fe8675fb2700000000, proof: 00000020e67d17e26a835ef6908dc53d3df10ec11447ff2e2cf401000000000000000000a5edec1fb14884f4d91dd3670135e4351aaec3c8e976b9ed13318d367875197d9d487c69a1fc01179e3678ef670b00000de18f42fa5fbce803e39c85b79c0b12e3ac41aaf57391184e96718e7f5406862614b4b7625aab6d003128248c31431c16e93e2cda808d7a9a63eaacfa79ae6a175578cb388029709c71f5590c03e6d254cd7068910251f30c10ceaba4f3748e46d6184d3b3dd743ef6033f2664830103881059ae8c26e792592e4b2db93acb6ab0e01f2312e73d2fb918b1977ac45c631066a1fbff4cededc4394c8eea8c1f6994fcf8eac574db5bcca603e56d142dca3a07fd83733faeb164e700fd82a3e821da3332e71ad3cd8f0f3843f8f80f16c9c668d03c6fd76fbcf845dced13a83708d29f1ba8550143e4841a10205a30202ec2ca8163a5e3fef928536e64612110b86ecd1cbbfe8c1c496346a46760edc33723e472ed9d8b35dd30f9dbefa4cac3f86f8eec2bc997cbef3136cbe4a7f21303efa55e7b04ac5bd1532419b82cc752ba53306d2a97e3f498d53ddcfe95c87e831c780ed513c3438b5e64db4d98d67796fba6fbb641ff92c51aaecb15d6df48b7993d966a3df0fe066e5a3dabe2e4ce639d5178235b0e05389a6d12cb4be8acf7770f955a73a7844732561c60f84cae52f04ebab0600, headers: [0020092042685204c1d593020a0e4a04fcaae7cbd146662c105c010000000000000000000f9d569050c3db02605efe19a24f50ebb6cc0567154662993ff682aaeeb8d9fccf487c69a1fc0117c8e0d65a, 00600624fe6344692b6693004e3ba99eb240402e4061ac015ef9000000000000000000008cc52b45e82d205b486314723fe865f196e84ec4fb247ddbea5b42e8fda23351fc4a7c69a1fc01178d3ae452, 0000eb23416b11e4c80cbb1d03c22b7957e108ccb958aef2fdc70100000000000000000013e9da44cbd9dd81b8c4269a5c8a88e850fb5af075e714991504d4e815fe95ac184b7c69a1fc011714370fe6, 00000034c603010c44c62e293b4e9476f4176dcd50c590c942a201000000000000000000b79acf6981a4cadcac7b843e4e4c7f155f87fc6add4ce2ea800fb77b4685cb26bd4e7c69a1fc01177e66ec4c, 04a0da26722d4343dc67afbc27aacff592d9ab2a0f7584df56fb01000000000000000000c315a0ca900f1d334523a4e5aeffbae7f95d69e60eb12c331e7a2ad5da2870fe5f507c69a1fc0117932dd198, 0080072070d9db116f24106e39b4da8a205725cfc701cfe141d400000000000000000000ee5e2b33f543016f8588935dbe972f36365b6db1c663d883f703f7e4f69c2426c8507c69a1fc01173560a4cb]}".to_string();

        let txs = from_strings(&[b_tx_hex]).unwrap();
        let Tx::Bitcoin(tx) = &txs[0] else {
            unreachable!()
        };
        assert!(tx.proven_final());
    }

    #[test]
    fn tx_from_string_cardano() {
        let b_tx_hex = "!cardano {tx: 84ab00d901028182582022d4a83d2e823c28c9d531d135cd12fe8d0d2a33140cac7b446a11888d37ff47010dd90102818258203cf7822be2f4e9eaeeed3c242f484d3789d6e973fecc8a16df154cbb644edadb0012d901028182582049d1f96be0002bcd0241917142aa6a58344923eda8ed54fb46da4ec5f4e3bff2000182a300583901466609ab4003d2a479cc0c3d3c24c4e576d550670c417266066288b3a983900c94aa06dea303d2c70cc955c054d98fe2c347d2e318d2bcd501821a002625a0a1581cb8f72e95dee612df98ac5a90b7604f7815c2af07a6db209a5c70abe4a15820000643b0cea6121947af73d70e5119bebd8aa5b7edfe74bfaf6e779a1847bd9b01028201d81858b5d8799fa6446e616d654342726f4b6465736372697074696f6e581b546865206d656d65636f696e206f66207468652055545842726f73467469636b65724342524f4375726c5668747470733a2f2f62726f2e636861726d732e64657648646563696d616c7308446c6f676f5f5840697066733a2f2f6261666b726569626e376f763478763577617365356271766266326233696275796e366979646369756a326b727737756c7864363262746661426e6dff01a0ff82583901466609ab4003d2a479cc0c3d3c24c4e576d550670c417266066288b3a983900c94aa06dea303d2c70cc955c054d98fe2c347d2e318d2bcd51a00244a541082583901466609ab4003d2a479cc0c3d3c24c4e576d550670c417266066288b3a983900c94aa06dea303d2c70cc955c054d98fe2c347d2e318d2bcd51a0046815e111a0005c9e2021a0003dbec05a1581df129764648940a3b7208bc99a246bc96a69817bea017560972432f076f000ed9010281581c15bf560dabf4fe7f7ef78ac49c4fa846ebcde7009b1e886dd70d350d09a1581cb8f72e95dee612df98ac5a90b7604f7815c2af07a6db209a5c70abe4a15820000643b0cea6121947af73d70e5119bebd8aa5b7edfe74bfaf6e779a1847bd9b010b58207e59f8de1d538bc0fff5c4c3e80bafb309cba960af9be62a4ee18d9b1ade02f4a300d901028282582030e99359bc028dbf5a369df63744eb2a2e0e99512d8f6bdb0124ef2f5c7cf80a5840d542f8f9efcc0ce936980e54fb6c8ae5dd4a3bb89d50cfdecf5e5d44c970764292a4d37b6f6169689afd041c11484dcce13ccbf820aa4dc277d1cffc067fb30b825820720c93bc822efbf4aabccaa7ae875cd46a556c99bc1b3f2fbdd8c561f4723d535840d8b4992c95a69c174b4940b30a7629ff18647480a1fd0dd1dcfe00d0ecdba35d74862f056a0ef66cad5d67011123bcd8465f9ef9e578c6136138cb4d3e2ff10207d901028159026e59026b010100332229800aba2aba1aba0aab9faab9eaab9dab9a9bae0039bae0024888888889660033001300537540152259800800c5300103d87a80008992cc004006266e9520003300a300b0024bd7044cc00c00c0050091805800a010918049805000cdc3a400091111991194c004c02cdd5000cc03c01e44464b30013008300f37540031325980099b87323322330020020012259800800c00e2646644b30013372201400515980099b8f00a0028800c01901544cc014014c06c0110151bae3014001375a602a002602e00280a8c8c8cc004004dd59806980a1baa300d3014375400844b3001001801c4c8cc896600266e4403000a2b30013371e0180051001803202c899802802980e002202c375c602a0026eacc058004c0600050160a5eb7bdb180520004800a264b3001300a301137540031323322330020020012259800800c528456600266ebc00cc050c0600062946266004004603200280990161bab30163017301730173017301730173017301730173013375400a66e952004330143374a90011980a180a98091baa0014bd7025eb822c8080c050c054c054c054c044dd5180518089baa0018b201e301330103754003164038600a6eb0c020c03cdd5000cc03c00d222259800980400244ca600201d375c005004400c6eb8c04cc040dd5002c56600266e1d200200489919914c0040426eb801200c8028c050004c050c054004c040dd5002c5900e201c1807180780118068021801801a29344d959003130011e581c1775920b2f415d295553835fb7d26d8186cff73d352c9e9b98cad240004c01225820c975d4e0c292fb95efbda5c13312d6ac1d8b5aeff7f0f1e5578645a2da70ff5f000105a28201008247000de1407631308219e79b1a013d68ca82030082d8798082193c091a0047e66cf5f6, signature: 17376c1207369310a25f1caa1ee4fa5da9a2219e3a5132dcbe73f369f3c2f04599b402ccbe1c1668b042c7d507cacba45d1b79e378f1578e4f01a8feff1fa40c}".to_string();

        let txs = from_strings(&[b_tx_hex]).unwrap();
        let Tx::Cardano(tx) = &txs[0] else {
            unreachable!()
        };
        assert!(tx.proven_final());

        let CardanoTx::WithFinalityProof { tx, .. } = tx else {
            unreachable!()
        };
        let str = serde_yaml::to_string(&tx.body.outputs[0].amount()).unwrap();
        eprintln!("{}", str)
    }
}
