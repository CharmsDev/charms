use charms_data::{App, Data, TxId, UtxoId, VkHash};
use ciborium::Value;
use serde::{Deserialize, Serialize};
use sp1_sdk::{ProverClient, SP1Stdin};
use spell_prover::{AppContractProof, NormalizedSpell, SpellProof};
use std::collections::BTreeMap;

/// Charm as represented in a spell.
/// Map of `$TICKER: data`
pub type TextCharm = BTreeMap<String, Value>;

/// UTXO as represented in a spell.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TextUtxo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub utxo_id: Option<UtxoId>,
    pub charm: TextCharm,
}

/// Defines how spells are represented on the wire,
/// in both human-friendly (JSON/YAML) and machine-friendly (CBOR) formats.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TextSpell {
    pub version: u32,

    pub apps: BTreeMap<String, App>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_inputs: Option<BTreeMap<String, Data>>,

    pub ins: Vec<TextUtxo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<TextUtxo>>,
    pub outs: Vec<TextUtxo>,

    /// folded proof of all validation predicates plus all pre-requisite spells
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Box<[u8]>>,
}

pub fn prove(
    spell: TextSpell,
    prev_spells: &[TextSpell],
    binaries: BTreeMap<VkHash, Box<[u8]>>,
) -> anyhow::Result<TextSpell> {
    Ok(todo!())
}

pub fn prove_check(
    spell: &NormalizedSpell,
    pre_req_spell_proofs: &BTreeMap<TxId, (Box<dyn SpellProof>, NormalizedSpell)>,
    app_contract_proofs: &BTreeMap<App, Box<dyn AppContractProof>>,
) -> bool {
    // impl
    sp1_sdk::utils::setup_logger();

    let client = ProverClient::new();
    let mut stdin = SP1Stdin::new();
    // stdin.write(&args.n);

    todo!();
    true
}

#[cfg(test)]
mod test {
    use crate::spell::TextCharm;
    use charms_data::{App, AppState, Charm, Data, Transaction, UtxoId, VkHash, TOKEN};
    use ciborium::Value;
    use hex;
    use std::{collections::BTreeMap, str::FromStr};

    #[test]
    fn deserialize_compact_charm() {
        let y = r#"
$TOAD_SUB: 10
$TOAD: 9
"#;

        let charm = serde_yaml::from_str::<TextCharm>(y).unwrap();
        dbg!(&charm);

        let utxo_id =
            UtxoId::from_str("f72700ac56bd4dd61f2ccb4acdf21d0b11bb294fc3efa9012b77903932197d2f:2")
                .unwrap();
        let mut buf = vec![];
        ciborium::ser::into_writer(&utxo_id, &mut buf).unwrap();

        let utxo_id_value: Value = ciborium::de::from_reader(buf.as_slice()).unwrap();

        let utxo_id: UtxoId = dbg!(utxo_id_value).deserialized().unwrap();
        dbg!(utxo_id);
    }

    #[test]
    fn empty_postcard() {
        use postcard;

        let value: Vec<u8> = vec![];
        let buf = postcard::to_stdvec(&value).unwrap();
        dbg!(buf.len());
        dbg!(buf);

        let mut cbor_buf = vec![];
        let value: Vec<u8> = vec![];
        ciborium::into_writer(&value, &mut cbor_buf).unwrap();
        dbg!(cbor_buf.len());
        dbg!(cbor_buf);
    }

    #[test]
    fn app_postcard() {
        use postcard;

        let app_orig = App {
            tag: TOKEN,
            id: UtxoId::default(),
            vk_hash: VkHash::default(),
        };

        let tx_orig = Transaction {
            ins: BTreeMap::from([(
                UtxoId::default(),
                Charm::from([(app_orig.clone(), 1u64.into())]),
            )]),
            refs: BTreeMap::new(),
            outs: vec![Charm::from([(app_orig.clone(), 1u64.into())])],
        };

        let app_state_orig: AppState = 1u64.into();

        let mut buf = [0u8; 4096];
        let mut writer: &mut [u8] = &mut buf;

        let _ = postcard::to_io(&app_orig, &mut writer).unwrap();
        // let _ = postcard::to_io(&tx_orig, &mut writer).unwrap();
        // let _ = postcard::to_io(&app_state_orig, &mut writer).unwrap();
        // let _ = postcard::to_io(&Data::empty(), &mut writer).unwrap();
        // let _ = postcard::to_io(&Data::empty(), &mut writer).unwrap();

        let mut buf: &mut [u8] = &mut buf;

        let (app, _) = postcard::take_from_bytes::<App>(&mut buf).unwrap();
        // let (tx, _) = postcard::take_from_bytes::<Transaction>(&mut buf).unwrap();
        // let (app_state, _) = postcard::take_from_bytes::<AppState>(&mut buf).unwrap();
        // let (x, _) = postcard::take_from_bytes::<Data>(&mut buf).unwrap();
        // let (w, _) = postcard::take_from_bytes::<Data>(&mut buf).unwrap();

        assert_eq!(app, app_orig);
        // assert_eq!(tx, tx_orig);
        // assert_eq!(app_state, app_state_orig);
        // assert_eq!(x, Data::empty());
        // assert_eq!(w, Data::empty());

        let mut buf = [0u8; 4096];
        let mut output_slice: &mut [u8] = &mut buf;

        ciborium::ser::into_writer(&app_orig, &mut output_slice).unwrap();
        ciborium::ser::into_writer(&tx_orig, &mut output_slice).unwrap();
        ciborium::ser::into_writer(&app_state_orig, &mut output_slice).unwrap();
        ciborium::ser::into_writer(&Data::empty(), &mut output_slice).unwrap();
        ciborium::ser::into_writer(&Data::empty(), &mut output_slice).unwrap();

        let input_vec = buf.to_vec();
        let input_slice = input_vec.as_slice();
        let mut input_slice = input_slice;

        let app: App = ciborium::de::from_reader(&mut input_slice).unwrap();
        let tx: Transaction = ciborium::de::from_reader(&mut input_slice).unwrap();
        let app_state: AppState = ciborium::de::from_reader(&mut input_slice).unwrap();
        let x: Data = ciborium::de::from_reader(&mut input_slice).unwrap();
        let w: Data = ciborium::de::from_reader(&mut input_slice).unwrap();

        assert_eq!(app, app_orig);
        assert_eq!(tx, tx_orig);
        assert_eq!(app_state, app_state_orig);
        assert_eq!(x, Data::empty());
        assert_eq!(w, Data::empty());

        let hex_bytes =
            hex::decode("f72700ac56bd4dd61f2ccb4acdf21d0b11bb294fc3efa9012b77903932197d2f")
                .unwrap();
        let utxo_id_orig = UtxoId(hex_bytes.try_into().unwrap(), 0);

        let mut buf = [0u8; 100];

        let buf = postcard::to_slice(&utxo_id_orig, &mut buf).unwrap();
        dbg!(buf.len());

        let (utxo_id, buf) = postcard::take_from_bytes::<UtxoId>(buf).unwrap();
        assert_eq!(utxo_id, utxo_id_orig);
    }
}
