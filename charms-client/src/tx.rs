use crate::{
    CURRENT_VERSION, MOCK_SPELL_VK, NormalizedSpell, V0, V0_SPELL_VK, V1, V1_SPELL_VK, V2,
    V2_SPELL_VK, V3, V3_SPELL_VK, V4, V4_SPELL_VK, V5, V5_SPELL_VK, V6, V6_SPELL_VK, V7,
    V7_SPELL_VK, V8, V8_SPELL_VK, V9, V9_SPELL_VK, V10, V10_SPELL_VK, V11, V11_SPELL_VK, V12,
    V12_SPELL_VK, V13, V13_SPELL_VK, ark, bitcoin_tx::BitcoinTx, cardano_tx::CardanoTx,
};
use anyhow::{anyhow, bail};
use charms_data::{NativeOutput, TxId, UtxoId, util};
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sp1_primitives::io::SP1PublicValues;
use sp1_verifier::{Groth16Verifier, decode_sp1_vkey_hash, hash_public_inputs};
use std::collections::BTreeMap;
use strum::{AsRefStr, EnumDiscriminants, EnumString};
use thiserror::Error;

/// Returned by [`spell_vk`] and [`groth16_vk`] when the requested spell version
/// is not supported by this build of `charms-client`.
///
/// Downstream callers (e.g. ICP canisters that delegate to a newer-version
/// canister) should detect this via `err.downcast_ref::<UnsupportedSpellVersion>()`
/// rather than substring-matching the `Display` output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
#[error("unsupported spell version: {0}")]
pub struct UnsupportedSpellVersion(pub u32);

#[enum_dispatch]
pub trait EnchantedTx {
    fn extract_and_verify_spell(
        &self,
        spell_vk: &str,
        mock: bool,
    ) -> anyhow::Result<NormalizedSpell>;
    fn virtual_spell(
        &self,
        spell_vk: &str,
        next_spell: &NormalizedSpell,
    ) -> anyhow::Result<NormalizedSpell>;
    fn tx_outs_len(&self) -> usize;
    fn tx_id(&self) -> TxId;
    fn hex(&self) -> String;
    fn spell_ins(&self) -> Vec<UtxoId>;
    fn all_coin_outs(&self, spell: &NormalizedSpell) -> anyhow::Result<Vec<NativeOutput>>;
    fn proven_final(&self) -> bool;
}

#[enum_dispatch(EnchantedTx)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, EnumDiscriminants)]
#[serde(rename_all = "snake_case")]
#[strum_discriminants(
    name(Chain),
    derive(AsRefStr, EnumString, Ord, PartialOrd, Serialize, Deserialize),
    serde(rename_all = "snake_case"),
    strum(serialize_all = "snake_case")
)]
pub enum Tx {
    Bitcoin(BitcoinTx),
    Cardano(CardanoTx),
}

impl TryFrom<&str> for Tx {
    type Error = anyhow::Error;

    fn try_from(hex: &str) -> Result<Self, Self::Error> {
        if let Ok(b_tx) = BitcoinTx::from_hex(hex) {
            Ok(Self::Bitcoin(b_tx))
        } else if let Ok(c_tx) = CardanoTx::from_hex(hex) {
            Ok(Self::Cardano(c_tx))
        } else {
            bail!("invalid hex")
        }
    }
}

impl Tx {
    pub fn new(tx: impl Into<Tx>) -> Self {
        tx.into()
    }

    pub fn hex(&self) -> String {
        match self {
            Tx::Bitcoin(tx) => tx.hex(),
            Tx::Cardano(tx) => tx.hex(),
        }
    }
}

/// Extract a [`NormalizedSpell`] from a transaction and verify it.
/// Incorrect spells are rejected.
#[tracing::instrument(level = "debug", skip_all)]
pub fn committed_normalized_spell(
    spell_vk: &str,
    tx: &Tx,
    mock: bool,
) -> anyhow::Result<NormalizedSpell> {
    tx.extract_and_verify_spell(spell_vk, mock)
}

/// Extract and verify [`NormalizedSpell`] from a transaction. Return an empty spell if the
/// transaction does not have one. Extend with native coin output amounts if necessary.
pub fn extended_normalized_spell(
    spell_vk: &str,
    next_spell: &NormalizedSpell,
    tx: &Tx,
) -> anyhow::Result<NormalizedSpell> {
    tx.virtual_spell(spell_vk, next_spell)
}

pub fn spell_vk(spell_version: u32, spell_vk: &str, mock: bool) -> anyhow::Result<&str> {
    if mock {
        return Ok(MOCK_SPELL_VK);
    }
    match spell_version {
        CURRENT_VERSION => Ok(spell_vk),
        V13 => Ok(V13_SPELL_VK),
        V12 => Ok(V12_SPELL_VK),
        V11 => Ok(V11_SPELL_VK),
        V10 => Ok(V10_SPELL_VK),
        V9 => Ok(V9_SPELL_VK),
        V8 => Ok(V8_SPELL_VK),
        V7 => Ok(V7_SPELL_VK),
        V6 => Ok(V6_SPELL_VK),
        V5 => Ok(V5_SPELL_VK),
        V4 => Ok(V4_SPELL_VK),
        V3 => Ok(V3_SPELL_VK),
        V2 => Ok(V2_SPELL_VK),
        V1 => Ok(V1_SPELL_VK),
        V0 => Ok(V0_SPELL_VK),
        _ => Err(UnsupportedSpellVersion(spell_version).into()),
    }
}

pub fn groth16_vk(spell_version: u32, mock: bool) -> anyhow::Result<&'static [u8]> {
    if mock {
        return Ok(MOCK_GROTH16_VK_BYTES);
    }
    match spell_version {
        CURRENT_VERSION => Ok(CURRENT_GROTH16_VK_BYTES),
        V13 => Ok(V13_GROTH16_VK_BYTES),
        V12 => Ok(V12_GROTH16_VK_BYTES),
        V11 => Ok(V11_GROTH16_VK_BYTES),
        V10 => Ok(V10_GROTH16_VK_BYTES),
        V9 => Ok(V9_GROTH16_VK_BYTES),
        V8 => Ok(V8_GROTH16_VK_BYTES),
        V7 => Ok(V7_GROTH16_VK_BYTES),
        V6 => Ok(V6_GROTH16_VK_BYTES),
        V5 => Ok(V5_GROTH16_VK_BYTES),
        V4 => Ok(V4_GROTH16_VK_BYTES),
        V3 => Ok(V3_GROTH16_VK_BYTES),
        V2 => Ok(V2_GROTH16_VK_BYTES),
        V1 => Ok(V1_GROTH16_VK_BYTES),
        V0 => Ok(V0_GROTH16_VK_BYTES),
        _ => Err(UnsupportedSpellVersion(spell_version).into()),
    }
}

pub const MOCK_GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../vk/mock/mock-groth16-vk.bin");

pub const V0_GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../vk/v0/groth16_vk.bin");
pub const V1_GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../vk/v1/groth16_vk.bin");
pub const V2_GROTH16_VK_BYTES: &'static [u8] = V1_GROTH16_VK_BYTES;
pub const V3_GROTH16_VK_BYTES: &'static [u8] = V1_GROTH16_VK_BYTES;
pub const V4_GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../vk/v4/groth16_vk.bin");
pub const V5_GROTH16_VK_BYTES: &'static [u8] = V4_GROTH16_VK_BYTES;
pub const V6_GROTH16_VK_BYTES: &'static [u8] = V4_GROTH16_VK_BYTES;
pub const V7_GROTH16_VK_BYTES: &'static [u8] = V4_GROTH16_VK_BYTES;
pub const V8_GROTH16_VK_BYTES: &'static [u8] = V4_GROTH16_VK_BYTES;
pub const V9_GROTH16_VK_BYTES: &'static [u8] = V4_GROTH16_VK_BYTES;
pub const V10_GROTH16_VK_BYTES: &'static [u8] = V4_GROTH16_VK_BYTES;
pub const V11_GROTH16_VK_BYTES: &'static [u8] = V4_GROTH16_VK_BYTES;
pub const V12_GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../vk/v12/groth16_vk.bin");
pub const V13_GROTH16_VK_BYTES: &'static [u8] = V12_GROTH16_VK_BYTES;
pub const V14_GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../vk/v14/groth16_vk.bin");
pub const CURRENT_GROTH16_VK_BYTES: &'static [u8] = V14_GROTH16_VK_BYTES;

pub fn to_serialized_pv<T: Serialize>(spell_version: u32, t: &T) -> Vec<u8> {
    match spell_version {
        V0 => {
            // we used to commit to the tuple `(spell_vk, n_spell)`, which was serialized internally
            // by SP1
            let mut pv = SP1PublicValues::new();
            pv.write(t);
            pv.to_vec()
        }
        _ => {
            // we commit to CBOR-encoded tuple `(spell_vk, n_spell)`
            util::write(t).unwrap()
        }
    }
}

pub fn verify_snark_proof(
    proof: &[u8],
    public_inputs: &[u8],
    vk_hash: &str,
    spell_version: u32,
    mock: bool,
) -> anyhow::Result<()> {
    let groth16_vk = groth16_vk(spell_version, mock)?;
    match mock {
        false => match spell_version {
            v if v <= V11 => verify_gnark_v5(proof, public_inputs, vk_hash, groth16_vk),
            v if v <= V13 => {
                verify_gnark_v6(proof, public_inputs, vk_hash, groth16_vk, SP1_V6_0_VK_ROOT)
            }
            _ => verify_gnark_v6(proof, public_inputs, vk_hash, groth16_vk, SP1_V6_2_VK_ROOT),
        },
        true => ark::verify_groth16_proof(proof, public_inputs, groth16_vk),
    }
}

const VK_HASH_PREFIX_LENGTH: usize = 4;

/// `VK_ROOT_BYTES` from `sp1-verifier-legacy` 6.0.2 — covers spell versions V12 and V13.
const SP1_V6_0_VK_ROOT: [u8; 32] =
    hex_literal::hex!("008cd56e10c2fe24795cff1e1d1f40d3a324528d315674da45d26afb376e8670");

/// `VK_ROOT_BYTES` from `sp1-verifier` 6.2.0 — covers the current spell version (V14).
const SP1_V6_2_VK_ROOT: [u8; 32] =
    hex_literal::hex!("002f850ee998974d6cc00e50cd0814b098c05bfade466d28573240d057f25352");

fn verify_gnark_v5(
    proof: &[u8],
    public_inputs: &[u8],
    vk_hash: &str,
    groth16_vk: &[u8],
) -> anyhow::Result<()> {
    if proof.len() < VK_HASH_PREFIX_LENGTH {
        bail!("could not verify spell proof: invalid proof");
    }
    let groth16_vk_hash: [u8; 4] = Sha256::digest(groth16_vk)[..VK_HASH_PREFIX_LENGTH]
        .try_into()
        .map_err(|_| anyhow!("could not verify spell proof: invalid groth16 vk"))?;
    if groth16_vk_hash != proof[..VK_HASH_PREFIX_LENGTH] {
        bail!("could not verify spell proof: groth16 vkey hash mismatch");
    }
    let sp1_vkey_hash = decode_sp1_vkey_hash(vk_hash)
        .map_err(|e| anyhow!("could not verify spell proof: {:?}", e))?;
    Groth16Verifier::verify_gnark_proof(
        &proof[VK_HASH_PREFIX_LENGTH..],
        &[sp1_vkey_hash, hash_public_inputs(public_inputs)],
        groth16_vk,
    )
    .map_err(|e| anyhow!("could not verify spell proof: {:?}", e))
}

fn verify_gnark_v6(
    proof: &[u8],
    public_inputs: &[u8],
    vk_hash: &str,
    groth16_vk: &[u8],
    expected_vk_root: [u8; 32],
) -> anyhow::Result<()> {
    if proof.len() < VK_HASH_PREFIX_LENGTH + 32 * 3 {
        bail!("could not verify spell proof: invalid proof");
    }
    let groth16_vk_hash: [u8; 4] = Sha256::digest(groth16_vk)[..VK_HASH_PREFIX_LENGTH]
        .try_into()
        .map_err(|_| anyhow!("could not verify spell proof: invalid groth16 vk"))?;
    if groth16_vk_hash != proof[..VK_HASH_PREFIX_LENGTH] {
        bail!("could not verify spell proof: groth16 vkey hash mismatch");
    }
    let sp1_vkey_hash = decode_sp1_vkey_hash(vk_hash)
        .map_err(|e| anyhow!("could not verify spell proof: {:?}", e))?;

    let exit_code: [u8; 32] = proof[VK_HASH_PREFIX_LENGTH..VK_HASH_PREFIX_LENGTH + 32]
        .try_into()
        .unwrap();
    let vk_root: [u8; 32] = proof[VK_HASH_PREFIX_LENGTH + 32..VK_HASH_PREFIX_LENGTH + 64]
        .try_into()
        .unwrap();
    let proof_nonce: [u8; 32] = proof[VK_HASH_PREFIX_LENGTH + 64..VK_HASH_PREFIX_LENGTH + 96]
        .try_into()
        .unwrap();

    if vk_root != expected_vk_root {
        bail!("could not verify spell proof: vkey root mismatch");
    }
    if exit_code != [0u8; 32] {
        bail!("could not verify spell proof: exit code mismatch");
    }

    Groth16Verifier::verify_gnark_proof(
        &proof[VK_HASH_PREFIX_LENGTH + 96..],
        &[
            sp1_vkey_hash,
            hash_public_inputs(public_inputs),
            exit_code,
            vk_root,
            proof_nonce,
        ],
        groth16_vk,
    )
    .map_err(|e| anyhow!("could not verify spell proof: {:?}", e))
}

pub fn by_txid(prev_txs: &[Tx]) -> BTreeMap<TxId, Tx> {
    prev_txs
        .iter()
        .map(|prev_tx| (prev_tx.tx_id(), prev_tx.clone()))
        .collect::<BTreeMap<_, _>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn current_sp1_vk_root_matches_hardcoded_constant() {
        assert_eq!(SP1_V6_2_VK_ROOT, *sp1_verifier::VK_ROOT_BYTES);
    }

    #[test]
    fn spell_vk_unsupported_version_typed_error() {
        let err = spell_vk(u32::MAX, "vk", false).unwrap_err();
        assert_eq!(
            err.downcast_ref::<UnsupportedSpellVersion>(),
            Some(&UnsupportedSpellVersion(u32::MAX))
        );
    }

    #[test]
    fn groth16_vk_unsupported_version_typed_error() {
        let err = groth16_vk(u32::MAX, false).unwrap_err();
        assert_eq!(
            err.downcast_ref::<UnsupportedSpellVersion>(),
            Some(&UnsupportedSpellVersion(u32::MAX))
        );
    }

    #[test]
    fn chain_names() {
        assert_eq!(Chain::Bitcoin.as_ref(), "bitcoin");
        assert_eq!(Chain::Cardano.as_ref(), "cardano");
    }

    #[test]
    fn chain_name_from_str() {
        assert_eq!(Chain::from_str("bitcoin").unwrap(), Chain::Bitcoin);
        assert_eq!(Chain::from_str("cardano").unwrap(), Chain::Cardano);
    }

    #[test]
    fn chain_name_deserialize() {
        assert_eq!(
            serde_json::from_str::<Chain>(r#""bitcoin""#).unwrap(),
            Chain::Bitcoin
        );
        assert_eq!(
            serde_json::from_str::<Chain>(r#""cardano""#).unwrap(),
            Chain::Cardano
        );
    }

    #[test]
    fn chain_name_serialize() {
        assert_eq!(
            serde_json::to_string(&Chain::Bitcoin).unwrap(),
            r#""bitcoin""#
        );
        assert_eq!(
            serde_json::to_string(&Chain::Cardano).unwrap(),
            r#""cardano""#
        );
    }

    #[test]
    fn ser_to_json() {
        let c_tx_hex = "84a400d901028182582011a2338987035057f6c36286cf5aadc02573059b2cde9790017eb4e148f0c67a0001828258390174f84e13070bb755eaa01cb717da8c7450daf379948e979f6de99d26ba89ff199fde572546b9a044eb129ad2edb184bd79cde63ab4b47aec1a01312d008258390184f1c3b1fff5241088acc4ce0aec81f45a71a70e35c94e30a70b7cdfeb0785cdec744029db6b4f344b1123497c9cabfeeb94af20fcfddfe01a33e578fd021a000299e90758201e8eb8575d879922d701c12daa7366cb71b6518a9500e083a966a8e66b56ed23a10081825820ea444825bbd5cc97b6c795437849fe55694b52e2f51485ac76ca2d9f991e83305840d59db4fa0b4bb233504f5e6826261a2e18b2e22cb3df4f631ab77d94d62e8df3200536271f3f3a625bc86919714972964f070f909f145b342f2889f58ccc210ff5a11902a2a1636d736765546f6b656f";

        let b_tx_hex = "0200000000010115ccf0534b7969e5ac0f4699e51bf7805168244057059caa333397fcf8a9acdd0000000000fdffffff027a6faf85150000001600147b458433d0c04323426ef88365bd4cfef141ac7520a107000000000022512087a397fc19d816b6f938dad182a54c778d2d5db8b31f4528a758b989d42f0b78024730440220072d64b2e3bbcd27bd79cb8859c83ca524dad60dc6310569c2a04c997d116381022071d4df703d037a9fe16ccb1a2b8061f10cda86ccbb330a49c5dcc95197436c960121030db9616d96a7b7a8656191b340f77e905ee2885a09a7a1e80b9c8b64ec746fb300000000";

        let c_tx: Tx = Tx::try_from(c_tx_hex).unwrap();
        let Tx::Cardano(_) = c_tx.clone() else {
            unreachable!("not a cardano tx: {c_tx:?}")
        };
        let b_tx: Tx = Tx::try_from(b_tx_hex).unwrap();
        let Tx::Bitcoin(_) = b_tx.clone() else {
            unreachable!("not a bitcoin tx: {b_tx:?}")
        };

        let v = vec![b_tx, c_tx];
        let json_str = serde_json::to_string_pretty(&v).unwrap();
        eprintln!("{json_str}");
    }

    #[test]
    fn ser_to_cbor() {
        let c_tx_hex = "84a400d901028182582011a2338987035057f6c36286cf5aadc02573059b2cde9790017eb4e148f0c67a0001828258390174f84e13070bb755eaa01cb717da8c7450daf379948e979f6de99d26ba89ff199fde572546b9a044eb129ad2edb184bd79cde63ab4b47aec1a01312d008258390184f1c3b1fff5241088acc4ce0aec81f45a71a70e35c94e30a70b7cdfeb0785cdec744029db6b4f344b1123497c9cabfeeb94af20fcfddfe01a33e578fd021a000299e90758201e8eb8575d879922d701c12daa7366cb71b6518a9500e083a966a8e66b56ed23a10081825820ea444825bbd5cc97b6c795437849fe55694b52e2f51485ac76ca2d9f991e83305840d59db4fa0b4bb233504f5e6826261a2e18b2e22cb3df4f631ab77d94d62e8df3200536271f3f3a625bc86919714972964f070f909f145b342f2889f58ccc210ff5a11902a2a1636d736765546f6b656f";

        let b_tx_hex = "0200000000010115ccf0534b7969e5ac0f4699e51bf7805168244057059caa333397fcf8a9acdd0000000000fdffffff027a6faf85150000001600147b458433d0c04323426ef88365bd4cfef141ac7520a107000000000022512087a397fc19d816b6f938dad182a54c778d2d5db8b31f4528a758b989d42f0b78024730440220072d64b2e3bbcd27bd79cb8859c83ca524dad60dc6310569c2a04c997d116381022071d4df703d037a9fe16ccb1a2b8061f10cda86ccbb330a49c5dcc95197436c960121030db9616d96a7b7a8656191b340f77e905ee2885a09a7a1e80b9c8b64ec746fb300000000";

        let c_tx: Tx = Tx::try_from(c_tx_hex).unwrap();
        let b_tx: Tx = Tx::try_from(b_tx_hex).unwrap();

        let v0 = vec![b_tx, c_tx];
        let v0_cbor = ciborium::Value::serialized(&v0).unwrap();

        let v1: Vec<Tx> = ciborium::Value::deserialized(&v0_cbor).unwrap();
        let v1_cbor = ciborium::Value::serialized(&v1).unwrap();
        assert_eq!(v0, v1);
        assert_eq!(v0_cbor, v1_cbor);
    }
}
