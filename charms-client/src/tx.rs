use crate::{
    bitcoin_tx::BitcoinTx, cardano_tx::CardanoTx, NormalizedSpell, CURRENT_VERSION, V0,
    V0_SPELL_VK, V1, V1_SPELL_VK, V2, V2_SPELL_VK, V3, V3_SPELL_VK, V4, V4_SPELL_VK,
};
use anyhow::bail;
use charms_data::{util, TxId};
use enum_dispatch::enum_dispatch;
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, IfIsHumanReadable};
use sp1_primitives::io::SP1PublicValues;

#[enum_dispatch]
pub trait EnchantedTx {
    fn extract_and_verify_spell(&self, spell_vk: &str) -> anyhow::Result<NormalizedSpell>;
    fn tx_outs_len(&self) -> usize;
    fn tx_id(&self) -> TxId;
    fn hex(&self) -> String;
}

serde_with::serde_conv!(
    BitcoinTxHex,
    BitcoinTx,
    |tx: &BitcoinTx| tx.hex(),
    |s: &str| BitcoinTx::from_hex(s)
);

serde_with::serde_conv!(
    CardanoTxHex,
    CardanoTx,
    |tx: &CardanoTx| tx.hex(),
    |s: &str| CardanoTx::from_hex(s)
);

#[serde_as]
#[enum_dispatch(EnchantedTx)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Tx {
    Bitcoin(#[serde_as(as = "IfIsHumanReadable<BitcoinTxHex>")] BitcoinTx),
    Cardano(#[serde_as(as = "IfIsHumanReadable<CardanoTxHex>")] CardanoTx),
}

impl Tx {
    pub fn new(tx: impl Into<Tx>) -> Self {
        tx.into()
    }

    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        if let Ok(b_tx @ BitcoinTx(_)) = BitcoinTx::from_hex(hex) {
            Ok(Self::Bitcoin(b_tx))
        } else if let Ok(c_tx @ CardanoTx(_)) = CardanoTx::from_hex(hex) {
            Ok(Self::Cardano(c_tx))
        } else {
            bail!("invalid hex")
        }
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
pub fn extract_and_verify_spell(spell_vk: &str, tx: &Tx) -> anyhow::Result<NormalizedSpell> {
    tx.extract_and_verify_spell(spell_vk)
}

pub fn vks(spell_version: u32, spell_vk: &str) -> anyhow::Result<(&str, &[u8])> {
    match spell_version {
        CURRENT_VERSION => Ok((spell_vk, CURRENT_GROTH16_VK_BYTES)),
        V4 => Ok((V4_SPELL_VK, V4_GROTH16_VK_BYTES)),
        V3 => Ok((V3_SPELL_VK, V3_GROTH16_VK_BYTES)),
        V2 => Ok((V2_SPELL_VK, V2_GROTH16_VK_BYTES)),
        V1 => Ok((V1_SPELL_VK, V1_GROTH16_VK_BYTES)),
        V0 => Ok((V0_SPELL_VK, V0_GROTH16_VK_BYTES)),
        _ => bail!("unsupported spell version: {}", spell_version),
    }
}

pub const V0_GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../vk/v0/groth16_vk.bin");
pub const V1_GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../vk/v1/groth16_vk.bin");
pub const V2_GROTH16_VK_BYTES: &'static [u8] = V1_GROTH16_VK_BYTES;
pub const V3_GROTH16_VK_BYTES: &'static [u8] = V1_GROTH16_VK_BYTES;
pub const V4_GROTH16_VK_BYTES: &'static [u8] = include_bytes!("../vk/v4/groth16_vk.bin");
pub const V5_GROTH16_VK_BYTES: &'static [u8] = V4_GROTH16_VK_BYTES;
pub const CURRENT_GROTH16_VK_BYTES: &'static [u8] = V5_GROTH16_VK_BYTES;

pub fn to_sp1_pv<T: Serialize>(spell_version: u32, t: &T) -> SP1PublicValues {
    let mut pv = SP1PublicValues::new();
    match spell_version {
        CURRENT_VERSION | V4 | V3 | V2 | V1 => {
            // we commit to CBOR-encoded tuple `(spell_vk, n_spell)`
            pv.write_slice(util::write(t).unwrap().as_slice());
        }
        V0 => {
            // we used to commit to the tuple `(spell_vk, n_spell)`, which was serialized internally
            // by SP1
            pv.write(t);
        }
        _ => unreachable!(),
    }
    pv
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ser_to_json() {
        let c_tx_hex = "84a400d901028182582011a2338987035057f6c36286cf5aadc02573059b2cde9790017eb4e148f0c67a0001828258390174f84e13070bb755eaa01cb717da8c7450daf379948e979f6de99d26ba89ff199fde572546b9a044eb129ad2edb184bd79cde63ab4b47aec1a01312d008258390184f1c3b1fff5241088acc4ce0aec81f45a71a70e35c94e30a70b7cdfeb0785cdec744029db6b4f344b1123497c9cabfeeb94af20fcfddfe01a33e578fd021a000299e90758201e8eb8575d879922d701c12daa7366cb71b6518a9500e083a966a8e66b56ed23a10081825820ea444825bbd5cc97b6c795437849fe55694b52e2f51485ac76ca2d9f991e83305840d59db4fa0b4bb233504f5e6826261a2e18b2e22cb3df4f631ab77d94d62e8df3200536271f3f3a625bc86919714972964f070f909f145b342f2889f58ccc210ff5a11902a2a1636d736765546f6b656f";

        let b_tx_hex = "0200000000010115ccf0534b7969e5ac0f4699e51bf7805168244057059caa333397fcf8a9acdd0000000000fdffffff027a6faf85150000001600147b458433d0c04323426ef88365bd4cfef141ac7520a107000000000022512087a397fc19d816b6f938dad182a54c778d2d5db8b31f4528a758b989d42f0b78024730440220072d64b2e3bbcd27bd79cb8859c83ca524dad60dc6310569c2a04c997d116381022071d4df703d037a9fe16ccb1a2b8061f10cda86ccbb330a49c5dcc95197436c960121030db9616d96a7b7a8656191b340f77e905ee2885a09a7a1e80b9c8b64ec746fb300000000";

        let c_tx = Tx::from_hex(c_tx_hex).unwrap();
        let b_tx = Tx::from_hex(b_tx_hex).unwrap();

        let v = vec![b_tx, c_tx];
        let json_str = serde_json::to_string_pretty(&v).unwrap();
        eprintln!("{json_str}");
    }

    #[test]
    fn ser_to_cbor() {
        let c_tx_hex = "84a400d901028182582011a2338987035057f6c36286cf5aadc02573059b2cde9790017eb4e148f0c67a0001828258390174f84e13070bb755eaa01cb717da8c7450daf379948e979f6de99d26ba89ff199fde572546b9a044eb129ad2edb184bd79cde63ab4b47aec1a01312d008258390184f1c3b1fff5241088acc4ce0aec81f45a71a70e35c94e30a70b7cdfeb0785cdec744029db6b4f344b1123497c9cabfeeb94af20fcfddfe01a33e578fd021a000299e90758201e8eb8575d879922d701c12daa7366cb71b6518a9500e083a966a8e66b56ed23a10081825820ea444825bbd5cc97b6c795437849fe55694b52e2f51485ac76ca2d9f991e83305840d59db4fa0b4bb233504f5e6826261a2e18b2e22cb3df4f631ab77d94d62e8df3200536271f3f3a625bc86919714972964f070f909f145b342f2889f58ccc210ff5a11902a2a1636d736765546f6b656f";

        let b_tx_hex = "0200000000010115ccf0534b7969e5ac0f4699e51bf7805168244057059caa333397fcf8a9acdd0000000000fdffffff027a6faf85150000001600147b458433d0c04323426ef88365bd4cfef141ac7520a107000000000022512087a397fc19d816b6f938dad182a54c778d2d5db8b31f4528a758b989d42f0b78024730440220072d64b2e3bbcd27bd79cb8859c83ca524dad60dc6310569c2a04c997d116381022071d4df703d037a9fe16ccb1a2b8061f10cda86ccbb330a49c5dcc95197436c960121030db9616d96a7b7a8656191b340f77e905ee2885a09a7a1e80b9c8b64ec746fb300000000";

        let c_tx = Tx::from_hex(c_tx_hex).unwrap();
        let b_tx = Tx::from_hex(b_tx_hex).unwrap();

        let v0 = vec![b_tx, c_tx];
        let v0_cbor = ciborium::Value::serialized(&v0).unwrap();

        let v1: Vec<Tx> = ciborium::Value::deserialized(&v0_cbor).unwrap();
        let v1_cbor = ciborium::Value::serialized(&v1).unwrap();
        assert_eq!(v0, v1);
        assert_eq!(v0_cbor, v1_cbor);
    }
}
