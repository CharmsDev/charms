use charms_client::{
    BeamSource, NormalizedSpell,
    tx::{Chain, Tx},
};
use charms_data::{App, B32, Data, UtxoId, util};
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, IfIsHumanReadable, base64::Base64, serde_as};
use std::collections::BTreeMap;

pub type FeeAddressForNetwork = BTreeMap<String, String>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CharmsFee {
    /// Fee addresses for each chain (bitcoin, cardano, etc.) further broken down by network
    /// (mainnet, testnet, etc.).
    pub fee_addresses: BTreeMap<Chain, FeeAddressForNetwork>,
    /// Fee rate in sats per mega cycle.
    pub fee_rate: u64,
    /// Base fee in sats.
    pub fee_base: u64,
}

impl CharmsFee {
    pub fn fee_address(&self, chain: &Chain, network: &str) -> Option<&str> {
        self.fee_addresses.get(chain).and_then(|fee_addresses| {
            fee_addresses
                .get(network)
                .map(|fee_address| fee_address.as_str())
        })
    }
}

serde_with::serde_conv!(
    NormalizedSpellHex,
    NormalizedSpell,
    |data: &NormalizedSpell| hex::encode(util::write(data).expect("failed to write Data")),
    |s: String| util::read(hex::decode(&s)?.as_slice())
);

serde_with::serde_conv!(
    DataHex,
    Data,
    |data: &Data| hex::encode(util::write(data).expect("failed to write Data")),
    |s: String| util::read(hex::decode(&s)?.as_slice())
);

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProveRequest {
    #[serde_as(as = "IfIsHumanReadable<NormalizedSpellHex>")]
    pub spell: NormalizedSpell,
    #[serde_as(as = "IfIsHumanReadable<BTreeMap<DisplayFromStr, DataHex>>")]
    pub app_private_inputs: BTreeMap<App, Data>,
    #[serde_as(as = "IfIsHumanReadable<BTreeMap<DisplayFromStr, _>>")]
    pub tx_ins_beamed_source_utxos: BTreeMap<usize, BeamSource>,
    #[serde_as(as = "IfIsHumanReadable<BTreeMap<_, Base64>>")]
    pub binaries: BTreeMap<B32, Vec<u8>>,
    pub prev_txs: Vec<Tx>,
    pub change_address: String,
    pub fee_rate: f64,
    pub chain: Chain,
    pub collateral_utxo: Option<UtxoId>,
}
