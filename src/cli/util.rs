use crate::cli::DestParams;
use anyhow::{bail, ensure};
use charms_client::{cardano_tx::proxy_script_hash, tx::Chain};
use cml_core::serialization::RawBytesEncoding;
use std::str::FromStr;

pub fn dest(params: DestParams) -> anyhow::Result<()> {
    let has_addr = params.addr.is_some();
    let has_apps = !params.apps.is_empty();
    ensure!(
        has_addr != has_apps,
        "exactly one of --addr or --apps must be provided"
    );
    if has_apps {
        if let Some(Chain::Bitcoin) = params.chain {
            bail!("--apps only works with Cardano");
        };
    }

    let dest_bytes = if let Some(addr) = &params.addr {
        dest_from_addr(addr, params.chain)?
    } else {
        dest_from_apps(&params.apps)?
    };

    println!("{}", hex::encode(dest_bytes));
    Ok(())
}

fn dest_from_addr(addr: &str, chain: Option<Chain>) -> anyhow::Result<Vec<u8>> {
    match chain {
        Some(Chain::Bitcoin) => bitcoin_dest(addr),
        Some(Chain::Cardano) => cardano_dest(addr),
        None => {
            // Auto-detect: try Cardano first (bech32 with addr/addr_test prefix),
            // then Bitcoin
            if let Ok(bytes) = cardano_dest(addr) {
                return Ok(bytes);
            }
            if let Ok(bytes) = bitcoin_dest(addr) {
                return Ok(bytes);
            }
            bail!("could not parse address as Bitcoin or Cardano; try specifying --chain")
        }
    }
}

fn bitcoin_dest(addr: &str) -> anyhow::Result<Vec<u8>> {
    let address = bitcoin::Address::from_str(addr)?;
    Ok(address.assume_checked().script_pubkey().to_bytes())
}

fn cardano_dest(addr: &str) -> anyhow::Result<Vec<u8>> {
    let address = pallas_addresses::Address::from_bech32(addr)
        .map_err(|e| anyhow::anyhow!("invalid Cardano address: {:?}", e))?;
    Ok(address.to_vec())
}

fn dest_from_apps(apps: &[charms_data::App]) -> anyhow::Result<Vec<u8>> {
    ensure!(!apps.is_empty(), "--apps must not be empty");

    let app_refs: Vec<&charms_data::App> = apps.iter().collect();
    let (script_hash, _) = proxy_script_hash(&app_refs);

    let hash_bytes: [u8; 28] = script_hash
        .to_raw_bytes()
        .try_into()
        .expect("script hash must be 28 bytes");
    let pallas_hash = pallas_crypto::hash::Hash::<28>::new(hash_bytes);
    let shelley_addr = pallas_addresses::ShelleyAddress::new(
        pallas_addresses::Network::Mainnet,
        pallas_addresses::ShelleyPaymentPart::Script(pallas_hash),
        pallas_addresses::ShelleyDelegationPart::Null,
    );
    Ok(pallas_addresses::Address::Shelley(shelley_addr).to_vec())
}
