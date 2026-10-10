use crate::{
    cli,
    cli::{ShowSpellParams, TxBuildParams},
    tx,
};
use anyhow::{Context, Result, bail, ensure};
use charms_client::{
    bitcoin_tx::BitcoinTx,
    cardano_tx::CardanoTx,
    tx::{Chain, Tx},
};

pub fn tx_show_spell(params: ShowSpellParams) -> Result<()> {
    let ShowSpellParams {
        chain,
        tx,
        json,
        mock,
    } = params;
    let tx = match chain {
        Chain::Bitcoin => Tx::Bitcoin(BitcoinTx::from_hex(&tx)?),
        Chain::Cardano => Tx::Cardano(CardanoTx::from_hex(&tx)?),
        Chain::Ethereum => {
            let Some(eth) = charms_client::ethereum_tx::from_envelope_hex(&tx)? else {
                anyhow::bail!("invalid hex");
            };
            Tx::Ethereum(eth)
        }
    };

    match tx::spell(&tx, mock) {
        Some(spell) => cli::print_output(&spell, json)?,
        None => eprintln!("No spell found in the transaction"),
    }

    Ok(())
}

pub fn tx_build(params: TxBuildParams) -> Result<()> {
    ensure!(
        params.chain == Chain::Ethereum,
        "tx build is implemented for ethereum"
    );
    println!("{}", ethereum_transact_json(&params.tx)?);
    Ok(())
}

pub(crate) fn ethereum_transact_json(tx_json: &str) -> Result<String> {
    let tx: Tx = serde_json::from_str(tx_json).context("expected the JSON tx object")?;
    let Tx::Ethereum(record) = tx else {
        bail!("tx build expects an Ethereum record");
    };
    let call = charms_client::ethereum_tx::transact_call(&record)?;
    Ok(serde_json::to_string(&call)?)
}
