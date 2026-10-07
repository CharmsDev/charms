use crate::{cli, cli::ShowSpellParams, tx};
use anyhow::Result;
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
