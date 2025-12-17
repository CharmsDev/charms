use charms_sdk::data::{
    charm_values, check, sum_token_amount, App, Data, Transaction, UtxoId, B32, NFT, TOKEN,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::str::FromStr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftContent {
    pub ticker: String,
    pub remaining: u64,
}

pub fn app_contract(app: &App, tx: &Transaction, x: &Data, w: &Data) -> bool {
    let empty = Data::empty();
    assert_eq!(x, &empty);
    match app.tag {
        NFT => {
            check!(nft_contract_satisfied(app, tx, w))
        }
        TOKEN => {
            check!(token_contract_satisfied(app, tx))
        }
        _ => unreachable!(),
    }
    true
}

fn nft_contract_satisfied(app: &App, tx: &Transaction, w: &Data) -> bool {
    let token_app = &App {
        tag: TOKEN,
        identity: app.identity.clone(),
        vk: app.vk.clone(),
    };
    check!(can_mint_nft(app, tx, w) || can_mint_token(&token_app, tx));
    true
}

fn can_mint_nft(nft_app: &App, tx: &Transaction, w: &Data) -> bool {
    let w_str: Option<String> = w.value().ok();

    check!(w_str.is_some());
    let w_str = w_str.unwrap();

    // can only mint an NFT with this contract if the hash of `w` is the identity of the NFT.
    check!(hash(&w_str) == nft_app.identity);

    // can only mint an NFT with this contract if spending a UTXO with the same ID as passed in `w`.
    let w_utxo_id = UtxoId::from_str(&w_str).unwrap();
    check!(tx.ins.iter().any(|(utxo_id, _)| utxo_id == &w_utxo_id));

    let nft_charms = charm_values(nft_app, tx.outs.iter()).collect::<Vec<_>>();

    // can mint exactly one NFT.
    check!(nft_charms.len() == 1);
    // the NFT has the correct structure.
    check!(nft_charms[0].value::<NftContent>().is_ok());
    true
}

pub(crate) fn hash(data: &str) -> B32 {
    let hash = Sha256::digest(data);
    B32(hash.into())
}

fn token_contract_satisfied(token_app: &App, tx: &Transaction) -> bool {
    check!(can_mint_token(token_app, tx));
    true
}

fn can_mint_token(token_app: &App, tx: &Transaction) -> bool {
    let nft_app = App {
        tag: NFT,
        identity: token_app.identity.clone(),
        vk: token_app.vk.clone(),
    };

    let Some(nft_content): Option<NftContent> =
        charm_values(&nft_app, tx.ins.iter().map(|(_, v)| v)).find_map(|data| data.value().ok())
    else {
        eprintln!("could not determine incoming remaining supply");
        return false;
    };
    let incoming_supply = nft_content.remaining;

    let Some(nft_content): Option<NftContent> =
        charm_values(&nft_app, tx.outs.iter()).find_map(|data| data.value().ok())
    else {
        eprintln!("could not determine outgoing remaining supply");
        return false;
    };
    let outgoing_supply = nft_content.remaining;

    if !(incoming_supply >= outgoing_supply) {
        eprintln!("incoming remaining supply must be >= outgoing remaining supply");
        return false;
    }

    let Some(input_token_amount) = sum_token_amount(&token_app, tx.ins.iter().map(|(_, v)| v)).ok()
    else {
        eprintln!("could not determine input total token amount");
        return false;
    };
    let Some(output_token_amount) = sum_token_amount(&token_app, tx.outs.iter()).ok() else {
        eprintln!("could not determine output total token amount");
        return false;
    };

    // can mint no more than what's allowed by the managing NFT state change.
    output_token_amount - input_token_amount == incoming_supply - outgoing_supply
}

#[cfg(test)]
mod test {
    use super::*;
    use charms_sdk::data::UtxoId;
    use std::str::FromStr;

    #[test]
    fn dummy() {}

    #[test]
    fn test_hash() {
        let utxo_id =
            UtxoId::from_str("dc78b09d767c8565c4a58a95e7ad5ee22b28fc1685535056a395dc94929cdd5f:1")
                .unwrap();
        let data = dbg!(utxo_id.to_string());
        let expected = "f54f6d40bd4ba808b188963ae5d72769ad5212dd1d29517ecc4063dd9f033faa";
        assert_eq!(&hash(&data).to_string(), expected);
    }
}
