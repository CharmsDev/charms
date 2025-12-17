use charms_sdk::data::{charm_values, check, App, Data, Transaction, B32, NFT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NftContent {
    pub ticker: String,
    pub name: String,
    pub description: String,
    pub image: String,
    pub image_hash: String,
    pub url: String,
}

pub fn app_contract(app: &App, tx: &Transaction, x: &Data, w: &Data) -> bool {
    let empty = Data::empty();
    assert_eq!(x, &empty);
    match app.tag {
        NFT => {
            check!(nft_contract_satisfied(app, tx, w))
        }
        _ => unreachable!(),
    }
    true
}

// TODO replace with your own logic
fn nft_contract_satisfied(app: &App, tx: &Transaction, w: &Data) -> bool {
    check!(can_mint_nft(app, tx, w));
    true
}

fn can_mint_nft(nft_app: &App, tx: &Transaction, _w: &Data) -> bool {
    // can only mint an NFT with this contract if the first (index 0) spent UTXO has
    // the same hash as app identity.
    let w_str: Option<String> = tx.ins.get(0).map(|(utxo_id, _)| utxo_id.to_string());

    check!(w_str.is_some());
    let w_str = w_str.unwrap();

    // can only mint an NFT with this contract if the hash of `w` is the identity of the NFT.
    check!(hash(&w_str) == nft_app.identity);

    let nft_charms = charm_values(nft_app, tx.outs.iter()).collect::<Vec<_>>();

    // can mint exactly one NFT.
    check!(nft_charms.len() == 1);

    // the NFT has the correct structure.
    let nft = nft_charms[0].value::<NftContent>();
    check!(nft.is_ok());

    // TODO add more checks
    true
}

pub(crate) fn hash(data: &str) -> B32 {
    let hash = Sha256::digest(data);
    B32(hash.into())
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
