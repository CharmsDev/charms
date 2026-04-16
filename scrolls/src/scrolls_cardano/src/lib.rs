mod mithril;

use anyhow::{anyhow, ensure};
use candid::CandidType;
use charms_lib::{
    cardano_tx::CardanoTx,
    extract_and_verify_spell,
    tx::{EnchantedTx, Tx},
};
use cml_chain::{
    NonemptySetVkeywitness,
    address::Address,
    crypto::{Ed25519KeyHash, Ed25519Signature, Vkey, Vkeywitness},
    transaction::Transaction,
};
use cml_core::serialization::RawBytesEncoding;
use getrandom::register_custom_getrandom;
use hex_literal::hex;
use ic_cdk::management_canister::{
    HttpRequestResult, SchnorrAlgorithm, SchnorrKeyId, SignWithSchnorrArgs, TransformArgs,
    schnorr_public_key, sign_with_schnorr,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::LazyLock};

const SCROLLS: &[u8] = b"scrolls";
const FINALITY: &[u8] = b"finality";

pub type CardanoAddresses = BTreeMap<String, String>;

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct Config {
    pub fee_address: CardanoAddresses,
    pub fixed_cost: u64,
}

static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let config_bytes = include_bytes!("../config.yaml");
    let config: Config = serde_yaml::from_slice(config_bytes).unwrap();
    config
});

#[ic_cdk::init]
fn init() {
    do_init();
}

#[ic_cdk::post_upgrade]
fn post_upgrade() {
    do_init();
}

fn do_init() {
    for network in vec!["mainnet", "preprod"] {
        let address = &CONFIG.fee_address[network];
        let address = cml_chain::address::Address::from_bech32(address).unwrap();
        let _ = address.network_id().unwrap();
    }
}

#[ic_cdk::query]
pub fn config() -> Config {
    CONFIG.clone()
}

const ED25519_VKEY: [u8; 32] =
    hex!("30e99359bc028dbf5a369df63744eb2a2e0e99512d8f6bdb0124ef2f5c7cf80a");

/// Policy ID for CIP-68 reference NFT minting bypass
const CIP68_REF_NFT_POLICY_ID: [u8; 28] =
    hex!("552b22f4989ea698fabbf6314b70d2e5edb49c1fdbdeb6096e8c84b6");

/// CIP-68 reference NFT label (100) prefix: 000643b0
const CIP68_REF_NFT_LABEL: [u8; 4] = hex!("000643b0");

/// Payment verification key that must sign inputs for CIP-68 ref NFT minting bypass
const CIP68_REF_NFT_SIGNER_VKEY: [u8; 32] =
    hex!("720c93bc822efbf4aabccaa7ae875cd46a556c99bc1b3f2fbdd8c561f4723d53");

#[ic_cdk::update]
pub async fn vkey() -> anyhow::Result<String, String> {
    let vkey_bytes = get_vkey(&[])
        .await
        .map_err(|e| format!("System error: getting Schnorr public key: {}", e))?;
    let vkey_hex = hex::encode(&vkey_bytes);
    Ok(vkey_hex)
}

async fn get_vkey(path: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
    let schnorr_public_key_args = ic_cdk::management_canister::SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: derivation_path(path),
        key_id: key_id(),
    };
    let schnorr_public_key_result = schnorr_public_key(&schnorr_public_key_args).await?;

    let public_key = schnorr_public_key_result.public_key;

    let vkey_bytes = public_key;
    // let vkey_bytes = ED25519_VKEY.to_vec();
    Ok(vkey_bytes)
}

#[ic_cdk::update]
pub async fn finality_vkey() -> anyhow::Result<String, String> {
    let vkey_bytes = get_vkey(&[FINALITY])
        .await
        .map_err(|e| format!("System error: getting Schnorr public key: {}", e))?;
    let vkey_hex = hex::encode(&vkey_bytes);
    Ok(vkey_hex)
}

fn derivation_path(path: &[&[u8]]) -> Vec<Vec<u8>> {
    std::iter::once(SCROLLS)
        .chain(path.iter().copied())
        .map(|p| p.to_vec())
        .collect()
}

#[ic_cdk::update]
pub async fn sign(tx_to_sign: String) -> Result<String, String> {
    do_sign(tx_to_sign).await.map_err(|e| e.to_string())
}

async fn do_sign(tx_to_sign: String) -> anyhow::Result<String> {
    // Parse the transaction hex into a Cardano transaction
    let cardano_tx =
        CardanoTx::from_hex(&tx_to_sign).map_err(|e| anyhow!("Input error: parsing tx: {}", e))?;

    let tx: Tx = Tx::Cardano(cardano_tx);

    verify_tx(&tx)?;

    let Tx::Cardano(cardano_tx) = tx else {
        unreachable!()
    };

    // Get the transaction ID (hash) as bytes
    let tx_hash = cardano_tx.inner().body.hash();
    let tx_hash_bytes: [u8; 32] = tx_hash.into();

    let signature_bytes = sign_tx_hash(tx_hash_bytes, &[]).await?;

    // let vkey_bytes = get_vkey(&[]).await?;
    let vkey_bytes = ED25519_VKEY; // save a few cycles
    let CardanoTx::Simple(inner_tx) = cardano_tx else {
        unreachable!()
    };
    let signed_tx = add_vkey_witness(inner_tx, &vkey_bytes, signature_bytes)?;

    // Return the signed tx as hex
    Ok(CardanoTx::Simple(signed_tx).hex())
}

async fn sign_tx_hash(tx_hash_bytes: [u8; 32], path: &[&[u8]]) -> anyhow::Result<Vec<u8>> {
    // Sign the transaction hash using threshold Schnorr
    let sign_args = SignWithSchnorrArgs {
        message: tx_hash_bytes.to_vec(),
        derivation_path: derivation_path(path),
        key_id: key_id(),
        aux: None,
    };

    let sign_result = sign_with_schnorr(&sign_args)
        .await
        .map_err(|e| anyhow!("System error: signing tx hash: {}", e))?;

    Ok(sign_result.signature)
}

#[derive(CandidType, Clone, Debug, Deserialize, Serialize)]
pub struct CertifiedTx {
    tx: String,
    cert_sig: String,
}

const AGGREGATOR_ENDPOINT: &str =
    "https://aggregator.release-mainnet.api.mithril.network/aggregator";

/// Verify that a transaction has been finalized on the Cardano blockchain using Mithril.
///
/// Uses IC's http_outcall API to communicate with the Mithril aggregator, implementing
/// custom `CertificateAggregatorRequest` and `CardanoTransactionAggregatorRequest` traits
/// that replace the default reqwest-based HTTP client.
async fn verify_transaction_finality(tx_hash: &[u8; 32]) -> anyhow::Result<()> {
    let tx_hash_hex = hex::encode(tx_hash);
    mithril::verify_transaction_finality(&tx_hash_hex).await
}

#[ic_cdk::update]
pub async fn certify_final(tx: String) -> Result<String, String> {
    do_certify_final(tx).await.map_err(|e| e.to_string())
}

async fn do_certify_final(tx_hex: String) -> anyhow::Result<String> {
    // Parse the transaction hex into a Cardano transaction
    let cardano_tx =
        CardanoTx::from_hex(&tx_hex).map_err(|e| anyhow!("Input error: parsing tx: {}", e))?;

    let tx: Tx = Tx::Cardano(cardano_tx);

    verify_tx(&tx)?;

    let Tx::Cardano(cardano_tx) = tx else {
        unreachable!()
    };

    // Get the transaction ID (hash) as bytes
    let tx_hash = cardano_tx.inner().body.hash();
    let tx_hash_bytes: [u8; 32] = tx_hash.into();

    // Verify the transaction has been finalized on-chain
    verify_transaction_finality(&tx_hash_bytes).await?;

    let cert_sig_bytes = sign_tx_hash(tx_hash_bytes, &[FINALITY]).await?;

    Ok(hex::encode(&cert_sig_bytes))
}

fn verify_tx(tx: &Tx) -> anyhow::Result<()> {
    // Allow CIP-68 reference NFT minting transactions without spell verification
    if is_cip68_ref_nft_mint_only(tx) {
        return Ok(());
    }

    // Extract and verify the spell from the transaction
    let spell = extract_and_verify_spell(tx, false)
        .map_err(|e| anyhow!("Input error: extracting and verifying spell: {}", e))?;

    let Tx::Cardano(cardano_tx) = tx else {
        unreachable!()
    };

    let fee_addr_bytes = fee_addr_bytes()?;
    ensure!(
        (cardano_tx.inner().body.outputs)
            .get(spell.tx.outs.len())
            .is_some_and(|output| output.address().to_raw_bytes() == fee_addr_bytes)
    );

    Ok(())
}

fn fee_addr_bytes() -> anyhow::Result<Vec<u8>> {
    let config = config();
    let fee_addr_str = (config.fee_address.get("mainnet"))
        .ok_or_else(|| anyhow!("could not get the fee address from config"))?;
    let fee_addr_bytes = Address::from_bech32(fee_addr_str)
        .map_err(|e| anyhow!("Error parsing address from bech32: {}", e))?
        .to_raw_bytes();
    Ok(fee_addr_bytes)
}

/// Check if the transaction only mints CIP-68 reference NFTs for the allowed policy ID,
/// doesn't spend anything besides ADA, and is signed by the allowed payment key.
fn is_cip68_ref_nft_mint_only(tx: &Tx) -> bool {
    let Tx::Cardano(cardano_tx) = tx else {
        return false;
    };

    let inner = cardano_tx.inner();
    let body = &inner.body;
    let witness_set = &inner.witness_set;

    // Check that the transaction has a mint field
    let Some(mint) = &body.mint else {
        return false;
    };

    // Check that mint only contains the allowed policy ID
    if mint.len() != 1 {
        return false;
    }

    let allowed_policy_id: cml_chain::PolicyId = CIP68_REF_NFT_POLICY_ID.into();

    // Iterate over minted assets and verify they match our requirements
    for (policy_id, assets) in mint.iter() {
        if *policy_id != allowed_policy_id {
            return false;
        }
        // Check that all minted assets are CIP-68 reference NFTs (label 100 = 000643b0 prefix)
        for (asset_name, quantity) in assets.iter() {
            let name_bytes = asset_name.to_raw_bytes();
            // Asset name must start with CIP-68 reference NFT label and quantity must be positive
            // (minting, not burning)
            if !name_bytes.starts_with(&CIP68_REF_NFT_LABEL) || *quantity <= 0 {
                return false;
            }
        }
    }

    // Check that outputs only contain ADA (no other native tokens being spent)
    for output in &body.outputs {
        let value = match output {
            cml_chain::transaction::TransactionOutput::AlonzoFormatTxOut(tx_out) => &tx_out.amount,
            cml_chain::transaction::TransactionOutput::ConwayFormatTxOut(tx_out) => &tx_out.amount,
        };
        // If output has multiasset, check it only contains the minted tokens from our policy
        if !value.multiasset.is_empty() {
            for (policy_id, _) in value.multiasset.iter() {
                if *policy_id != allowed_policy_id {
                    return false;
                }
            }
        }
    }

    // Check that the transaction is signed by the allowed payment key
    let Some(vkeywitnesses) = &witness_set.vkeywitnesses else {
        return false;
    };

    let allowed_vkey = match Vkey::from_raw_bytes(&CIP68_REF_NFT_SIGNER_VKEY) {
        Ok(vkey) => vkey,
        Err(_) => return false,
    };
    let allowed_key_hash: Ed25519KeyHash = allowed_vkey.hash();

    let has_required_signature = vkeywitnesses
        .iter()
        .any(|witness| witness.vkey.hash() == allowed_key_hash);

    has_required_signature
}

fn key_id() -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: "key_1".to_string(),
    }
}

/// Add a VKey witness (signature) to the transaction
fn add_vkey_witness(
    mut tx: Transaction,
    vk_bytes: &[u8],
    signature: Vec<u8>,
) -> anyhow::Result<Transaction> {
    // Create VKey from the public key
    let vkey = Vkey::from_raw_bytes(vk_bytes)
        .map_err(|e| anyhow!("Error creating VKey from public key: {}", e))?;

    // Create signature from bytes
    let ed25519_signature = Ed25519Signature::from_raw_bytes(&signature)
        .map_err(|e| anyhow!("Error creating Ed25519Signature: {}", e))?;

    // Create VKeyWitness
    let vkey_witness = Vkeywitness::new(vkey, ed25519_signature);

    // Add to witness set
    let witness_set = &mut tx.witness_set;

    if let Some(vkeywitnesses) = witness_set.vkeywitnesses.as_mut() {
        vkeywitnesses.push(vkey_witness);
    } else {
        let vkeywitnesses: NonemptySetVkeywitness = vec![vkey_witness].into();
        witness_set.vkeywitnesses = Some(vkeywitnesses);
    }

    Ok(tx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cml_chain::Deserialize;
    use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

    /// Test that verifies the Ed25519 signature over the transaction body hash is correct.
    /// This test:
    /// 1. Creates a keypair
    /// 2. Parses a sample transaction
    /// 3. Computes the transaction body hash (what Cardano signs)
    /// 4. Signs the hash with Ed25519
    /// 5. Verifies the signature
    /// 6. Adds the witness to the transaction and verifies it can be extracted
    #[test]
    fn test_signature_verification() {
        // Create a test keypair
        let secret_bytes: [u8; 32] =
            hex!("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key: VerifyingKey = (&signing_key).into();
        let public_key_bytes = verifying_key.to_bytes();

        // Create a minimal valid transaction for testing
        // This is a simple transaction structure in CBOR
        let tx_cbor = create_test_transaction();
        let tx = Transaction::from_cbor_bytes(&tx_cbor).expect("Failed to parse test transaction");

        // Compute the transaction body hash - this is what Cardano signs
        let tx_hash = tx.body.hash();
        let tx_hash_bytes: [u8; 32] = tx_hash.into();

        // Sign the transaction hash with Ed25519
        let signature = signing_key.sign(&tx_hash_bytes);
        let signature_bytes = signature.to_bytes();

        // Verify the signature is valid
        assert!(
            verifying_key
                .verify_strict(&tx_hash_bytes, &signature)
                .is_ok(),
            "Signature verification failed"
        );

        // Now test add_vkey_witness by temporarily using our test public key
        let vkey =
            Vkey::from_raw_bytes(&public_key_bytes).expect("Failed to create Vkey from test key");

        let ed25519_sig = Ed25519Signature::from_raw_bytes(&signature_bytes)
            .expect("Failed to create Ed25519Signature");

        // Create witness and add to transaction
        let vkey_witness = Vkeywitness::new(vkey, ed25519_sig);

        let mut signed_tx = tx.clone();
        let witness_set = &mut signed_tx.witness_set;
        let vkeywitnesses: NonemptySetVkeywitness = vec![vkey_witness].into();
        witness_set.vkeywitnesses = Some(vkeywitnesses);

        // Verify the witness was added correctly
        let witnesses = signed_tx.witness_set.vkeywitnesses.as_ref().unwrap();
        assert_eq!(witnesses.len(), 1, "Expected exactly one witness");

        let witness = &witnesses[0];
        let witness_vkey_bytes = witness.vkey.to_raw_bytes();
        let witness_sig_bytes = witness.ed25519_signature.to_raw_bytes();

        assert_eq!(
            witness_vkey_bytes, &public_key_bytes,
            "Witness vkey doesn't match"
        );
        assert_eq!(
            witness_sig_bytes,
            &signature_bytes[..],
            "Witness signature doesn't match"
        );

        // Verify the extracted signature is still valid against the tx hash
        let extracted_verifying_key =
            VerifyingKey::from_bytes(&public_key_bytes).expect("Failed to parse verifying key");
        let extracted_signature = ed25519_dalek::Signature::from_bytes(
            witness_sig_bytes.try_into().expect("Invalid sig length"),
        );

        assert!(
            extracted_verifying_key
                .verify_strict(&tx_hash_bytes, &extracted_signature)
                .is_ok(),
            "Extracted signature verification failed"
        );
    }

    /// Test that add_vkey_witness correctly adds a witness to a transaction
    #[test]
    fn test_add_vkey_witness() {
        let tx_cbor = create_test_transaction();
        let tx = Transaction::from_cbor_bytes(&tx_cbor).expect("Failed to parse test transaction");

        // Create a dummy 64-byte signature
        let dummy_signature = vec![0u8; 64];

        let result = add_vkey_witness(tx, &vec![0; 32], dummy_signature);
        assert!(
            result.is_ok(),
            "add_vkey_witness failed: {:?}",
            result.err()
        );

        let signed_tx = result.unwrap();
        assert!(
            signed_tx.witness_set.vkeywitnesses.is_some(),
            "No witnesses added"
        );
        assert_eq!(
            signed_tx.witness_set.vkeywitnesses.as_ref().unwrap().len(),
            1,
            "Expected one witness"
        );
    }

    /// Test that add_vkey_witness appends to existing witnesses
    #[test]
    fn test_add_vkey_witness_appends() {
        let tx_cbor = create_test_transaction();
        let tx = Transaction::from_cbor_bytes(&tx_cbor).expect("Failed to parse test transaction");

        let dummy_signature1 = vec![1u8; 64];
        let dummy_signature2 = vec![2u8; 64];

        let tx =
            add_vkey_witness(tx, &vec![0; 32], dummy_signature1).expect("First witness failed");
        let tx =
            add_vkey_witness(tx, &vec![0; 32], dummy_signature2).expect("Second witness failed");

        assert_eq!(
            tx.witness_set.vkeywitnesses.as_ref().unwrap().len(),
            2,
            "Expected two witnesses"
        );
    }

    /// Create a minimal valid Cardano transaction for testing
    fn create_test_transaction() -> Vec<u8> {
        use cml_chain::{
            Serialize, Value,
            transaction::{TransactionBody, TransactionInput, TransactionOutput},
        };
        use cml_crypto::TransactionHash;

        // Create a dummy input
        let input_tx_hash = TransactionHash::from_hex(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let input = TransactionInput::new(input_tx_hash, 0);

        // Create a dummy output address (preprod testnet)
        let addr = cml_chain::address::Address::from_bech32(
            "addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp"
        ).unwrap();

        // Create output
        let output = TransactionOutput::new(addr, Value::from(2_000_000_u64), None, None);

        // Create transaction body
        let tx_body = TransactionBody::new(vec![input].into(), vec![output], 200_000);

        // Create full transaction with empty witness set
        let witness_set = cml_chain::transaction::TransactionWitnessSet::new();
        let tx = Transaction::new(tx_body, witness_set, true, None);

        tx.to_cbor_bytes()
    }
}

// Enable Candid export
ic_cdk::export_candid!();

register_custom_getrandom!(custom_getrandom);
fn custom_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
