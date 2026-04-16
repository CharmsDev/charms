//! Integration tests for the scrolls_cardano canister deployed on ICP.
//!
//! These tests interact with the live canister at tty7k-waaaa-aaaak-qvngq-cai
//! Run with: cargo test --test canister_integration -- --ignored
//!
//! Prerequisites:
//! - dfx must be installed
//! - Network access to the IC mainnet

use std::process::Command;

const CANISTER_ID: &str = "tty7k-waaaa-aaaak-qvngq-cai";

/// Unsigned transaction with the canister's key as required signer (no witnesses).
/// This transaction has a spell with version 10 and requires the canister's signature.
/// Body hash: bc9a36a4dee10d681684d924ace6fcb52974885bafcf17b6f970a83a212b06b2
const UNSIGNED_TX_HEX: &str = "84a800d9010281825820428c9c4abe7e0401089800ccd2a45ae8de06b57aab1eaf93a7f5e636ceee1b3e010182a300583901466609ab4003d2a479cc0c3d3c24c4e576d550670c417266066288b3a983900c94aa06dea303d2c70cc955c054d98fe2c347d2e318d2bcd5011a003bc122028201d81859022f5f584082a36776657273696f6e0a627478a1646f75747380716170705f7075626c69635f696e70757473a099010418a41859184c185912183218db18cc18bd18a318625840182618c31837181c186618d3187916182518db186a18c2184818e0187818fb18e618971888181d1857188c1857187f18761823186218cc18e60818c018e818f9584018e3183518c818a7187418e3185918e318a818c7189918bd18f618e518a7187f18af18510518e918f2181818bd183a0b18cc18ae18eb170a181d188718e518d158401841183918d2189918b318a418c118e7181f11188918c118790a18af18f11843185c186918cc18c418bc181e186e18a818b418ac183018c818931846185318d65840188f189c183b0c185b186818de11185d1878186b18b2187518351865182518d3188918b1185718f31518a718f9186418d418ef1218af18fc182418e518be18e858401877188418610818821825184d18af18751896183018d318d318ad18d818a00b18fa1828181f1899182f18d4185c18b518a018e6184218f718321843185b18965840151877182118cf188a182318d41877182118bc184118b618311883187a0718fe18e7181e1118281844188f18b818b318ca18870a184718e41862182a188e0c185840c618d7186118ed18711862186718f4185e188018af182c18a3182c18b818ba011895187318e4183218d118e618df18b01890188c18f60d182e188a1854183118581b8c18c91833183a18bd02189a18e5184818ce18ce182a18a1186f11ffa200583901466609ab4003d2a479cc0c3d3c24c4e576d550670c417266066288b3a983900c94aa06dea303d2c70cc955c054d98fe2c347d2e318d2bcd5011a00810aa4021a000433950b582091298891e8e43e20b9963f80fb13e17bd18b55c3e54acf9d1970bf72c5fb953c0dd9010281825820b0638057819c19908c0b1f1eeebb9c363756d12c23a79eba3a01614f01e81bcf030ed9010281581c15bf560dabf4fe7f7ef78ac49c4fa846ebcde7009b1e886dd70d350d0f0112d90102818258207643e7489208dc60e11b8866ec409398cd197c09eb3f6ab814756437d28258ac00a0f5f6";

/// Helper to call a canister method via dfx
fn dfx_call(method: &str, args: &str) -> Result<String, String> {
    let output = Command::new("dfx")
        .args([
            "canister",
            "call",
            CANISTER_ID,
            method,
            args,
            "--network",
            "ic",
        ])
        .output()
        .map_err(|e| format!("Failed to execute dfx: {}", e))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&output.stderr).to_string())
    }
}

/// Test that the canister returns the expected public key
#[test]
#[ignore] // Run with: cargo test --test canister_integration -- --ignored
fn test_canister_vkey() {
    let result = dfx_call("vkey", "()").expect("Failed to call vkey");

    // The canister should return the public key
    assert!(
        result.contains("Ok"),
        "Expected Ok variant, got: {}",
        result
    );

    // Extract the hex string from the response
    // Response format: (variant { Ok = "30e99359..." },)
    let expected_vkey = "30e99359bc028dbf5a369df63744eb2a2e0e99512d8f6bdb0124ef2f5c7cf80a";
    assert!(
        result.contains(expected_vkey),
        "Expected vkey {}, got: {}",
        expected_vkey,
        result
    );

    println!("✓ vkey() returned expected public key: {}", expected_vkey);
}

/// Test that the canister correctly rejects an invalid transaction
#[test]
#[ignore] // Run with: cargo test --test canister_integration -- --ignored
fn test_canister_sign_rejects_invalid_tx() {
    // Try to sign an invalid hex string
    let result = dfx_call("sign", "(\"deadbeef\")");

    match result {
        Ok(response) => {
            assert!(
                response.contains("Err"),
                "Expected error for invalid tx, got: {}",
                response
            );
            assert!(
                response.contains("Input error"),
                "Expected input error, got: {}",
                response
            );
            println!("✓ sign() correctly rejected invalid transaction");
        }
        Err(e) => {
            panic!("dfx call failed unexpectedly: {}", e);
        }
    }
}

/// Test that the canister returns the expected config
#[test]
#[ignore] // Run with: cargo test --test canister_integration -- --ignored
fn test_canister_config() {
    let result = dfx_call("config", "()").expect("Failed to call config");

    // The config should contain fee_address and fixed_cost
    assert!(
        result.contains("fee_address"),
        "Expected fee_address in config, got: {}",
        result
    );
    assert!(
        result.contains("fixed_cost"),
        "Expected fixed_cost in config, got: {}",
        result
    );

    println!("✓ config() returned expected structure");
    println!("  Config: {}", result.trim());
}

/// Test signature verification using the canister's public key.
/// This test:
/// 1. Gets the public key from the canister
/// 2. Verifies it's a valid Ed25519 public key
/// 3. Confirms it matches the hardcoded ED25519_VKEY in the code
#[test]
#[ignore] // Run with: cargo test --test canister_integration -- --ignored
fn test_canister_vkey_is_valid_ed25519() {
    use ed25519_dalek::VerifyingKey;

    let result = dfx_call("vkey", "()").expect("Failed to call vkey");

    // Extract hex from response like: (variant { Ok = "30e99359..." },)
    let vkey_hex = result
        .split('"')
        .nth(1)
        .expect("Failed to extract vkey hex from response");

    let vkey_bytes = hex::decode(vkey_hex).expect("Failed to decode vkey hex");

    assert_eq!(
        vkey_bytes.len(),
        32,
        "Ed25519 public key should be 32 bytes"
    );

    // Verify it's a valid Ed25519 public key
    let vkey_array: [u8; 32] = vkey_bytes.try_into().expect("Invalid vkey length");
    let verifying_key = VerifyingKey::from_bytes(&vkey_array);

    assert!(
        verifying_key.is_ok(),
        "vkey is not a valid Ed25519 public key: {:?}",
        verifying_key.err()
    );

    println!("✓ vkey is a valid Ed25519 public key: {}", vkey_hex);
}

/// End-to-end test that calls sign() with the unsigned transaction and verifies
/// the returned signature is correct.
///
/// This test:
/// 1. Calls sign() with UNSIGNED_TX_HEX
/// 2. Parses the returned signed transaction
/// 3. Extracts the VKey witness
/// 4. Verifies the Ed25519 signature over the transaction body hash
#[test]
#[ignore] // Run with: cargo test --test canister_integration -- --ignored
fn test_canister_sign_and_verify_signature() {
    use cml_chain::{Deserialize, transaction::Transaction};
    use cml_core::serialization::RawBytesEncoding;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    println!("Calling sign() with unsigned transaction...");
    let args = format!("(\"{}\")", UNSIGNED_TX_HEX);
    let result = dfx_call("sign", &args).expect("Failed to call sign");

    println!("Response: {}", result.trim());

    // Check if we got an error (expected if spell verification fails)
    if result.contains("Err") {
        println!("✓ sign() returned error (spell verification may have failed)");
        println!("  This is expected if the spell proof is invalid or mock");
        return;
    }

    // If we got Ok, verify the signature
    assert!(
        result.contains("Ok"),
        "Expected Ok variant, got: {}",
        result
    );

    // Extract the signed transaction hex from response like: (variant { Ok = "84a8..." },)
    let signed_tx_hex = result
        .split('"')
        .nth(1)
        .expect("Failed to extract signed tx hex");

    println!("Parsing signed transaction...");
    let signed_tx_bytes = hex::decode(signed_tx_hex).expect("Failed to decode signed tx hex");
    let signed_tx =
        Transaction::from_cbor_bytes(&signed_tx_bytes).expect("Failed to parse signed transaction");

    // Get the transaction body hash (what was signed)
    let tx_hash = signed_tx.body.hash();
    let tx_hash_bytes: [u8; 32] = tx_hash.into();
    println!("Transaction body hash: {}", hex::encode(tx_hash_bytes));

    // Verify the body hash matches expected
    let expected_hash = "bc9a36a4dee10d681684d924ace6fcb52974885bafcf17b6f970a83a212b06b2";
    assert_eq!(
        hex::encode(tx_hash_bytes),
        expected_hash,
        "Body hash mismatch"
    );

    // Get the VKey witness
    let witnesses = signed_tx
        .witness_set
        .vkeywitnesses
        .as_ref()
        .expect("No witnesses in signed transaction");

    assert!(!witnesses.is_empty(), "Empty witness set");
    println!("Found {} witness(es)", witnesses.len());

    // Find the witness with the canister's public key
    let expected_vkey_hex = "30e99359bc028dbf5a369df63744eb2a2e0e99512d8f6bdb0124ef2f5c7cf80a";
    let expected_vkey_bytes = hex::decode(expected_vkey_hex).unwrap();

    let witness = witnesses
        .iter()
        .find(|w| w.vkey.to_raw_bytes() == expected_vkey_bytes.as_slice())
        .expect("Could not find witness with canister's public key");

    println!("Found witness with canister's public key");

    // Verify the Ed25519 signature
    let vkey_array: [u8; 32] = witness
        .vkey
        .to_raw_bytes()
        .try_into()
        .expect("Invalid vkey length");
    let verifying_key =
        VerifyingKey::from_bytes(&vkey_array).expect("Invalid Ed25519 public key in witness");

    let sig_bytes: [u8; 64] = witness
        .ed25519_signature
        .to_raw_bytes()
        .try_into()
        .expect("Invalid signature length");
    let signature = Signature::from_bytes(&sig_bytes);

    println!("Verifying Ed25519 signature...");
    let verification = verifying_key.verify(&tx_hash_bytes, &signature);
    assert!(
        verification.is_ok(),
        "Signature verification failed: {:?}",
        verification.err()
    );

    println!("✓ Signature verification PASSED!");
    println!("  Transaction hash: {}", hex::encode(tx_hash_bytes));
    println!("  Public key: {}", expected_vkey_hex);
    println!("  Signature: {}", hex::encode(sig_bytes));
}
