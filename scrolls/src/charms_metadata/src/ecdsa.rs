use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::metadata::keccak;

pub(crate) fn ethereum_address(public_key: &[u8]) -> Result<[u8; 20], String> {
    let key = verifying_key(public_key)?;
    let encoded = key.to_encoded_point(false);
    let hash = keccak(&encoded.as_bytes()[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    Ok(address)
}

pub(crate) fn signature_65(
    public_key: &[u8],
    digest: &[u8; 32],
    rs: &[u8],
) -> Result<[u8; 65], String> {
    if rs.len() != 64 {
        return Err("System error: signature length".into());
    }
    let signature = Signature::from_slice(rs).map_err(|_| "System error: signature".to_string())?;
    let expected = verifying_key(public_key)?;
    for rec in 0u8..2 {
        let id = RecoveryId::try_from(rec).map_err(|_| "System error: recovery id".to_string())?;
        let Ok(key) = VerifyingKey::recover_from_prehash(digest, &signature, id) else {
            continue;
        };
        if key == expected {
            let mut out = [0u8; 65];
            out[..64].copy_from_slice(rs);
            out[64] = rec + 27;
            return Ok(out);
        }
    }
    Err("System error: recovery id".into())
}

fn verifying_key(public_key: &[u8]) -> Result<VerifyingKey, String> {
    VerifyingKey::from_sec1_bytes(public_key).map_err(|_| "System error: public key".to_string())
}
