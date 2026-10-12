use anyhow::{anyhow, ensure};
use ark_bls12_381::Bls12_381;
use ark_ff::ToConstraintField;
use ark_groth16::{Groth16, Proof, VerifyingKey, prepare_verifying_key};
use ark_serialize::CanonicalDeserialize;
use ark_snark::SNARK;
use sha2::{Digest, Sha256};

pub fn verify_groth16_proof(
    proof: &[u8],
    public_inputs: &[u8],
    vk_bytes: &[u8],
) -> anyhow::Result<()> {
    let vk = VerifyingKey::deserialize_compressed(vk_bytes)
        .map_err(|e| anyhow!("Failed to deserialize verifying key: {}", e))?;
    let pvk = prepare_verifying_key::<Bls12_381>(&vk);
    let proof = Proof::deserialize_compressed(proof)?;
    let field_elements = Sha256::digest(public_inputs)
        .to_field_elements()
        .expect("non-empty vector");
    let verified = Groth16::<Bls12_381>::verify_with_processed_vk(
        &pvk,
        &[field_elements[0]],
        &proof,
    )?;
    ensure!(verified, "could not verify spell proof");
    Ok(())
}
