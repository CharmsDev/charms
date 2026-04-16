use sp1_primitives::io::sha256_hash;
use sp1_zkvm::lib::verify::verify_sp1_proof;

pub const SPELL_CHECKER_VK: [u32; 8] = [
    1753668998, 687107284, 1206964347, 2021451334, 1670905855, 1862602036, 1636180012, 348104726,
];

pub fn main() {
    let input_vec = sp1_zkvm::io::read_vec();
    verify_proof(&SPELL_CHECKER_VK, &input_vec);
    sp1_zkvm::io::commit_slice(&input_vec);
}

fn verify_proof(vk: &[u32; 8], committed_data: &[u8]) {
    let Ok(pv) = sha256_hash(committed_data).try_into() else {
        unreachable!()
    };
    verify_sp1_proof(vk, &pv);
}

#[cfg(test)]
mod test {
    use super::*;
    use sp1_sdk::{
        HashableKey, ProvingKey,
        blocking::{Prover, ProverClient},
    };

    /// RISC-V binary compiled from `charms-spell-checker`.
    pub const SPELL_CHECKER_BINARY: &[u8] = include_bytes!("../../src/bin/charms-spell-checker");

    #[test]
    fn test_spell_vk() {
        let client = ProverClient::builder().light().build();

        dbg!("client built");

        let pk = client.setup(SPELL_CHECKER_BINARY.into()).unwrap();

        dbg!("pk obtained");

        assert_eq!(SPELL_CHECKER_VK, pk.verifying_key().hash_u32());
    }
}
