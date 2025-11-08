use sp1_primitives::io::sha256_hash;
use sp1_zkvm::lib::verify::verify_sp1_proof;

pub const SPELL_CHECKER_VK: [u32; 8] = [
    184226853, 1264227414, 1363912669, 679332880, 1895391812, 573275183, 834781992, 163717450,
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
    use sp1_sdk::{HashableKey, Prover, ProverClient};

    /// RISC-V binary compiled from `charms-spell-checker`.
    pub const SPELL_CHECKER_BINARY: &[u8] = include_bytes!("../../src/bin/charms-spell-checker");

    #[test]
    fn test_spell_vk() {
        let client = ProverClient::builder().cpu().build();

        let (_, vk) = client.setup(SPELL_CHECKER_BINARY);
        assert_eq!(SPELL_CHECKER_VK, vk.hash_u32());
    }
}
