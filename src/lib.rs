pub mod app;
pub mod cli;
pub mod script;
pub mod spell;
pub mod tx;
pub mod utils;

/// RISC-V binary compiled from `charms-spell-checker`.
pub const SPELL_CHECKER_BINARY: &[u8] = include_bytes!("./bin/charms-spell-checker");

/// Verification key for the `charms-spell-checker` binary.
pub const SPELL_VK: &str = "0x00bd312b6026dbe4a2c16da1e8118d4fea31587a4b572b63155252d2daf69280";

#[cfg(test)]
mod test {
    use super::*;
    use sp1_sdk::{HashableKey, Prover, ProverClient};

    #[test]
    fn test_spell_vk() {
        let client = ProverClient::builder().cpu().build();
        let (_, vk) = client.setup(SPELL_CHECKER_BINARY);
        let s = vk.bytes32();

        assert_eq!(SPELL_VK, s.as_str());
    }
}
