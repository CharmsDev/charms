use std::{fs::File, io::BufReader};

use crate::BitcoinFinalityInput;

/// RISC-V binary compiled from `charms-spell-checker`.
pub const BTC_FINALITY_BINARY: &[u8] = include_bytes!("../../src/bin/btc-finality");

/// Verification key for the `btc-finality` binary.
pub const BTC_FINALITY_VK: &str =
    "00c94046701e60fb4812584e39f4a00a667313bca8fe91fe06ef0c9c0dd67dfe";
pub const U32_BTC_FINALITY_VK: [u32; 8] = [
    0x00c94046, 0x701e60fb, 0x4812584e, 0x39f4a00a, 0x667313bc, 0xa8fe91fe, 0x06ef0c9c, 0x0dd67dfe,
];

pub fn load_finality_input(path: &str) -> Result<BitcoinFinalityInput, Box<dyn std::error::Error>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let input: BitcoinFinalityInput = serde_json::from_reader(reader)?;
    Ok(input)
}
