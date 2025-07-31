use blite_lib::{ConsensusProofData, TxInclusionProofData};

pub const BTC_FINALITY_VK: [u32; 8] = [
    1829666674, 1913898501, 857404790, 1897356812, 1850924786, 1322828146, 1286890552, 1814706686,
];

pub fn prove_consensus(
    previous_proof: Option<String>,
    block_height: u32,
) -> anyhow::Result<(), anyhow::Error> {
    let data = ConsensusProofData {
        previous_proof,
        block_height,
    };

    blite_script::prove_consensus(data)?;

    Ok(())
}

pub fn prove_tx_inclusion(
    includes_tx: String,
    previous_proof: String,
    block_height: u32,
) -> anyhow::Result<(), anyhow::Error> {
    let data = TxInclusionProofData {
        includes_tx,
        previous_proof,
        block_height,
    };

    blite_script::prove_tx_inclusion(data)?;

    Ok(())
}
