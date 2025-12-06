use crate::{NormalizedSpell, Proof, V7, tx, tx::EnchantedTx};
use anyhow::{anyhow, bail, ensure};
use bitcoin::{
    CompactTarget, MerkleBlock, Target, Transaction, TxIn, Txid,
    block::Header,
    consensus::encode::{deserialize_hex, serialize_hex},
    hashes::Hash,
    opcodes::all::{OP_ENDIF, OP_IF},
    script::{Instruction, PushBytes},
};
use charms_data::{NativeOutput, TxId, UtxoId, util};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

serde_with::serde_conv!(
    TransactionHex,
    Transaction,
    |tx: &Transaction| serialize_hex(tx),
    |s: String| deserialize_hex(&s)
);

serde_with::serde_conv!(
    MerkleBlockHex,
    MerkleBlock,
    |tx: &MerkleBlock| serialize_hex(tx),
    |s: String| deserialize_hex(&s)
);

serde_with::serde_conv!(
    HeaderHex,
    Header,
    |tx: &Header| serialize_hex(tx),
    |s: String| deserialize_hex(&s)
);

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BitcoinTx {
    Simple(#[serde_as(as = "TransactionHex")] Transaction),
    WithBlockProof {
        #[serde_as(as = "TransactionHex")]
        tx: Transaction,

        #[serde_as(as = "MerkleBlockHex")]
        proof: MerkleBlock,

        #[serde_as(as = "Vec<HeaderHex>")]
        headers: Vec<Header>,
    },
}

impl BitcoinTx {
    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        let tx = deserialize_hex(hex)?;
        Ok(Self::Simple(tx))
    }

    pub fn inner(&self) -> &bitcoin::Transaction {
        match self {
            BitcoinTx::Simple(tx) => tx,
            BitcoinTx::WithBlockProof { tx, .. } => tx,
        }
    }
}

impl EnchantedTx for BitcoinTx {
    fn extract_and_verify_spell(
        &self,
        spell_vk: &str,
        mock: bool,
    ) -> anyhow::Result<NormalizedSpell> {
        let tx = self.inner();

        let Some((spell_tx_in, _tx_ins)) = tx.input.split_last() else {
            bail!("transaction does not have inputs")
        };

        let (spell, proof) = parse_spell_and_proof(spell_tx_in)?;

        if !mock {
            ensure!(!spell.mock, "spell is a mock, but we are not in mock mode");
        }
        ensure!(
            spell.tx.ins.is_none(),
            "spell must inherit inputs from the enchanted tx"
        );
        ensure!(
            spell.tx.outs.len() <= tx.output.len(),
            "spell tx outs mismatch"
        );
        let spell = spell_with_committed_ins_and_coins(self, spell);

        let spell_vk = tx::spell_vk(spell.version, spell_vk, spell.mock)?;

        let public_values = tx::to_serialized_pv(spell.version, &(spell_vk, &spell));

        tx::verify_snark_proof(&proof, &public_values, spell_vk, spell.version, spell.mock)?;

        Ok(spell)
    }

    fn tx_outs_len(&self) -> usize {
        self.inner().output.len()
    }

    fn tx_id(&self) -> TxId {
        TxId(self.inner().compute_txid().to_byte_array())
    }

    fn hex(&self) -> String {
        serialize_hex(self.inner())
    }

    fn spell_ins(&self) -> Vec<UtxoId> {
        let tx = self.inner();
        tx.input[..tx.input.len() - 1] // exclude spell commitment input
            .iter()
            .map(|tx_in| {
                let out_point = tx_in.previous_output;
                UtxoId(TxId(out_point.txid.to_byte_array()), out_point.vout)
            })
            .collect()
    }

    fn all_coin_outs(&self) -> Vec<NativeOutput> {
        self.inner()
            .output
            .iter()
            .map(|tx_out| NativeOutput {
                amount: tx_out.value.to_sat(),
                dest: tx_out.script_pubkey.to_bytes(),
            })
            .collect()
    }

    fn has_finality_proof(&self) -> bool {
        match self {
            BitcoinTx::Simple(_) => false,
            BitcoinTx::WithBlockProof { tx, proof, headers } => {
                verify_finality_proof(tx, proof, headers).is_ok()
            }
        }
    }
}

const FINALITY_TARGET_BITS: u32 = 0x16507000; // mainnet finality target bits (6 blocks)

fn verify_finality_proof(
    tx: &Transaction,
    tx_block_proof: &MerkleBlock,
    headers: &[Header],
) -> anyhow::Result<()> {
    block_has_tx(&tx_block_proof, tx.compute_txid())?;

    let tx_block_header = &tx_block_proof.header;
    let _ = tx_block_header.validate_pow(tx_block_header.target())?;

    let finality_target = Target::from_compact(CompactTarget::from_consensus(FINALITY_TARGET_BITS));
    let total_required_work = finality_target.to_work();

    let (_, cumulative_work) = headers.iter().try_fold(
        (tx_block_header, tx_block_header.work()),
        |(prev_header, prev_work), header| {
            ensure!(header.prev_blockhash == prev_header.block_hash());
            Ok((header, prev_work + header.work()))
        },
    )?;

    ensure!(cumulative_work >= total_required_work, "insufficient work");

    Ok(())
}

fn block_has_tx(tx_block_proof: &MerkleBlock, txid: Txid) -> anyhow::Result<()> {
    let mut txs = vec![];
    {
        let mut _indexes = vec![];
        tx_block_proof.extract_matches(&mut txs, &mut _indexes)?;
    }
    ensure!(txs.first() == Some(&txid));
    Ok(())
}

#[tracing::instrument(level = "debug", skip_all)]
pub(crate) fn spell_with_committed_ins_and_coins(
    tx: &BitcoinTx,
    mut spell: NormalizedSpell,
) -> NormalizedSpell {
    let tx_ins = tx.spell_ins();

    spell.tx.ins = Some(tx_ins);
    if spell.version > V7 {
        let mut coins = tx.all_coin_outs();
        coins.truncate(spell.tx.outs.len());
        spell.tx.coins = Some(coins);
    }

    spell
}

#[tracing::instrument(level = "debug", skip_all)]
pub fn parse_spell_and_proof(spell_tx_in: &TxIn) -> anyhow::Result<(NormalizedSpell, Proof)> {
    ensure!(
        spell_tx_in
            .witness
            .taproot_control_block()
            .ok_or(anyhow!("no control block"))?
            .len()
            == 33,
        "the Taproot tree contains more than one leaf: only a single script is supported"
    );

    let leaf_script = spell_tx_in
        .witness
        .taproot_leaf_script()
        .ok_or(anyhow!("no spell data in the last input's witness"))?;

    let mut instructions = leaf_script.script.instructions();

    ensure!(instructions.next() == Some(Ok(Instruction::PushBytes(PushBytes::empty()))));
    ensure!(instructions.next() == Some(Ok(Instruction::Op(OP_IF))));
    let Some(Ok(Instruction::PushBytes(push_bytes))) = instructions.next() else {
        bail!("no spell data")
    };
    if push_bytes.as_bytes() != b"spell" {
        bail!("no spell marker")
    }

    let mut spell_data = vec![];

    loop {
        match instructions.next() {
            Some(Ok(Instruction::PushBytes(push_bytes))) => {
                spell_data.extend(push_bytes.as_bytes());
            }
            Some(Ok(Instruction::Op(OP_ENDIF))) => {
                break;
            }
            _ => {
                bail!("unexpected opcode")
            }
        }
    }

    let (spell, proof): (NormalizedSpell, Proof) = util::read(spell_data.as_slice())
        .map_err(|e| anyhow!("could not parse spell and proof: {}", e))?;
    Ok((spell, proof))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn compute_finality_target(target_bits: u32) -> CompactTarget {
        let compact = CompactTarget::from_consensus(target_bits);
        let work = Target::from_compact(compact).to_work();
        let required = work + work + work + work + work + work;
        required.to_target().to_compact_lossy()
    }

    const TARGET_BITS: u32 = 0x1701e2a0;

    #[test]
    fn test_target_bits() {
        let finality_target_bits = compute_finality_target(TARGET_BITS);
        dbg!(format!("0x{:x}", finality_target_bits));
        assert_eq!(
            FINALITY_TARGET_BITS,
            finality_target_bits.to_consensus() + 1,
        );
    }

    #[test]
    fn cumulative_work_test() {
        let finality_target =
            Target::from_compact(CompactTarget::from_consensus(FINALITY_TARGET_BITS));

        let work = Target::from_compact(CompactTarget::from_consensus(TARGET_BITS)).to_work();
        let cumulative_work = work + work + work + work + work + work;

        let required_work = finality_target.to_work();
        assert!(dbg!(cumulative_work) >= dbg!(required_work));
    }
}
