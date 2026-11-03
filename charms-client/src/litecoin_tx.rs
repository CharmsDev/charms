use bitcoin::block::Header;
use bitcoin::consensus::encode::{deserialize_hex, serialize, serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, CompactTarget, MerkleBlock, Target, Txid};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::bitcoin_tx::{self, LitecoinTx};
use crate::tx::EnchantedTx;

pub const LITECOIN_NBITS_3206445: u32 = 0x192b8d45;

serde_with::serde_conv!(
    MerkleBlockHex,
    MerkleBlock,
    |block: &MerkleBlock| serialize_hex(block),
    |s: String| deserialize_hex(&s)
);

serde_with::serde_conv!(
    HeaderHex,
    Header,
    |header: &Header| serialize_hex(header),
    |s: String| deserialize_hex(&s)
);

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LitecoinCarried {
    Simple(LitecoinTx),
    WithBlockProof(LitecoinFinality),
}

#[serde_as]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LitecoinFinality {
    tx: LitecoinTx,
    #[serde_as(as = "MerkleBlockHex")]
    proof: MerkleBlock,
    #[serde_as(as = "Vec<HeaderHex>")]
    headers: Vec<Header>,
}

impl From<LitecoinTx> for LitecoinCarried {
    fn from(tx: LitecoinTx) -> Self {
        Self::Simple(tx)
    }
}

impl LitecoinCarried {
    pub fn inner(&self) -> &bitcoin::Transaction {
        self.litecoin_tx().inner()
    }

    fn litecoin_tx(&self) -> &LitecoinTx {
        match self {
            Self::Simple(tx) => tx,
            Self::WithBlockProof(finality) => &finality.tx,
        }
    }
}

impl EnchantedTx for LitecoinCarried {
    fn extract_and_verify_spell(
        &self,
        spell_vk: &[u8; 32],
        mock: bool,
    ) -> anyhow::Result<crate::NormalizedSpell> {
        self.litecoin_tx().extract_and_verify_spell(spell_vk, mock)
    }

    fn virtual_spell(
        &self,
        spell_vk: &[u8; 32],
        next_spell: &crate::NormalizedSpell,
    ) -> anyhow::Result<crate::NormalizedSpell> {
        self.litecoin_tx().virtual_spell(spell_vk, next_spell)
    }

    fn tx_outs_len(&self) -> usize {
        self.litecoin_tx().tx_outs_len()
    }

    fn tx_id(&self) -> charms_data::TxId {
        self.litecoin_tx().tx_id()
    }

    fn hex(&self) -> String {
        self.litecoin_tx().hex()
    }

    fn spell_ins(&self) -> Vec<charms_data::UtxoId> {
        self.litecoin_tx().spell_ins()
    }

    fn all_coin_outs(
        &self,
        spell: &crate::NormalizedSpell,
    ) -> anyhow::Result<Vec<charms_data::NativeOutput>> {
        self.litecoin_tx().all_coin_outs(spell)
    }

    fn proven_final(&self) -> bool {
        match self {
            Self::Simple(_) => false,
            Self::WithBlockProof(finality) => {
                scrypt_chain_is_final(&finality.tx, &finality.proof, &finality.headers)
            }
        }
    }
}

struct ScryptPow([u8; 32]);

impl ScryptPow {
    // Header::validate_pow hashes SHA256d. Litecoin proof of work is scrypt of the same 80 bytes.
    fn of_header(header: &Header) -> Self {
        let raw = serialize(header);
        assert_eq!(raw.len(), 80);
        let params = scrypt::Params::new(10, 1, 1).expect("litecoin scrypt parameters");
        let mut out = [0u8; 32];
        scrypt::scrypt(&raw, &raw, &params, &mut out).expect("32-byte scrypt output");
        Self(out)
    }

    fn meets(&self, target: Target) -> bool {
        target.is_met_by(BlockHash::from_byte_array(self.0))
    }
}

fn scrypt_chain_is_final(tx: &LitecoinTx, proof: &MerkleBlock, headers: &[Header]) -> bool {
    let txid: Txid = tx.inner().compute_txid();
    if bitcoin_tx::block_has_tx(proof, txid).is_err() {
        return false;
    }
    let inclusion = &proof.header;
    if !ScryptPow::of_header(inclusion).meets(inclusion.target()) {
        return false;
    }
    let mut prev = inclusion;
    let mut work = inclusion.work();
    for header in headers {
        if header.prev_blockhash != prev.block_hash() {
            return false;
        }
        if !ScryptPow::of_header(header).meets(header.target()) {
            return false;
        }
        work = work + header.work();
        prev = header;
    }
    work >= litecoin_finality_work()
}

fn litecoin_finality_target_bits() -> u32 {
    let one =
        Target::from_compact(CompactTarget::from_consensus(LITECOIN_NBITS_3206445)).to_work();
    let six = one + one + one + one + one + one;
    six.to_target()
        .to_compact_lossy()
        .to_consensus()
        .wrapping_add(1)
}

fn litecoin_finality_work() -> bitcoin::Work {
    Target::from_compact(CompactTarget::from_consensus(
        litecoin_finality_target_bits(),
    ))
    .to_work()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UtxoId;
    use crate::bitcoin_tx::BitcoinTx;
    use crate::tx::{EnchantedTx, Tx};
    use bitcoin::absolute::LockTime;
    use bitcoin::block::Version;
    use bitcoin::consensus::encode::deserialize_hex;
    use bitcoin::{
        Amount, Block, OutPoint, ScriptBuf, Sequence, TxIn, TxMerkleNode, TxOut, Txid, Witness,
    };
    use charms_data::TxId;
    use std::collections::BTreeMap;

    const BLOCK_29255_HEADER: &str = "01000000f615f7ce3b4fc6b8f61e8f89aedb1d0852507650533a9e3b10b9bbcc30639f279fcaa86746e1ef52d3edb3c4ad8259920d509bd073605c9bf1d59983752a6b06b817bb4ea78e011d012d59d4";

    const MAINNET_COINBASE: &str = "010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff55032ded30040f45e96a0afabe6d6d6349b435103ce020ba8722e963bac11ed10754c6936b47840b18b643368568b700010000000000004000000064eaa80700001900122f4d696e696e672d44757463682f2d505053000000000278294d25000000001976a91466b4153493a3034dd256ef416ac7ed2c1b1b310d88ac0000000000000000266a24aa21a9ed864e2eaa421bd2cbd7338194d62c543e8f20803fcac6d6e757aeeb43b71bf1fe0120000000000000000000000000000000000000000000000000000000000000000000000000";

    const MAINNET_PROOF: &str = "0000002039fe22eef67c0e29bde27d8dbf0afba0bcd9900b4a1ddb441ba1d6b020ffaa5162eddf3ff97974dc1882f455b3cd9077656e856f08be1b1456c6e5eb364c29610e45e96a458d2b1941805c8b3a0100000a6713d306f9d3132cb89c0fcbcbaca39b91627bdeed961545f44867c42d4c9625c72886a930e194ae7bcdf132bcca0d8af068135dd6c9bf7883a50a80101f1df0ee8fdf5a7ed581b425ff8ec945bbb6e8945dfc3f09ff2064010bbe9a8c3756790deae9bfc0e5d0373016e2c694a66a5e191f8cbe4c89d8a88f8ea3e994493b2b358ff133f0ea832f8b0623cc1f07cbc2617fa795a52e6348a1416de8d55bf7ceefc565cd2ac904f928991cd4805d8d080bb3d96caac5f52898c97f2bb2757a947d00d459b71356e32aadb6e2f14bb175cf5bfd0e8a1a0809d87fe652d0954fa2ecd493ad85ec2599d654229e7079b666552d2ce89400ac47177ec9d7bc5e271a51362416d446aee5561e1120bfb28dd2481467ed56f8c960afa2a8c1aefe1db3d453cb1a480cb369ce4017b6eb6dc675a6aa949c783e152e1b3ecf7584a6d22e03ff0300";

    const MAINNET_HEADERS: [&str; 5] = [
        "00000020f450b58e22dc899c9030a66ca44b627dd203e0d23b193d673a80a85ed036dad77efe307501967aeb5aea286aeeb00b8d8d89f1b8a36458a08eaf6a0cf2bac9283045e96a458d2b19036ea7aa",
        "000000204162d1fe537c2bd821535761fd3ae3dc85246a2723ec784f05cd3d186ec002903e298a235061e835b125516464e78d6a593c0b4c3546290b9ee9767eb314ce50d945e96a458d2b19cba101c0",
        "000000208f5c8e92094b41276552e2132c073064a2a3ed3c6ecd2b18334d9b437270f209f6333a4807c217959e3c4208d3ddbcf33f1da127e6c098b877999171fda21a677b46e96a458d2b1942f776aa",
        "00000020c3684ad146d848b920a72907ac5340c08437699fbbb7fed304c779b15cf10bb6c28a72f106eb9179ed80550f54bcefcf7016f00641b0dee2c9a87be90c4c6fe70f47e96a458d2b1952708398",
        "0000002069dbadebb2dbae1adc07655e866fe56175f518009287fb1609b47bfee42d8c06a50e1b04b42f164bc756babad5e67017e7cde72f9c06a5c582105fa6f374582c5247e96a458d2b192802ad2c",
    ];

    const MAINNET_HEADER_IDS: [&str; 5] = [
        "9002c06e183dcd054f78ec23276a2485dce33afd61575321d82b7c53fed16241",
        "09f27072439b4d33182bcd6e3ceda3a26430072c13e2526527414b09928e5c8f",
        "b60bf15cb179c704d3feb7bb9f693784c04053ac0729a720b948d846d14a68c3",
        "068c2de4fe7bb40916fb87920018f57561e56f865e6507dc1aaedbb2ebaddb69",
        "2c86d8954013b9f6efed66fb3c39b6d8406c28efc83be5875218276f696fbb2b",
    ];

    fn mainnet_carried() -> LitecoinCarried {
        let headers = MAINNET_HEADERS
            .iter()
            .map(|hex| deserialize_hex(*hex).unwrap())
            .collect::<Vec<Header>>();
        LitecoinCarried::WithBlockProof(LitecoinFinality {
            tx: LitecoinTx::from_hex(MAINNET_COINBASE).unwrap(),
            proof: deserialize_hex(MAINNET_PROOF).unwrap(),
            headers,
        })
    }

    #[test]
    fn block_29255_splits_sha256d_from_scrypt() {
        let header: Header = deserialize_hex(BLOCK_29255_HEADER).unwrap();
        let pow = ScryptPow::of_header(&header);
        assert_eq!(
            header.block_hash().to_string(),
            "adf6e2e56df692822f5e064a8b6404a05d67cccd64bc90f57f65b46805e9a54b"
        );
        assert_eq!(
            BlockHash::from_byte_array(pow.0).to_string(),
            "0000000110c8357966576df46f3b802ca897deb7ad18b12f1c24ecff6386ebd9"
        );
        assert!(pow.meets(header.target()));
        assert!(header.validate_pow(header.target()).is_err());
    }

    #[test]
    fn six_reference_blocks_meet_the_bar() {
        let one =
            Target::from_compact(CompactTarget::from_consensus(LITECOIN_NBITS_3206445)).to_work();
        let six = one + one + one + one + one + one;
        assert!(six >= litecoin_finality_work());
        let five = one + one + one + one + one;
        assert!(five < litecoin_finality_work());
    }

    #[test]
    fn litecoin_headers_are_not_bitcoin_final() {
        let carried = mainnet_carried();
        let LitecoinCarried::WithBlockProof(finality) = &carried else {
            unreachable!()
        };
        assert_eq!(
            finality.tx.inner().compute_txid().to_string(),
            "25964c2dc46748f4451596edde7b62919ba3accbcb0f9cb82c13d3f906d31367"
        );
        assert_eq!(
            finality.proof.header.block_hash().to_string(),
            "d7da36d05ea8803a673d193bd2e003d27d624ba46ca630909c89dc228eb550f4"
        );
        assert_eq!(
            finality.proof.header.bits.to_consensus(),
            LITECOIN_NBITS_3206445
        );
        assert!(ScryptPow::of_header(&finality.proof.header).meets(finality.proof.header.target()));
        assert!(
            finality
                .proof
                .header
                .validate_pow(finality.proof.header.target())
                .is_err()
        );
        for (header, id) in finality.headers.iter().zip(MAINNET_HEADER_IDS) {
            assert_eq!(header.block_hash().to_string(), id);
            assert_eq!(header.bits.to_consensus(), LITECOIN_NBITS_3206445);
            assert!(ScryptPow::of_header(header).meets(header.target()));
            assert!(header.validate_pow(header.target()).is_err());
        }
        assert!(carried.proven_final());

        let as_bitcoin = BitcoinTx::WithBlockProof {
            tx: finality.tx.inner().clone(),
            proof: finality.proof.clone(),
            headers: finality.headers.clone(),
        };
        assert!(!as_bitcoin.proven_final());

        let mut short = finality.headers.clone();
        short.pop();
        let five = LitecoinCarried::WithBlockProof(LitecoinFinality {
            tx: finality.tx.clone(),
            proof: finality.proof.clone(),
            headers: short,
        });
        assert!(!five.proven_final());

        let raw = Tx::try_from(MAINNET_COINBASE).unwrap();
        assert!(matches!(raw, Tx::Bitcoin(_)));
        assert!(!raw.proven_final());

        let yaml = serde_yaml::to_string(&Tx::Litecoin(carried)).unwrap();
        let parsed: Tx = serde_yaml::from_str(&yaml).unwrap();
        assert!(matches!(parsed, Tx::Litecoin(_)));
        assert!(parsed.proven_final());
    }

    fn host_transaction(marker: u8) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([marker; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn beam_of(source: &Tx) -> BTreeMap<usize, crate::BeamSource> {
        let mut beamed = BTreeMap::new();
        beamed.insert(
            0,
            crate::BeamSource(UtxoId(TxId(source.tx_id().0), 0), None),
        );
        beamed
    }

    fn beam_gate(host: Tx, source: &Tx) -> bool {
        assert_ne!(host.tx_id(), source.tx_id());
        crate::beaming_txs_have_finality_proofs(&vec![host, source.clone()], &beam_of(source))
    }

    #[test]
    fn bitcoin_host_beam_gate_accepts_scrypt_final_litecoin_source() {
        let source = Tx::Litecoin(mainnet_carried());
        assert!(source.proven_final());
        let host = Tx::Bitcoin(BitcoinTx::Simple(host_transaction(1)));
        assert!(matches!(host, Tx::Bitcoin(BitcoinTx::Simple(_))));
        assert!(beam_gate(host.clone(), &source));

        let Tx::Litecoin(LitecoinCarried::WithBlockProof(finality)) = &source else {
            panic!("litecoin source must carry headers");
        };
        let as_bitcoin = Tx::Bitcoin(BitcoinTx::WithBlockProof {
            tx: finality.tx.inner().clone(),
            proof: finality.proof.clone(),
            headers: finality.headers.clone(),
        });
        assert_eq!(as_bitcoin.tx_id(), source.tx_id());
        assert!(!as_bitcoin.proven_final());
        assert!(!beam_gate(host, &as_bitcoin));
    }

    #[test]
    fn litecoin_host_beam_gate_accepts_bitcoin_final_source() {
        let yaml = include_str!("../testdata/bitcoin-final-prev.yaml");
        let source: Tx = serde_yaml::from_str(yaml).unwrap();
        let Tx::Bitcoin(BitcoinTx::WithBlockProof { .. }) = &source else {
            panic!("bitcoin source must carry headers");
        };
        assert!(source.proven_final());
        let host = Tx::from(LitecoinTx::new(host_transaction(2)));
        assert!(matches!(host, Tx::Litecoin(LitecoinCarried::Simple(_))));
        assert!(beam_gate(host.clone(), &source));

        let retag = yaml.replacen("!bitcoin", "!litecoin", 1);
        let as_litecoin: Tx = serde_yaml::from_str(&retag).unwrap();
        assert!(matches!(
            as_litecoin,
            Tx::Litecoin(LitecoinCarried::WithBlockProof(_))
        ));
        assert_eq!(as_litecoin.tx_id(), source.tx_id());
        assert!(!as_litecoin.proven_final());
        assert!(!beam_gate(host, &as_litecoin));
    }

    #[test]
    fn claimed_litecoin_work_without_scrypt_is_not_final() {
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time: u32::MAX,
                bits,
                nonce: 0,
            },
            txdata: vec![tx.clone()],
        };
        block.header.merkle_root = block.compute_merkle_root().expect("merkle root");
        let target = block.header.target();
        while !ScryptPow::of_header(&block.header).meets(target) {
            block.header.nonce = block.header.nonce.wrapping_add(1);
        }
        let proof = MerkleBlock::from_block_with_predicate(&block, |_| true);
        let claimed = CompactTarget::from_consensus(0x1701e2a0);
        assert!(Target::from_compact(claimed).to_work() >= litecoin_finality_work());
        let fake = Header {
            version: Version::ONE,
            prev_blockhash: block.header.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: u32::MAX,
            bits: claimed,
            nonce: 0,
        };
        assert!(!ScryptPow::of_header(&fake).meets(fake.target()));
        let carried = LitecoinCarried::WithBlockProof(LitecoinFinality {
            tx: LitecoinTx::new(tx),
            proof,
            headers: vec![fake],
        });
        assert!(!carried.proven_final());
    }
}
