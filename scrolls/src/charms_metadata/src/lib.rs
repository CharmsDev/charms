mod ecdsa;
mod metadata;

use std::cell::RefCell;

use candid::{CandidType, Deserialize};
use charms_data::{App, B32};
use charms_lib::bitcoin_tx::BitcoinTx;
use charms_lib::tx::{EnchantedTx, Tx};
use getrandom::register_custom_getrandom;

use ecdsa::{ethereum_address, signature_65};
use metadata::{created_reference, metadata_digest, metadata_from, metadata_hash, reference_nft};

#[cfg(not(test))]
use ic_cdk_management_canister::{
    EcdsaCurve, EcdsaKeyId, EcdsaPublicKeyArgs, SignWithEcdsaArgs, cost_sign_with_ecdsa,
    ecdsa_public_key, sign_with_ecdsa,
};

use charms_lib::extract_and_verify_spell;

#[derive(CandidType, Deserialize, Clone, Debug)]
struct AppId {
    tag: String,
    identity: Vec<u8>,
    vk: Vec<u8>,
}

#[derive(CandidType, Clone, Debug)]
struct Charm {
    app: AppId,
    data: Vec<u8>,
}

#[derive(CandidType, Clone, Debug)]
struct SignedCharm {
    charm: Charm,
    version: u64,
    signature: Vec<u8>,
}

#[derive(CandidType, Clone, Debug)]
struct Signer {
    public_key: Vec<u8>,
    address: Vec<u8>,
}

thread_local! {
    static PUBLIC_KEY: RefCell<Option<Vec<u8>>> = const { RefCell::new(None) };
}

#[ic_cdk::update]
async fn sign_metadata(app: AppId, tx: Vec<u8>) -> Result<SignedCharm, String> {
    let token = parse_app(&app)?;
    let nft = reference_nft(&token)?;
    let tx = decode_tx(&tx)?;
    if !tx_is_final(&tx) {
        return Err("Input error: transaction is not final".into());
    }
    let version = bitcoin_block_time(&tx)?;
    let spell = open_spell(&tx)?;
    let data = created_reference(&spell, &nft)?;
    let hash = metadata_hash(&metadata_from(data)?);
    let digest = metadata_digest(&token, version, &hash);
    let signature = sign_digest(&digest).await?;
    Ok(SignedCharm {
        charm: Charm {
            app: app_id(&nft),
            data: data.bytes(),
        },
        version,
        signature: signature.to_vec(),
    })
}

fn bitcoin_block_time(tx: &Tx) -> Result<u64, String> {
    let Tx::Bitcoin(BitcoinTx::WithBlockProof { proof, .. }) = tx else {
        return Err("Input error: metadata version is the bitcoin block time".into());
    };
    let time = proof.header.time;
    if time == 0 {
        return Err("Input error: bitcoin block time".into());
    }
    Ok(u64::from(time))
}

#[ic_cdk::update]
async fn public_key() -> Result<Signer, String> {
    let public_key = cached_public_key().await?;
    let address = ethereum_address(&public_key)?;
    Ok(Signer {
        public_key,
        address: address.to_vec(),
    })
}

fn parse_app(app: &AppId) -> Result<App, String> {
    let mut chars = app.tag.chars();
    let Some(tag) = chars.next() else {
        return Err("Input error: app tag".into());
    };
    if chars.next().is_some() {
        return Err("Input error: app tag".into());
    }
    Ok(App {
        tag,
        identity: b32(&app.identity)?,
        vk: b32(&app.vk)?,
    })
}

fn b32(bytes: &[u8]) -> Result<B32, String> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "Input error: expected 32 bytes".to_string())?;
    Ok(B32(bytes))
}

fn app_id(app: &App) -> AppId {
    AppId {
        tag: app.tag.to_string(),
        identity: app.identity.0.to_vec(),
        vk: app.vk.0.to_vec(),
    }
}

fn decode_tx(bytes: &[u8]) -> Result<Tx, String> {
    charms_data::util::read(bytes).map_err(|e| format!("Input error: transaction: {e}"))
}

#[cfg(not(test))]
fn tx_is_final(tx: &Tx) -> bool {
    tx.proven_final()
}

#[cfg(test)]
fn tx_is_final(tx: &Tx) -> bool {
    tx.proven_final() || tests::regtest_final(tx)
}

fn open_spell(tx: &Tx) -> Result<charms_lib::NormalizedSpell, String> {
    #[cfg(test)]
    if tests::skip_spell_proof() {
        return tests::spell_from_tx(tx);
    }
    extract_and_verify_spell(tx, false).map_err(|e| format!("Input error: {e}"))
}

async fn sign_digest(digest: &[u8; 32]) -> Result<[u8; 65], String> {
    let public_key = cached_public_key().await?;
    let rs = load_signature_rs(digest).await?;
    signature_65(&public_key, digest, &rs)
}

async fn cached_public_key() -> Result<Vec<u8>, String> {
    if let Some(public_key) = PUBLIC_KEY.with(|cell| cell.borrow().clone()) {
        return Ok(public_key);
    }
    let public_key = load_public_key().await?;
    PUBLIC_KEY.with(|cell| *cell.borrow_mut() = Some(public_key.clone()));
    Ok(public_key)
}

#[cfg(not(test))]
fn derivation_path() -> Vec<Vec<u8>> {
    vec![b"scrolls".to_vec(), b"metadata".to_vec()]
}

#[cfg(not(test))]
fn key_id() -> EcdsaKeyId {
    EcdsaKeyId {
        curve: EcdsaCurve::Secp256k1,
        name: "key_1".to_string(),
    }
}

#[cfg(not(test))]
fn accept_signature_cycles(args: &SignWithEcdsaArgs) -> Result<(), String> {
    let cycles =
        cost_sign_with_ecdsa(args).map_err(|e| format!("System error: signing cost: {e}"))?;
    let available = ic_cdk::api::msg_cycles_available();
    if available < cycles {
        return Err(format!(
            "Input error: insufficient cycles attached: provided {available}, minimum {cycles}"
        ));
    }
    let accepted = ic_cdk::api::msg_cycles_accept(cycles);
    if accepted < cycles {
        return Err("Input error: could not accept cycles for signing".into());
    }
    Ok(())
}

#[cfg(not(test))]
async fn load_public_key() -> Result<Vec<u8>, String> {
    let result = ecdsa_public_key(&EcdsaPublicKeyArgs {
        canister_id: None,
        derivation_path: derivation_path(),
        key_id: key_id(),
    })
    .await
    .map_err(|e| format!("System error: public key: {e}"))?;
    Ok(result.public_key)
}

#[cfg(not(test))]
async fn load_signature_rs(digest: &[u8; 32]) -> Result<Vec<u8>, String> {
    let args = SignWithEcdsaArgs {
        message_hash: digest.to_vec(),
        derivation_path: derivation_path(),
        key_id: key_id(),
    };
    accept_signature_cycles(&args)?;
    let result = sign_with_ecdsa(&args)
        .await
        .map_err(|e| format!("System error: signing: {e}"))?;
    Ok(result.signature)
}

#[cfg(test)]
async fn load_public_key() -> Result<Vec<u8>, String> {
    Ok(tests::local_public_key())
}

#[cfg(test)]
async fn load_signature_rs(digest: &[u8; 32]) -> Result<Vec<u8>, String> {
    Ok(tests::local_signature_rs(digest))
}

register_custom_getrandom!(custom_getrandom);

fn custom_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

ic_cdk::export_candid!();

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash;
    use bitcoin::script::{Builder, PushBytesBuf};
    use bitcoin::{
        Amount, Block, BlockHash, CompactTarget, MerkleBlock, OutPoint, ScriptBuf, Sequence,
        Transaction, TxIn, TxMerkleNode, TxOut, Txid, Witness,
    };
    use charms_data::{Data, NFT, TOKEN};
    use charms_lib::bitcoin_tx::{
        BitcoinTx, FINALITY_TARGET_BITS, parse_spell_and_proof_from_op_return,
    };
    use charms_lib::{NormalizedCharms, NormalizedSpell};
    use k256::ecdsa::SigningKey;
    use serde::Serialize;
    use std::cell::Cell;
    use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    thread_local! {
        static SKIP_SPELL_PROOF: Cell<bool> = const { Cell::new(false) };
        static SIGN_CALLS: Cell<u32> = const { Cell::new(0) };
    }

    pub(super) fn skip_spell_proof() -> bool {
        SKIP_SPELL_PROOF.with(|cell| cell.get())
    }

    fn use_spell_parser() {
        SKIP_SPELL_PROOF.with(|cell| cell.set(true));
    }

    fn sign_calls() -> u32 {
        SIGN_CALLS.with(|cell| cell.get())
    }

    const SECRET: [u8; 32] = [0x11; 32];

    #[derive(Serialize)]
    struct Meta {
        name: &'static str,
        description: &'static str,
        ticker: &'static str,
        url: &'static str,
        image: &'static str,
        image_hash: String,
        decimals: u8,
    }

    fn example() -> Meta {
        Meta {
            name: "Example",
            description: "One fungible charm.",
            ticker: "EX",
            url: "https://example.com",
            image: "ipfs://bafyexample",
            image_hash: "11".repeat(32),
            decimals: 8,
        }
    }

    fn identity() -> B32 {
        B32([0x22; 32])
    }

    fn vk() -> B32 {
        B32([0x33; 32])
    }

    fn token_app() -> AppId {
        AppId {
            tag: TOKEN.to_string(),
            identity: identity().0.to_vec(),
            vk: vk().0.to_vec(),
        }
    }

    fn spell_with(meta: Option<&Meta>) -> NormalizedSpell {
        let nft = App {
            tag: NFT,
            identity: identity(),
            vk: vk(),
        };
        let mut spell = NormalizedSpell::default();
        spell.app_public_inputs.insert(nft, Data::empty());
        if let Some(meta) = meta {
            let mut out = NormalizedCharms::new();
            out.insert(0, Data::from(meta));
            spell.tx.outs = vec![out];
        }
        spell
    }

    fn bitcoin_tx(spell: &NormalizedSpell) -> Transaction {
        bitcoin_tx_with_proof(spell, &[])
    }

    fn bitcoin_tx_with_proof(spell: &NormalizedSpell, proof: &[u8]) -> Transaction {
        let payload = charms_data::util::write(&(spell, proof)).unwrap();
        let push = PushBytesBuf::try_from(payload).unwrap();
        let script = Builder::new()
            .push_opcode(bitcoin::opcodes::all::OP_RETURN)
            .push_slice(b"spell")
            .push_slice(push.as_push_bytes())
            .into_script();
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([1; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: ScriptBuf::new(),
                },
                TxOut {
                    value: Amount::ZERO,
                    script_pubkey: script,
                },
            ],
        }
    }

    fn mine(tx: &Transaction) -> (Transaction, MerkleBlock) {
        mine_at(tx, 1_700_000_000)
    }

    fn mine_at(tx: &Transaction, time: u32) -> (Transaction, MerkleBlock) {
        let bits = CompactTarget::from_consensus(0x207f_ffff);
        let mut block = Block {
            header: Header {
                version: Version::ONE,
                prev_blockhash: BlockHash::all_zeros(),
                merkle_root: TxMerkleNode::all_zeros(),
                time,
                bits,
                nonce: 0,
            },
            txdata: vec![tx.clone()],
        };
        block.header.merkle_root = block.compute_merkle_root().unwrap();
        let target = block.header.target();
        while block.header.validate_pow(target).is_err() {
            block.header.nonce = block.header.nonce.wrapping_add(1);
            if block.header.nonce == 0 {
                block.header.time = block.header.time.wrapping_add(1);
            }
        }
        let proof = MerkleBlock::from_block_with_predicate(&block, |_| true);
        (tx.clone(), proof)
    }

    fn encode(tx: &Tx) -> Vec<u8> {
        charms_data::util::write(tx).unwrap()
    }

    fn final_tx(spell: &NormalizedSpell) -> Vec<u8> {
        final_tx_with_proof(spell, &[])
    }

    fn final_tx_at(spell: &NormalizedSpell, time: u32) -> Vec<u8> {
        let raw = bitcoin_tx(spell);
        let (tx, proof) = mine_at(&raw, time);
        encode(&Tx::Bitcoin(BitcoinTx::WithBlockProof {
            tx,
            proof,
            headers: vec![],
        }))
    }

    fn final_tx_with_proof(spell: &NormalizedSpell, spell_proof: &[u8]) -> Vec<u8> {
        let raw = bitcoin_tx_with_proof(spell, spell_proof);
        let (tx, proof) = mine(&raw);
        encode(&Tx::Bitcoin(BitcoinTx::WithBlockProof {
            tx,
            proof,
            headers: vec![],
        }))
    }

    fn bare_tx(spell: &NormalizedSpell) -> Vec<u8> {
        encode(&Tx::Bitcoin(BitcoinTx::Simple(bitcoin_tx(spell))))
    }

    pub(super) fn spell_from_tx(tx: &Tx) -> Result<NormalizedSpell, String> {
        let Tx::Bitcoin(bitcoin) = tx else {
            return Err("Input error: spell".into());
        };
        let (spell, _) = parse_spell_and_proof_from_op_return(bitcoin.inner())
            .map_err(|e| format!("Input error: {e}"))?;
        Ok(spell)
    }

    pub(super) fn regtest_final(tx: &Tx) -> bool {
        let Tx::Bitcoin(BitcoinTx::WithBlockProof { tx, proof, headers }) = tx else {
            return false;
        };
        let mut matches = Vec::new();
        let mut indexes = Vec::new();
        if proof.extract_matches(&mut matches, &mut indexes).is_err()
            || matches.first() != Some(&tx.compute_txid())
        {
            return false;
        }
        let header = proof.header;
        if header.validate_pow(header.target()).is_err() {
            return false;
        }
        let mut prev = header.block_hash();
        for next in headers {
            if next.prev_blockhash != prev || next.validate_pow(next.target()).is_err() {
                return false;
            }
            prev = next.block_hash();
        }
        true
    }

    pub(super) fn local_public_key() -> Vec<u8> {
        let key = SigningKey::from_slice(&SECRET).unwrap();
        key.verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    pub(super) fn local_signature_rs(digest: &[u8; 32]) -> Vec<u8> {
        SIGN_CALLS.with(|cell| cell.set(cell.get() + 1));
        let key = SigningKey::from_slice(&SECRET).unwrap();
        let (signature, _) = key.sign_prehash_recoverable(digest).unwrap();
        signature.to_bytes().to_vec()
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        fn clone(ptr: *const ()) -> RawWaker {
            raw(ptr)
        }
        fn drop(_: *const ()) {}
        fn raw(ptr: *const ()) -> RawWaker {
            RawWaker::new(ptr, &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, drop, drop, drop);
        let waker = unsafe { Waker::from_raw(raw(std::ptr::null())) };
        let mut context = Context::from_waker(&waker);
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("sign_metadata waited"),
        }
    }

    #[test]
    fn a_final_tx_that_creates_the_reference_nft_returns_the_charm_and_signature() {
        use_spell_parser();
        PUBLIC_KEY.with(|cell| *cell.borrow_mut() = None);
        let meta = example();
        let signed = block_on(sign_metadata(
            token_app(),
            final_tx(&spell_with(Some(&meta))),
        ))
        .expect("signed");
        assert_eq!(signed.charm.app.tag, "n");
        assert_eq!(signed.charm.app.identity, identity().0);
        assert_eq!(signed.charm.app.vk, vk().0);
        assert_eq!(signed.signature.len(), 65);
        assert!(signed.signature[64] == 27 || signed.signature[64] == 28);

        assert_eq!(signed.version, 1_700_000_000);
        let signer = block_on(public_key()).unwrap();
        let hash = metadata_hash(
            &metadata_from(&charms_data::util::read(signed.charm.data.as_slice()).unwrap())
                .unwrap(),
        );
        let digest = metadata_digest(&parse_app(&token_app()).unwrap(), signed.version, &hash);
        let recovered = signature_65(&signer.public_key, &digest, &signed.signature[..64]).unwrap();
        assert_eq!(recovered.as_slice(), signed.signature.as_slice());
        assert_eq!(hex::encode(hash), hex::encode(shared_bytes("metadataHash")));
        assert_eq!(hex::encode(digest), hex::encode(shared_bytes("digest")));
        assert_eq!(
            hex::encode(&signed.signature),
            hex::encode(shared_hex("signature"))
        );
        assert_eq!(
            hex::encode(signer.address),
            "19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
        );
    }

    #[test]
    fn the_signature_recovers_on_the_shared_digest() {
        use_spell_parser();
        PUBLIC_KEY.with(|cell| *cell.borrow_mut() = None);
        let meta = example();
        let signed = block_on(sign_metadata(
            token_app(),
            final_tx(&spell_with(Some(&meta))),
        ))
        .expect("signed");
        let digest = shared_bytes("digest");
        let signer = block_on(public_key()).unwrap();
        assert_eq!(signed.version, 1_700_000_000);
        let recovered = signature_65(&signer.public_key, &digest, &signed.signature[..64])
            .expect("shared digest");
        assert_eq!(recovered.as_slice(), signed.signature.as_slice());
        assert_eq!(
            hex::encode(signer.address),
            hex::encode(shared_hex("address"))
        );
    }

    #[test]
    fn a_zero_block_time_is_rejected() {
        use_spell_parser();
        let err = block_on(sign_metadata(
            token_app(),
            final_tx_at(&spell_with(Some(&example())), 0),
        ))
        .unwrap_err();
        assert_eq!(err, "Input error: bitcoin block time");
    }

    #[test]
    fn a_header_that_only_claims_work_is_not_signed() {
        use_spell_parser();
        let raw = bitcoin_tx(&spell_with(Some(&example())));
        let (tx, proof) = mine_at(&raw, u32::MAX);
        let fake = Header {
            version: Version::ONE,
            prev_blockhash: proof.header.block_hash(),
            merkle_root: TxMerkleNode::all_zeros(),
            time: u32::MAX,
            bits: CompactTarget::from_consensus(FINALITY_TARGET_BITS),
            nonce: 0,
        };
        let encoded = encode(&Tx::Bitcoin(BitcoinTx::WithBlockProof {
            tx,
            proof,
            headers: vec![fake],
        }));
        let err = block_on(sign_metadata(token_app(), encoded)).unwrap_err();
        assert_eq!(err, "Input error: transaction is not final");
    }

    #[test]
    fn a_transaction_without_a_bitcoin_block_has_no_metadata_version() {
        let tx = Tx::Bitcoin(BitcoinTx::Simple(bitcoin_tx(&spell_with(Some(&example())))));
        let err = bitcoin_block_time(&tx).unwrap_err();
        assert_eq!(
            err,
            "Input error: metadata version is the bitcoin block time"
        );
    }

    fn shared_bytes(key: &str) -> [u8; 32] {
        let bytes = shared_hex(key);
        bytes
            .try_into()
            .unwrap_or_else(|bytes: Vec<u8>| panic!("short {key}: {}", bytes.len()))
    }

    fn shared_hex(key: &str) -> Vec<u8> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../ethereum/test/vectors/metadata-digest.json"
        );
        let file = std::fs::read_to_string(path).unwrap();
        let needle = format!("\"{key}\"");
        let at = file
            .find(&needle)
            .unwrap_or_else(|| panic!("missing {key}"));
        let rest = &file[at + needle.len()..];
        let start = rest
            .find("0x")
            .unwrap_or_else(|| panic!("missing hex {key}"));
        let rest = &rest[start + 2..];
        let end = rest
            .find('"')
            .unwrap_or_else(|| panic!("unterminated {key}"));
        hex::decode(&rest[..end]).unwrap_or_else(|_| panic!("bad hex {key}"))
    }

    #[test]
    fn a_non_final_tx_is_rejected() {
        let err = block_on(sign_metadata(
            token_app(),
            bare_tx(&spell_with(Some(&example()))),
        ))
        .unwrap_err();
        assert_eq!(err, "Input error: transaction is not final");
    }

    #[test]
    fn a_wrong_tag_is_rejected() {
        let mut app = token_app();
        app.tag = NFT.to_string();
        let err =
            block_on(sign_metadata(app, final_tx(&spell_with(Some(&example()))))).unwrap_err();
        assert_eq!(err, "Input error: app tag is not t");
    }

    #[test]
    fn a_tx_that_does_not_create_the_reference_nft_is_rejected() {
        use_spell_parser();
        let err = block_on(sign_metadata(token_app(), final_tx(&spell_with(None)))).unwrap_err();
        assert_eq!(
            err,
            "Input error: transaction does not create the reference NFT"
        );
    }

    #[test]
    fn two_reference_nfts_are_rejected() {
        use_spell_parser();
        let mut spell = spell_with(Some(&example()));
        let again = spell.tx.outs[0].clone();
        spell.tx.outs.push(again);
        let err = block_on(sign_metadata(token_app(), final_tx(&spell))).unwrap_err();
        assert_eq!(
            err,
            "Input error: transaction creates more than one reference NFT"
        );
    }

    #[test]
    fn a_bad_spell_proof_is_rejected_before_signing() {
        for spell_proof in [Vec::new(), vec![0xab; 100]] {
            let err = block_on(sign_metadata(
                token_app(),
                final_tx_with_proof(&spell_with(Some(&example())), &spell_proof),
            ))
            .unwrap_err();
            assert!(
                err.starts_with("Input error: ") && err.contains("could not verify spell proof"),
                "{err}"
            );
            assert_eq!(sign_calls(), 0);
        }
    }

    #[test]
    fn did_file_matches_the_service() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/charms_metadata.did");
        let on_disk = std::fs::read_to_string(path).unwrap_or_default();
        assert_eq!(on_disk, __export_service());
    }
}
