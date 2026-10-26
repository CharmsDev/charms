use charms_data::{App, Data, NFT, TOKEN};
use charms_lib::NormalizedSpell;
use serde::Deserialize;
use sha3::{Digest, Keccak256};

pub(crate) struct Metadata {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub description: String,
    pub url: String,
    pub image: String,
    pub image_hash: [u8; 32],
}

#[derive(Deserialize)]
struct Fields {
    #[serde(default)]
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    ticker: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    image: String,
    #[serde(default)]
    image_hash: Option<HashField>,
    #[serde(default)]
    decimals: u8,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum HashField {
    Hex(String),
    Bytes(Vec<u8>),
}

pub(crate) fn reference_nft(token: &App) -> Result<App, String> {
    if token.tag != TOKEN {
        return Err("Input error: app tag is not t".into());
    }
    Ok(App {
        tag: NFT,
        identity: token.identity.clone(),
        vk: token.vk.clone(),
    })
}

pub(crate) fn created_reference<'a>(
    spell: &'a NormalizedSpell,
    nft: &App,
) -> Result<&'a Data, String> {
    let Some(index) = spell.app_public_inputs.keys().position(|app| app == nft) else {
        return Err("Input error: transaction does not create the reference NFT".into());
    };
    let index = u32::try_from(index).map_err(|_| "Input error: app index".to_string())?;
    let mut found: Option<&Data> = None;
    for charms in &spell.tx.outs {
        if let Some(data) = charms.get(&index) {
            if found.is_some() {
                return Err("Input error: transaction creates more than one reference NFT".into());
            }
            found = Some(data);
        }
    }
    found.ok_or_else(|| "Input error: transaction does not create the reference NFT".into())
}

pub(crate) fn metadata_from(data: &Data) -> Result<Metadata, String> {
    let fields: Fields = data
        .value()
        .map_err(|e| format!("Input error: reference NFT data: {e}"))?;
    let image_hash = parse_hash(fields.image_hash)?;
    let metadata = Metadata {
        name: fields.name,
        symbol: fields.ticker,
        decimals: fields.decimals,
        description: fields.description,
        url: fields.url,
        image: fields.image,
        image_hash,
    };
    check(&metadata)?;
    Ok(metadata)
}

pub(crate) fn metadata_hash(metadata: &Metadata) -> [u8; 32] {
    keccak(&abi_encode(metadata))
}

pub(crate) fn app_key(app: &App) -> [u8; 32] {
    let mut preimage = [0u8; 96];
    preimage[28..32].copy_from_slice(&(app.tag as u32).to_be_bytes());
    preimage[32..64].copy_from_slice(&app.identity.0);
    preimage[64..96].copy_from_slice(&app.vk.0);
    keccak(&preimage)
}

pub(crate) fn metadata_digest(app: &App, version: u64, metadata_hash: &[u8; 32]) -> [u8; 32] {
    let mut preimage = [0u8; 128];
    preimage[..32].copy_from_slice(&keccak(
        b"CharmsMetadata(bytes32 appKey,uint64 version,bytes32 metadataHash)",
    ));
    preimage[32..64].copy_from_slice(&app_key(app));
    preimage[88..96].copy_from_slice(&version.to_be_bytes());
    preimage[96..].copy_from_slice(metadata_hash);
    keccak(&preimage)
}

fn check(metadata: &Metadata) -> Result<(), String> {
    if metadata.name.len() > 64 {
        return Err("Input error: name".into());
    }
    if metadata.symbol.is_empty() || metadata.symbol.len() > 32 {
        return Err("Input error: symbol".into());
    }
    if metadata.description.len() > 256 {
        return Err("Input error: description".into());
    }
    if metadata.url.len() > 128 {
        return Err("Input error: url".into());
    }
    check_url(&metadata.url)?;
    check_image(&metadata.image, &metadata.image_hash)
}

fn check_url(url: &str) -> Result<(), String> {
    if url.is_empty()
        || url.starts_with("https://")
        || url.starts_with("ipfs://")
        || url.starts_with("ar://")
        || url.starts_with("data:")
    {
        return Ok(());
    }
    Err("Input error: url".into())
}

const IMAGE_SVG_MAX: usize = 256;
const IMAGE_REMOTE_MAX: usize = 128;
const BASE58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE32: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";

fn check_image(image: &str, hash: &[u8; 32]) -> Result<(), String> {
    let zero = hash == &[0u8; 32];
    if image.is_empty() {
        return if zero {
            Ok(())
        } else {
            Err("Input error: image".into())
        };
    }
    if image.starts_with("data:image/svg+xml") {
        return if image.len() <= IMAGE_SVG_MAX && zero {
            Ok(())
        } else {
            Err("Input error: image".into())
        };
    }
    if zero {
        return if image.len() <= IMAGE_REMOTE_MAX && ipfs_content_commitment(image.as_bytes()) {
            Ok(())
        } else {
            Err("Input error: image".into())
        };
    }
    let loose =
        image.starts_with("https://") || image.starts_with("ipfs://") || image.starts_with("ar://");
    if image.len() <= IMAGE_REMOTE_MAX && loose {
        Ok(())
    } else {
        Err("Input error: image".into())
    }
}

fn ipfs_content_commitment(image: &[u8]) -> bool {
    let Some(rest) = image.strip_prefix(b"ipfs://") else {
        return false;
    };
    cid_v0(rest) || cid_v1(rest)
}

fn cid_v0(rest: &[u8]) -> bool {
    if rest.len() != 46 {
        return false;
    }
    let mut acc = [0u8; 34];
    for &c in rest {
        let Some(mut carry) = alphabet_index(BASE58, c) else {
            return false;
        };
        for i in (0..acc.len()).rev() {
            carry += 58 * u32::from(acc[i]);
            acc[i] = (carry % 256) as u8;
            carry /= 256;
        }
        if carry != 0 {
            return false;
        }
    }
    acc[0] == 0x12 && acc[1] == 0x20
}

fn cid_v1(rest: &[u8]) -> bool {
    if rest.len() != 59 || rest[0] != b'b' {
        return false;
    }
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut n = 0usize;
    let mut out = [0u8; 36];
    for &c in &rest[1..] {
        let Some(v) = alphabet_index(BASE32, c) else {
            return false;
        };
        acc = (acc << 5) + v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out[n] = ((acc >> bits) & 0xff) as u8;
            n += 1;
            acc &= (1u32 << bits) - 1;
        }
    }
    if bits != 2 || (acc & 3) != 0 || n != 36 {
        return false;
    }
    out[0] == 0x01 && (0x01..=0x7f).contains(&out[1]) && out[2] == 0x12 && out[3] == 0x20
}

fn alphabet_index(alphabet: &[u8], byte: u8) -> Option<u32> {
    let index = alphabet.iter().position(|&candidate| candidate == byte)?;
    u32::try_from(index).ok()
}

fn parse_hash(field: Option<HashField>) -> Result<[u8; 32], String> {
    let Some(field) = field else {
        return Ok([0u8; 32]);
    };
    let bytes = match field {
        HashField::Bytes(bytes) => bytes,
        HashField::Hex(text) => {
            let text = text.strip_prefix("0x").unwrap_or(&text);
            if text.is_empty() {
                return Ok([0u8; 32]);
            }
            hex::decode(text).map_err(|_| "Input error: image_hash".to_string())?
        }
    };
    bytes
        .try_into()
        .map_err(|_| "Input error: image_hash".to_string())
}

fn abi_encode(metadata: &Metadata) -> Vec<u8> {
    let parts = [
        encode_string(&metadata.name),
        encode_string(&metadata.symbol),
        encode_string(&metadata.description),
        encode_string(&metadata.url),
        encode_string(&metadata.image),
    ];
    let mut cursor = 32 * 7;
    let mut offsets = [0usize; 5];
    for (offset, part) in offsets.iter_mut().zip(&parts) {
        *offset = cursor;
        cursor += part.len();
    }
    let mut out = Vec::with_capacity(cursor);
    out.extend(word(offsets[0]));
    out.extend(word(offsets[1]));
    out.extend(word(usize::from(metadata.decimals)));
    out.extend(word(offsets[2]));
    out.extend(word(offsets[3]));
    out.extend(word(offsets[4]));
    out.extend(metadata.image_hash);
    for part in parts {
        out.extend(part);
    }
    out
}

fn encode_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = word(bytes.len()).to_vec();
    out.extend_from_slice(bytes);
    let pad = (32 - (bytes.len() % 32)) % 32;
    out.extend(std::iter::repeat_n(0u8, pad));
    out
}

fn word(value: usize) -> [u8; 32] {
    let mut out = [0u8; 32];
    let bytes = value.to_be_bytes();
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

pub(crate) fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}
