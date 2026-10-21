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
        if image.len() > 256 || !zero {
            return Err("Input error: image".into());
        }
        return Ok(());
    }
    let remote =
        image.starts_with("https://") || image.starts_with("ipfs://") || image.starts_with("ar://");
    if remote && image.len() <= 128 && !zero {
        return Ok(());
    }
    Err("Input error: image".into())
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
