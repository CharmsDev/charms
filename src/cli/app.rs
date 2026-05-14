use anyhow::{Context, Result, anyhow, ensure};
use charms_app_runner::AppRunner;
use charms_data::{AppSignature, B32};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub fn new(name: &str) -> Result<()> {
    if !Command::new("which")
        .args(&["cargo-generate"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success()
    {
        Command::new("cargo")
            .args(&["install", "cargo-generate"])
            .stdout(Stdio::null())
            .status()?;
    }
    let status = Command::new("cargo")
        .args(&[
            "generate",
            "--git=https://github.com/CharmsDev/charms-app",
            "--name",
            name,
        ])
        .status()?;
    ensure!(status.success());
    Ok(())
}

fn do_build() -> Result<String> {
    let mut child = Command::new("cargo")
        .args(&["build", "--locked", "--release", "--target=wasm32-wasip1"])
        .stdout(Stdio::piped())
        .spawn()?;
    let stdout = child.stdout.take().expect("Failed to open stdout");
    io::copy(&mut io::BufReader::new(stdout), &mut io::stderr())?;
    let status = child.wait()?;
    ensure!(status.success());
    Ok(wasm_path()?)
}

fn wasm_path() -> Result<String> {
    let cargo_toml_contents = fs::read("./Cargo.toml")?;
    let toml_value: toml::Value = toml::from_slice(&cargo_toml_contents)?;
    toml_value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(|name| name.as_str())
        .and_then(|name| Some(format!("./target/wasm32-wasip1/release/{}.wasm", name)))
        .ok_or_else(|| anyhow!("Cargo.toml should set a package name"))
}

pub fn build() -> Result<()> {
    let bin_path = do_build()?;
    println!("{}", bin_path);
    Ok(())
}

pub fn vk(path: Option<PathBuf>, pubkey: Option<PathBuf>) -> Result<()> {
    let vk = match pubkey {
        Some(pubkey_path) => {
            let pk_bytes = read_public_key(&pubkey_path)?;
            B32(Sha256::digest(&pk_bytes).into())
        }
        None => {
            let binary = match path {
                Some(path) => fs::read(path)?,
                None => {
                    let bin_path = do_build()?;
                    fs::read(bin_path)?
                }
            };
            B32(Sha256::digest(&binary).into())
        }
    };

    println!("{}", vk);
    Ok(())
}

#[tracing::instrument(level = "debug", skip(app_runner))]
pub fn binaries_by_vk(
    app_runner: &AppRunner,
    app_bins: Vec<PathBuf>,
) -> Result<BTreeMap<B32, Vec<u8>>> {
    let binaries: BTreeMap<B32, Vec<u8>> = app_bins
        .iter()
        .map(|path| {
            let binary = std::fs::read(path)?;
            let vk = app_runner.vk(&binary);
            Ok((vk, binary))
        })
        .collect::<Result<_>>()?;
    Ok(binaries)
}

/// JSON-serializable BIP-340 Schnorr keypair, written by `app keygen` and read by `app sign`.
#[derive(Debug, Serialize, Deserialize)]
pub struct AppKeypair {
    /// Hex-encoded 32-byte BIP-340 x-only public key.
    pub public_key: String,
    /// Hex-encoded 32-byte secp256k1 secret key.
    pub secret_key: String,
    /// Hex-encoded 32-byte VK (SHA-256 of `public_key`).
    pub vk: String,
}

pub fn keygen(out: Option<PathBuf>) -> Result<()> {
    let secp = Secp256k1::new();
    let (secret_key, public_key_bytes) = loop {
        let mut seed = [0u8; 32];
        getrandom::getrandom(&mut seed).context("failed to obtain OS randomness")?;
        let Ok(sk) = SecretKey::from_slice(&seed) else {
            continue;
        };
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = keypair.x_only_public_key();
        break (sk, xonly.serialize());
    };
    let vk = Sha256::digest(&public_key_bytes);

    let keypair = AppKeypair {
        public_key: hex::encode(public_key_bytes),
        secret_key: hex::encode(secret_key.secret_bytes()),
        vk: hex::encode(vk),
    };

    let s = serde_json::to_string_pretty(&keypair)?;
    match out {
        Some(p) => fs::write(p, s.as_bytes())?,
        None => println!("{}", s),
    }
    Ok(())
}

pub fn sign(key: PathBuf, bin: Option<PathBuf>, out: Option<PathBuf>) -> Result<()> {
    let secp = Secp256k1::new();
    let keypair = load_keypair(&secp, &key)?;
    let (xonly_pk, _parity) = keypair.x_only_public_key();

    let binary = match bin {
        Some(p) => fs::read(p)?,
        None => fs::read(do_build()?)?,
    };
    let binary_hash: [u8; 32] = Sha256::digest(&binary).into();
    let msg = Message::from_digest(binary_hash);
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &keypair);

    let app_sig = AppSignature {
        public_key: B32(xonly_pk.serialize()),
        signature: signature.as_ref().to_vec(),
    };
    let s = serde_json::to_string_pretty(&app_sig)?;
    match out {
        Some(p) => fs::write(p, s.as_bytes())?,
        None => println!("{}", s),
    }
    Ok(())
}

fn load_keypair<C: secp256k1::Signing>(
    secp: &Secp256k1<C>,
    path: &Path,
) -> Result<Keypair> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("failed to read keypair file: {}", path.display()))?;
    let kp: AppKeypair = serde_json::from_str(&s)
        .with_context(|| format!("failed to parse keypair JSON: {}", path.display()))?;
    let secret_bytes = hex::decode(&kp.secret_key).context("invalid hex in secret_key")?;
    let sk = SecretKey::from_slice(&secret_bytes)
        .map_err(|e| anyhow!("invalid secp256k1 secret key: {}", e))?;
    Ok(Keypair::from_secret_key(secp, &sk))
}

fn read_public_key(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read public key file: {}", path.display()))?;
    // Accept either: raw 32 bytes; a hex string (64 chars); or an AppKeypair JSON.
    if bytes.len() == 32 {
        return Ok(bytes.as_slice().try_into().unwrap());
    }
    if let Ok(s) = std::str::from_utf8(&bytes) {
        let s = s.trim();
        if s.starts_with('{') {
            let kp: AppKeypair = serde_json::from_str(s)?;
            let pk = hex::decode(&kp.public_key)?;
            return pk
                .try_into()
                .map_err(|_| anyhow!("public_key must be 32 bytes"));
        }
        let pk = hex::decode(s.trim_start_matches("0x")).context("invalid hex public key")?;
        return pk
            .try_into()
            .map_err(|_| anyhow!("public key must be 32 bytes"));
    }
    Err(anyhow!(
        "unrecognized public key file format: expected raw 32 bytes, hex, or AppKeypair JSON"
    ))
}

pub fn read_app_signatures(path: &Path) -> Result<BTreeMap<B32, AppSignature>> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read app signatures file: {}", path.display()))?;
    let map: BTreeMap<B32, AppSignature> = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("failed to parse app signatures: {}", path.display()))?;
    Ok(map)
}
