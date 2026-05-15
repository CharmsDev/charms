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
    ensure!(
        !(path.is_some() && pubkey.is_some()),
        "pass at most one of <PATH> or --pubkey: <PATH> computes SHA-256 of a Wasm binary \
         (simple app VK), --pubkey computes SHA-256 of a signing public key (versioned app VK)"
    );
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
///
/// `secret_key` is the raw 32-byte secp256k1 secret scalar (not a BIP-340 "tweaked"
/// secret). It's paired with `Keypair::from_secret_key`, whose `.x_only_public_key()`
/// derivation produces `public_key`. Any third-party tool that interprets `secret_key`
/// differently and produces a different x-only public key will be rejected by
/// `load_keypair`, which re-derives `public_key` and `vk` from `secret_key` and
/// requires both to match what's on disk.
#[derive(Debug, Serialize, Deserialize)]
pub struct AppKeypair {
    /// Hex-encoded 32-byte BIP-340 x-only public key (derived from `secret_key`).
    pub public_key: String,
    /// Hex-encoded 32-byte raw secp256k1 secret scalar.
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
        Some(p) => write_secret_file(&p, s.as_bytes())?,
        None => {
            eprintln!(
                "WARNING: writing the secret key to stdout. Capture it directly (e.g. \
                 `... > key.json`) and protect the file; do not paste into chats or logs. \
                 Prefer `--out <FILE>` (which writes with mode 0600 on Unix)."
            );
            println!("{}", s);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to open {} for writing", path.display()))?;
    use std::io::Write as _;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    fs::write(path, contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
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

    // BIP-340 recommends fresh auxiliary randomness for each signature to defend
    // against fault attacks; pull 32 bytes from the OS.
    let mut aux_rand = [0u8; 32];
    getrandom::getrandom(&mut aux_rand).context("failed to obtain OS randomness")?;
    let signature = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);

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

/// Load a keypair, deriving the verifying key from the on-disk secret key and rejecting
/// inconsistent `public_key` / `vk` fields. Catches accidental edits or swaps in the file
/// before any signed material is produced.
fn load_keypair<C: secp256k1::Signing>(secp: &Secp256k1<C>, path: &Path) -> Result<Keypair> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("failed to read keypair file: {}", path.display()))?;
    let kp: AppKeypair = serde_json::from_str(&s)
        .with_context(|| format!("failed to parse keypair JSON: {}", path.display()))?;
    let secret_bytes = hex::decode(&kp.secret_key).context("invalid hex in secret_key")?;
    let sk = SecretKey::from_slice(&secret_bytes)
        .map_err(|e| anyhow!("invalid secp256k1 secret key: {}", e))?;
    let keypair = Keypair::from_secret_key(secp, &sk);

    let (derived_xonly, _parity) = keypair.x_only_public_key();
    let derived_pk = derived_xonly.serialize();
    let declared_pk = hex::decode(&kp.public_key).context("invalid hex in public_key")?;
    ensure!(
        declared_pk.as_slice() == derived_pk.as_slice(),
        "keypair file is corrupt: public_key does not match the x-only public key derived \
         from secret_key (declared {}, derived {})",
        kp.public_key,
        hex::encode(derived_pk)
    );

    let derived_vk: [u8; 32] = Sha256::digest(&derived_pk).into();
    let declared_vk = hex::decode(&kp.vk).context("invalid hex in vk")?;
    ensure!(
        declared_vk.as_slice() == &derived_vk,
        "keypair file is corrupt: vk does not match SHA-256 of public_key \
         (declared {}, derived {})",
        kp.vk,
        hex::encode(derived_vk)
    );

    Ok(keypair)
}

/// Read a BIP-340 x-only public key from `path`. Accepts either:
/// - a hex string (with optional `0x` prefix), or
/// - an [`AppKeypair`] JSON document (the file produced by `app keygen`).
///
/// Raw binary input is rejected to avoid ambiguity (a 32-byte file could plausibly be a
/// raw key, a hex string of a 16-byte key, or truncated text).
fn read_public_key(path: &Path) -> Result<[u8; 32]> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("failed to read public key file: {}", path.display()))?;
    let s = s.trim();
    let pk_hex = if s.starts_with('{') {
        let kp: AppKeypair = serde_json::from_str(s).with_context(|| {
            format!("failed to parse keypair JSON: {}", path.display())
        })?;
        kp.public_key
    } else {
        s.trim_start_matches("0x").to_string()
    };
    let pk = hex::decode(&pk_hex).context("invalid hex public key")?;
    pk.try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes (hex-encoded as 64 characters)"))
}

pub fn read_app_signatures(path: &Path) -> Result<BTreeMap<B32, AppSignature>> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read app signatures file: {}", path.display()))?;
    let map: BTreeMap<B32, AppSignature> = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("failed to parse app signatures: {}", path.display()))?;
    Ok(map)
}
