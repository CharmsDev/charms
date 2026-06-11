use anyhow::{Context, Result, anyhow, ensure};
use charms_app_runner::AppRunner;
use charms_data::{AppSignature, B32};
use secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey, schnorr};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const APP_KEY_FILE: &str = ".charms/app-key.json";

fn default_app_key_path() -> PathBuf {
    PathBuf::from(APP_KEY_FILE)
}

fn signatures_path_for_wasm(wasm_path: impl AsRef<Path>) -> PathBuf {
    let mut path = wasm_path.as_ref().as_os_str().to_os_string();
    path.push(".sig.yaml");
    PathBuf::from(path)
}

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
    let name = toml_value
        .get("package")
        .and_then(|package| package.get("name"))
        .and_then(|name| name.as_str())
        .ok_or_else(|| anyhow!("Cargo.toml should set a package name"))?;
    let prefix = workspace_target_prefix()?;
    Ok(format!("{prefix}target/wasm32-wasip1/release/{name}.wasm"))
}

/// Relative path prefix from the current crate directory to the workspace root,
/// including a trailing slash. Standalone crates and workspace roots use `./`.
fn workspace_target_prefix() -> Result<String> {
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let workspace_root = find_workspace_root(&cwd)?;
    if workspace_root == cwd {
        return Ok("./".to_string());
    }
    let rel = relative_path(&cwd, &workspace_root)?;
    Ok(format!("{}/", rel.display()))
}

fn find_workspace_root(start: &Path) -> Result<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let cargo_toml = dir.join("Cargo.toml");
        if cargo_toml.exists() {
            let contents = fs::read(&cargo_toml)?;
            let value: toml::Value = toml::from_slice(&contents)?;
            if value.get("workspace").is_some() {
                return Ok(dir);
            }
        }
        if !dir.pop() {
            return Ok(start.to_path_buf());
        }
    }
}

fn relative_path(from: &Path, to: &Path) -> Result<PathBuf> {
    let from = from
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", from.display()))?;
    let to = to
        .canonicalize()
        .with_context(|| format!("failed to canonicalize {}", to.display()))?;

    let from_components: Vec<_> = from.components().collect();
    let to_components: Vec<_> = to.components().collect();

    let mut common = 0;
    while common < from_components.len()
        && common < to_components.len()
        && from_components[common] == to_components[common]
    {
        common += 1;
    }

    let mut result = PathBuf::new();
    for _ in common..from_components.len() {
        result.push("..");
    }
    for component in &to_components[common..] {
        result.push(component.as_os_str());
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    Ok(result)
}

pub fn build() -> Result<()> {
    let bin_path = do_build()?;
    maybe_auto_sign(&bin_path)?;
    println!("{}", bin_path);
    Ok(())
}

fn maybe_auto_sign(wasm_path: &str) -> Result<()> {
    maybe_auto_sign_with_key(&default_app_key_path(), wasm_path)
}

fn maybe_auto_sign_with_key(key_path: &Path, wasm_path: &str) -> Result<()> {
    if !key_path.exists() {
        return Ok(());
    }
    let (vk, app_sig) = sign_wasm_at(key_path, Path::new(wasm_path))?;
    write_signed_wasm(&signatures_path_for_wasm(wasm_path), vk, app_sig)
}

fn write_signed_wasm(path: &Path, vk: B32, app_sig: AppSignature) -> Result<()> {
    write_app_signatures(path, &[(vk, app_sig)])?;
    eprintln!(
        "signed wasm module; wrote app signature to {} (pass to `charms spell prove \
         --app-signatures` / `charms spell check --app-signatures`)",
        path.display()
    );
    Ok(())
}

fn resolve_app_vk(path: Option<PathBuf>, pubkey: Option<PathBuf>) -> Result<B32> {
    ensure!(
        !(path.is_some() && pubkey.is_some()),
        "pass at most one of <PATH> or --pubkey: <PATH> computes SHA-256 of a Wasm binary \
         (simple app VK), --pubkey computes SHA-256 of a signing public key (versioned app VK)"
    );
    match pubkey {
        Some(pubkey_path) => {
            let pk_bytes = read_public_key(&pubkey_path)?;
            Ok(B32(Sha256::digest(&pk_bytes).into()))
        }
        None => match path {
            Some(path) => {
                let binary = fs::read(path)?;
                Ok(B32(Sha256::digest(&binary).into()))
            }
            None => app_vk_from_key_or_wasm(&default_app_key_path()),
        },
    }
}

fn app_vk_from_key_or_wasm(key_path: &Path) -> Result<B32> {
    if key_path.exists() {
        let secp = Secp256k1::signing_only();
        let (_, vk) = load_keypair(&secp, key_path)?;
        return Ok(vk);
    }
    let bin_path = do_build()?;
    let binary = fs::read(bin_path)?;
    Ok(B32(Sha256::digest(&binary).into()))
}

pub fn vk(path: Option<PathBuf>, pubkey: Option<PathBuf>) -> Result<()> {
    println!("{}", resolve_app_vk(path, pubkey)?);
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

    let out = out.unwrap_or_else(default_app_key_path);
    if out.parent().is_some_and(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(out.parent().expect("parent path"))
            .with_context(|| format!("failed to create {}", out.parent().unwrap().display()))?;
    }
    let s = serde_json::to_string_pretty(&keypair)?;
    write_secret_file(&out, s.as_bytes())?;
    eprintln!(
        "wrote app signing keypair to {} (keep this file secret; do not commit it to source \
         control)",
        out.display()
    );
    Ok(())
}

fn write_secret_file(path: &Path, contents: &[u8]) -> Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    opts.mode(0o600);

    let mut file = opts.open(path).map_err(|e| {
        if e.kind() == io::ErrorKind::AlreadyExists {
            anyhow!(
                "refusing to overwrite existing keypair at {}; delete it first or pass --out <path>",
                path.display()
            )
        } else {
            e.into()
        }
    })?;
    file.write_all(contents)
        .with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn resolve_wasm_path(bin: Option<PathBuf>) -> Result<PathBuf> {
    match bin {
        Some(p) => Ok(p),
        None => {
            let path = wasm_path()?;
            ensure!(
                Path::new(&path).exists(),
                "wasm binary not found at {path}; run `charms app build` first or pass --bin"
            );
            Ok(PathBuf::from(path))
        }
    }
}

pub fn sign(key: PathBuf, bin: Option<PathBuf>, out: Option<PathBuf>) -> Result<()> {
    let wasm_path = resolve_wasm_path(bin)?;
    let (vk, app_sig) = sign_wasm_at(&key, &wasm_path)?;
    match out {
        Some(p) => {
            if p.extension()
                .is_some_and(|ext| ext == "yaml" || ext == "yml")
            {
                write_signed_wasm(&p, vk, app_sig)?;
            } else {
                let s = serde_json::to_string_pretty(&app_sig)?;
                fs::write(&p, s.as_bytes())
                    .with_context(|| format!("failed to write {}", p.display()))?;
            }
        }
        None => write_signed_wasm(&signatures_path_for_wasm(&wasm_path), vk, app_sig)?,
    }
    Ok(())
}

pub fn verify(bin: Option<PathBuf>, sig: Option<PathBuf>) -> Result<()> {
    let wasm_path = resolve_wasm_path(bin)?;
    let sig_path = sig.unwrap_or_else(|| signatures_path_for_wasm(&wasm_path));
    verify_wasm_at(&wasm_path, &sig_path)?;
    eprintln!(
        "signature verified for {} (signature file: {})",
        wasm_path.display(),
        sig_path.display()
    );
    Ok(())
}

fn verify_wasm_at(wasm_path: &Path, sig_path: &Path) -> Result<()> {
    let binary = fs::read(wasm_path)
        .with_context(|| format!("failed to read wasm binary: {}", wasm_path.display()))?;
    let binary_hash: [u8; 32] = Sha256::digest(&binary).into();
    let msg = Message::from_digest(binary_hash);

    let signatures = read_signature_entries(sig_path)?;
    ensure!(
        !signatures.is_empty(),
        "no signatures found in {}",
        sig_path.display()
    );

    let secp = Secp256k1::verification_only();
    for (vk, app_sig) in &signatures {
        let pk_hash = B32(Sha256::digest(&app_sig.public_key.0).into());
        ensure!(
            pk_hash == *vk,
            "public key hash does not match VK key in signature file (vk {}, derived {})",
            vk,
            pk_hash
        );
        let xonly_pk = XOnlyPublicKey::from_slice(&app_sig.public_key.0)
            .map_err(|e| anyhow!("invalid BIP-340 x-only public key: {}", e))?;
        let signature = schnorr::Signature::from_slice(&app_sig.signature)
            .map_err(|e| anyhow!("invalid BIP-340 Schnorr signature: {}", e))?;
        secp.verify_schnorr(&signature, &msg, &xonly_pk)
            .map_err(|e| {
                anyhow!(
                    "BIP-340 Schnorr signature verification failed for vk {}: {}",
                    vk,
                    e
                )
            })?;
    }
    Ok(())
}

fn sign_wasm_at(key_path: &Path, wasm_path: &Path) -> Result<(B32, AppSignature)> {
    let secp = Secp256k1::new();
    let (keypair, vk) = load_keypair(&secp, key_path)?;
    let (xonly_pk, _parity) = keypair.x_only_public_key();

    let binary = fs::read(wasm_path)
        .with_context(|| format!("failed to read wasm binary: {}", wasm_path.display()))?;
    let binary_hash: [u8; 32] = Sha256::digest(&binary).into();
    let msg = Message::from_digest(binary_hash);

    // BIP-340 recommends fresh auxiliary randomness for each signature to defend
    // against fault attacks; pull 32 bytes from the OS.
    let mut aux_rand = [0u8; 32];
    getrandom::getrandom(&mut aux_rand).context("failed to obtain OS randomness")?;
    let signature = secp.sign_schnorr_with_aux_rand(&msg, &keypair, &aux_rand);

    let app_sig = AppSignature {
        public_key: B32(xonly_pk.serialize()),
        signature: *signature.as_ref(),
    };
    Ok((vk, app_sig))
}

fn write_app_signatures(path: &Path, entries: &[(B32, AppSignature)]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
    }
    let map: BTreeMap<B32, AppSignature> = entries.iter().cloned().collect();
    let s = serde_yaml::to_string(&map)?;
    fs::write(path, s.as_bytes()).with_context(|| format!("failed to write {}", path.display()))?;
    Ok(())
}

fn read_app_keypair(path: &Path) -> Result<AppKeypair> {
    let s = fs::read_to_string(path)
        .with_context(|| format!("failed to read keypair file: {}", path.display()))?;
    serde_json::from_str(&s)
        .with_context(|| format!("failed to parse keypair JSON: {}", path.display()))
}

/// Load a keypair, deriving the verifying key from the on-disk secret key and rejecting
/// inconsistent `public_key` / `vk` fields. Catches accidental edits or swaps in the file
/// before any signed material is produced.
fn load_keypair<C: secp256k1::Signing>(secp: &Secp256k1<C>, path: &Path) -> Result<(Keypair, B32)> {
    let kp = read_app_keypair(path)?;
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

    Ok((keypair, B32(derived_vk)))
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
        let kp: AppKeypair = serde_json::from_str(s)
            .with_context(|| format!("failed to parse keypair JSON: {}", path.display()))?;
        kp.public_key
    } else {
        s.trim_start_matches("0x").to_string()
    };
    let pk = hex::decode(&pk_hex).context("invalid hex public key")?;
    pk.try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes (hex-encoded as 64 characters)"))
}

fn read_signature_entries(path: &Path) -> Result<BTreeMap<B32, AppSignature>> {
    let bytes = fs::read(path)
        .with_context(|| format!("failed to read signature file: {}", path.display()))?;
    if path.extension().is_some_and(|ext| ext == "json") {
        let app_sig: AppSignature = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse JSON signature: {}", path.display()))?;
        let vk = B32(Sha256::digest(&app_sig.public_key.0).into());
        return Ok(BTreeMap::from([(vk, app_sig)]));
    }
    let map: BTreeMap<B32, AppSignature> = serde_yaml::from_slice(&bytes)
        .with_context(|| format!("failed to parse app signatures: {}", path.display()))?;
    Ok(map)
}

pub fn read_app_signatures(path: &Path) -> Result<BTreeMap<B32, AppSignature>> {
    read_signature_entries(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_test_dir(prefix: &str) -> PathBuf {
        let n = TEST_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("{prefix}-{n}-{}", std::process::id()))
    }

    fn remove_test_dir(dir: &Path) {
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn find_workspace_root_from_member() -> Result<()> {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let member = repo_root.join("charms-data");
        assert_eq!(find_workspace_root(&member)?, repo_root);
        Ok(())
    }

    #[test]
    fn find_workspace_root_from_root() -> Result<()> {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        assert_eq!(find_workspace_root(&repo_root)?, repo_root);
        Ok(())
    }

    #[test]
    fn relative_path_to_workspace_root() -> Result<()> {
        let repo_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let member = repo_root.join("charms-data");
        assert_eq!(relative_path(&member, &repo_root)?, PathBuf::from(".."));
        Ok(())
    }

    #[test]
    fn signatures_path_for_wasm_appends_suffix() {
        assert_eq!(
            signatures_path_for_wasm("./target/wasm32-wasip1/release/myapp.wasm"),
            PathBuf::from("./target/wasm32-wasip1/release/myapp.wasm.sig.yaml")
        );
    }

    #[test]
    fn write_app_signatures_roundtrip() -> Result<()> {
        let dir = unique_test_dir("charms-app-signatures");
        fs::create_dir_all(&dir)?;
        let path = dir.join("app-signatures.yaml");
        let vk = B32([1u8; 32]);
        let sig = AppSignature {
            public_key: B32([2u8; 32]),
            signature: [3u8; 64],
        };
        write_app_signatures(&path, &[(vk.clone(), sig.clone())])?;
        let parsed = read_app_signatures(&path)?;
        assert_eq!(parsed.get(&vk), Some(&sig));
        remove_test_dir(&dir);
        Ok(())
    }

    #[test]
    fn maybe_auto_sign_writes_signatures_yaml() -> Result<()> {
        let dir = unique_test_dir("charms-auto-sign");
        fs::create_dir_all(&dir)?;
        let key_path = dir.join("app-key.json");
        let wasm_path = dir.join("app.wasm");
        fs::write(&wasm_path, b"test wasm binary")?;
        keygen(Some(key_path.clone()))?;

        maybe_auto_sign_with_key(&key_path, wasm_path.to_str().unwrap())?;

        let sig_path = signatures_path_for_wasm(&wasm_path);
        let parsed = read_app_signatures(&sig_path)?;
        assert_eq!(parsed.len(), 1);
        remove_test_dir(&dir);
        Ok(())
    }

    #[test]
    fn maybe_auto_sign_skips_when_key_missing() -> Result<()> {
        let dir = unique_test_dir("charms-auto-sign-skip");
        fs::create_dir_all(&dir)?;
        let wasm_path = dir.join("app.wasm");
        fs::write(&wasm_path, b"test wasm binary")?;
        let key_path = dir.join("missing-key.json");
        let sig_path = signatures_path_for_wasm(&wasm_path);

        maybe_auto_sign_with_key(&key_path, wasm_path.to_str().unwrap())?;

        assert!(!sig_path.exists());
        remove_test_dir(&dir);
        Ok(())
    }

    #[test]
    fn vk_uses_app_key_when_no_path_or_pubkey() -> Result<()> {
        use std::str::FromStr;

        let dir = unique_test_dir("charms-vk-app-key");
        fs::create_dir_all(dir.join(".charms"))?;
        let key_path = dir.join(".charms/app-key.json");
        keygen(Some(key_path.clone()))?;
        let expected_vk = B32::from_str(&read_app_keypair(&key_path)?.vk)?;

        let vk = app_vk_from_key_or_wasm(&key_path)?;
        assert_eq!(vk, expected_vk);
        remove_test_dir(&dir);
        Ok(())
    }

    #[test]
    fn verify_accepts_signature_from_sign() -> Result<()> {
        let dir = unique_test_dir("charms-verify-ok");
        fs::create_dir_all(&dir)?;
        let key_path = dir.join("app-key.json");
        let wasm_path = dir.join("app.wasm");
        fs::write(&wasm_path, b"test wasm binary")?;
        keygen(Some(key_path.clone()))?;
        sign(key_path, Some(wasm_path.clone()), None)?;

        verify(Some(wasm_path.clone()), None)?;
        remove_test_dir(&dir);
        Ok(())
    }

    #[test]
    fn verify_accepts_json_signature_from_sign() -> Result<()> {
        let dir = unique_test_dir("charms-verify-json");
        fs::create_dir_all(&dir)?;
        let key_path = dir.join("app-key.json");
        let wasm_path = dir.join("app.wasm");
        let sig_path = dir.join("sig.json");
        fs::write(&wasm_path, b"test wasm binary")?;
        keygen(Some(key_path.clone()))?;
        sign(key_path, Some(wasm_path.clone()), Some(sig_path.clone()))?;

        verify(Some(wasm_path), Some(sig_path))?;
        remove_test_dir(&dir);
        Ok(())
    }

    #[test]
    fn verify_rejects_tampered_binary() -> Result<()> {
        let dir = unique_test_dir("charms-verify-bad-binary");
        fs::create_dir_all(&dir)?;
        let key_path = dir.join("app-key.json");
        let wasm_path = dir.join("app.wasm");
        fs::write(&wasm_path, b"test wasm binary")?;
        keygen(Some(key_path.clone()))?;
        sign(key_path, Some(wasm_path.clone()), None)?;

        fs::write(&wasm_path, b"tampered wasm binary")?;
        let err = verify(Some(wasm_path), None).unwrap_err();
        assert!(
            err.to_string().contains("signature verification failed"),
            "unexpected error: {err}"
        );
        remove_test_dir(&dir);
        Ok(())
    }

    #[test]
    fn keygen_refuses_to_overwrite_existing_key() -> Result<()> {
        let dir = unique_test_dir("charms-keygen-overwrite");
        fs::create_dir_all(&dir)?;
        let key_path = dir.join("app-key.json");
        keygen(Some(key_path.clone()))?;
        let err = keygen(Some(key_path)).unwrap_err();
        assert!(
            err.to_string().contains("refusing to overwrite"),
            "unexpected error: {err}"
        );
        remove_test_dir(&dir);
        Ok(())
    }
}
