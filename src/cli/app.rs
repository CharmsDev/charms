use crate::spell::Spell;
use anyhow::{Result, anyhow, ensure};
use charms_app_runner::AppRunner;
use charms_data::{B32, Data};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs, io,
    path::PathBuf,
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
        .env("RUSTFLAGS", "-C target-cpu=generic")
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
    let cargo_toml_contents = fs::read_to_string("./Cargo.toml")?;
    let toml_value: toml::Value = cargo_toml_contents.parse()?;
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

pub fn vk(path: Option<PathBuf>) -> Result<()> {
    let binary = match path {
        Some(path) => fs::read(path)?,
        None => {
            let bin_path = do_build()?;
            fs::read(bin_path)?
        }
    };
    let hash = Sha256::digest(binary);
    let vk = B32(hash.into());

    println!("{}", vk);
    Ok(())
}

pub fn run(spell: PathBuf, path: Option<PathBuf>) -> Result<()> {
    let binary = match path {
        Some(path) => fs::read(path)?,
        None => {
            let bin_path = do_build()?;
            fs::read(bin_path)?
        }
    };
    let app_runner = AppRunner::new(true);
    let vk = app_runner.vk(&binary);

    let spell: Spell = serde_yaml::from_slice(
        &fs::read(&spell).map_err(|e| anyhow!("error reading {:?}: {}", &spell, e))?,
    )?;
    let tx = spell.to_tx(BTreeMap::new())?; // TODO pass prev_txs OR remove app run command

    let public_inputs = spell.public_args.unwrap_or_default();
    let private_inputs = spell.private_args.unwrap_or_default();

    let mut app_present = false;
    for (k, app) in spell.apps.iter().filter(|(_, app)| app.vk == vk) {
        app_present = true;
        let x = data_for_key(&public_inputs, k);
        let w = data_for_key(&private_inputs, k);
        app_runner.run(&binary, app, &tx, &x, &w)?;
        eprintln!("✅  satisfied app contract for: {}", app);
    }
    if !app_present {
        eprintln!("⚠️  app not present for VK: {}", vk);
    }

    Ok(())
}

fn data_for_key(inputs: &BTreeMap<String, Data>, k: &String) -> Data {
    match inputs.get(k) {
        Some(v) => v.clone(),
        None => Data::empty(),
    }
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
