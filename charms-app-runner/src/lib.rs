use anyhow::{Result, bail, ensure};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use charms_data::{
    App, AppSignature, B32, Data, Transaction, VersionedApp, is_simple_transfer, util,
};
use secp256k1::{Message, Secp256k1, VerifyOnly, XOnlyPublicKey, schnorr};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    sync::{Arc, Mutex, OnceLock},
};
use wasmi::{
    Caller, CompilationMode, Config, Engine, Extern, Linker, Memory, Module, Store, TypedFunc,
};

/// Single shared verification-only secp256k1 context. The context owns precomputed tables
/// (~1 MB) and is expensive to allocate; `verify_app_binary` may be called many times per
/// spell, so we build it once and reuse.
fn secp_verifier() -> &'static Secp256k1<VerifyOnly> {
    static CTX: OnceLock<Secp256k1<VerifyOnly>> = OnceLock::new();
    CTX.get_or_init(Secp256k1::verification_only)
}

#[derive(Clone)]
pub struct AppRunner {
    count_cycles: bool,
    engine: Engine,
}

#[derive(Clone)]
struct HostState {
    stdin: Arc<Mutex<Vec<u8>>>,    // Stdin buffer
    stderr: Arc<Mutex<dyn Write>>, // Stderr buffer
    stream: Arc<Mutex<ChaCha20>>,
}

// Wasm32 addresses are `u32`. Values at or above 2 GiB arrive as a negative `i32`.
fn guest_addr(value: i32) -> usize {
    value as u32 as usize
}

// Lengths at or above 2 GiB stay rejected. Zero-extending them would allocate gigabytes.
fn guest_len(value: i32) -> Result<usize> {
    usize::try_from(value).map_err(|_| anyhow::anyhow!("guest length out of range"))
}

fn iovec_addr(iovs: i32, index: i32) -> Result<u32> {
    let offset = (index as u32)
        .checked_mul(8)
        .ok_or_else(|| anyhow::anyhow!("iovec address overflow"))?;
    (iovs as u32)
        .checked_add(offset)
        .ok_or_else(|| anyhow::anyhow!("iovec address overflow"))
}

fn read_i32(memory: &Memory, caller: &mut Caller<'_, HostState>, ptr: u32) -> Result<i32> {
    let data = read_memory(memory, caller, ptr as usize, 4)?;
    Ok(i32::from_le_bytes(data.try_into().unwrap()))
}

fn write_i32(
    memory: &Memory,
    caller: &mut Caller<'_, HostState>,
    ptr: i32,
    value: i32,
) -> Result<()> {
    let data = value.to_le_bytes();
    write_memory(memory, caller, guest_addr(ptr), &data)
}

fn read_memory(
    memory: &Memory,
    caller: &mut Caller<'_, HostState>,
    ptr: usize,
    len: usize,
) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(len)
        .map_err(|_| anyhow::anyhow!("guest buffer too large"))?;
    buffer.resize(len, 0);
    memory.read(caller, ptr, &mut buffer)?;
    Ok(buffer)
}

fn read_iovec(
    memory: &Memory,
    caller: &mut Caller<'_, HostState>,
    iovs: i32,
    index: i32,
) -> Result<(usize, usize)> {
    let iov_addr = iovec_addr(iovs, index)?;
    let buf_ptr = guest_addr(read_i32(memory, caller, iov_addr)?);
    let len_addr = iov_addr
        .checked_add(4)
        .ok_or_else(|| anyhow::anyhow!("iovec address overflow"))?;
    let buf_len = guest_len(read_i32(memory, caller, len_addr)?)?;
    Ok((buf_ptr, buf_len))
}

fn write_memory(
    memory: &Memory,
    caller: &mut Caller<'_, HostState>,
    ptr: usize,
    data: &[u8],
) -> Result<()> {
    memory.write(caller, ptr, data)?;
    Ok(())
}

fn fd_read_impl(
    mut caller: Caller<'_, HostState>,
    fd: i32,
    iovs: i32,
    iovs_len: i32,
    nread: i32,
) -> Result<i32> {
    if fd != 0 {
        return Ok(-1); // Only handle stdin (fd=0)
    }

    let memory = caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| anyhow::anyhow!("No memory export"))?;

    let mut iov_info = Vec::new();
    for i in 0..iovs_len {
        iov_info.push(read_iovec(&memory, &mut caller, iovs, i)?);
    }

    // Then, read from stdin and prepare operations
    let stdin_data = {
        let state = caller.data();
        let mut stdin = state.stdin.lock().unwrap();

        let mut total_read = 0;
        let mut operations = Vec::new();

        for (buf_ptr, buf_len) in iov_info {
            // Read from stdin buffer
            let to_read = buf_len.min(stdin.len());
            if to_read == 0 {
                break; // No more input
            }
            let data = stdin.drain(..to_read).collect::<Vec<_>>();
            operations.push((buf_ptr, data));
            total_read += to_read;
        }

        (operations, total_read)
    };

    // Now perform memory writes without holding any borrows
    for (buf_ptr, data) in stdin_data.0 {
        write_memory(&memory, &mut caller, buf_ptr, &data)?;
    }

    // Write number of bytes read to nread
    write_i32(&memory, &mut caller, nread, stdin_data.1 as i32)?;

    Ok(0) // Success
}

fn fd_write_impl(
    mut caller: Caller<'_, HostState>,
    fd: i32,
    iovs: i32,
    iovs_len: i32,
    nwritten: i32,
) -> Result<i32> {
    if fd != 2 {
        bail!("can only write to stderr"); // stderr fd=2
    }

    let memory = caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| anyhow::anyhow!("No memory export"))?;

    let mut total_written = 0;
    let mut all_data = Vec::new();

    for i in 0..iovs_len {
        let (buf_ptr, buf_len) = read_iovec(&memory, &mut caller, iovs, i)?;
        let data = read_memory(&memory, &mut caller, buf_ptr, buf_len)?;
        all_data.extend_from_slice(&data);
        total_written += buf_len;
    }

    // Now write to stderr without holding any borrows on caller
    {
        let state = caller.data_mut();
        let mut stderr = state.stderr.lock().unwrap();
        stderr.write_all(&all_data)?;
    }

    // Write number of bytes written to nwritten
    write_i32(&memory, &mut caller, nwritten, total_written as i32)?;

    Ok(0) // Success
}

fn fd_write(
    caller: Caller<'_, HostState>,
    fd: i32,
    iovs: i32,
    iovs_len: i32,
    nwritten: i32,
) -> i32 {
    let result = fd_write_impl(caller, fd, iovs, iovs_len, nwritten);
    result.unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        -1
    })
}

fn fd_read(
    caller: Caller<'_, HostState>,
    fd: i32,
    iovs: i32,
    iovs_len: i32,
    nread: i32,
) -> Result<i32, wasmi::Error> {
    fd_read_impl(caller, fd, iovs, iovs_len, nread).map_err(|e| wasmi::Error::new(e.to_string()))
}

fn environ_sizes_get_impl(
    mut caller: Caller<'_, HostState>,
    environc_ptr: i32,
    environ_buf_size_ptr: i32,
) -> Result<i32> {
    let memory = caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| anyhow::anyhow!("No memory export"))?;

    // Write 0 for number of environment variables
    write_i32(&memory, &mut caller, environc_ptr, 0)?;
    // Write 0 for total buffer size needed
    write_i32(&memory, &mut caller, environ_buf_size_ptr, 0)?;

    Ok(0) // Success
}

fn environ_get_impl(
    _caller: Caller<'_, HostState>,
    _environ_ptr: i32,
    _environ_buf_ptr: i32,
) -> Result<i32> {
    // Nothing to write for empty environment
    Ok(0) // Success
}

fn environ_sizes_get(
    caller: Caller<'_, HostState>,
    environc_ptr: i32,
    environ_buf_size_ptr: i32,
) -> i32 {
    environ_sizes_get_impl(caller, environc_ptr, environ_buf_size_ptr).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        -1
    })
}

fn environ_get(caller: Caller<'_, HostState>, environ_ptr: i32, environ_buf_ptr: i32) -> i32 {
    environ_get_impl(caller, environ_ptr, environ_buf_ptr).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        -1
    })
}

const MAX_RANDOM_GET_LEN: usize = 65_536;
const RANDOM_GET_CHUNK: usize = 4096;

/// The bytes are a public deterministic function of `(wasm hash, version, app, tx, x)`.
/// `w` cannot change them. The transaction author still chooses `tx` and `x`, so this
/// is not a beacon and must not be used for secret keys, nonces, or unbiased lotteries.
/// The CBOR from `util::write` is part of the consensus encoding. Do not bump `ciborium` casually.
fn random_seed(
    wasm_hash: &B32,
    version: u32,
    app: &App,
    tx: &Transaction,
    x: &Data,
) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(b"charms-app-runner/random/v1\0");
    hasher.update(wasm_hash.0);
    hasher.update(version.to_le_bytes());
    hasher.update(util::write(&(app, tx, x))?);
    Ok(hasher.finalize().into())
}

/// IETF ChaCha20 stream for `random_get`.
///
/// `chacha20` 0.10.2 `ChaChaCore::new_internal` zero-fills the state and does not
/// write the counter word, so the 32-bit block counter starts at 0.
fn random_stream(seed: [u8; 32]) -> ChaCha20 {
    ChaCha20::new(&seed.into(), &[0u8; 12].into())
}

/// The bytes are a public deterministic function of `(wasm hash, version, app, tx, x)`.
/// `w` cannot change them. The transaction author still chooses `tx` and `x`, so this
/// is not a beacon and must not be used for secret keys, nonces, or unbiased lotteries.
/// The CBOR from `util::write` is part of the consensus encoding. Do not bump `ciborium` casually.
fn random_get_impl(mut caller: Caller<'_, HostState>, buf: i32, buf_len: i32) -> Result<i32> {
    let len = guest_len(buf_len)?;
    if len > MAX_RANDOM_GET_LEN {
        bail!("random_get length exceeds {MAX_RANDOM_GET_LEN}");
    }
    let memory = caller
        .get_export("memory")
        .and_then(Extern::into_memory)
        .ok_or_else(|| anyhow::anyhow!("No memory export"))?;
    let addr = guest_addr(buf);
    let end = addr
        .checked_add(len)
        .ok_or_else(|| anyhow::anyhow!("out of bounds memory access"))?;
    if end > memory.data_size(&caller) {
        bail!("out of bounds memory access");
    }
    match caller.get_fuel() {
        Ok(remaining) => {
            let cost = len as u64;
            if remaining < cost {
                bail!("insufficient fuel");
            }
            caller.set_fuel(remaining - cost)?;
        }
        Err(err)
            if matches!(
                err.kind(),
                wasmi::errors::ErrorKind::Fuel(wasmi::errors::FuelError::FuelMeteringDisabled)
            ) => {}
        Err(err) => return Err(anyhow::anyhow!(err.to_string())),
    }

    let mut offset = 0;
    while offset < len {
        let n = (len - offset).min(RANDOM_GET_CHUNK);
        let mut chunk = [0u8; RANDOM_GET_CHUNK];
        caller
            .data()
            .stream
            .lock()
            .unwrap()
            .apply_keystream(&mut chunk[..n]);
        memory.write(&mut caller, addr + offset, &chunk[..n])?;
        offset += n;
    }
    Ok(0)
}

fn random_get(caller: Caller<'_, HostState>, buf: i32, buf_len: i32) -> Result<i32, wasmi::Error> {
    random_get_impl(caller, buf, buf_len).map_err(|e| wasmi::Error::new(e.to_string()))
}

const MAX_FUEL_PER_RUN: u64 = 1000000000;

#[cfg(test)]
thread_local! {
    static CAPTURE_GUEST_MEMORY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static GUEST_MEMORY: std::cell::RefCell<Option<Vec<u8>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn store_guest_memory(instance: &wasmi::Instance, store: &Store<HostState>) {
    if !CAPTURE_GUEST_MEMORY.with(|flag| flag.get()) {
        return;
    }
    let Some(memory) = instance.get_memory(store, "memory") else {
        return;
    };
    let mut bytes = vec![0u8; memory.data_size(store)];
    if memory.read(store, 0, &mut bytes).is_ok() {
        GUEST_MEMORY.with(|slot| *slot.borrow_mut() = Some(bytes));
    }
}

impl AppRunner {
    pub fn new(count_cycles: bool) -> Self {
        let mut config = Config::default();
        if count_cycles {
            config.consume_fuel(true);
        }
        config.compilation_mode(CompilationMode::LazyTranslation);
        Self {
            count_cycles,
            engine: Engine::new(&config),
        }
    }

    pub fn vk(&self, binary: &[u8]) -> B32 {
        let hash = Sha256::digest(binary);
        B32(hash.into())
    }

    /// Verify that `app_binary` is the correct binary for `app`, either as a simple (immutable)
    /// app where `app.vk == SHA256(binary)`, or as a versioned app where the binary hash matches
    /// the spell's [`VersionedApp::wasm_hash`] and is signed by a key whose SHA256 equals
    /// `app.vk`. Returns the SHA256 hash of the binary.
    fn verify_app_binary(
        &self,
        app: &App,
        app_binary: &[u8],
        versioned_apps: &BTreeMap<B32, VersionedApp>,
        app_signatures: &BTreeMap<B32, AppSignature>,
    ) -> Result<B32> {
        let binary_hash = self.vk(app_binary);
        match versioned_apps.get(&app.vk) {
            None => {
                ensure!(
                    !app_signatures.contains_key(&app.vk),
                    "signature provided for non-versioned app: {}",
                    app
                );
                ensure!(
                    app.vk == binary_hash,
                    "app.vk mismatch (binary hash) for app: {}",
                    app
                );
            }
            Some(versioned_app) => {
                ensure!(
                    versioned_app.wasm_hash == binary_hash,
                    "Wasm hash mismatch for versioned app: {}",
                    app
                );
                let sig = app_signatures.get(&app.vk).ok_or_else(|| {
                    anyhow::anyhow!("missing signature for versioned app: {}", app)
                })?;
                let pk_hash = self.vk(&sig.public_key.0);
                ensure!(
                    pk_hash == app.vk,
                    "public key hash does not match app.vk: {}",
                    app
                );
                let xonly_pk = XOnlyPublicKey::from_slice(&sig.public_key.0).map_err(|e| {
                    anyhow::anyhow!("invalid BIP-340 x-only public key for {}: {}", app, e)
                })?;
                let signature = schnorr::Signature::from_slice(&sig.signature).map_err(|e| {
                    anyhow::anyhow!("invalid BIP-340 Schnorr signature for {}: {}", app, e)
                })?;
                let msg = Message::from_digest(binary_hash.0);
                secp_verifier()
                    .verify_schnorr(&signature, &msg, &xonly_pk)
                    .map_err(|e| {
                        anyhow::anyhow!(
                            "BIP-340 Schnorr signature verification failed for {}: {}",
                            app,
                            e
                        )
                    })?;
            }
        }
        Ok(binary_hash)
    }

    pub fn run(
        &self,
        app_binary: &[u8],
        app: &App,
        tx: &Transaction,
        x: &Data,
        w: &Data,
        versioned_apps: &BTreeMap<B32, VersionedApp>,
        app_signatures: &BTreeMap<B32, AppSignature>,
    ) -> Result<u64> {
        let wasm_hash = self.verify_app_binary(app, app_binary, versioned_apps, app_signatures)?;

        let stdin_content = util::write(&(app, tx, x, w))?;
        let version = versioned_apps
            .get(&app.vk)
            .map(|versioned| versioned.version)
            .unwrap_or(0);
        let seed = random_seed(&wasm_hash, version, app, tx, x)?;
        let stream = random_stream(seed);
        let state = HostState {
            stdin: Arc::new(Mutex::new(stdin_content)),
            stderr: Arc::new(Mutex::new(std::io::stderr())),
            stream: Arc::new(Mutex::new(stream)),
        };

        let mut store = Store::new(&self.engine, state.clone());
        if self.count_cycles {
            store.set_fuel(MAX_FUEL_PER_RUN)?;
        }
        let mut linker = Linker::new(&self.engine);

        linker.func_wrap("wasi_snapshot_preview1", "fd_write", fd_write)?;
        linker.func_wrap("wasi_snapshot_preview1", "fd_read", fd_read)?;
        linker.func_wrap("wasi_snapshot_preview1", "environ_get", environ_get)?;
        linker.func_wrap(
            "wasi_snapshot_preview1",
            "environ_sizes_get",
            environ_sizes_get,
        )?;
        linker.func_wrap(
            "wasi_snapshot_preview1",
            "proc_exit",
            |_: Caller<'_, HostState>, _: i32| {},
        )?;
        linker.func_wrap("wasi_snapshot_preview1", "random_get", random_get)?;

        #[cfg(feature = "validate")]
        let module = Module::new(&self.engine, app_binary)?;
        #[cfg(not(feature = "validate"))]
        // SAFETY: this build leaves wasmi validation off. Invalid wasm is undefined behavior.
        let module = unsafe { Module::new_unchecked(&self.engine, app_binary) }?;

        let instance = linker.instantiate_and_start(&mut store, &module)?;

        if let Some(versioned_app) = versioned_apps.get(&app.vk) {
            let version_func = instance.get_func(&store, "__app_version").ok_or_else(|| {
                anyhow::anyhow!("versioned app {} does not export `__app_version`", app)
            })?;
            let typed: TypedFunc<(), u32> = version_func.typed(&store)?;
            let exported_version = typed.call(&mut store, ())?;
            ensure!(
                exported_version == versioned_app.version,
                "Wasm `__app_version` ({}) does not match spell version ({}) for app {}",
                exported_version,
                versioned_app.version,
                app
            );
        }

        let Some(main_func) = instance.get_func(&store, "_start") else {
            bail!("we should have a main function")
        };
        let result = main_func.typed::<(), ()>(&store)?.call(&mut store, ());

        state.stderr.lock().unwrap().flush()?;

        result.map_err(|e| anyhow::anyhow!("error running wasm: {:?}", e))?;
        #[cfg(test)]
        store_guest_memory(&instance, &store);

        let cycles = match self.count_cycles {
            true => MAX_FUEL_PER_RUN - store.get_fuel()?,
            false => 0,
        };
        Ok(cycles)
    }

    pub fn run_all(
        &self,
        app_binaries: &BTreeMap<B32, Vec<u8>>,
        versioned_apps: &BTreeMap<B32, VersionedApp>,
        app_signatures: &BTreeMap<B32, AppSignature>,
        tx: &Transaction,
        app_public_inputs: &BTreeMap<App, Data>,
        app_private_inputs: &BTreeMap<App, Data>,
        version_changed_apps: &BTreeSet<App>,
    ) -> Result<Vec<u64>> {
        let empty = Data::empty();
        let app_cycles = app_public_inputs
            .iter()
            .map(|(app, x)| {
                let w = app_private_inputs.get(app).unwrap_or(&empty);
                // Apps whose version is changing in this spell must execute so the new
                // contract authorizes the transition (the previous spell only signed off
                // on `(vk, prev_version, prev_wasm_hash)`). For all other apps, the
                // simple-transfer fast path is sound: same version implies same Wasm hash
                // (enforced by `check_app_version_continuity`), and the previous spell
                // already authenticated `(vk, version, wasm_hash)`.
                if !version_changed_apps.contains(app)
                    && x.is_empty()
                    && w.is_empty()
                    && is_simple_transfer(app, tx)
                {
                    eprintln!("➡️  simple transfer w.r.t. app: {}", app);
                    return Ok(0);
                }
                let binary_lookup_key = versioned_apps
                    .get(&app.vk)
                    .map(|va| &va.wasm_hash)
                    .unwrap_or(&app.vk);
                match app_binaries.get(binary_lookup_key) {
                    Some(app_binary) => {
                        let cycles =
                            self.run(app_binary, app, tx, x, w, versioned_apps, app_signatures)?;
                        eprintln!("✅  app contract satisfied: {}", app);
                        Ok(cycles)
                    }
                    None => bail!("app binary not found: {}", app),
                }
            })
            .collect::<Result<_>>()?;

        Ok(app_cycles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chacha20::ChaCha20;
    use chacha20::cipher::{KeyIvInit, StreamCipher};

    const VALID_START: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, b'm', b'e', b'm',
        b'o', b'r', b'y', 0x02, 0x00, 0x06, b'_', b's', b't', b'a', b'r', b't', 0x00, 0x00, 0x0a,
        0x04, 0x01, 0x02, 0x00, 0x0b,
    ];

    const UNCALLED_ILL_TYPED: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03,
        0x03, 0x02, 0x00, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, b'm', b'e',
        b'm', b'o', b'r', b'y', 0x02, 0x00, 0x06, b'_', b's', b't', b'a', b'r', b't', 0x00, 0x00,
        0x0a, 0x08, 0x02, 0x02, 0x00, 0x0b, 0x03, 0x00, 0x6a, 0x0b,
    ];

    fn run_wasm(runner: &AppRunner, wasm: &[u8]) -> Result<u64> {
        let app = App {
            tag: 't',
            identity: B32::default(),
            vk: runner.vk(wasm),
        };
        let tx = Transaction {
            ins: vec![],
            refs: vec![],
            outs: vec![],
            coin_ins: None,
            coin_outs: None,
            prev_txs: BTreeMap::new(),
            app_public_inputs: BTreeMap::new(),
        };
        let empty = Data::empty();
        runner.run(
            wasm,
            &app,
            &tx,
            &empty,
            &empty,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
    }

    #[test]
    fn valid_start_without_fuel_returns_zero() {
        let cycles = run_wasm(&AppRunner::new(false), VALID_START).unwrap();
        assert_eq!(cycles, 0);
    }

    #[test]
    fn valid_start_with_fuel_returns_observed_cycles() {
        let cycles = run_wasm(&AppRunner::new(true), VALID_START).unwrap();
        assert_eq!(cycles, 15);
    }

    #[cfg(feature = "validate")]
    #[test]
    fn uncalled_ill_typed_function_is_rejected() {
        for count_cycles in [false, true] {
            let err = run_wasm(&AppRunner::new(count_cycles), UNCALLED_ILL_TYPED)
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("type mismatch: expected i32 but nothing on stack"),
                "{err}"
            );
        }
    }

    #[cfg(not(feature = "validate"))]
    #[test]
    fn uncalled_ill_typed_function_is_not_checked() {
        assert_eq!(
            run_wasm(&AppRunner::new(false), UNCALLED_ILL_TYPED).unwrap(),
            0
        );
        assert_eq!(
            run_wasm(&AppRunner::new(true), UNCALLED_ILL_TYPED).unwrap(),
            15
        );
    }

    #[test]
    fn truncated_module_is_rejected() {
        for count_cycles in [false, true] {
            let err = run_wasm(&AppRunner::new(count_cycles), b"\0asm")
                .unwrap_err()
                .to_string();
            assert!(err.contains("unexpected end-of-file"), "{err}");
        }
    }

    const RANDOM_NEG_LEN: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x25, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73,
        0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77,
        0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d,
        0x6f, 0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a,
        0x0b, 0x01, 0x09, 0x00, 0x41, 0x00, 0x41, 0x7f, 0x10, 0x00, 0x1a, 0x0b,
    ];

    const RANDOM_NEG_PTR: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x25, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73,
        0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77,
        0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d,
        0x6f, 0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a,
        0x0b, 0x01, 0x09, 0x00, 0x41, 0x7f, 0x41, 0x10, 0x10, 0x00, 0x1a, 0x0b,
    ];

    const FD_READ_NEG_LEN: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x22, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69,
        0x5f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69,
        0x65, 0x77, 0x31, 0x07, 0x66, 0x64, 0x5f, 0x72, 0x65, 0x61, 0x64, 0x00, 0x01, 0x03, 0x02,
        0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d, 0x6f,
        0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a, 0x1d,
        0x01, 0x1b, 0x00, 0x41, 0x00, 0x41, 0x00, 0x36, 0x02, 0x00, 0x41, 0x04, 0x41, 0x7f, 0x36,
        0x02, 0x00, 0x41, 0x00, 0x41, 0x00, 0x41, 0x01, 0x41, 0x10, 0x10, 0x00, 0x1a, 0x0b,
    ];

    const FD_READ_HIGH_IOV: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0c, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x04, 0x7f, 0x7f, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x22, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69,
        0x5f, 0x73, 0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69,
        0x65, 0x77, 0x31, 0x07, 0x66, 0x64, 0x5f, 0x72, 0x65, 0x61, 0x64, 0x00, 0x01, 0x03, 0x02,
        0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d, 0x6f,
        0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a, 0x13,
        0x01, 0x11, 0x00, 0x41, 0x00, 0x41, 0x80, 0x80, 0x80, 0x80, 0x78, 0x41, 0x01, 0x41, 0x00,
        0x10, 0x00, 0x1a, 0x0b,
    ];

    const MEMORY64: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x04, 0x01, 0x60, 0x00, 0x00, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x04, 0x01, 0x07, 0x13, 0x02, 0x06, b'm', b'e', b'm',
        b'o', b'r', b'y', 0x02, 0x00, 0x06, b'_', b's', b't', b'a', b'r', b't', 0x00, 0x00, 0x0a,
        0x04, 0x01, 0x02, 0x00, 0x0b,
    ];

    #[test]
    fn wasm32_address_at_or_above_2gib_is_zero_extended() {
        assert_eq!(guest_addr(i32::MIN), 0x8000_0000);
        assert_eq!(guest_addr(-1), 0xFFFF_FFFF);
        assert_eq!(iovec_addr(i32::MIN, 0).unwrap(), 0x8000_0000);
        assert_eq!(iovec_addr(i32::MIN, 1).unwrap(), 0x8000_0008);
    }

    #[test]
    fn guest_controlled_shim_args_trap() {
        for wasm in [RANDOM_NEG_LEN, FD_READ_NEG_LEN] {
            let err = run_wasm(&AppRunner::new(false), wasm)
                .unwrap_err()
                .to_string();
            assert!(err.contains("guest length out of range"), "{err}");
        }
        for wasm in [RANDOM_NEG_PTR, FD_READ_HIGH_IOV] {
            let err = run_wasm(&AppRunner::new(false), wasm)
                .unwrap_err()
                .to_string();
            assert!(err.contains("out of bounds"), "{err}");
            assert!(!err.contains("guest length out of range"), "{err}");
            assert!(!err.contains("iovec address overflow"), "{err}");
        }
    }

    #[cfg(feature = "validate")]
    #[test]
    fn memory64_module_is_rejected() {
        let err = run_wasm(&AppRunner::new(false), MEMORY64)
            .unwrap_err()
            .to_string();
        assert!(err.contains("memory64"), "{err}");
    }

    #[cfg(not(feature = "validate"))]
    #[test]
    #[should_panic(expected = "received invalid `MemoryType` from `wasmparser`")]
    fn memory64_module_panics_without_validation() {
        let _ = run_wasm(&AppRunner::new(false), MEMORY64);
    }

    const SIMPLE_SEED: [u8; 32] = [
        0xdf, 0xa0, 0x26, 0x40, 0xaf, 0x4f, 0xeb, 0xb3, 0xb4, 0x22, 0xb1, 0x6e, 0x2b, 0x7e, 0x55,
        0x0a, 0x9d, 0x26, 0x36, 0xcb, 0xea, 0x84, 0x17, 0xba, 0x3c, 0xb6, 0x04, 0xcc, 0xfa, 0x60,
        0x92, 0x6b,
    ];

    const SIMPLE_KEYSTREAM: [u8; 64] = [
        0xe1, 0x51, 0x36, 0x47, 0xf6, 0x81, 0x3f, 0x87, 0xe4, 0xd3, 0x2d, 0x47, 0x36, 0xeb, 0x26,
        0x8e, 0x8d, 0xeb, 0xc0, 0x10, 0xcb, 0xd7, 0xe7, 0xd2, 0xe3, 0xae, 0xb8, 0x43, 0xe9, 0x9d,
        0x40, 0x40, 0x5a, 0x3d, 0x87, 0x49, 0xdf, 0x9f, 0x78, 0x5b, 0x90, 0x76, 0xde, 0xee, 0x1e,
        0x7a, 0x9b, 0xc6, 0xe3, 0x37, 0xcc, 0x7b, 0xfc, 0x67, 0x94, 0x3d, 0x00, 0x5b, 0xb4, 0x26,
        0x3e, 0x51, 0xf2, 0x20,
    ];

    fn spell_inputs() -> (App, Transaction, Data) {
        let app = App {
            tag: 't',
            identity: B32([0x11; 32]),
            vk: B32([0x22; 32]),
        };
        let tx = Transaction {
            ins: vec![],
            refs: vec![],
            outs: vec![],
            coin_ins: None,
            coin_outs: None,
            prev_txs: BTreeMap::new(),
            app_public_inputs: BTreeMap::new(),
        };
        let x = Data::from(&0x5au8);
        (app, tx, x)
    }

    #[test]
    fn random_seed_keystream_matches_ietf_chacha20() {
        let (app, tx, x) = spell_inputs();
        let seed = random_seed(&app.vk, 0, &app, &tx, &x).unwrap();
        assert_eq!(seed, SIMPLE_SEED);

        let mut from_stream = [0u8; 64];
        random_stream(seed).apply_keystream(&mut from_stream);
        let mut from_literal_seed = [0u8; 64];
        ChaCha20::new(&SIMPLE_SEED.into(), &[0u8; 12].into())
            .apply_keystream(&mut from_literal_seed);
        assert_eq!(from_stream, SIMPLE_KEYSTREAM);
        assert_eq!(from_literal_seed, SIMPLE_KEYSTREAM);
    }

    #[test]
    fn private_input_does_not_change_seed_and_public_input_does() {
        let (app, tx, x) = spell_inputs();
        let seed = random_seed(&app.vk, 0, &app, &tx, &x).unwrap();
        let empty_w = Data::empty();
        let other_w = Data::from(&0x99u8);
        let stdin_empty = util::write(&(&app, &tx, &x, &empty_w)).unwrap();
        let stdin_other = util::write(&(&app, &tx, &x, &other_w)).unwrap();
        assert_ne!(stdin_empty, stdin_other);
        assert_eq!(seed, SIMPLE_SEED);
        let other_x = Data::from(&0x5bu8);
        assert_ne!(seed, random_seed(&app.vk, 0, &app, &tx, &other_x).unwrap());
    }

    #[test]
    fn simple_app_seed_uses_version_zero_and_wasm_hash() {
        let (app, tx, x) = spell_inputs();
        let wasm_hash = app.vk.clone();
        assert_eq!(wasm_hash, app.vk);
        let simple = random_seed(&wasm_hash, 0, &app, &tx, &x).unwrap();
        let version_3 = random_seed(&wasm_hash, 3, &app, &tx, &x).unwrap();
        let version_4 = random_seed(&wasm_hash, 4, &app, &tx, &x).unwrap();
        let other_hash = B32([0x23; 32]);
        let other_hash_version_3 = random_seed(&other_hash, 3, &app, &tx, &x).unwrap();
        assert_ne!(simple, version_3);
        assert_ne!(version_3, version_4);
        assert_ne!(version_3, other_hash_version_3);
    }

    const RANDOM_GET_65537_AT_0: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x25, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73,
        0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77,
        0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d,
        0x6f, 0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a,
        0x0d, 0x01, 0x0b, 0x00, 0x41, 0x00, 0x41, 0x81, 0x80, 0x04, 0x10, 0x00, 0x1a, 0x0b,
    ];

    const RANDOM_GET_65537_AT_NEG1: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x25, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73,
        0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77,
        0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d,
        0x6f, 0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a,
        0x0d, 0x01, 0x0b, 0x00, 0x41, 0x7f, 0x41, 0x81, 0x80, 0x04, 0x10, 0x00, 0x1a, 0x0b,
    ];

    const RANDOM_GET_65536_AT_0: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x25, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73,
        0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77,
        0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d,
        0x6f, 0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a,
        0x0d, 0x01, 0x0b, 0x00, 0x41, 0x00, 0x41, 0x80, 0x80, 0x04, 0x10, 0x00, 0x1a, 0x0b,
    ];

    const RANDOM_GET_65536_AT_1: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x25, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73,
        0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77,
        0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d,
        0x6f, 0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a,
        0x0d, 0x01, 0x0b, 0x00, 0x41, 0x01, 0x41, 0x80, 0x80, 0x04, 0x10, 0x00, 0x1a, 0x0b,
    ];

    const RANDOM_GET_32_AT_0: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x25, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73,
        0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77,
        0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d,
        0x6f, 0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a,
        0x0b, 0x01, 0x09, 0x00, 0x41, 0x00, 0x41, 0x20, 0x10, 0x00, 0x1a, 0x0b,
    ];

    const RANDOM_GET_0_AT_0: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x25, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73,
        0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77,
        0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d,
        0x6f, 0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a,
        0x0b, 0x01, 0x09, 0x00, 0x41, 0x00, 0x41, 0x00, 0x10, 0x00, 0x1a, 0x0b,
    ];

    #[test]
    fn random_get_rejects_length_above_64k_before_bounds() {
        for wasm in [RANDOM_GET_65537_AT_0, RANDOM_GET_65537_AT_NEG1] {
            let err = run_wasm(&AppRunner::new(false), wasm)
                .unwrap_err()
                .to_string();
            assert!(err.contains("random_get length exceeds 65536"), "{err}");
            assert!(!err.contains("out of bounds"), "{err}");
        }
    }

    #[test]
    fn random_get_one_page_fits_at_zero_and_not_at_one() {
        assert_eq!(
            run_wasm(&AppRunner::new(false), RANDOM_GET_65536_AT_0).unwrap(),
            0
        );
        let err = run_wasm(&AppRunner::new(false), RANDOM_GET_65536_AT_1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("out of bounds"), "{err}");
        assert!(!err.contains("random_get length exceeds"), "{err}");
    }

    #[test]
    fn random_get_fuel_charges_one_per_byte() {
        let charged = run_wasm(&AppRunner::new(true), RANDOM_GET_32_AT_0).unwrap();
        let baseline = run_wasm(&AppRunner::new(true), RANDOM_GET_0_AT_0).unwrap();
        assert_eq!((baseline, charged), (67, 99));
        assert!(charged >= baseline + 32);
        assert_eq!(
            run_wasm(&AppRunner::new(false), RANDOM_GET_32_AT_0).unwrap(),
            0
        );
    }

    /// 60 bytes, then 20, then 4100. The second call crosses the 64-byte ChaCha
    /// block. The third call is one guest request that the host writes as 4096
    /// bytes and then the remainder.
    const RANDOM_GET_SPLIT: &[u8] = &[
        0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0a, 0x02, 0x60, 0x00, 0x00, 0x60,
        0x02, 0x7f, 0x7f, 0x01, 0x7f, 0x02, 0x25, 0x01, 0x16, 0x77, 0x61, 0x73, 0x69, 0x5f, 0x73,
        0x6e, 0x61, 0x70, 0x73, 0x68, 0x6f, 0x74, 0x5f, 0x70, 0x72, 0x65, 0x76, 0x69, 0x65, 0x77,
        0x31, 0x0a, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d, 0x5f, 0x67, 0x65, 0x74, 0x00, 0x01, 0x03,
        0x02, 0x01, 0x00, 0x05, 0x03, 0x01, 0x00, 0x01, 0x07, 0x13, 0x02, 0x06, 0x6d, 0x65, 0x6d,
        0x6f, 0x72, 0x79, 0x02, 0x00, 0x06, 0x5f, 0x73, 0x74, 0x61, 0x72, 0x74, 0x00, 0x01, 0x0a,
        0x1b, 0x01, 0x19, 0x00, 0x41, 0x00, 0x41, 0x3c, 0x10, 0x00, 0x1a, 0x41, 0x3c, 0x41, 0x14,
        0x10, 0x00, 0x1a, 0x41, 0xd0, 0x00, 0x41, 0x84, 0x20, 0x10, 0x00, 0x1a, 0x0b,
    ];
    const SPLIT_TOTAL: usize = 60 + 20 + 4100;
    const BLOCK_AT: usize = 64;
    const CHUNK_AT: usize = 80 + 4096;

    fn empty_tx() -> Transaction {
        Transaction {
            ins: vec![],
            refs: vec![],
            outs: vec![],
            coin_ins: None,
            coin_outs: None,
            prev_txs: BTreeMap::new(),
            app_public_inputs: BTreeMap::new(),
        }
    }

    fn run_guest(wasm: &[u8], x: &Data, w: &Data) -> Vec<u8> {
        let runner = AppRunner::new(false);
        let app = App {
            tag: 't',
            identity: B32::default(),
            vk: runner.vk(wasm),
        };
        let tx = empty_tx();
        CAPTURE_GUEST_MEMORY.with(|flag| flag.set(true));
        GUEST_MEMORY.with(|slot| *slot.borrow_mut() = None);
        let ran = runner.run(wasm, &app, &tx, x, w, &BTreeMap::new(), &BTreeMap::new());
        CAPTURE_GUEST_MEMORY.with(|flag| flag.set(false));
        let memory = GUEST_MEMORY.with(|slot| slot.borrow_mut().take());
        ran.expect("guest ran");
        memory.expect("guest memory")
    }

    fn expected_keystream(wasm: &[u8], x: &Data) -> Vec<u8> {
        let runner = AppRunner::new(false);
        let app = App {
            tag: 't',
            identity: B32::default(),
            vk: runner.vk(wasm),
        };
        let tx = empty_tx();
        let seed = random_seed(&app.vk, 0, &app, &tx, x).unwrap();
        let mut bytes = vec![0u8; SPLIT_TOTAL];
        ChaCha20::new(&seed.into(), &[0u8; 12].into()).apply_keystream(&mut bytes);
        let mut again = vec![0u8; SPLIT_TOTAL];
        ChaCha20::new(&seed.into(), &[0u8; 12].into()).apply_keystream(&mut again);
        assert_eq!(bytes, again);
        bytes
    }

    #[test]
    fn random_get_bytes_ignore_w_follow_x_and_cross_block_and_chunk() {
        let x = Data::empty();
        let with_empty_w = run_guest(RANDOM_GET_SPLIT, &x, &Data::empty());
        let with_other_w = run_guest(RANDOM_GET_SPLIT, &x, &Data::from(&0x99u8));
        assert_eq!(&with_empty_w[..SPLIT_TOTAL], &with_other_w[..SPLIT_TOTAL]);

        let other_x = Data::from(&0x5bu8);
        let with_other_x = run_guest(RANDOM_GET_SPLIT, &other_x, &Data::empty());
        assert_ne!(&with_empty_w[..SPLIT_TOTAL], &with_other_x[..SPLIT_TOTAL]);

        let expected = expected_keystream(RANDOM_GET_SPLIT, &x);
        assert_eq!(&with_empty_w[..SPLIT_TOTAL], expected.as_slice());
        const AROUND_BLOCK: [u8; 16] = [
            0x1a, 0x31, 0xa3, 0xd3, 0x0c, 0x81, 0x1d, 0xb5, 0x65, 0xc5, 0x08, 0x87, 0x57, 0x03,
            0x6c, 0xbc,
        ];
        const AROUND_CHUNK: [u8; 8] = [0xb3, 0x20, 0x79, 0x2d, 0x22, 0x52, 0x70, 0x5f];
        assert_eq!(
            &with_empty_w[BLOCK_AT - 4..BLOCK_AT + 12],
            &AROUND_BLOCK,
            "block {:02x?}",
            &with_empty_w[BLOCK_AT - 4..BLOCK_AT + 12]
        );
        assert_eq!(
            &with_empty_w[CHUNK_AT - 4..CHUNK_AT + 4],
            &AROUND_CHUNK,
            "chunk {:02x?}",
            &with_empty_w[CHUNK_AT - 4..CHUNK_AT + 4]
        );
    }
}
