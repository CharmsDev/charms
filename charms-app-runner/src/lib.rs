use anyhow::{Result, bail, ensure};
use charms_data::{App, B32, Data, Transaction, is_simple_transfer, util};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::Write,
    sync::{Arc, Mutex},
};
use wasmi::{Caller, CompilationMode, Config, Engine, Extern, Linker, Memory, Module, Store};

#[derive(Clone)]
pub struct AppRunner {
    pub count_cycles: bool,
    pub engine: Engine,
}

#[derive(Clone)]
struct HostState {
    stdin: Arc<Mutex<Vec<u8>>>,    // Stdin buffer
    stderr: Arc<Mutex<dyn Write>>, // Stderr buffer
}

// Helper functions for memory access
fn read_i32(memory: &Memory, caller: &mut Caller<'_, HostState>, ptr: i32) -> Result<i32> {
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
    write_memory(memory, caller, ptr as usize, &data)
}

fn read_memory(
    memory: &Memory,
    caller: &mut Caller<'_, HostState>,
    ptr: usize,
    len: usize,
) -> Result<Vec<u8>> {
    let mut buffer = vec![0; len];
    memory.read(caller, ptr, &mut buffer)?;
    Ok(buffer)
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

    // First, read iovec addresses and lengths
    let iov_size = 8;
    let mut iov_info = Vec::new();
    for i in 0..iovs_len {
        let iov_addr = iovs + i * iov_size;
        let buf_ptr = read_i32(&memory, &mut caller, iov_addr).unwrap() as usize;
        let buf_len = read_i32(&memory, &mut caller, iov_addr + 4).unwrap() as usize;
        iov_info.push((buf_ptr, buf_len));
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
        write_memory(&memory, &mut caller, buf_ptr, &data).unwrap();
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

    // Read iovec array from WASM memory
    let iov_size = 8; // sizeof(wasi_iovec_t) = ptr (i32) + len (i32)
    let mut total_written = 0;
    let mut all_data = Vec::new();

    for i in 0..iovs_len {
        let iov_addr = iovs + i * iov_size;
        // Read iovec (buf: i32, buf_len: i32)
        let buf_ptr = read_i32(&memory, &mut caller, iov_addr)? as usize;
        let buf_len = read_i32(&memory, &mut caller, iov_addr + 4)? as usize;

        // Read buffer from WASM memory
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

fn fd_read(caller: Caller<'_, HostState>, fd: i32, iovs: i32, iovs_len: i32, nread: i32) -> i32 {
    fd_read_impl(caller, fd, iovs, iovs_len, nread).unwrap_or_else(|e| {
        eprintln!("error: {}", e);
        -1
    })
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
const MAX_FUEL_PER_RUN: u64 = 1000000000;

impl AppRunner {
    pub fn new(count_cycles: bool) -> Self {
        let mut config = Config::default();
        if count_cycles {
            config.consume_fuel(true);
        }
        config.compilation_mode(CompilationMode::Lazy);
        Self {
            count_cycles,
            engine: Engine::new(&config),
        }
    }

    pub fn vk(&self, binary: &[u8]) -> B32 {
        let hash = Sha256::digest(binary);
        B32(hash.into())
    }

    pub fn run(
        &self,
        app_binary: &[u8],
        app: &App,
        tx: &Transaction,
        x: &Data,
        w: &Data,
    ) -> Result<u64> {
        let vk = self.vk(app_binary);
        ensure!(app.vk == vk, "app.vk mismatch");

        let stdin_content = util::write(&(app, tx, x, w))?;

        let state = HostState {
            stdin: Arc::new(Mutex::new(stdin_content)),
            stderr: Arc::new(Mutex::new(std::io::stderr())),
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

        let module = Module::new(&self.engine, app_binary)?;

        let instance = linker.instantiate_and_start(&mut store, &module)?;

        let Some(main_func) = instance.get_func(&store, "_start") else {
            unreachable!("we should have a main function")
        };
        let result = main_func.typed::<(), ()>(&store)?.call(&mut store, ());

        state.stderr.lock().unwrap().flush()?;

        result.map_err(|e| anyhow::anyhow!("error running wasm: {:?}", e))?;

        let cycles = match self.count_cycles {
            true => MAX_FUEL_PER_RUN - store.get_fuel()?,
            false => 0,
        };
        Ok(cycles)
    }

    pub fn run_all(
        &self,
        app_binaries: &BTreeMap<B32, Vec<u8>>,
        tx: &Transaction,
        app_public_inputs: &BTreeMap<App, Data>,
        app_private_inputs: &BTreeMap<App, Data>,
    ) -> Result<Vec<u64>> {
        let empty = Data::empty();
        let app_cycles = app_public_inputs
            .iter()
            .map(|(app, x)| {
                let w = app_private_inputs.get(app).unwrap_or(&empty);
                if x.is_empty() && w.is_empty() && is_simple_transfer(app, tx) {
                    eprintln!("➡️  simple transfer w.r.t. app: {}", app);
                    return Ok(0);
                }
                match app_binaries.get(&app.vk) {
                    Some(app_binary) => {
                        let cycles = self.run(app_binary, app, tx, x, w)?;
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
