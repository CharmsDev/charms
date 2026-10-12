use std::time::Instant;

use helios_consensus_core::types::bls::agg_bench;
use wasmtime::{Engine, Linker, Module, Store};

const FUNCS: &[&str] = &[
    "bench_aggregate",
    "bench_verify",
    "bench_both",
    "bench_subgroup",
    "bench_torsion",
    "bench_pairing",
    "bench_hash",
    "bench_decompress",
    "bench_add",
];

fn median(samples: &mut [u128]) -> u128 {
    samples.sort_unstable();
    samples[samples.len() / 2]
}

fn native_side() -> bool {
    let prepared = agg_bench::bench_prepare();
    println!("native_prepare {prepared}");
    if prepared != 1 {
        return false;
    }
    let mut failed = false;
    for name in FUNCS {
        let mut samples = Vec::new();
        let mut ok = true;
        for _ in 0..6 {
            let start = Instant::now();
            let result = match *name {
                "bench_aggregate" => agg_bench::bench_aggregate(),
                "bench_verify" => agg_bench::bench_verify(),
                "bench_both" => agg_bench::bench_both(),
                "bench_subgroup" => agg_bench::bench_subgroup(),
                "bench_torsion" => agg_bench::bench_torsion(),
                "bench_pairing" => agg_bench::bench_pairing(),
                "bench_hash" => agg_bench::bench_hash(),
                "bench_decompress" => agg_bench::bench_decompress(),
                "bench_add" => agg_bench::bench_add(),
                _ => 0,
            };
            let elapsed = start.elapsed().as_micros();
            ok &= result == 1;
            samples.push(elapsed);
        }
        let warmup = samples.remove(0);
        let med = median(&mut samples);
        let lo = samples.iter().copied().min().unwrap_or(0);
        let hi = samples.iter().copied().max().unwrap_or(0);
        println!(
            "native {name} ok={ok} warmup_us={warmup} median_us={med} min_us={lo} max_us={hi} n=5"
        );
        failed |= !ok;
    }
    !failed
}

fn wasm_side(path: &str) -> bool {
    let mut config = wasmtime::Config::new();
    config.cranelift_opt_level(wasmtime::OptLevel::Speed);
    let engine = Engine::new(&config).expect("engine");
    let module = Module::from_file(&engine, path).expect("module");
    println!("wasm_imports {}", module.imports().len());
    for import in module.imports() {
        println!("wasm_import {} {}", import.module(), import.name());
    }
    let linker = Linker::new(&engine);
    let mut store = Store::new(&engine, ());
    let instance = linker
        .instantiate(&mut store, &module)
        .expect("instantiate");
    let prepare = instance
        .get_typed_func::<(), u32>(&mut store, "bench_prepare")
        .expect("prepare export");
    let start = Instant::now();
    let prepared = prepare.call(&mut store, ()).expect("prepare call");
    println!(
        "wasm_prepare {prepared} us={}",
        start.elapsed().as_micros()
    );
    if prepared != 1 {
        return false;
    }
    let mut failed = false;

    for name in FUNCS {
        let func = instance
            .get_typed_func::<(), u32>(&mut store, name)
            .expect(name);
        let mut samples = Vec::new();
        let mut ok = true;
        for _ in 0..6 {
            let start = Instant::now();
            let result = func.call(&mut store, ()).expect(name);
            let elapsed = start.elapsed().as_micros();
            ok &= result == 1;
            samples.push(elapsed);
        }
        let warmup = samples.remove(0);
        let med = median(&mut samples);
        let lo = samples.iter().copied().min().unwrap_or(0);
        let hi = samples.iter().copied().max().unwrap_or(0);
        println!(
            "wasm {name} ok={ok} warmup_us={warmup} median_us={med} min_us={lo} max_us={hi} n=5"
        );
        failed |= !ok;
    }

    let mut fuel_config = wasmtime::Config::new();
    fuel_config.consume_fuel(true);
    fuel_config.cranelift_opt_level(wasmtime::OptLevel::Speed);
    let fuel_engine = Engine::new(&fuel_config).expect("fuel engine");
    let fuel_module = Module::from_file(&fuel_engine, path).expect("fuel module");
    let fuel_linker = Linker::new(&fuel_engine);
    let mut fuel_store = Store::new(&fuel_engine, ());
    fuel_store.set_fuel(u64::MAX).expect("set fuel");
    let fuel_instance = fuel_linker
        .instantiate(&mut fuel_store, &fuel_module)
        .expect("fuel instantiate");
    let fuel_prepare = fuel_instance
        .get_typed_func::<(), u32>(&mut fuel_store, "bench_prepare")
        .expect("fuel prepare");
    let before = fuel_store.get_fuel().expect("fuel");
    let prepared = fuel_prepare
        .call(&mut fuel_store, ())
        .expect("fuel prepare call");
    let prepare_fuel = before - fuel_store.get_fuel().expect("fuel");
    println!("wasm_fuel bench_prepare result={prepared} fuel={prepare_fuel}");
    failed |= prepared != 1;
    for name in FUNCS {
        let func = fuel_instance
            .get_typed_func::<(), u32>(&mut fuel_store, name)
            .expect(name);
        let before = fuel_store.get_fuel().expect("fuel");
        let result = func.call(&mut fuel_store, ()).expect(name);
        let used = before - fuel_store.get_fuel().expect("fuel");
        println!("wasm_fuel {name} result={result} fuel={used}");
        failed |= result != 1;
    }
    !failed
}

fn main() {
    let wasm_path = std::env::args().nth(1).expect("wasm path");
    println!("runner_start");
    let mut ok = true;
    if std::env::var("SKIP_NATIVE").is_err() {
        ok &= native_side();
    }
    ok &= wasm_side(&wasm_path);
    if ok {
        println!("runner_done");
    } else {
        println!("runner_failed");
        std::process::exit(1);
    }
}
