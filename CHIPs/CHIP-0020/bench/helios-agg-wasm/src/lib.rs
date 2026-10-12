use getrandom::register_custom_getrandom;
use helios_consensus_core::types::bls::agg_bench;

register_custom_getrandom!(custom_getrandom);

fn custom_getrandom(_dest: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}

#[no_mangle]
pub extern "C" fn bench_prepare() -> u32 {
    agg_bench::bench_prepare()
}

#[no_mangle]
pub extern "C" fn bench_aggregate() -> u32 {
    agg_bench::bench_aggregate()
}

#[no_mangle]
pub extern "C" fn bench_verify() -> u32 {
    agg_bench::bench_verify()
}

#[no_mangle]
pub extern "C" fn bench_both() -> u32 {
    agg_bench::bench_both()
}

#[no_mangle]
pub extern "C" fn bench_subgroup() -> u32 {
    agg_bench::bench_subgroup()
}

#[no_mangle]
pub extern "C" fn bench_torsion() -> u32 {
    agg_bench::bench_torsion()
}

#[no_mangle]
pub extern "C" fn bench_pairing() -> u32 {
    agg_bench::bench_pairing()
}

#[no_mangle]
pub extern "C" fn bench_hash() -> u32 {
    agg_bench::bench_hash()
}

#[no_mangle]
pub extern "C" fn bench_decompress() -> u32 {
    agg_bench::bench_decompress()
}

#[no_mangle]
pub extern "C" fn bench_add() -> u32 {
    agg_bench::bench_add()
}
