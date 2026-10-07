use sp1_sdk::{
    HashableKey, ProvingKey,
    blocking::{Prover, ProverClient},
};

fn main() {
    let mut args = std::env::args().skip(1);
    let elf_path = args.next().expect("elf path");
    let lib_path = args.next().expect("path to charms-proof-wrapper/src/lib.rs");

    let elf = std::fs::read(&elf_path).unwrap_or_else(|err| panic!("read {elf_path}: {err}"));
    let client = ProverClient::builder().light().build();
    let pk = client
        .setup(elf.into())
        .unwrap_or_else(|err| panic!("setup {elf_path}: {err}"));
    let vk = pk.verifying_key().hash_u32();
    let rendered = format!(
        "pub const SPELL_CHECKER_VK: [u32; 8] = [\n    {},\n];",
        vk.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")
    );

    let src = std::fs::read_to_string(&lib_path)
        .unwrap_or_else(|err| panic!("read {lib_path}: {err}"));
    let start = src
        .find("pub const SPELL_CHECKER_VK:")
        .expect("SPELL_CHECKER_VK constant missing");
    let end = src[start..]
        .find("];")
        .expect("SPELL_CHECKER_VK constant is not closed")
        + start
        + 2;
    let mut updated = String::with_capacity(src.len() + rendered.len());
    updated.push_str(&src[..start]);
    updated.push_str(&rendered);
    updated.push_str(&src[end..]);
    if updated != src {
        std::fs::write(&lib_path, updated)
            .unwrap_or_else(|err| panic!("write {lib_path}: {err}"));
        println!("updated {lib_path}");
    } else {
        println!("{lib_path} already has this verification key");
    }
    println!("{rendered}");
}
