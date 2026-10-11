use sp1_sdk::{
    HashableKey, ProvingKey,
    blocking::{Prover, ProverClient},
};
use std::{env, fs};

fn main() {
    let mut args = env::args().skip(1);
    let mode = match args.next().as_deref() {
        Some("checker") => Mode::Checker,
        Some("wrapper") => Mode::Wrapper,
        _ => panic!("usage: spell-checker-vk <checker|wrapper> <elf> <lib.rs> <vk.bin>"),
    };
    let elf_path = args.next().expect("elf path");
    let lib_path = args
        .next()
        .expect("path to the source file that holds the verification key");
    let vk_path = args.next().expect("path to the serialized verifying key");
    if args.next().is_some() {
        panic!("usage: spell-checker-vk <checker|wrapper> <elf> <lib.rs> <vk.bin>");
    }

    let elf = fs::read(&elf_path).unwrap_or_else(|err| panic!("read {elf_path}: {err}"));
    let client = ProverClient::builder().light().build();
    let pk = client
        .setup(elf.into())
        .unwrap_or_else(|err| panic!("setup {elf_path}: {err}"));
    let vk = pk.verifying_key();

    let src = fs::read_to_string(&lib_path).unwrap_or_else(|err| panic!("read {lib_path}: {err}"));
    let updated = match mode {
        Mode::Checker => replace_spell_checker_vk(&src, &vk.hash_u32()),
        Mode::Wrapper => replace_spell_vk(&src, &vk.bytes32_raw()),
    };
    if updated != src {
        fs::write(&lib_path, updated).unwrap_or_else(|err| panic!("write {lib_path}: {err}"));
        println!("updated {lib_path}");
    } else {
        println!("{lib_path} already has this verification key");
    }

    let bytes =
        bincode::serialize(vk).unwrap_or_else(|err| panic!("serialize verifying key: {err}"));
    fs::write(&vk_path, bytes).unwrap_or_else(|err| panic!("write {vk_path}: {err}"));
    println!("wrote {vk_path}");
    match mode {
        Mode::Checker => println!("{}", render_spell_checker_vk(&vk.hash_u32())),
        Mode::Wrapper => println!("{}", vk.bytes32()),
    }
}

enum Mode {
    Checker,
    Wrapper,
}

fn render_spell_checker_vk(vk: &[u32; 8]) -> String {
    let body = vk.iter().map(u32::to_string).collect::<Vec<_>>().join(", ");
    format!("pub const SPELL_CHECKER_VK: [u32; 8] = [\n    {body},\n];")
}

fn replace_spell_checker_vk(src: &str, vk: &[u32; 8]) -> String {
    let rendered = render_spell_checker_vk(vk);
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
    updated
}

fn replace_spell_vk(src: &str, vk: &[u8; 32]) -> String {
    let start = src
        .find("pub const SPELL_VK:")
        .expect("SPELL_VK constant missing");
    let hex_open = src[start..]
        .find("hex!(\"")
        .expect("SPELL_VK hex literal missing")
        + start
        + "hex!(\"".len();
    let hex_end = src[hex_open..]
        .find('"')
        .expect("SPELL_VK hex literal is not closed")
        + hex_open;
    let mut updated = String::with_capacity(src.len());
    updated.push_str(&src[..hex_open]);
    updated.push_str(&hex_encode(vk));
    updated.push_str(&src[hex_end..]);
    updated
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{hex_encode, replace_spell_checker_vk, replace_spell_vk};

    const SPELL_CHECKER_VK: [u32; 8] = [
        594351357, 1129065526, 1335503287, 1134438958, 1095361067, 1699468311, 1887077198,
        882329457,
    ];

    #[test]
    fn spell_checker_renderer_matches_wrapper_source() {
        let src = include_str!("../../src/lib.rs");
        assert_eq!(replace_spell_checker_vk(src, &SPELL_CHECKER_VK), src);
    }

    #[test]
    fn spell_checker_renderer_replaces_only_the_constant() {
        let src = include_str!("../../src/lib.rs");
        let mut vk = SPELL_CHECKER_VK;
        vk[0] = 1;
        let updated = replace_spell_checker_vk(src, &vk);
        assert!(updated.contains("pub const SPELL_CHECKER_VK: [u32; 8] = [\n    1, "));
        assert!(updated.ends_with(&src[src.find("pub fn main()").unwrap()..]));
        assert_eq!(replace_spell_checker_vk(&updated, &vk), updated);
    }

    #[test]
    fn spell_vk_replacement_matches_charms_lib_source() {
        let src = include_str!("../../../charms-lib/src/lib.rs");
        let vk = hex_decode_32("00425796f4c4fa050043eee14d801b4f935244e44aad6a28de0cd5cb3de0ae52");
        assert_eq!(replace_spell_vk(src, &vk), src);
    }

    #[test]
    fn spell_vk_replacement_writes_lowercase_hex() {
        let src = include_str!("../../../charms-lib/src/lib.rs");
        let vk = [0xab; 32];
        let updated = replace_spell_vk(src, &vk);
        let encoded = hex_encode(&vk);
        assert!(updated.contains(&format!("hex!(\"{encoded}\")")));
        assert!(
            !updated.contains("00425796f4c4fa050043eee14d801b4f935244e44aad6a28de0cd5cb3de0ae52")
        );
        assert_eq!(replace_spell_vk(&updated, &vk), updated);
    }

    fn hex_decode_32(hex: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }
}
