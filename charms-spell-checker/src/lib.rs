use charms_client::{NormalizedSpell, SpellProverInput, is_correct};
use charms_data::util;

pub fn main() {
    // Read an input to the program.
    let input_vec = sp1_zkvm::io::read_vec();
    let input: SpellProverInput = util::read(input_vec.as_slice()).unwrap();

    let output = run(input);

    // Commit to the public values of the program.
    let output_vec = util::write(&output).unwrap();
    sp1_zkvm::io::commit_slice(output_vec.as_slice());
}

pub fn run(input: SpellProverInput) -> (String, NormalizedSpell) {
    let SpellProverInput {
        self_spell_vk,
        prev_txs,
        spell,
        tx_ins_beamed_source_utxos,
        app_input,
    } = input;

    // Check the spell that we're proving is correct.
    assert!(is_correct(
        &spell,
        &prev_txs,
        app_input,
        &self_spell_vk,
        &tx_ins_beamed_source_utxos,
        false,
    ));

    eprintln!("Spell is correct!");

    (self_spell_vk, spell)
}

#[cfg(test)]
mod test {
    #[test]
    fn dummy() {}
}
