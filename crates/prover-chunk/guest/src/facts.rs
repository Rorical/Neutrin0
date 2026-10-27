//! Early cryptographic fact compression; does not authorize a sanction.
#![no_main]
#![deny(unsafe_code)]

sp1_zkvm::entrypoint!(main);
fn main() {
    let bytes = sp1_zkvm::io::read_vec();
    let input: neutrin0_prover_chunk::facts::FactWitness =
        borsh::from_slice(&bytes).expect("canonical facts");
    let statement = neutrin0_prover_chunk::facts::validate_facts(&input)
        .expect("objective cryptographic facts");
    sp1_zkvm::io::commit_slice(&borsh::to_vec(&statement).expect("canonical fact statement"));
}
