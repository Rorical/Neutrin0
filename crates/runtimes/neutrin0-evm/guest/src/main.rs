//! Neutrin0 EVM runtime SP1 Guest.
//!
//! Reads a borsh-encoded `(RuntimeBlockInput, StateWitness, evidence memberships,
//! prover address)` from stdin, builds a `WitnessState`, runs the shared
//! `apply_block`, and commits the borsh-encoded `BlockReceiptStatement`, the
//! `RuntimeBlockOutput` plus the prover-chosen attribution, as the proof's
//! public values (design 08).

#![no_main]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use neutrin0_evm_runtime_core::{apply_prepared_block, prepare_block};

use neutrin0_runtime_abi::{BlockReceiptStatement, RuntimeBlockOutput};
use neutrin0_runtime_abi::{RuntimeBlockInput, StateWitness};
use neutrin0_runtime_core::WitnessState;
use sha2::{Digest, Sha256};

sp1_zkvm::entrypoint!(main);

fn main() {
    // Single borsh blob carries runtime input, state witness and evidence openings
    // so we only touch sp1_zkvm I/O once.
    let bytes: Vec<u8> = sp1_zkvm::io::read_vec();
    assert!(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX)
            <= neutrin0_consensus_types::evidence::EvidenceAnchor::MAX_PROVING_INPUT_BYTES,
        "absolute block input allocation ceiling"
    );
    let (input, witness, memberships, prover_address): (
        RuntimeBlockInput,
        StateWitness,
        Vec<neutrin0_consensus_types::evidence::EvidenceMembership>,
        [u8; 32],
    ) = borsh::from_slice(&bytes).expect("decode block input, evidence memberships and prover");
    assert!(
        input
            .evidence_anchor
            .accepts_proving_input_size(u64::try_from(bytes.len()).unwrap_or(u64::MAX)),
        "authenticated block input allocation limit"
    );
    drop(bytes);

    let checked = prepare_block(&input).expect("valid EVM runtime block input");
    let submissions: Vec<_> = input
        .transactions
        .iter()
        .filter_map(|tx| match tx {
            neutrin0_runtime_abi::RuntimeTransaction::SubmitEvidence(submission) => {
                Some(submission)
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        submissions.len(),
        memberships.len(),
        "exact attachment coverage"
    );
    let mut verified = alloc::collections::BTreeSet::new();
    for (submission, membership) in submissions.iter().zip(&memberships) {
        assert!(
            membership.binds(
                &submission.statement,
                &input.evidence_anchor.fact_guest_vk_digest
            ),
            "batch membership"
        );
        let public_values = borsh::to_vec(&membership.batch).expect("canonical evidence batch");
        let digest: [u8; 32] = Sha256::digest(&public_values).into();
        if verified.insert(digest) {
            sp1_zkvm::lib::verify::verify_sp1_proof(
                &input.evidence_anchor.evidence_guest_vk_digest,
                &digest,
            );
        }
    }

    // Authenticate the claimed pre-state root before state execution.
    let mut state =
        WitnessState::from_owned(witness).expect("witness must match claimed pre_state_root");

    let output: RuntimeBlockOutput = apply_prepared_block(&checked, &mut state);

    // Attribution is committed next to the statement and accepted at any
    // value by verifiers; it never influences execution.
    let statement = BlockReceiptStatement {
        output,
        prover_address,
    };
    let output_bytes = borsh::to_vec(&statement).expect("encode BlockReceiptStatement");
    sp1_zkvm::io::commit_slice(&output_bytes);
}
