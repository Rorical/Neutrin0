use super::*;
use neutrin0_consensus_engine::Engine;
use neutrin0_consensus_types::{BlockProofPublicInputs, Header};
use neutrin0_proof_system::MockProofSystem;
use neutrin0_storage::MemoryDatabase;

fn header(height: u64) -> Header {
    Header {
        height,
        slot: height,
        parent_hash: [height as u8; 32],
        state_root: [0; 32],
        // Each fixture claim names its own offender.
        proposer_index: height as u32,
        vrf_proof: [0; 96],
        transactions_root: [0; 32],
        votes_root: [0; 32],
        da_root: [0; 32],
        runtime_extra: [0; 32],
        inputs_root: [0; 32],
        receipts_root: [0; 32],
        gas_used: 0,
        gas_limit: 1_000_000,
        timestamp: height * 4,
        signature: [0; 96],
    }
}

fn claim(height: u64) -> SlashingEvidence {
    let header = header(height);
    SlashingEvidence::InvalidExecutionClaim {
        proposer_index: header.proposer_index,
        parent: Some(header.clone()),
        receipt: BlockProof {
            height,
            block_hash: header.hash(),
            public_inputs: BlockProofPublicInputs {
                context: Box::default(),
                chain_id: 7,
                height,
                parent_block_hash: header.parent_hash,
                block_hash: header.hash(),
                state_root_before: [0; 32],
                state_root_after: [1; 32],
                transactions_root: [0; 32],
                receipt_root: [0; 32],
                da_root: [0; 32],
                vm_code_hash: [0; 32],
                block_program: [0; 8],
                gas_used: 0,
                gas_limit: 1_000_000,
                proposer_address: [2; 32],
                runtime_extra: [0; 32],
                inputs_root: [0; 32],
            },
            proof_bytes: Vec::new(),
            prover_address: [2; 32],
            statement_key: [3; 32],
        },
        header,
    }
}

#[test]
fn proven_claims_persist_once_per_offender_within_the_bound_and_wait_for_their_chunk() {
    let backend = ChainBackend::new(
        Engine::genesis(
            super::super::state_sync_tests::spec(),
            MemoryDatabase::new(),
        )
        .unwrap(),
        MockProofSystem,
    );
    let first = claim(1);
    let SlashingEvidence::InvalidExecutionClaim { header, .. } = &first else {
        unreachable!()
    };
    persist_claim(&backend.engine, &header.hash(), &first).unwrap();
    let stored = backend.with_engine(|engine| {
        engine
            .store()
            .db()
            .get(Column::Meta, &claim_key(&header.hash()))
            .unwrap()
    });
    assert_eq!(
        stored.map(|bytes| borsh::from_slice::<SlashingEvidence>(&bytes).unwrap()),
        Some(first.clone())
    );
    // A second claim against the same proposer in the same chunk adds
    // nothing: one is enough to slash.
    let SlashingEvidence::InvalidExecutionClaim {
        proposer_index,
        header: mut duplicate,
        parent,
        receipt,
    } = first.clone()
    else {
        unreachable!()
    };
    duplicate.state_root = [9; 32];
    let again = SlashingEvidence::InvalidExecutionClaim {
        proposer_index,
        header: duplicate.clone(),
        parent,
        receipt,
    };
    persist_claim(&backend.engine, &duplicate.hash(), &again).unwrap();
    assert!(backend.with_engine(|engine| {
        engine
            .store()
            .db()
            .get(Column::Meta, &claim_key(&duplicate.hash()))
            .unwrap()
            .is_none()
    }));
    for height in 2..=u64::try_from(MAX_PERSISTED_CLAIMS).unwrap() {
        let evidence = claim(height);
        persist_claim(&backend.engine, &header_hash(&evidence), &evidence).unwrap();
    }
    // Held claims are never evicted for another offender's.
    let extra = claim(200);
    assert!(persist_claim(&backend.engine, &header_hash(&extra), &extra).is_err());
    assert!(backend.with_engine(|engine| {
        engine
            .store()
            .db()
            .get(Column::Meta, &claim_key(&header.hash()))
            .unwrap()
            .is_some()
    }));

    // Nothing is finalized yet, so no claim is ready and none is dropped.
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(backend.submit_execution_claims());
    let held = backend.with_engine(|engine| {
        engine
            .store()
            .db()
            .iter_prefix(Column::Meta, CLAIM_PREFIX)
            .unwrap()
            .len()
    });
    assert_eq!(held, MAX_PERSISTED_CLAIMS);
}

#[test]
fn a_claim_is_forgotten_only_once_the_pool_holds_it() {
    let backend = ChainBackend::new(
        Engine::genesis(
            super::super::state_sync_tests::spec(),
            MemoryDatabase::new(),
        )
        .unwrap(),
        MockProofSystem,
    );
    let evidence = claim(1);
    // A claim the pool does not hold against a live offender is kept for
    // the next finalization.
    assert_eq!(
        backend.evidence_disposition(&evidence),
        super::super::EvidenceDisposition::Retry
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(backend.pool_and_gossip_slashing(evidence.clone()));
    assert_eq!(
        backend.evidence_disposition(&evidence),
        super::super::EvidenceDisposition::Held
    );
}

fn header_hash(evidence: &SlashingEvidence) -> Hash {
    let SlashingEvidence::InvalidExecutionClaim { header, .. } = evidence else {
        unreachable!()
    };
    header.hash()
}
