use super::*;
use alloc::collections::BTreeMap;
use alloc::vec;

fn block_proof() -> BlockProof {
    BlockProof {
        height: 3,
        block_hash: [4; 32],
        public_inputs: neutrin0_consensus_types::BlockProofPublicInputs {
            context: alloc::boxed::Box::default(),
            chain_id: 1,
            height: 3,
            parent_block_hash: [2; 32],
            block_hash: [4; 32],
            state_root_before: [5; 32],
            state_root_after: [6; 32],
            transactions_root: [7; 32],
            receipt_root: [8; 32],
            da_root: [9; 32],
            vm_code_hash: [10; 32],
            block_program: [11; 8],
            gas_used: 12,
            gas_limit: 13,
            proposer_address: [14; 32],
            runtime_extra: [15; 32],
            inputs_root: [0; 32],
        },
        prover_address: [14; 32],
        statement_key: [0; 32],
        proof_bytes: vec![16, 17],
    }
}

#[test]
fn borrowed_requests_encode_and_identify_like_owned_requests() {
    let requests = [
        FactRequest::Signature {
            key: [1; 48],
            message: vec![2, 3],
            signature: [4; 96],
            possession: false,
        },
        FactRequest::Signature {
            key: [1; 48],
            message: vec![1; 48],
            signature: [4; 96],
            possession: true,
        },
        FactRequest::Aggregate {
            keys: vec![[5; 48], [6; 48]],
            message: Vec::new(),
            signature: [7; 96],
        },
        FactRequest::Block {
            key: [8; 8],
            proof: block_proof(),
        },
    ];
    for request in &requests {
        let borrowed = request.borrowed();
        assert_eq!(
            borsh::to_vec(&borrowed).unwrap(),
            borsh::to_vec(request).unwrap()
        );
        assert_eq!(
            request.id(),
            neutrin0_consensus_types::tagged_commitment(b"neutrin0-cryptographic-fact", request)
        );
        assert_eq!(borrowed.id(), request.id());
        assert_eq!(&borrowed.to_request(), request);
    }
}

#[test]
fn packing_groups_messages_but_preserves_ids_verdicts_and_statement_order() {
    let requests: Vec<_> = (0_u16..128)
        .map(|index| {
            let mut signature = [1; 96];
            signature[..2].copy_from_slice(&index.to_le_bytes());
            (
                FactRequest::Signature {
                    key: [3; 48],
                    message: vec![u8::from(index % 2 != 0)],
                    signature,
                    possession: false,
                },
                index % 3 != 0,
            )
        })
        .collect();
    let originals: BTreeMap<_, _> = requests
        .iter()
        .map(|(request, valid)| (request.id(), *valid))
        .collect();
    let mut reversed = requests.clone();
    reversed.reverse();
    let batches = pack_requests(requests).unwrap();
    assert_eq!(batches, pack_requests(reversed).unwrap());
    assert_eq!(batches.len(), 2);
    for batch in &batches {
        assert_eq!(batch.len(), MAX_FACTS);
        assert!(batch.windows(2).all(|pair| pair[0].0.id() < pair[1].0.id()));
        let FactRequest::Signature { message, .. } = &batch[0].0 else {
            panic!("signature batch");
        };
        assert!(batch.iter().all(|(request, _)| matches!(request, FactRequest::Signature { message: other, .. } if other == message)));
    }
    let packed: BTreeMap<_, _> = batches
        .into_iter()
        .flatten()
        .map(|(request, valid)| (request.id(), valid))
        .collect();
    assert_eq!(packed, originals);
}

#[test]
fn packing_separates_kinds_and_suites_and_rejects_duplicate_ids() {
    let signature = FactRequest::Signature {
        key: [1; 48],
        message: vec![1; 48],
        signature: [2; 96],
        possession: false,
    };
    let pop = FactRequest::Signature {
        key: [1; 48],
        message: vec![1; 48],
        signature: [2; 96],
        possession: true,
    };
    let aggregate = FactRequest::Aggregate {
        keys: vec![[1; 48]],
        message: vec![1; 48],
        signature: [2; 96],
    };
    let block = FactRequest::Block {
        key: [3; 8],
        proof: block_proof(),
    };
    assert_ne!(signature.scheduling_key(), pop.scheduling_key());
    assert_ne!(signature.scheduling_key(), aggregate.scheduling_key());
    assert_ne!(aggregate.scheduling_key(), block.scheduling_key());
    let batch = pack_requests(vec![
        (block, false),
        (aggregate, true),
        (pop, false),
        (signature.clone(), true),
    ])
    .unwrap();
    assert!(
        batch[0]
            .windows(2)
            .all(|pair| pair[0].0.id() < pair[1].0.id())
    );
    assert!(pack_requests(vec![(signature.clone(), true), (signature, false)]).is_err());
    assert_eq!(
        pack_requests(Vec::new()).unwrap(),
        Vec::<Vec<(FactRequest, bool)>>::new()
    );
}

#[test]
fn the_fact_guest_proves_no_block_acceptance() {
    let block = FactRequest::Block {
        key: [3; 8],
        proof: block_proof(),
    };
    // Acceptance is recursion where the receipt is consumed; the witness
    // is refused before any verifier runs.
    let accepted = FactWitness {
        statement: FactStatement {
            facts: vec![ProvenFact {
                id: block.id(),
                valid: true,
            }],
        },
        requests: vec![block],
    };
    assert_eq!(validate_facts(&accepted), Err(HistoryError::Evidence));
}
