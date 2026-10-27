use super::*;
use neutrin0_consensus_types::ChunkProofPublicInputs;
use neutrin0_consensus_types::history_proof::{
    ChainBinding, ChunkReceiptStatement, ConsensusBoundary, ConsensusStatement,
};
use neutrin0_primitives::{BoundedBytes, ScheduledFork, runtime_account};

/// A pinned one-validator predecessor file and its specification.
fn predecessor() -> (String, ChainSpec) {
    let raw = format!(
        "name = \"fork-test\"\nchain_id = 7\ngenesis_time = 1700000000\n\
         genesis_gas_limit = 30000000\n\n[[validators]]\n{}effective_stake = \"32000000000000000000\"\n",
        crate::chain_spec::test_validator_fields(1, [0xab; 20])
    );
    let mut file = ChainSpecFile::from_toml_str(&raw).unwrap();
    file.pin_embedded_programs().unwrap();
    let raw = format!("{}\n{}", raw.trim_end(), file.programs_toml().unwrap());
    let spec = ChainSpecFile::from_toml_str(&raw)
        .unwrap()
        .to_chain_spec()
        .unwrap();
    (raw, spec)
}

/// The predecessor's History proof of chunk 0, ending at a boundary that
/// carries `fork`.
fn proof(spec: &ChainSpec, fork: Option<ScheduledFork>) -> HistoryProof {
    let end = ConsensusBoundary {
        next_chunk_id: 1,
        height: spec.consensus.chunk_size,
        block_hash: [9; 32],
        slot: 7,
        fork,
        ..ConsensusBoundary::genesis(spec)
    };
    HistoryProof {
        statement: ChunkReceiptStatement {
            statement: ConsensusStatement {
                chain: ChainBinding::new(spec),
                start: ConsensusBoundary::genesis(spec),
                end,
                chunk: ChunkProofPublicInputs {
                    chunk_id: 0,
                    start_height: 1,
                    end_height: end.height,
                    start_state_root: [0; 32],
                    end_state_root: [0; 32],
                    start_block_hash: [0; 32],
                    end_block_hash: [9; 32],
                    block_hash_root: [0; 32],
                    block_proof_root: [0; 32],
                    vrf_proof_root: [0; 32],
                    active_validator_set_root: [0; 32],
                    next_validator_set_root: [0; 32],
                    next_identity_sanctions_root: [0; 32],
                    da_root: [0; 32],
                },
                finality_cert_hash: [0; 32],
            },
            chunk_prover_address: runtime_account([5; 20]),
        },
        receipt: BoundedBytes::new(vec![7]).unwrap(),
    }
}

/// The successor keeps the predecessor's file and genesis, starts at the
/// endpoint with this binary's programs and signs below it under the
/// predecessor's domain, but only when governance scheduled exactly these
/// programs at the endpoint.
#[test]
fn the_successor_derives_only_for_the_programs_governance_scheduled() {
    let (raw, predecessor) = predecessor();
    assert!(successor_template(&raw, &predecessor, &proof(&predecessor, None)).is_err());
    let other = ScheduledFork {
        count: 1,
        successor: [3; 32],
    };
    let template =
        successor_template(&raw, &predecessor, &proof(&predecessor, Some(other))).unwrap();
    assert!(
        complete_successor(&template)
            .unwrap_err()
            .to_string()
            .contains("schedules no fork to these programs")
    );

    // This binary is its own successor here: same pinned programs.
    let scheduled = ScheduledFork {
        count: 1,
        successor: predecessor.pinned_programs().commitment(),
    };
    let endpoint = proof(&predecessor, Some(scheduled));
    let template = successor_template(&raw, &predecessor, &endpoint).unwrap();
    let (text, derived) = complete_successor(&template).unwrap();
    let anchor = derived.fork.as_deref().unwrap();
    assert_eq!(anchor.predecessor, predecessor.hash());
    assert_eq!(anchor.count, 1);
    assert_eq!(derived.fork_endpoint(), Some(*endpoint.end()));
    assert_eq!(anchor.start.fork, None);
    assert_eq!(anchor.endpoint_prover, runtime_account([5; 20]));
    assert_eq!(derived.genesis_state_root, predecessor.genesis_state_root);
    let domain = derived.consensus_domain();
    assert_eq!(domain.at_chunk(0).chain_spec_hash, predecessor.hash());
    assert_eq!(domain.at_chunk(1).chain_spec_hash, derived.hash());

    // A node derives the file once and reads it afterwards.
    let directory = std::env::temp_dir().join(format!(
        "neutrin0-fork-handoff-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = fs::remove_dir_all(&directory);
    let (predecessor_dir, successor_dir) = (directory.join("old"), directory.join("new"));
    assert!(Handoff::prepare(&predecessor_dir, &successor_dir).is_err());
    fs::create_dir_all(predecessor_dir.join(ENDPOINT_DIR)).unwrap();
    fs::write(predecessor_dir.join(ENDPOINT_DIR).join(TEMPLATE), &template).unwrap();
    let handoff = Handoff::prepare(&predecessor_dir, &successor_dir).unwrap();
    assert_eq!(fs::read_to_string(&handoff.spec_path).unwrap(), text);
    fs::remove_dir_all(&predecessor_dir).unwrap();
    assert!(Handoff::prepare(&predecessor_dir, &successor_dir).is_ok());
    fs::remove_dir_all(&directory).unwrap();
}

#[test]
fn named_tables_are_dropped_with_their_keys() {
    let raw = "name = \"a\"\n[programs]\nx = 1\n[fork]\ny = 2\n[[fork.prior_domains]]\nz = 3\n[[validators]]\nw = 4\n";
    assert_eq!(
        strip_tables(raw, &["programs", "fork", "fork.prior_domains"]),
        "name = \"a\"\n[[validators]]\nw = 4\n"
    );
}
