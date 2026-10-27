use super::*;
use alloc::vec;

fn sample_steps() -> Vec<ProofStep> {
    vec![
        ProofStep::Branch {
            sibling: [0xAA; 32],
            descended_right: true,
        },
        ProofStep::Extension {
            prefix: BitPath::from_key(&[0b1010_1100]).prefix(5),
        },
        ProofStep::Branch {
            sibling: [0x55; 32],
            descended_right: false,
        },
    ]
}

#[test]
fn proof_round_trips_through_borsh_for_inclusion_leaf() {
    let proof = Proof {
        steps: sample_steps(),
        terminal: ProofTerminal::Leaf {
            key_suffix: BitPath::from_key(&[0xDE, 0xAD]).suffix(3),
            value_hash: [0x42; 32],
        },
    };
    let encoded = borsh::to_vec(&proof).expect("borsh encode");
    let decoded: Proof = borsh::from_slice(&encoded).expect("borsh decode");
    assert_eq!(decoded, proof);
}

#[test]
fn proof_round_trips_through_borsh_for_empty_terminal() {
    let proof = Proof {
        steps: Vec::new(),
        terminal: ProofTerminal::Empty,
    };
    let encoded = borsh::to_vec(&proof).expect("borsh encode");
    let decoded: Proof = borsh::from_slice(&encoded).expect("borsh decode");
    assert_eq!(decoded, proof);
}

#[test]
fn proof_round_trips_through_borsh_for_divergent_extension() {
    let proof = Proof {
        steps: sample_steps(),
        terminal: ProofTerminal::DivergentExtension {
            prefix: BitPath::from_key(&[0xCA, 0xFE]).prefix(12),
            child_hash: [0x99; 32],
        },
    };
    let encoded = borsh::to_vec(&proof).expect("borsh encode");
    let decoded: Proof = borsh::from_slice(&encoded).expect("borsh decode");
    assert_eq!(decoded, proof);
}
