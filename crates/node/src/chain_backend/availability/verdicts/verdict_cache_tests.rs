use super::{ProofVerdict, Rejection, VerdictCache, VerdictToken};

const fn token(program: Option<[u32; 8]>) -> VerdictToken {
    VerdictToken {
        program,
        chain_spec: [3; 32],
        source: [7; 32],
        generation: 0,
    }
}

#[test]
fn verdict_cache_binds_program_and_exact_source() {
    let mut cache = VerdictCache::default();
    let original = token(Some([1; 8]));
    assert!(cache.remember(
        original,
        original.program,
        original.chain_spec,
        ProofVerdict::Valid
    ));
    assert_eq!(
        cache.get(original, original.program, original.chain_spec),
        Some(ProofVerdict::Valid)
    );

    let other_program = VerdictToken {
        program: Some([2; 8]),
        ..original
    };
    assert_eq!(
        cache.get(
            other_program,
            other_program.program,
            other_program.chain_spec
        ),
        None
    );
    assert_eq!(
        cache.get(original, other_program.program, original.chain_spec),
        None
    );
    assert!(!cache.remember(
        original,
        other_program.program,
        original.chain_spec,
        ProofVerdict::Valid
    ));
    let other_source = VerdictToken {
        source: [8; 32],
        ..original
    };
    assert_eq!(
        cache.get(other_source, other_source.program, other_source.chain_spec),
        None
    );
}

#[test]
fn verdict_cache_binds_chain_spec() {
    let mut cache = VerdictCache::default();
    let original = token(Some([1; 8]));
    let rejection = ProofVerdict::Rejected(Rejection::VerifierRejected);
    assert!(cache.remember(original, original.program, original.chain_spec, rejection));
    let changed = VerdictToken {
        chain_spec: [4; 32],
        ..original
    };
    assert_eq!(
        cache.get(changed, changed.program, changed.chain_spec),
        None
    );
    assert_eq!(
        cache.get(original, original.program, changed.chain_spec),
        None
    );
    assert!(!cache.remember(original, original.program, changed.chain_spec, rejection));
}

#[test]
fn bootstrap_generation_fences_late_verdicts() {
    let mut cache = VerdictCache::default();
    let original = token(Some([1; 8]));
    assert!(cache.remember(
        original,
        original.program,
        original.chain_spec,
        ProofVerdict::Valid
    ));
    cache.reset();
    assert_eq!(
        cache.get(original, original.program, original.chain_spec),
        None
    );
    for late in [
        ProofVerdict::Valid,
        ProofVerdict::Rejected(Rejection::VerifierRejected),
    ] {
        assert!(!cache.remember(original, original.program, original.chain_spec, late));
    }
    let current = VerdictToken {
        generation: cache.generation,
        ..original
    };
    assert!(cache.remember(
        current,
        current.program,
        current.chain_spec,
        ProofVerdict::Valid
    ));
    assert_eq!(
        cache.get(original, original.program, original.chain_spec),
        None
    );
    assert_eq!(
        cache.get(current, current.program, current.chain_spec),
        Some(ProofVerdict::Valid)
    );
}

#[test]
fn unkeyed_backend_verdicts_are_never_reused() {
    let mut cache = VerdictCache::default();
    let unkeyed = token(None);
    assert!(cache.remember(unkeyed, None, unkeyed.chain_spec, ProofVerdict::Valid));
    assert!(cache.remember(
        unkeyed,
        None,
        unkeyed.chain_spec,
        ProofVerdict::Rejected(Rejection::VerifierRejected)
    ));
    assert_eq!(cache.get(unkeyed, None, unkeyed.chain_spec), None);
    assert_eq!(cache.entries.len(), 0);
    let keyed = VerdictToken {
        program: Some([1; 8]),
        ..unkeyed
    };
    assert_eq!(cache.get(keyed, keyed.program, keyed.chain_spec), None);
}
