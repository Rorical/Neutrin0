//! Which peer-import failures are verdicts that may penalize the relaying peer.

use super::ChainBackend;
use neutrin0_consensus_engine::ImportError;
use neutrin0_proof_system::MockProofSystem;
use neutrin0_storage::MemoryDatabase;
use neutrin0_sync::SyncBackendError;

type Backend = ChainBackend<MemoryDatabase, MockProofSystem>;

fn gas_limit_mismatch() -> ImportError<<MemoryDatabase as neutrin0_storage::Database>::Error> {
    ImportError::GasLimitMismatch {
        expected: 30_000_000,
        actual: 1,
    }
}

#[test]
fn a_header_failing_only_against_a_projected_context_is_ignored() {
    // Another candidate of the open chunk may still win and give the header
    // another committee or seed, so the peer relaying it is not penalized.
    let projected = ImportError::ProjectedContext(Box::new(gas_limit_mismatch()));
    assert!(matches!(
        Backend::map_import_err(projected),
        SyncBackendError::NotAvailable(_)
    ));
    // The same failure against a confirmed context is a verdict.
    assert!(matches!(
        Backend::map_import_err(gas_limit_mismatch()),
        SyncBackendError::Rejected(_)
    ));
}

#[test]
fn a_candidate_whose_execution_diverges_from_reproducing_writes_is_ignored() {
    // Following nodes accept such a candidate on its writes; only a receipt
    // can settle it, as an invalid execution claim against the proposer.
    let diverged = ImportError::ExecutionDiverges(Box::new(gas_limit_mismatch()));
    assert!(matches!(
        Backend::map_import_err(diverged),
        SyncBackendError::NotAvailable(_)
    ));
}
