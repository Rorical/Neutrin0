//! Authenticated historical membership and objective offence validation.
//!
//! Roots belong to the incoming consensus context. Opening a history root does
//! not establish its canonicality: the verifier authenticates that context from
//! the preceding chunk statement (or the chain's genesis specification).

mod abandonment;
mod carried;
mod header_offences;
mod offences;
mod penalties;
mod records;
mod vote_offences;
mod witness;

pub(crate) use abandonment::authorize_abandonment;
pub use carried::{verify_carried, verify_participation};
pub(crate) use carried::{verify_carried_using, verify_participation_using};
pub use header_offences::headerless_parent;
pub(crate) use offences::authorize_evidence_with;
pub use offences::{
    authorize_evidence, authorize_evidence_at_record, authorize_evidence_using, evidence_chunk_id,
};
pub use penalties::{
    PENALTY_ABANDONMENT, PENALTY_DA_COMMITMENT_FRAUD, PENALTY_DOUBLE_BFT_PROPOSAL,
    PENALTY_DOUBLE_PROPOSAL, PENALTY_INACTIVITY, PENALTY_INVALID_EXECUTION,
    PENALTY_INVALID_PROOF_SIGNING, PENALTY_LOCK_VIOLATION, PENALTY_PRECOMMIT_EQUIVOCATION,
    PENALTY_PREVOTE_EQUIVOCATION, penalty_id, vote_kind,
};
pub use records::{HistoricalChunk, HistoricalContext, HistoricalSource, history_commitment};
pub use witness::{
    HistoricalContextOpening, HistoricalOpening, HistoryWitness, MAX_HISTORY_CONTEXT_BYTES,
    MAX_HISTORY_CONTEXT_RECORD_BYTES, MAX_HISTORY_READS, MAX_HISTORY_RECORD_BYTES,
};

/// Historical authorization failure. No failure authorizes a punishment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HistoryError {
    /// Opening, chronological index or incoming root is inconsistent.
    Anchor,
    /// Evidence does not objectively establish the claimed offence.
    Evidence,
    /// Runtime transaction does not match its authorized evidence or amount.
    Transaction,
    /// A program-artifact piece violates the DA lane bounds.
    Program,
    /// A rule lacks an objective witness or its verifier is unavailable.
    Unsupported,
}
