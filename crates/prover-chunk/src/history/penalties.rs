//! Evidence-independent penalty identities shared by evidence guest and runtime.

use neutrin0_consensus_types::FinalityVotePhase;
use neutrin0_consensus_types::tagged_commitment;
use neutrin0_primitives::{Hash, Validator};

/// [`penalty_id`] kind: two headers signed for one slot.
pub const PENALTY_DOUBLE_PROPOSAL: u8 = 0;
/// [`penalty_id`] kind: prevote equivocation, including nil/value conflicts
/// and long-range fork prevotes.
pub const PENALTY_PREVOTE_EQUIVOCATION: u8 = 2;
/// [`penalty_id`] kind: precommit equivocation, including nil/value conflicts
/// and long-range fork precommits.
pub const PENALTY_PRECOMMIT_EQUIVOCATION: u8 = 3;
/// [`penalty_id`] kind: a later vote violating an earlier lock.
pub const PENALTY_LOCK_VIOLATION: u8 = 4;
/// [`penalty_id`] kind: signed acceptance of a rejected block proof.
pub const PENALTY_INVALID_PROOF_SIGNING: u8 = 5;
/// [`penalty_id`] kind: a DA commitment contradicting the published bundle.
pub const PENALTY_DA_COMMITMENT_FRAUD: u8 = 6;
/// [`penalty_id`] kind: absence from an authenticated finality certificate.
pub const PENALTY_INACTIVITY: u8 = 7;
/// [`penalty_id`] kind: a round leader signing two proposals for one round.
pub const PENALTY_DOUBLE_BFT_PROPOSAL: u8 = 8;
/// [`penalty_id`] kind: a header claiming execution results that a valid
/// receipt of the same block and inputs contradicts (design 08).
pub const PENALTY_INVALID_EXECUTION: u8 = 9;
/// [`penalty_id`] kind: a signed block the canonical chain replaced after its
/// exclusive proof window (design 08).
pub const PENALTY_ABANDONMENT: u8 = 10;

/// [`penalty_id`] kind of an equivocation in `phase`. Every equivocation form
/// in one phase shares it, so one offence is never deducted twice.
#[must_use]
pub const fn vote_kind(phase: FinalityVotePhase) -> u8 {
    match phase {
        FinalityVotePhase::Prevote => PENALTY_PREVOTE_EQUIVOCATION,
        FinalityVotePhase::Precommit => PENALTY_PRECOMMIT_EQUIVOCATION,
    }
}

/// Evidence-independent event identifier shared by evidence guest and runtime.
// The offence scope, not the evidence encoding, is consumed. Reordering votes,
// changing a diagnostic reason or supplying a different locking QC cannot
// turn the same offence into a fresh deduction.
pub fn penalty_id(kind: u8, validator: &Validator, scope: u64, round: u32) -> Hash {
    tagged_commitment(
        b"neutrin0-penalty",
        &(
            kind,
            validator.pubkey,
            validator.withdrawal_credentials,
            scope,
            round,
        ),
    )
}
