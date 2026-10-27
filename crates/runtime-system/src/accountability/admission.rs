//! Admission of proof-authenticated evidence: the policy checks, the replay
//! and eligibility checks of every claim, and queueing the admitted
//! obligations with their amounts fixed.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;

use neutrin0_consensus_types::evidence::SanctionKind;
use neutrin0_primitives::{BlsPublicKey, Hash};
use neutrin0_runtime_abi::{RuntimeBlockInput, RuntimeTransaction, Sanction};
use neutrin0_runtime_core::StateBackend;

use super::PendingSanction;
use super::markers::{marker_key, replay_marker};
use crate::RuntimePolicy;
use crate::state::liveness_eligible;

/// Check the block's admissions against the governed policy.
///
/// The policy is authenticated state; the anchor supplies the genesis-fixed
/// facts it must respect. These bounds read state, so the stateless input
/// check cannot hold them: they are producer obligations the engine meets
/// when it selects evidence, and a body breaking one has no execution, so
/// its block is never proven and goes stale.
pub(super) fn check_policy(input: &RuntimeBlockInput, policy: &RuntimePolicy) {
    assert!(
        policy.is_valid_for(&input.evidence_anchor),
        "invalid accountability policy"
    );
    let mut admissions = 0_u32;
    for tx in &input.transactions {
        let RuntimeTransaction::SubmitEvidence(submission) = tx else {
            break;
        };
        assert!(
            liveness_amount(submission.statement.kind, policy) != Some(0),
            "liveness penalty disabled by runtime policy"
        );
        // Liveness claims expire with the governable window; safety claims
        // never do. Replay protection is the identity tombstone.
        assert!(
            submission.within_age(input.block_height, policy.evidence_max_age_blocks),
            "evidence window"
        );
        admissions += 1;
    }
    assert!(
        admissions <= policy.evidence_admissions_per_block,
        "evidence admission cap"
    );
}

/// The governed deduction of a liveness class; `None` for safety.
const fn liveness_amount(kind: SanctionKind, policy: &RuntimePolicy) -> Option<u128> {
    match kind {
        SanctionKind::Slash => None,
        SanctionKind::Inactivity => Some(policy.inactivity_leak_amount),
        SanctionKind::Abandonment => Some(policy.abandonment_penalty_amount),
    }
}

/// Validate every admission and its replay key before any state mutates.
///
/// A safety claim duplicates an earlier safety admission of the same
/// identity; a liveness claim duplicates an earlier admission, of either
/// kind, with the same offence id. A liveness claim must also charge a
/// validator its chunk's certified precommit left out: any quorum subset of
/// published precommits forms a valid certificate, so absence from the
/// submitted certificate alone would let anyone charge the validators that
/// subset omits.
pub(super) fn collect_admissions<B: StateBackend>(
    input: &RuntimeBlockInput,
    state: &mut B,
) -> Vec<Sanction> {
    let mut admitted = Vec::new();
    let mut slashed_identities: BTreeSet<BlsPublicKey> = BTreeSet::new();
    let mut offence_ids: BTreeSet<Hash> = BTreeSet::new();
    for tx in &input.transactions {
        let RuntimeTransaction::SubmitEvidence(submission) = tx else {
            break;
        };
        let claim = &submission.statement;
        assert!(state.read(&marker_key(claim)).is_none(), "offence replay");
        assert!(
            claim.kind != SanctionKind::Inactivity
                || liveness_eligible(
                    state,
                    input.evidence_anchor.chunk_id,
                    claim.context.chunk_id,
                    &claim.offender.pubkey,
                    &claim.offender.withdrawal_credentials
                ),
            "unmatured or acknowledged inactivity"
        );
        let fresh = if claim.kind.is_safety() {
            slashed_identities.insert(claim.offender.pubkey)
        } else {
            !offence_ids.contains(&claim.offence_id)
        };
        assert!(fresh, "duplicate offence");
        offence_ids.insert(claim.offence_id);
        admitted.push(Sanction {
            offence_id: claim.offence_id,
            offender: claim.offender.clone(),
            kind: claim.kind,
        });
    }
    admitted
}

pub(super) fn enqueue_admissions<B: StateBackend>(
    state: &mut B,
    input: &RuntimeBlockInput,
    policy: &RuntimePolicy,
    admitted: &[Sanction],
    queue: &mut Vec<PendingSanction>,
) {
    for (sanction, transaction) in admitted.iter().zip(&input.transactions) {
        let RuntimeTransaction::SubmitEvidence(submission) = transaction else {
            unreachable!("admissions form the transaction prefix")
        };
        state.write(
            &replay_marker(
                sanction.kind,
                &sanction.offender.pubkey,
                &sanction.offence_id,
            ),
            alloc::vec![0],
        );
        if sanction.kind == SanctionKind::Slash {
            crate::staking::hold_offender(state, &sanction.offender);
        }
        // A safety offence deducts the whole slashable balance, stake and
        // not-yet-withdrawn unbonding alike; only liveness amounts are
        // governable.
        let amount = liveness_amount(sanction.kind, policy).unwrap_or(u128::MAX);
        queue.push(PendingSanction {
            sanction: sanction.clone(),
            amount,
            reporter: (sanction.kind == SanctionKind::Slash)
                .then_some(submission.statement.reporter)
                .flatten(),
            reporter_reward_bps: if sanction.kind == SanctionKind::Slash {
                policy.reporter_reward_bps
            } else {
                0
            },
        });
    }
}
