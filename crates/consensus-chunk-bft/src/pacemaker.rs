//! Persistent, phase-aware deadlines and authenticated round synchronization.

use alloc::{collections::BTreeMap, vec::Vec};
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::{RoundChange, RoundChangeCertificate};
use neutrin0_primitives::Validator;

use crate::BftError;
use crate::stake::{quorum_reached, total_active_stake};
use crate::verify::verify_round_change_native;

/// Current local signing phase. Received votes remain useful in every phase.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub enum RoundStep {
    /// Wait for the designated leader's independently valid proposal.
    Propose,
    /// Collect value/nil prevotes before choosing a precommit.
    Prevote,
    /// Collect value/nil precommits before changing round.
    Precommit,
    /// Local timeout has emitted its next-round report.
    AwaitRound,
}

/// Required local action when a phase's deadline expires.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeoutAction {
    /// No legal timely proposal: sign an explicit nil prevote.
    PrevoteNil,
    /// No value QC: sign an explicit nil precommit while preserving every lock.
    PrecommitNil,
    /// Signed readiness for a later round after completing this round's phases.
    RoundChange {
        /// Exact requested next round.
        round: u32,
    },
}

/// Phase deadlines and bounded signed-report collection, durable with the session.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct Pacemaker {
    chunk_id: u64,
    round: u32,
    step: RoundStep,
    deadline: u64,
    base_timeout: u64,
    timeout_step: u64,
    reports: BTreeMap<u32, BTreeMap<u32, RoundChange>>,
}

impl Pacemaker {
    /// Start at propose with an increasing per-round deadline.
    /// A positive backoff is required for unknown eventual network delay.
    #[must_use]
    pub fn new(chunk_id: u64, round: u32, now: u64, base_timeout: u64, timeout_step: u64) -> Self {
        let mut state = Self {
            chunk_id,
            round,
            step: RoundStep::Propose,
            deadline: now,
            base_timeout: base_timeout.max(1),
            timeout_step: timeout_step.max(1),
            reports: BTreeMap::new(),
        };
        state.reset_deadline(now);
        state
    }

    /// Current round.
    #[must_use]
    pub const fn round(&self) -> u32 {
        self.round
    }

    /// Current local phase.
    #[must_use]
    pub const fn step(&self) -> RoundStep {
        self.step
    }

    /// Absolute phase deadline in the caller's monotonic clock units.
    #[must_use]
    pub const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// A legal proposal has selected the local prevote; never rewind a later phase.
    pub fn enter_prevote(&mut self, now: u64) {
        if self.step == RoundStep::Propose {
            self.step = RoundStep::Prevote;
            self.reset_deadline(now);
        }
    }

    /// A verified value/nil QC selects precommit; never rewind an emitted report.
    pub fn enter_precommit(&mut self, now: u64) {
        if matches!(self.step, RoundStep::Propose | RoundStep::Prevote) {
            self.step = RoundStep::Precommit;
            self.reset_deadline(now);
        }
    }

    /// Finish this round before reporting readiness for the next one.
    /// Duplicate quorum observations cannot postpone retransmission deadlines.
    pub fn enter_await_round(&mut self, now: u64) {
        if self.step != RoundStep::AwaitRound {
            self.step = RoundStep::AwaitRound;
            self.reset_deadline(now);
        }
    }

    /// Emit each deadline action once. Nil never changes or clears a value lock.
    pub fn on_timeout(&mut self, now: u64) -> Option<TimeoutAction> {
        if now < self.deadline {
            return None;
        }
        let action = match self.step {
            RoundStep::Propose => {
                self.step = RoundStep::Prevote;
                TimeoutAction::PrevoteNil
            }
            RoundStep::Prevote => {
                self.step = RoundStep::Precommit;
                TimeoutAction::PrecommitNil
            }
            RoundStep::Precommit => {
                let round = self.round.checked_add(1)?;
                self.step = RoundStep::AwaitRound;
                TimeoutAction::RoundChange { round }
            }
            RoundStep::AwaitRound => TimeoutAction::RoundChange {
                round: self.round.checked_add(1)?,
            },
        };
        self.reset_deadline(now);
        Some(action)
    }

    /// Advance after independently verified quorum-certified round entry.
    /// The caller persists this transition before any new-round signing.
    pub fn advance_round(&mut self, round: u32, now: u64) -> Result<(), BftError> {
        if round <= self.round {
            return Err(BftError::RoundNotIncreased {
                current: self.round,
                requested: round,
            });
        }
        self.round = round;
        self.step = RoundStep::Propose;
        self.reports.retain(|reported, _| *reported > round);
        self.reset_deadline(now);
        Ok(())
    }

    /// Validate the immutable context before restoring durable phase state.
    #[must_use]
    pub const fn context_matches(&self, chunk_id: u64, round: u32, base: u64, step: u64) -> bool {
        self.chunk_id == chunk_id
            && self.round == round
            && self.base_timeout == if base == 0 { 1 } else { base }
            && self.timeout_step == if step == 0 { 1 } else { step }
    }

    /// Reauthenticate every saved report instead of trusting serialized state.
    pub fn validate_saved_reports(
        &self,
        domain: neutrin0_primitives::ConsensusDomain,
        validators: &[Validator],
        fraction: (u64, u64),
    ) -> Result<(), BftError> {
        if self.reports.len() > 2 {
            return Err(BftError::WrongVoteTarget);
        }
        let mut verified = Vec::new();
        for (round, reports) in &self.reports {
            if *round <= self.round || reports.len() > validators.len() {
                return Err(BftError::WrongVoteTarget);
            }
            for (index, report) in reports {
                if report.chunk_id != self.chunk_id
                    || report.round != *round
                    || report.validator_index != *index
                {
                    return Err(BftError::WrongVoteTarget);
                }
                verify_round_change_native(
                    domain,
                    validators,
                    None,
                    report,
                    fraction,
                    &mut verified,
                )?;
            }
        }
        Ok(())
    }

    /// Collect independently authenticated readiness; one report per signer/round.
    /// Two nearest future rounds bound memory. Full certificates may authenticate
    /// direct catchup from any later round without trusting isolated hints.
    pub fn accept_round_change(
        &mut self,
        domain: neutrin0_primitives::ConsensusDomain,
        validators: &[Validator],
        fraction: (u64, u64),
        report: RoundChange,
    ) -> Result<Option<RoundChangeCertificate>, BftError> {
        if report.chunk_id != self.chunk_id || report.round <= self.round {
            return Err(BftError::WrongVoteTarget);
        }
        let reported_round = report.round;
        let reports = self.reports.entry(reported_round).or_default();
        // A held report was verified on arrival; only a new signer pays the
        // signature and carried-quorum checks.
        match reports.get(&report.validator_index) {
            Some(existing) if existing != &report => return Err(BftError::WrongVoteTarget),
            Some(_) => {}
            None => {
                verify_round_change_native(
                    domain,
                    validators,
                    None,
                    &report,
                    fraction,
                    &mut Vec::new(),
                )?;
                reports.insert(report.validator_index, report);
            }
        }
        while self.reports.len() > 2 {
            let last = *self.reports.last_key_value().expect("nonempty reports").0;
            self.reports.remove(&last);
        }
        let Some(reports) = self.reports.get(&reported_round) else {
            return Ok(None);
        };
        let stake = reports.keys().try_fold(0_u128, |stake, index| {
            stake
                .checked_add(validators[*index as usize].effective_stake)
                .ok_or(BftError::StakeOverflow)
        })?;
        if !quorum_reached(stake, total_active_stake(validators)?, fraction) {
            return Ok(None);
        }
        Ok(Some(RoundChangeCertificate {
            chunk_id: self.chunk_id,
            round: reported_round,
            reports: reports.values().cloned().collect::<Vec<_>>(),
        }))
    }

    fn reset_deadline(&mut self, now: u64) {
        self.deadline = now.saturating_add(
            self.base_timeout
                .saturating_add(u64::from(self.round).saturating_mul(self.timeout_step)),
        );
    }
}

#[cfg(test)]
mod tests;
