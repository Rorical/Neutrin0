//! Binding the configured local validator keys to the authenticated active set.

use neutrin0_storage::Database;

use crate::engine::Engine;
use crate::proposer::ProposerKey;

impl<DB: Database> Engine<DB> {
    /// Configure the local validator's BLS key used to sign prevotes
    /// and precommits during live BFT rounds.
    ///
    /// The configured index is a hint; the BLS public key is rebound to the
    /// authenticated current active set. An absent, slashed or zero-stake key
    /// remains configured, ready for a future activation, without signing.
    /// Nodes that follow without voting can leave this unset; the
    /// engine then opens BFT sessions purely to accumulate peer votes
    /// and emits no [`BftAction::BroadcastPrevote`](crate::BftAction::BroadcastPrevote) /
    /// [`BftAction::BroadcastPrecommit`](crate::BftAction::BroadcastPrecommit) actions.
    pub fn set_local_voter(&mut self, voter: ProposerKey) {
        self.local_voter = Some(self.bind_active_proposer(&voter).unwrap_or(voter));
    }

    /// Resolve a configured BLS identity against the authenticated current set.
    pub(crate) fn bind_active_proposer(&self, proposer: &ProposerKey) -> Option<ProposerKey> {
        self.active_validator_set()
            .iter()
            .position(|validator| {
                validator.pubkey == *proposer.public_key_bytes() && validator.effective_stake > 0
            })
            .and_then(|position| u32::try_from(position).ok())
            .map(|index| proposer.with_validator_index(index))
    }

    /// Retain an inactive configured key while selecting only active signers.
    pub(crate) fn active_local_voter(&self) -> Option<ProposerKey> {
        if !self.local_signing_enabled() || self.certified_execution.is_some() {
            return None;
        }
        self.local_voter
            .as_ref()
            .and_then(|voter| self.bind_active_proposer(voter))
    }

    /// Keep a second local key for a key rotation (design 19): once a
    /// verified validator-set transition seats it in place of the local
    /// voter, the two swap, so votes and blocks follow the seat's key.
    pub fn set_standby_voter(&mut self, voter: ProposerKey) {
        self.standby_voter = Some(voter);
        self.rebind_local_voter();
    }

    /// Refresh the stored hint after a verified validator-set transition, and
    /// swap in the standby key when a rotation seated it in place of the
    /// local voter.
    pub(crate) fn rebind_local_voter(&mut self) {
        if let Some(voter) = self.active_local_voter() {
            self.local_voter = Some(voter);
            return;
        }
        let seated = |key: Option<&ProposerKey>| key.and_then(|key| self.bind_active_proposer(key));
        if seated(self.local_voter.as_ref()).is_none()
            && let Some(standby) = seated(self.standby_voter.as_ref())
        {
            self.standby_voter = self.local_voter.replace(standby);
        }
    }

    /// The local key the production committee seats: `configured`, or the
    /// other local key once a rotation seated it.
    pub(crate) fn seated_production_key(&self, configured: &ProposerKey) -> Option<ProposerKey> {
        let committee = &self.production_committee().0;
        [
            Some(configured),
            self.local_voter.as_ref(),
            self.standby_voter.as_ref(),
        ]
        .into_iter()
        .flatten()
        .find_map(|key| {
            committee
                .iter()
                .position(|validator| {
                    validator.pubkey == *key.public_key_bytes() && validator.effective_stake > 0
                })
                .and_then(|index| u32::try_from(index).ok())
                .map(|index| key.with_validator_index(index))
        })
    }

    /// Borrow the configured local voter, if any.
    #[must_use]
    pub const fn local_voter(&self) -> Option<&ProposerKey> {
        self.local_voter.as_ref()
    }
}
