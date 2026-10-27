//! Single-node consensus engine state and lifecycle.
//!
//! [`Engine`] is the per-node orchestration object. This file covers
//! bootstrap and read accessors; block production, import, BFT,
//! finalization and recursion extend the struct through additional
//! `impl` blocks in sibling modules.

use alloc::collections::{BTreeMap, VecDeque};
use core::cell::RefCell;

use neutrin0_consensus_types::history_proof::ProgramSet;
use neutrin0_consensus_types::{
    BlockProof, FinalityCert, FinalityVotePhase, ProofRejectionReason, QuorumCertificate,
    SlashingEvidence,
};
use neutrin0_primitives::{
    BlockHash, ChainSpec, ChunkId, ConsensusDomain, Hash, Height, Seed, StateRoot, Validator,
};

use neutrin0_storage::Database;
use neutrin0_trie::Trie;

use crate::bft_loop::BftSession;
use crate::clock::SlotClock;
use crate::proposer::ProposerKey;
use crate::slashing::SlashingMonitor;
use crate::store::ChainStore;
use neutrin0_consensus_fork_choice::ForkChoice;

extern crate alloc;

mod accessors;
mod accountability;
mod evidence_verification;
mod head_state;
mod invalid_proof_signing;
mod lifecycle;
mod reopen;
mod subnets;

/// Engine state machine combining a chain store, slot clock, and the
/// running head pointers.
///
/// The engine owns the [`ChainStore`] and exposes typed accessors for
/// every value consumers might want. Mutating operations (block
/// production, chunk finalization, checkpoint recursion) live in
/// sibling modules.
#[derive(Debug)]
pub struct Engine<DB: Database> {
    chain_spec: ChainSpec,
    /// Canonical hash of the immutable `chain_spec`, computed once at boot.
    chain_spec_hash: Hash,
    /// Signing domain of the immutable `chain_spec`, computed once at boot.
    consensus_domain: ConsensusDomain,
    pub(crate) programs: Option<ProgramSet>,
    /// Upgrade records observed at unfinalized chunk boundaries, by block hash.
    pub(crate) program_switches: RefCell<BTreeMap<BlockHash, Option<Vec<u8>>>>,
    store: ChainStore<DB>,
    clock: SlotClock,
    /// Local wall clock in Unix seconds. Peer blocks whose slot has not
    /// started yet are refused against it.
    wall_clock: fn() -> u64,
    state: Trie,
    pub(crate) identity_sanctions: Trie,
    head_height: Height,
    head_hash: BlockHash,
    head_state_root: StateRoot,
    finalized_seed: Seed,
    latest_finalized_chunk_id: Option<ChunkId>,
    pub(crate) certified_execution: Option<crate::certified::CertifiedExecution>,
    /// Complete consensus validation of the certified witness, so committing
    /// that exact witness does not validate it again.
    pub(crate) certified_validation: Option<neutrin0_prover_chunk::consensus::ValidatedConsensus>,
    /// Successor state projected from a proven candidate before its
    /// certificate (design 08).
    pub(crate) projected_execution: Option<crate::projected::ProjectedExecution>,
    active_validator_set: Vec<Validator>,
    /// Validator-set root committed by the stored consensus state, or the
    /// genesis root before any chunk finalizes. Updated with every install.
    previous_validator_set_root: Hash,
    /// Live chunk-BFT sessions keyed by chunk id, used by the
    /// multi-validator finality loop. See [`crate::bft_loop`].
    pub(crate) bft_sessions: BTreeMap<ChunkId, BftSession>,
    /// Local validator key used by the BFT loop to sign prevotes and
    /// precommits. Unset on non-voting nodes.
    pub(crate) local_voter: Option<ProposerKey>,
    /// A second local key, seated in place of `local_voter` by a key
    /// rotation (design 19); the two swap when that happens.
    pub(crate) standby_voter: Option<ProposerKey>,
    pub(crate) local_signing_policy: crate::LocalSigningPolicy,
    pub(crate) local_control_faulted: bool,
    pub(crate) local_signer_stopping: bool,
    /// First slot this node signs in after its doppelganger quiet period.
    pub(crate) signing_quiet_until: neutrin0_primitives::Slot,
    /// The message by a local key this node did not sign, once one is seen.
    pub(crate) doppelganger: Option<crate::Doppelganger>,
    /// Account named in locally produced receipts when configured (design 08).
    pub(crate) prover_address: Option<Hash>,
    /// Equivocation detector for the slashing pipeline. See
    /// [`crate::slashing`].
    pub(crate) slashing_monitor: SlashingMonitor,
    /// Bounded cache of exact native BLS equations, never consensus decisions.
    pub(crate) bls_verifier: RefCell<crate::bls_verdicts::NativeBlsVerifier>,
    /// Successful validations of open BFT values under the current boundary.
    pub(crate) signing_verdicts: crate::signing_validation::SigningVerdicts,
    /// In-memory cache of rejected block proofs.
    ///
    /// Populated by the local proof backend's block verification at
    /// gossip-import time ([`Engine::import_block_proof`]). Used by the
    /// [`SlashingEvidence::InvalidProofSigning`] detector: when a
    /// peer precommit arrives for a chunk whose blocks have rejected
    /// proofs in the cache, the engine synthesises evidence carrying
    /// the rejected `BlockProof` so any replayer can independently
    /// re-verify the rejection.
    ///
    /// Bounded by [`MAX_REJECTED_PROOFS_CACHED`]: once the cache is
    /// full, the oldest insertion is evicted to make room. An accepted alternate
    /// envelope for the same block does not erase an exact rejected envelope's
    /// verdict; the signer's attestation identifies the proof bytes it accepted.
    pub(crate) rejected_proofs: RejectedProofCache,
    /// Receipt statement keys an authenticated proposal (by chunk and round)
    /// or a verified chunk certificate named. Their receipts are kept beyond
    /// the per-block cap when they arrive; cleared at finality.
    pub(crate) awaited_receipts: BTreeMap<(ChunkId, u32), Vec<neutrin0_primitives::Hash>>,
    /// The slot each proposal of an open chunk first arrived in, keyed by its
    /// commitment. A proposal deferred for missing receipts is judged as of
    /// its arrival, not the slot it is retried in (design 08).
    pub(crate) proposal_arrivals: BTreeMap<Hash, (ChunkId, u32, neutrin0_primitives::Slot)>,
    /// Invalid execution claims built from verified receipts that
    /// contradict their signed headers, awaiting the node (design 08).
    pub(crate) contradicting_receipts: Vec<SlashingEvidence>,
    /// How the materialized head state advances on this node: by executing
    /// imported bodies, or by applying authenticated diffs of verified
    /// Block receipts.
    pub(crate) state_source: StateSource,
    /// Vote-weighted heaviest-proven-chain fork choice.
    ///
    /// Records every imported block — including non-extending
    /// siblings and out-of-order arrivals — so multi-winner slots and
    /// vote-driven head selection are representable. After every
    /// fork-choice mutation that could shift the head (block import,
    /// proof import, vote ingest) the engine calls
    /// [`Engine::materialise_to_fork_choice_head`]
    /// to replay the new branch through the executor and commit the
    /// resulting state — so `head_hash` / `head_state_root` /
    /// `self.state` track [`Self::fork_choice_head`] automatically on
    /// nodes that have a block executor installed.
    pub(crate) fork_choice: ForkChoice,
}

/// How a node's materialized head state advances.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StateSource {
    /// Re-execute every imported body through the installed executor.
    #[default]
    Execution,
    /// Apply the state diff of each verified Block receipt; bodies are
    /// authenticated but never executed. Finality, History and pruning
    /// continue to require complete Chunk proofs.
    ReceiptDiffs,
}

/// Maximum cached rejected `BlockProof` envelopes.
///
/// The cache lives on `Engine::rejected_proofs`. Sized to
/// comfortably cover the `InvalidProofSigning` detector's lookup
/// window (a few chunks of blocks each); older entries get evicted
/// FIFO.
pub const MAX_REJECTED_PROOFS_CACHED: usize = 512;

/// Bounded FIFO cache of rejected block-proof envelopes.
///
/// The latest rejected envelope per block is retained independently of
/// successful alternate envelopes. At most [`MAX_REJECTED_PROOFS_CACHED`]
/// blocks are cached; the oldest insertion is evicted first.
#[derive(Debug, Default)]
pub(crate) struct RejectedProofCache {
    entries: BTreeMap<BlockHash, (BlockProof, ProofRejectionReason)>,
    /// Cached block hashes in insertion order.
    order: VecDeque<BlockHash>,
}

impl RejectedProofCache {
    fn record(&mut self, block_hash: BlockHash, proof: BlockProof, reason: ProofRejectionReason) {
        use alloc::collections::btree_map::Entry;
        // Eviction step first: drop the oldest cached entry until
        // there's headroom for the new insertion (or the FIFO is
        // already empty). The bound applies to both the map and the
        // FIFO companion.
        while self.order.len() >= MAX_REJECTED_PROOFS_CACHED
            && !self.entries.contains_key(&block_hash)
        {
            if let Some(oldest) = self.order.pop_front() {
                let _ = self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        // Same block hash arrived again: refresh the entry in place
        // but keep the FIFO position so a flood of duplicates cannot
        // starve genuine newcomers out of the cache.
        match self.entries.entry(block_hash) {
            Entry::Occupied(mut existing) => {
                existing.insert((proof, reason));
            }
            Entry::Vacant(slot) => {
                slot.insert((proof, reason));
                self.order.push_back(block_hash);
            }
        }
    }

    /// The rejected envelope cached for `block_hash` and its rejection reason.
    #[cfg(test)]
    pub(crate) fn get(
        &self,
        block_hash: &BlockHash,
    ) -> Option<&(BlockProof, ProofRejectionReason)> {
        self.entries.get(block_hash)
    }

    /// Rejected envelopes for blocks at heights `first..=last` on any branch,
    /// ordered by height and then block hash.
    fn within_heights(
        &self,
        first: Height,
        last: Height,
    ) -> alloc::vec::Vec<&(BlockProof, ProofRejectionReason)> {
        let mut entries: alloc::vec::Vec<_> = self
            .entries
            .values()
            .filter(|(proof, _)| (first..=last).contains(&proof.height))
            .collect();
        entries.sort_unstable_by_key(|(proof, _)| (proof.height, proof.block_hash));
        entries
    }

    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn len(&self) -> usize {
        debug_assert_eq!(self.entries.len(), self.order.len());
        self.entries.len()
    }

    /// Drop envelopes for blocks below `first_height`.
    pub(crate) fn retain_from_height(&mut self, first_height: Height) {
        self.entries
            .retain(|_, (proof, _)| proof.public_inputs.height >= first_height);
        self.order.retain(|hash| self.entries.contains_key(hash));
    }
}

/// Durable head, finality and trust-profile pointers an engine starts from.
struct EngineParts {
    state: Trie,
    identity_sanctions: Trie,
    head_height: Height,
    head_hash: BlockHash,
    head_state_root: StateRoot,
    finalized_seed: Seed,
    latest_finalized_chunk_id: Option<ChunkId>,
    active_validator_set: Vec<Validator>,
    previous_validator_set_root: Hash,
    programs: Option<ProgramSet>,
    fork_choice: ForkChoice,
}

/// The prevote quorum a finality certificate locked on.
pub(crate) fn prevote_quorum(certificate: &FinalityCert) -> QuorumCertificate {
    QuorumCertificate {
        data: certificate.vote_data(FinalityVotePhase::Prevote),
        aggregate: certificate.prevote.clone(),
    }
}

#[cfg(test)]
mod tests;
