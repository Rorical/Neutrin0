//! Per-slot block production.
//!
//! Block production has three concerns:
//!
//! 1. **VRF eligibility.** Owned by this module; consults the active
//!    validator set, finalized seed, and chain spec.
//! 2. **Dynamic execution.** Delegated to a
//!    [`BlockExecutor`](neutrin0_proof_system::BlockExecutor) — the
//!    node binary wires in `WasmExecutor` from `runtime-host`, but
//!    the trait keeps the engine decoupled from wasmtime and the
//!    runtime's types.
//! 3. **Header sealing.** Owned by this module; constructs the
//!    canonical [`Header`], signs it with the proposer key, persists
//!    the header / body / witness / FSM state, and advances the
//!    engine's in-memory head pointers.
//!
//! Per-block SP1 proving is a separate FSM step
//! ([`Engine::prove_block`](crate::Engine::prove_block)). It re-reads
//! the witness this path persists and produces the
//! `BlockProof` consensus stores alongside the block.

extern crate alloc;

use alloc::vec::Vec;

use neutrin0_consensus_types::{Block, Body, Header};
use neutrin0_consensus_vrf::total_active_stake;
use neutrin0_primitives::{BlockHash, BlsSignature, Slot, StateRoot, Validator, ZERO_HASH};
use neutrin0_proof_system::{ErasedBlockExecutor, ExecutionOutcome};
use neutrin0_storage::Database;

use crate::body::{apply_body_roots, compute_body_roots};
use crate::engine::Engine;
use crate::error::EngineError;
use crate::proposer::ProposerKey;

mod error;
mod steps;

pub use error::ProductionError;
use steps::{execute_body, produced_state_diff, select_transactions};

/// Runtime + proposer binding for [`Engine::try_produce_block`].
#[derive(Clone, Copy, Debug)]
pub struct ProductionConfig<'a> {
    /// Proposer BLS identity. Its index is resolved from the current active set.
    pub proposer: &'a ProposerKey,
}

/// Successful block-production outcome.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionOutcome {
    /// The signed block.
    pub block: Block,
    /// Canonical block hash (also equal to `block.hash()`).
    pub block_hash: BlockHash,
    /// Post-execution state root (also recorded in the header).
    pub state_root_after: StateRoot,
    /// Gas the runtime actually consumed.
    pub gas_used: u64,
    /// Validator-set root the runtime committed for the next chunk, if any.
    pub next_validator_set_root: Option<StateRoot>,
    /// Full active validator set when the runtime changed it in this block.
    pub next_validator_set: Option<Vec<Validator>>,
}

impl<DB: Database> Engine<DB> {
    /// Attempt to produce a block at `slot`.
    ///
    /// Flow:
    ///
    /// 1. Validate the requested slot is monotonic relative to the
    ///    local head (cheap, no eligibility cost on stale slots).
    /// 2. Evaluate VRF eligibility against the active validator set
    ///    and the finalized seed. Returns `Ok(None)` if the local
    ///    validator is inactive or not eligible for this slot. The configured
    ///    index never overrides the authenticated BLS identity's position.
    /// 3. Hand a copy of the head state, which reads the persisted state
    ///    on demand, and the body to the
    ///    [`BlockExecutor`](neutrin0_proof_system::BlockExecutor).
    /// 4. The executor returns `(state_root_after, runtime_extra,
    ///    gas_used, witness_bytes)` and mutates the supplied trie
    ///    in place with the block's writes.
    /// 5. Compute the body Merkle roots, build the canonical
    ///    [`Header`] (wiring `runtime_extra` from the executor's
    ///    `validator_set_root` commitment), sign it with the
    ///    proposer key, and persist the header / body / FSM state /
    ///    witness / tip pointer in one ordered batch.
    /// 6. Publish the in-memory head after the archive, index and trie
    ///    deltas commit atomically.
    /// 7. Return the [`ProductionOutcome`] so the chain backend can
    ///    gossip the block and the producer loop can hand it to the
    ///    SP1 prover ([`Engine::prove_block`](crate::Engine::prove_block)).
    ///
    /// # Errors
    ///
    /// - [`ProductionError::NonMonotonicSlot`] if `slot` does not
    ///   strictly advance the local head's slot.
    /// - [`ProductionError::NotEligible`] for VRF eligibility failures.
    /// - [`ProductionError::HeightOverflow`] if the block height
    ///   counter would overflow `u64`.
    /// - [`ProductionError::Executor`] if the dynamic runtime fails.
    /// - [`ProductionError::Engine`] on persistence failures.
    pub fn try_produce_block(
        &mut self,
        slot: Slot,
        cfg: ProductionConfig<'_>,
        mut body: Body,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<Option<ProductionOutcome>, ProductionError<DB::Error>> {
        let Some(parent_hash) = self.production_gate(slot, executor)? else {
            return Ok(None);
        };
        let Some((proposer, eligibility, height)) = self.eligible_production(slot, cfg)? else {
            return Ok(None);
        };

        // Execute on a copy of the head state. It reads the persisted state
        // on demand and holds only what this block writes; on failure the
        // head state is untouched and the error bubbles.
        let mut next_state = self.state().clone();
        // The proposer's runtime account receives any per-tx fees.
        // We source it from the active validator set rather than from
        // the chain spec's initial set so on-chain validator changes
        // (registrations, exits) propagate to fee routing automatically.
        let proposer_index = proposer.validator_index();
        // Peers accept only the chain specification's gas limit.
        let gas_limit = self.chain_spec().genesis_gas_limit;
        let timestamp = self.clock().timestamp_for(slot);
        if body.participation.is_none() {
            body.participation = self
                .production_participation_certificate(height)
                .map_err(ProductionError::Executor)?;
        }
        self.append_participation_votes(height, &mut body, executor, &next_state)
            .map_err(ProductionError::Executor)?;
        let ctx = self
            .execution_context(
                &Header {
                    height,
                    gas_limit,
                    proposer_index,
                    slot,
                    timestamp,
                    parent_hash,
                    vrf_proof: eligibility.vrf_proof,
                    state_root: ZERO_HASH,
                    transactions_root: ZERO_HASH,
                    votes_root: ZERO_HASH,
                    da_root: ZERO_HASH,
                    runtime_extra: ZERO_HASH,
                    inputs_root: [0; 32],
                    receipts_root: ZERO_HASH,
                    gas_used: 0,
                    signature: [0; 96],
                },
                &body,
            )
            .map_err(ProductionError::Executor)?;
        select_transactions(executor, &ctx, &mut body, &next_state)?;

        let parent_state_root = next_state.root();
        let ExecutionOutcome {
            artifacts,
            state_root_after,
            runtime_extra,
            receipts_root,
            gas_used,
            witness_bytes,
            state_writes,
        } = execute_body(executor, &ctx, &body, &mut next_state)?;
        body.artifacts = artifacts;

        // Compute body roots from the supplied body. The executor
        // emits `state_root_after` and `runtime_extra` directly; the
        // body Merkle roots are still derived host-side because the
        // header lanes are consensus-level commitments, not runtime
        // ones.
        let body_roots = compute_body_roots(&body);

        // Assemble the unsigned header. Its timestamp is exactly the slot's
        // start under the chain spec's `genesis_time + slot *
        // slot_duration_secs` schedule; peers reject any other.
        let chain_spec = self.chain_spec();
        let timestamp = chain_spec
            .genesis_time
            .saturating_add(slot.saturating_mul(chain_spec.consensus.slot_duration_secs));
        let mut header = Header {
            height,
            slot,
            parent_hash,
            proposer_index,
            vrf_proof: eligibility.vrf_proof,
            state_root: state_root_after,
            transactions_root: ZERO_HASH,
            votes_root: ZERO_HASH,
            da_root: ZERO_HASH,
            // Wire the validator-set commitment the runtime emitted
            // into `runtime_extra` so the chunk BFT and consensus
            // layer see the post-block stake distribution.
            runtime_extra,
            // Declare the consumed inputs (design 08).
            inputs_root: ctx.inputs_root(),
            // Wire the runtime's per-block receipts commitment into
            // `header.receipts_root`. Verifiers cross-check this
            // against the SP1 proof's committed receipts_root.
            receipts_root,
            gas_used,
            gas_limit,
            timestamp,
            signature: [0u8; 96],
        };
        apply_body_roots(&mut header, &body_roots);
        let (block, block_hash) = self.seal_block(&proposer, header, body)?;

        let state_diff = produced_state_diff(
            height,
            block_hash,
            parent_state_root,
            state_root_after,
            state_writes,
        )?;
        self.archive_produced_block(&block, &witness_bytes, &state_diff, next_state)?;

        Ok(Some(ProductionOutcome {
            block,
            block_hash,
            state_root_after,
            gas_used,
            next_validator_set_root: Some(runtime_extra),
            next_validator_set: None,
        }))
    }

    /// Whether this node may produce at `slot` now, and the head it extends:
    /// `None` while production is disabled, the execution window is closed,
    /// the head cannot leave a stale branch, or as many unproven candidates as
    /// the pending chain has heights already wait above finality.
    fn production_gate(
        &mut self,
        slot: Slot,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<Option<BlockHash>, ProductionError<DB::Error>> {
        if !self.local_production_enabled() {
            return Ok(None);
        }
        if self.programs.is_some() && !self.can_extend_execution() {
            return Ok(None);
        }
        // The stale rule (design 08): never extend a branch through a
        // candidate whose exclusive window passed without a receipt. Moving
        // the head off such a branch re-produces the stale block's height.
        // A branch the node cannot materialise leaves the head where it is,
        // and production waits: every peer excludes a block built on it.
        let _ = self.refresh_stale_candidates(slot, Some(executor));
        if self.fork_choice.on_stale_branch(self.head_hash()) {
            return Ok(None);
        }
        // Peers refuse candidates beyond this bound; producing waits for
        // receipts or finality like importing does.
        if self.fork_choice.unproven_count() >= self.unproven_candidate_limit() {
            return Ok(None);
        }
        let parent_hash = self.head_hash();
        let parent_slot = self.head_slot(parent_hash)?;
        if slot <= parent_slot {
            return Err(ProductionError::NonMonotonicSlot {
                parent_slot,
                requested: slot,
            });
        }
        Ok(Some(parent_hash))
    }

    /// The seated proposer key, its VRF eligibility at `slot` and the height
    /// it would produce; `None` when the local key is not seated, not
    /// eligible, or the height's chunk is not one this node proves.
    fn eligible_production(
        &self,
        slot: Slot,
        cfg: ProductionConfig<'_>,
    ) -> Result<Option<EligibleProduction>, ProductionError<DB::Error>> {
        let Some(proposer) = self.seated_production_key(cfg.proposer) else {
            return Ok(None);
        };
        let Some(eligibility) = self.evaluate_eligibility(slot, &proposer)? else {
            return Ok(None);
        };

        let height = self
            .head_height()
            .checked_add(1)
            .ok_or(ProductionError::HeightOverflow)?;
        if let Some(chunk) = self.chunk_of_height(height)
            && !self.proves_chunk(chunk)?
        {
            return Ok(None);
        }
        Ok(Some((proposer, eligibility, height)))
    }

    /// Check the unsigned block's gossip envelope, then sign and seal it.
    fn seal_block(
        &mut self,
        proposer: &ProposerKey,
        mut header: Header,
        body: Body,
    ) -> Result<(Block, BlockHash), ProductionError<DB::Error>> {
        let block_bytes = borsh::object_length(&(&header, &body))
            .map_err(|error| ProductionError::Executor(error.to_string()))?;
        if block_bytes > neutrin0_primitives::MAX_GOSSIP_BLOCK_BYTES {
            return Err(ProductionError::BodyTooLarge {
                actual: block_bytes,
                limit: neutrin0_primitives::MAX_GOSSIP_BLOCK_BYTES,
            });
        }

        // Sign and seal.
        header.signature = self.sign_proposal_durable(proposer, &header)?;
        let block_hash = header.hash();
        Ok((Block { header, body }, block_hash))
    }

    /// Persist the header, body, witness, diff and FSM state in one ordered
    /// batch with the trie deltas, publish the in-memory head and record the
    /// block in fork choice.
    fn archive_produced_block(
        &mut self,
        block: &Block,
        witness_bytes: &[u8],
        state_diff: &neutrin0_consensus_types::BlockStateDiff,
        next_state: neutrin0_trie::Trie,
    ) -> Result<(), ProductionError<DB::Error>> {
        let batch = crate::store::ChainStore::<DB>::block_archive_batch(
            block,
            Some(witness_bytes),
            Some(state_diff),
        )?;
        self.commit_materialized_head_with_batch(
            block.header.height,
            state_diff.block_hash,
            state_diff.state_root_after,
            Some(next_state),
            batch,
        )?;
        // Commits leave fork choice untouched, so recording the block after a
        // successful commit matches recording it before.
        let _ = self.fork_choice.add_block(&block.header);
        Ok(())
    }

    fn evaluate_eligibility(
        &self,
        slot: Slot,
        proposer: &ProposerKey,
    ) -> Result<Option<ProposerEligibility>, ProductionError<DB::Error>> {
        let (active_set, seed) = self.production_committee();
        let index = proposer.validator_index();
        let position = usize::try_from(index).expect("u32 fits usize on supported targets");
        let validator = active_set
            .get(position)
            .filter(|validator| {
                validator.pubkey == *proposer.public_key_bytes() && validator.effective_stake > 0
            })
            .ok_or(EngineError::Signing(
                crate::signing::SigningViolation::KeyNotActive,
            ))?;
        let total_stake = total_active_stake(active_set).map_err(ProductionError::NotEligible)?;

        let domain = self.consensus_domain();
        let expected = self.chain_spec().consensus.expected_proposers_per_slot;

        let vrf_proof = proposer
            .sign(domain, &crate::SignRequest::Vrf { seed, slot })
            .map_err(EngineError::Signer)?[0];
        if !neutrin0_vrf::is_eligible(
            &neutrin0_vrf::proof_output(&vrf_proof),
            validator.effective_stake,
            total_stake,
            expected,
        ) {
            return Ok(None);
        }
        Ok(Some(ProposerEligibility { vrf_proof }))
    }

    fn head_slot(&self, head_hash: BlockHash) -> Result<Slot, ProductionError<DB::Error>> {
        if head_hash == self.chain_spec().genesis_block_hash {
            return Ok(0);
        }
        let header = self
            .store()
            .get_header(&head_hash)?
            .ok_or(EngineError::NotInitialised)?;
        Ok(header.slot)
    }
}

/// The seated key, its eligibility and the height a production attempt may
/// produce.
type EligibleProduction = (ProposerKey, ProposerEligibility, u64);

#[derive(Clone, Copy, Debug)]
struct ProposerEligibility {
    vrf_proof: BlsSignature,
}
