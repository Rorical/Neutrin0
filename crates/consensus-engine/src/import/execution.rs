//! Private host execution contexts and checked execution of imported bodies.

use super::{CheckedExecution, ImportError, PROGRAMS_UNAVAILABLE};
use crate::engine::Engine;
use neutrin0_consensus_types::{Block, BlockStateDiff, Body, Header};
use neutrin0_primitives::{BlockHash, StateRoot};
use neutrin0_proof_system::{BlockExecutionContext, ErasedBlockExecutor, ExecutionOutcome};
use neutrin0_storage::{Batch, Column, Database};
use neutrin0_trie::Trie;

impl<DB: Database> Engine<DB> {
    /// Check `block` against a scratch clone of the materialized head trie.
    ///
    /// The caller has checked `parent_hash == head_hash()` and asserts the live
    /// trie root invariant in debug builds. Return the checked post-state for
    /// the caller's existing head-publication commit; a failed check leaves the
    /// live trie untouched.
    pub(super) fn dry_run_block_against_head(
        &self,
        executor: &dyn ErasedBlockExecutor,
        block: &Block,
    ) -> Result<(Trie, CheckedExecution), ImportError<DB::Error>> {
        let ctx = self.import_execution_context(&block.header, &block.body)?;

        // Snapshot the engine's state trie into a scratch buffer.
        // The executor advances the scratch on success; on every
        // cross-check failure the scratch is dropped and the
        // engine's `self.state` is untouched. On success the
        // scratch is returned to the caller for commit via
        // `commit_materialized_head`.
        let mut scratch = self.state().clone();
        scratch.drain_pending_nodes();
        scratch.drain_pending_values();
        let checked =
            Self::execute_checked(executor, &ctx, &block.header, &block.body, &mut scratch)?;
        Ok((scratch, checked))
    }

    /// Re-execute `block` against a reconstruction of `parent_state_root`
    /// and cross-check the resulting commitments against the
    /// header.  Used by [`Self::import_block_inner`] for sibling
    /// imports — blocks whose parent is not the locally materialised
    /// head (e.g. multi-winner slots, late-arriving sibling on a
    /// competing branch).
    ///
    /// Archive the verified post-state with the block without selecting it.
    /// Descendants can then replay against this parent root. If fork choice
    /// promotes this branch, [`Self::materialise_to_fork_choice_head`]
    /// replays the whole new branch through the same executor with
    /// the same checks.
    pub(super) fn dry_run_block_against_parent(
        &self,
        executor: &dyn ErasedBlockExecutor,
        block: &Block,
        parent_state_root: StateRoot,
    ) -> Result<(Trie, CheckedExecution), ImportError<DB::Error>> {
        let ctx = self.import_execution_context(&block.header, &block.body)?;

        // The persisted trie reads only the nodes on the paths execution
        // touches below `parent_state_root`.
        let mut scratch = self.persisted_trie(parent_state_root)?;
        let checked =
            Self::execute_checked(executor, &ctx, &block.header, &block.body, &mut scratch)?;
        Ok((scratch, checked))
    }

    /// Rebuild the proving witness of the retained, still unproven block
    /// `hash` by executing it over its parent's state, so this node can prove
    /// a block its proposer has not (design 08). Returns whether the block
    /// now has a witness.
    ///
    /// # Errors
    /// Returns execution failures and storage failures.
    pub fn retain_rescue_witness(
        &mut self,
        hash: &BlockHash,
        executor: &dyn ErasedBlockExecutor,
    ) -> Result<bool, ImportError<DB::Error>> {
        let (Some(header), Some(body)) =
            (self.store().get_header(hash)?, self.store().get_body(hash)?)
        else {
            return Ok(false);
        };
        self.retain_missing_import_witness(executor, &Block { header, body })?;
        Ok(self.store().get_witness(hash)?.is_some())
    }

    /// Authenticate an older pending archive's missing witness without changing
    /// its proof FSM or replacing any already retained proving input.
    pub(super) fn retain_missing_import_witness(
        &mut self,
        executor: &dyn ErasedBlockExecutor,
        block: &Block,
    ) -> Result<(), ImportError<DB::Error>> {
        let hash = block.hash();
        if self.store().get_witness(&hash)?.is_some()
            || !matches!(
                self.store().get_block_state(&hash)?,
                Some(
                    crate::block_state::BlockState::BlockProduced
                        | crate::block_state::BlockState::PendingProof
                )
            )
        {
            return Ok(());
        }
        let parent_root =
            self.state_root_before(&block.header)?
                .ok_or(ImportError::MissingParentHeader {
                    parent_hash: block.header.parent_hash,
                })?;
        let (state, checked) = self.dry_run_block_against_parent(executor, block, parent_root)?;
        let mut batch = Batch::new();
        batch.put(Column::Witnesses, hash, checked.witness);
        batch.put(Column::StateDiffs, hash, borsh::to_vec(&checked.diff)?);
        if hash == self.head_hash() {
            self.commit_materialized_head_with_batch(
                block.header.height,
                hash,
                block.header.state_root,
                Some(state),
                batch,
            )?;
        } else {
            self.write_sibling_state(hash, batch, Some(&state))?;
        }
        Ok(())
    }

    /// Execution context a header's block runs under, with import failures.
    pub(super) fn import_execution_context(
        &self,
        header: &Header,
        body: &Body,
    ) -> Result<BlockExecutionContext, ImportError<DB::Error>> {
        self.execution_context(header, body)
            .map_err(ImportError::DryRunFailed)
    }

    /// Execution context for the block at `height`: its evidence anchor,
    /// runtime artifact, gas limit, proposer account and participation report.
    ///
    /// # Errors
    /// Returns the evidence-anchor failure text, [`PROGRAMS_UNAVAILABLE`] or the
    /// participation failure text, checked in that order.
    pub(crate) fn execution_context(
        &self,
        header: &Header,
        body: &Body,
    ) -> Result<BlockExecutionContext, String> {
        let height = header.height;
        let chunk_id = height.saturating_sub(1) / self.chain_spec().consensus.chunk_size;
        let reports = self.reports_for_block(header, body)?;
        Ok(BlockExecutionContext {
            active_validators: self
                .validator_context_for_height(height)
                .map_err(|_| "execution committee unavailable".to_owned())?
                .0,
            context: neutrin0_consensus_types::runtime::ConsensusExecutionContext {
                slot: header.slot,
                timestamp: header.timestamp,
                parent_block_hash: header.parent_hash,
                proposer_vrf_output: neutrin0_vrf::proof_output(&header.vrf_proof),
                finalized: self
                    .execution_boundary(chunk_id)
                    .map_err(|_| "execution boundary unavailable".to_owned())?,
            },
            evidence_anchor: self.evidence_anchor(height)?,
            runtime_code_hash: self
                .runtime_code_hash_for(height)
                .map_err(|_| PROGRAMS_UNAVAILABLE.to_owned())?,
            chain_id: self.chain_spec().chain_id,
            block_height: height,
            gas_limit: header.gas_limit,
            proposer_address: self
                .proposer_runtime_address(header)
                .map_err(|_| "execution proposer context unavailable".to_owned())?,
            participation: reports
                .as_ref()
                .map(|(participation, _)| participation.clone()),
            proving: reports.map(|(_, proving)| proving),
            participation_acks: self
                .participation_acknowledgements(height, body)
                .map_err(|_| "invalid historical participation votes".to_owned())?,
            program_pieces: neutrin0_consensus_types::program_piece_refs(&body.programs),
        })
    }

    /// The inputs root an honest header of this block declares: its header
    /// facts over the incoming boundary, the reports carried on its branch, the
    /// acknowledgements authenticated from its vote lane and the evidence
    /// anchor, exactly as execution consumes them (design 08). It needs no
    /// runtime artifact, so a node that does not execute derives it too.
    ///
    /// # Errors
    /// Returns unavailable boundaries, history or programs and invalid carried
    /// reports or acknowledgements.
    pub fn expected_inputs_root(
        &self,
        header: &Header,
        body: &Body,
    ) -> Result<neutrin0_primitives::Hash, String> {
        let chunk_id = header.height.saturating_sub(1) / self.chain_spec().consensus.chunk_size;
        let context = neutrin0_consensus_types::runtime::ConsensusExecutionContext {
            slot: header.slot,
            timestamp: header.timestamp,
            parent_block_hash: header.parent_hash,
            proposer_vrf_output: neutrin0_vrf::proof_output(&header.vrf_proof),
            finalized: self
                .execution_boundary(chunk_id)
                .map_err(|_| "execution boundary unavailable".to_owned())?,
        };
        let reports = self.reports_for_block(header, body)?;
        let acknowledgements = self
            .participation_acknowledgements(header.height, body)
            .map_err(|_| "invalid historical participation votes".to_owned())?;
        Ok(neutrin0_proof_system::execution_inputs_commitment(
            &context,
            reports.as_ref().map(|(participation, _)| participation),
            &acknowledgements,
            reports.as_ref().map(|(_, proving)| proving),
            &neutrin0_consensus_types::program_piece_refs(&body.programs),
            &self.evidence_anchor(header.height)?,
        ))
    }

    /// Execute `body` on `state` and require exactly the results `header` commits.
    pub(super) fn execute_checked(
        executor: &dyn ErasedBlockExecutor,
        ctx: &BlockExecutionContext,
        header: &Header,
        body: &Body,
        state: &mut Trie,
    ) -> Result<CheckedExecution, ImportError<DB::Error>> {
        let state_root_before = state.root();
        let ExecutionOutcome {
            artifacts,
            state_root_after,
            runtime_extra,
            receipts_root,
            gas_used,
            witness_bytes,
            state_writes,
        } = executor
            .execute_block(ctx, body, state)
            .map_err(ImportError::DryRunFailed)?;

        if !ctx
            .evidence_anchor
            .accepts_proving_input_size(u64::try_from(witness_bytes.len()).unwrap_or(u64::MAX))
        {
            return Err(ImportError::DryRunFailed(
                "block proving input exceeds chain allocation ceiling".into(),
            ));
        }
        if state_root_after != header.state_root {
            return Err(ImportError::StateRootMismatch {
                expected: header.state_root,
                computed: state_root_after,
            });
        }
        if runtime_extra != header.runtime_extra {
            return Err(ImportError::HeaderRuntimeExtraMismatch {
                expected: header.runtime_extra,
                actual: runtime_extra,
            });
        }
        // The body's artifacts are what the header's receipts root commits, so
        // executed artifacts that differ contradict that root: a divergence a
        // receipt can prove, not a failure to execute.
        if artifacts != body.artifacts || artifacts.commitment() != receipts_root {
            return Err(ImportError::ReceiptsRootMismatch {
                expected: header.receipts_root,
                computed: artifacts.commitment(),
            });
        }
        if receipts_root != header.receipts_root {
            return Err(ImportError::ReceiptsRootMismatch {
                expected: header.receipts_root,
                computed: receipts_root,
            });
        }
        if gas_used != header.gas_used {
            return Err(ImportError::GasUsedMismatch {
                expected: header.gas_used,
                computed: gas_used,
            });
        }
        Ok(CheckedExecution {
            witness: witness_bytes,
            diff: BlockStateDiff {
                height: header.height,
                block_hash: header.hash(),
                state_root_before,
                state_root_after,
                writes: state_writes,
            },
        })
    }
}
