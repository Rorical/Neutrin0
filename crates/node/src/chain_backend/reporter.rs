//! Selective evidence retention driven exclusively by finalized runtime state.

mod economics;
#[cfg(test)]
mod tests;
mod tracking;

use super::{ChainBackend, reporter_retention, rpc_queries};
use neutrin0_primitives::Hash;
use neutrin0_runtime_abi::operational::{ReporterIdentity, ReporterStatus};
type Address = Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_trie::Trie;

struct ReporterTrackingSnapshot {
    boundary: neutrin0_consensus_types::history_proof::ConsensusBoundary,
    state: Trie<neutrin0_trie::Poseidon2Hasher>,
    runtime: Hash,
    identities: Vec<ReporterIdentity>,
    revision: u64,
}

type Engine<DB> = neutrin0_consensus_engine::Engine<DB>;

/// Generation of the tracked identity set; ordinary retention leaves it unchanged.
fn tracked_revision<DB: Database>(engine: &mut Engine<DB>) -> Result<u64, String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    engine
        .store_mut()
        .reporter_storage_stats()
        .map(|stats| stats.tracked_revision)
        .map_err(|error| error.to_string())
}

/// Finalized post-state and the runtime that wrote it, ready for a query.
fn finalized_query_state<DB: Database>(
    engine: &Engine<DB>,
    boundary: &neutrin0_consensus_types::history_proof::ConsensusBoundary,
) -> Result<(Trie<neutrin0_trie::Poseidon2Hasher>, Hash), String>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let state = rpc_queries::read_state_at(engine, boundary.state_root)
        .map_err(|error| error.to_string())?;
    // A boundary can activate new programs. Its post-state was written by
    // the runtime executing its final block, before that activation.
    let runtime = engine
        .runtime_code_hash_for(boundary.height)
        .map_err(|error| error.to_string())?;
    Ok((state, runtime))
}

pub(super) struct ReporterRuntime {
    pub(super) recipient: Address,
    last_finalized: Option<Hash>,
    last_tracked_revision: Option<u64>,
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Enable proof-bound rewards and refresh selective retention from finalized
    /// execution state. The configured address needs no local signing key.
    ///
    /// # Errors
    /// Rejects zero addresses and other retention roles. Unavailable execution
    /// state or economic queries retain existing sources until a later refresh.
    pub fn initialize_reporter(&self, recipient: Address) -> Result<(), String> {
        if recipient == [0; 32] || !neutrin0_primitives::is_runtime_account(&recipient) {
            return Err(
                "reporter reward address must be a nonzero runtime account (twelve zero bytes, then the 20-byte address)"
                    .into(),
            );
        }
        if !self.with_engine(reporter_retention) {
            return Err("reporter requires reporter retention policy".into());
        }
        *self.reporter.lock().expect("reporter runtime") = Some(ReporterRuntime {
            recipient,
            last_finalized: None,
            last_tracked_revision: None,
        });
        self.refresh_reporter_tracking();
        Ok(())
    }

    pub(super) fn reporter_recipient(&self) -> Option<Address> {
        self.reporter
            .lock()
            .expect("reporter runtime")
            .as_ref()
            .map(|runtime| runtime.recipient)
    }

    /// Resolve an old receipt's own authenticated program for forensic verdicts.
    /// This does not make old receipts eligible for execution or live BFT.
    pub(super) fn accountability_block_program(&self, height: u64) -> Option<[u32; 8]> {
        self.with_engine(|engine| {
            let chunk = height
                .checked_sub(1)?
                .checked_div(engine.chain_spec().consensus.chunk_size)?;
            if chunk < engine.finalized_next_chunk_id()
                && let Some(record) = engine.store().historical_chunk(chunk).ok().flatten()
            {
                // Finality bound this exact source key in its historical leaf.
                // In particular, a restarted backend's default genesis key
                // cannot replace the key of an already finalized chunk zero.
                return Some(record.block_guest_vk_digest);
            }
            engine
                .programs_for_height(height)
                .ok()
                .map(|programs| programs.execution.block)
        })
    }
}

fn eligible_identities(
    requested: &[ReporterIdentity],
    statuses: &[ReporterStatus],
) -> Result<Vec<(neutrin0_primitives::BlsPublicKey, Address)>, String> {
    if requested.len() != statuses.len()
        || requested
            .iter()
            .zip(statuses)
            .any(|(identity, status)| *identity != status.identity)
    {
        return Err("reporter status query changed its identity batch".into());
    }
    Ok(statuses
        .iter()
        .filter(|status| status.pending || (!status.tombstoned && status.slashable_balance != 0))
        .map(|status| {
            (
                status.identity.pubkey,
                status.identity.withdrawal_credentials,
            )
        })
        .collect())
}
