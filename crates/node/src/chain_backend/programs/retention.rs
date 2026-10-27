//! Which program identities the chain names and which must stay warm, and
//! their reconciliation with the executor, the proof backend and the store.

use std::collections::{BTreeMap, BTreeSet};

use neutrin0_consensus_types::history_proof::ProgramSet;
use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_proof_system::artifacts::ProgramRetention;
use neutrin0_storage::Database;

use super::{ChainBackend, ExpectedIdentity, expectations};

type Engine<DB> = neutrin0_consensus_engine::Engine<DB>;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(super) fn warm_identities(&self) -> BTreeSet<ExpectedIdentity> {
        let mut warm = BTreeSet::new();
        self.with_engine(|engine| live_program_identities(engine, &mut warm));
        for declaration in self
            .query_program_declarations()
            .unwrap_or_default()
            .into_iter()
            .filter(|declaration| declaration.enacted)
        {
            warm.extend(
                expectations(&declaration.programs, &declaration.artifacts)
                    .map(|(_, identity)| identity),
            );
        }
        warm.extend(self.bootstrap_program_retention().warm);
        warm
    }

    pub(super) fn reconcile_programs(&self, wanted: &BTreeMap<Hash, ExpectedIdentity>) {
        let warm = self.warm_identities();
        // One enacted schedule can warm alongside current/head programs.
        // Open or abandoned proposals own no compiled module or CUDA session.
        let retention = ProgramRetention {
            sources: self.named_identities().into_iter().collect(),
            warm: warm.into_iter().collect(),
        };
        self.proof_system.retain_programs(&retention);
        if let Some(executor) = self.block_executor_snapshot() {
            executor.retain_programs(&retention);
        }
        self.program_store().retain_sources(
            &retention.sources.iter().copied().collect(),
            &wanted.keys().copied().collect(),
        );
    }

    /// Identities the chain currently names: the program set in force at the
    /// chunk being built plus everything governance has proposed or
    /// scheduled. Only these may be installed from disk.
    pub(super) fn named_identities(&self) -> BTreeSet<ExpectedIdentity> {
        let mut named: BTreeSet<ExpectedIdentity> = self.wanted_artifacts().into_values().collect();
        self.with_engine(|engine| live_program_identities(engine, &mut named));
        // Historical state and artifacts must continue using the runtime that
        // produced them, including across restart. Retained authenticated boundaries
        // name those programs; ordinary pruning eventually removes this authority.
        self.with_engine(|engine| {
            retained_boundary_identities(engine, &mut named);
            historical_record_identities(engine, &mut named);
        });
        named.extend(self.bootstrap_program_retention().sources);
        named
    }
}

/// Name a complete program set: its runtime, then its Fact, Evidence and Block
/// Guests.
fn insert_program_set(named: &mut BTreeSet<ExpectedIdentity>, programs: &ProgramSet) {
    named.insert(ExpectedIdentity::Runtime(programs.runtime_code_hash));
    for digest in [
        programs.execution.fact,
        programs.execution.evidence,
        programs.execution.block,
    ] {
        named.insert(ExpectedIdentity::Guest(digest));
    }
}

/// The program sets in force at the first unfinalized chunk, the head and the
/// certified execution boundary.
fn live_program_identities<DB: Database>(
    engine: &Engine<DB>,
    named: &mut BTreeSet<ExpectedIdentity>,
) where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    // An unfinalized canonical head may already be past a scheduled
    // switch. Its runtime is needed to reopen state and query governance.
    for programs in [
        engine.programs_at_chunk(engine.finalized_next_chunk_id()),
        engine.programs_for_height(engine.head_height()),
        engine.programs_at_chunk(engine.certified_execution_boundary().map_or_else(
            || engine.finalized_next_chunk_id(),
            |boundary| boundary.next_chunk_id,
        )),
    ]
    .into_iter()
    .flatten()
    {
        if !engine.chain_spec().accepts_programs(&programs) {
            continue;
        }
        insert_program_set(named, &programs);
    }
}

/// The program sets of every retained consensus and reporter boundary.
fn retained_boundary_identities<DB: Database>(
    engine: &Engine<DB>,
    named: &mut BTreeSet<ExpectedIdentity>,
) where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    if let Ok(records) = engine
        .store()
        .db()
        .iter_column(neutrin0_storage::Column::ConsensusBoundaries)
    {
        for (_, bytes) in records {
            if let Ok(boundary) = borsh::from_slice::<
                neutrin0_consensus_types::history_proof::ConsensusBoundary,
            >(&bytes)
            {
                if !engine.chain_spec().accepts_programs(&boundary.programs) {
                    continue;
                }
                insert_program_set(named, &boundary.programs);
            }
        }
    }
    // Reporter boundaries use an owner wrapper on disk; decode them
    // through the store rather than interpreting that wrapper as a boundary.
    if let Ok(records) = engine
        .store()
        .db()
        .iter_column(neutrin0_storage::Column::ReporterBoundaries)
    {
        for (key, _) in records {
            if let Ok(bytes) = <[u8; 8]>::try_from(key.as_slice())
                && let Ok(Some(boundary)) =
                    engine.store().reporter_boundary(u64::from_be_bytes(bytes))
            {
                if !engine.chain_spec().accepts_programs(&boundary.programs) {
                    continue;
                }
                insert_program_set(named, &boundary.programs);
            }
        }
    }
}

/// The source runtime and Block Guest of every retained historical record.
fn historical_record_identities<DB: Database>(
    engine: &Engine<DB>,
    named: &mut BTreeSet<ExpectedIdentity>,
) where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    // Bootstrap preserves recent historical contexts, while it only
    // installs the genesis and endpoint consensus boundaries. Those
    // records still authorize their source runtime and Block Guest.
    if let Ok(records) = engine
        .store()
        .db()
        .iter_column(neutrin0_storage::Column::HistoricalChunks)
    {
        for (_, bytes) in records {
            if let Ok(record) =
                borsh::from_slice::<neutrin0_prover_chunk::history::HistoricalChunk>(&bytes)
            {
                named.insert(ExpectedIdentity::Runtime(record.runtime_code_hash));
                named.insert(ExpectedIdentity::Guest(record.block_guest_vk_digest));
            }
        }
    }
}
