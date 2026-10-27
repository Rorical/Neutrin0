//! Which artifacts governance names and which identities this node holds.

use std::collections::{BTreeMap, BTreeSet};

use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;

use super::{ChainBackend, ExpectedIdentity, named_artifacts};

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Artifacts the runtime's open proposal or enacted schedule names, with
    /// the identity each must produce, read through the installed runtime
    /// against the head state.
    pub(super) fn wanted_artifacts(&self) -> BTreeMap<Hash, ExpectedIdentity> {
        let declarations = self.query_program_declarations();
        *self
            .scheduled_programs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            declarations.as_ref().and_then(|declarations| {
                declarations
                    .iter()
                    .find(|declaration| declaration.enacted)
                    .map(|declaration| declaration.programs)
            });
        let wanted = declarations
            .as_deref()
            .and_then(named_artifacts)
            .unwrap_or_default();
        *self
            .wanted_programs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = wanted.keys().copied().collect();
        wanted
    }

    /// Programs of the enacted switch, as of the last program sync, that this
    /// node has not installed; `None` when no switch is scheduled. A node
    /// missing one when the switch activates cannot execute or verify under it.
    pub(crate) fn scheduled_missing_programs(&self) -> Option<Vec<&'static str>> {
        let programs = (*self
            .scheduled_programs
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))?;
        Some(
            [
                (
                    "runtime",
                    ExpectedIdentity::Runtime(programs.runtime_code_hash),
                ),
                ("fact", ExpectedIdentity::Guest(programs.execution.fact)),
                (
                    "evidence",
                    ExpectedIdentity::Guest(programs.execution.evidence),
                ),
                ("block", ExpectedIdentity::Guest(programs.execution.block)),
            ]
            .into_iter()
            .filter(|(_, identity)| !self.installed_program(*identity))
            .map(|(name, _)| name)
            .collect(),
        )
    }

    pub(super) fn query_program_declarations(
        &self,
    ) -> Option<Vec<neutrin0_runtime_abi::operational::ProgramDistribution>> {
        let executor = self.block_executor_snapshot()?;
        let (state, runtime, fact, anchor) = self.with_engine(|engine| {
            let spec = engine.chain_spec();
            // Heights 1..=chunk_size form chunk 0: the next block's chunk is
            // the head height over the chunk size. The runtime judges which
            // proposals are live there from these anchor fields alone.
            let anchor = neutrin0_consensus_types::evidence::EvidenceAnchor {
                chunk_id: engine.head_height() / spec.consensus.chunk_size,
                chunk_size: spec.consensus.chunk_size,
                unbonding_delay_blocks: spec.runtime.unbonding_delay_blocks,
                ..neutrin0_consensus_types::evidence::EvidenceAnchor::default()
            };
            engine
                .runtime_code_hash_for(engine.head_height())
                .ok()
                .map(|runtime| {
                    (
                        self.head_state_snapshot(engine),
                        runtime,
                        spec.genesis_execution.fact,
                        anchor,
                    )
                })
        })?;
        let request = neutrin0_runtime_abi::QueryRequest {
            method: neutrin0_runtime_abi::operational::QUERY_PROGRAMS.to_owned(),
            args: borsh::to_vec(&anchor).expect("borsh encoding into memory never fails"),
        };
        let response = executor.query(&request, runtime, &state).ok()?;
        if !response.is_ok() {
            return None;
        }
        let status =
            borsh::from_slice::<Vec<neutrin0_runtime_abi::operational::ProgramDistribution>>(
                &response.payload,
            )
            .ok()?;
        if status.len() > 2 {
            return None;
        }
        if status
            .iter()
            .filter(|declaration| declaration.enacted)
            .count()
            > 1
            || status
                .iter()
                .filter(|declaration| !declaration.enacted)
                .count()
                > 1
        {
            return None;
        }
        for declaration in &status {
            if !declaration.programs.is_complete() || declaration.programs.execution.fact != fact {
                return None;
            }
        }
        Some(status)
    }

    /// Identities this node needs bytes for: everything the chain names
    /// (see [`Self::named_identities`]) plus the specification's pinned
    /// genesis programs.
    pub(super) fn needed_programs(&self) -> BTreeSet<ExpectedIdentity> {
        let (programs, chunk) = self.with_engine(|engine| {
            let spec = engine.chain_spec();
            (spec.genesis_programs(), spec.genesis_chunk)
        });
        let mut needed = self.named_identities();
        needed.insert(ExpectedIdentity::Runtime(programs.runtime_code_hash));
        needed.extend(
            [
                programs.execution.fact,
                programs.execution.evidence,
                programs.execution.block,
                chunk,
            ]
            .map(ExpectedIdentity::Guest),
        );
        needed
    }

    /// The content hash `identity`'s artifact must have, when the chain pins
    /// one: the specification's genesis artifacts, or the artifacts an
    /// enacted program switch declares.
    pub(super) fn expected_program_content(&self, identity: ExpectedIdentity) -> Option<Hash> {
        self.genesis_program_content(identity).or_else(|| {
            self.wanted_artifacts()
                .into_iter()
                .find(|(_, named)| *named == identity)
                .map(|(content, _)| content)
        })
    }

    /// The content hash the specification pins for `identity`'s genesis
    /// artifact, if it is one.
    pub(in crate::chain_backend) fn genesis_program_content(
        &self,
        identity: ExpectedIdentity,
    ) -> Option<Hash> {
        self.with_engine(|engine| {
            let spec = engine.chain_spec();
            let programs = spec.genesis_programs();
            let artifacts = spec.genesis_artifacts;
            [
                (
                    ExpectedIdentity::Runtime(programs.runtime_code_hash),
                    artifacts.runtime,
                ),
                (
                    ExpectedIdentity::Guest(programs.execution.fact),
                    artifacts.fact,
                ),
                (
                    ExpectedIdentity::Guest(programs.execution.evidence),
                    artifacts.evidence,
                ),
                (
                    ExpectedIdentity::Guest(programs.execution.block),
                    artifacts.block,
                ),
                (ExpectedIdentity::Guest(spec.genesis_chunk), artifacts.chunk),
            ]
            .into_iter()
            .find(|(named, content)| *named == identity && *content != [0; 32])
            .map(|(_, content)| content)
        })
    }

    /// Whether this node holds the bytes of `identity`: installed, or
    /// indexed in the program store (checked by metadata, not by reading).
    pub(super) fn holds_program(&self, identity: ExpectedIdentity) -> bool {
        let store = self.program_store();
        self.installed_program(identity)
            || store
                .identity_content_hash(identity)
                .is_some_and(|hash| store.has_persisted(&hash))
    }

    /// The executor runs `identity`'s runtime or the proof backend has set
    /// up its Guest.
    fn installed_program(&self, identity: ExpectedIdentity) -> bool {
        match identity {
            ExpectedIdentity::Runtime(code_hash) => self
                .block_executor_snapshot()
                .is_some_and(|executor| executor.installed_runtimes().contains(&code_hash)),
            ExpectedIdentity::Guest(digest) => self
                .proof_system
                .installed_guests()
                .iter()
                .any(|(installed, _)| *installed == digest),
        }
    }
}
