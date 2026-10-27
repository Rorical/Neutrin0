//! The node's side of a hard-fork handoff (design 20): noticing that this
//! chain finalized up to a scheduled fork, writing the endpoint bundle, and
//! completing a successor's start from one (see [`crate::fork`]).

use std::path::{Path, PathBuf};

use neutrin0_consensus_engine::signing_transfer::SigningTransfer;
use neutrin0_primitives::ScheduledFork;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;

use super::ChainBackend;
use crate::fork::Handoff;

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Import a hard fork's carry file once, after the successor's start is
    /// installed; `None` when this directory already imported one.
    ///
    /// # Errors
    /// Returns an unreadable file and every carry the engine refuses.
    pub fn import_fork_carry(
        &self,
        path: &std::path::Path,
    ) -> Result<Option<neutrin0_consensus_engine::store::CarrySummary>, String> {
        let mut input =
            std::io::BufReader::new(std::fs::File::open(path).map_err(|error| error.to_string())?);
        self.with_engine_mut(|engine| engine.import_fork_carry(&mut input))
            .map_err(|error| error.to_string())
    }

    /// The fork this chain ended at: its latest finalized boundary is the
    /// endpoint, whose chunk the chain Guest refuses.
    pub fn reached_fork(&self) -> Option<ScheduledFork> {
        self.with_engine(|engine| {
            let count = engine.finalized_next_chunk_id();
            engine
                .canonical_boundary(count)
                .ok()?
                .fork
                .filter(|fork| fork.count == count)
        })
    }

    /// Write the endpoint bundle of the fork this chain ended at into
    /// `data_dir`, from `raw_spec`, the text of this node's specification
    /// file. A bundle already written stays as it is.
    ///
    /// # Errors
    /// Refuses a chain that has not reached a fork and returns every export
    /// failure.
    pub fn export_fork_endpoint(&self, raw_spec: &str, data_dir: &Path) -> Result<PathBuf, String> {
        let bundle = data_dir.join(crate::fork::ENDPOINT_DIR);
        if bundle.is_dir() {
            return Ok(bundle);
        }
        if self.reached_fork().is_none() {
            return Err("this chain has not reached a fork's endpoint".into());
        }
        let proof = self
            .with_engine(neutrin0_consensus_engine::Engine::latest_history_proof)
            .map_err(|error| error.to_string())?
            .ok_or("no finalized History proof at the fork's endpoint")?;
        let template = self.with_engine(|engine| {
            crate::fork::successor_template(raw_spec, engine.chain_spec(), &proof)
        })?;
        let transfer = self.with_engine(|engine| SigningTransfer::export(engine.store().db()))?;
        crate::fork::write_bundle(
            data_dir,
            &template,
            &transfer,
            |path| self.export_snapshot(path, None).map(drop),
            |out| {
                self.with_engine(|engine| engine.store().export_fork_carry(out))
                    .map(drop)
                    .map_err(|error| error.to_string())
            },
        )
    }

    /// Start this successor from `handoff`'s bundle where it has not yet:
    /// the endpoint snapshot as its start, then the carry, once each. The
    /// signing protection was imported before the engine opened.
    ///
    /// # Errors
    /// Returns every snapshot and carry the engine refuses.
    pub async fn complete_fork_handoff(&self, handoff: &Handoff) -> Result<(), String> {
        let (count, started) = self.with_engine(|engine| {
            let count = engine.chain_spec().first_chunk();
            (count, engine.finalized_next_chunk_id() >= count)
        });
        if !started {
            self.import_snapshot(&handoff.snapshot()).await?;
        }
        let carried = self
            .with_engine(|engine| engine.store().fork_carry_imported())
            .map_err(|error| error.to_string())?;
        if !carried {
            let summary = self.import_fork_carry(&handoff.carry())?;
            tracing::info!(
                fork_count = count,
                rows = summary.map_or(0, |summary| summary.rows),
                "hard fork handoff complete; the predecessor's data directory is no longer read"
            );
        }
        Ok(())
    }
}
