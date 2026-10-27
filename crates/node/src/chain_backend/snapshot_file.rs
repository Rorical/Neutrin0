//! Offline snapshot files: a node's latest finalized endpoint, written so
//! another node can bootstrap from it without peers.
//!
//! A file holds the manifest a peer serves (the History proof inside
//! [`BootstrapData`], plus an optional anchor opening), then every program,
//! state and sanctions object the manifest names, each under its content key.
//! Import authenticates the manifest as a network bootstrap does, except that
//! an operator-supplied endpoint is not judged stale; it stages the objects,
//! resolves the download locally and installs it like any other, a bounded
//! slice at a time. Nothing is held in memory whole on either side.

mod format;

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use neutrin0_consensus_types::bootstrap::{BootstrapData, StateItem, StateItemKind};
use neutrin0_consensus_types::history_proof::ConsensusBoundary;
use neutrin0_primitives::{Hash, ZERO_HASH};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;
use neutrin0_trie::Node;

use super::ChainBackend;
use super::bootstrap::{bootstrap_program_items, validate_data};
use format::{END, Header, MAGIC, MAX_HEADER_BYTES, Writer, read_u32, tag_kind};

/// Objects staged per engine-lock hold while importing.
const STAGE_OBJECTS: usize = 1024;
/// Bytes staged per engine-lock hold while importing.
const STAGE_BYTES: usize = 16 * 1024 * 1024;
/// State objects written between renewals of the snapshot's leases.
const LEASE_RENEWAL: u64 = 4096;

/// What an export wrote.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotSummary {
    /// Checkpoint hash of the exported endpoint.
    pub endpoint: Hash,
    /// Finalized chunks the endpoint covers.
    pub chunks: u64,
    /// Objects written, programs included.
    pub objects: u64,
    /// Programs the manifest names that this node does not hold, left out:
    /// an importer must hold them already, as it must from a peer that lacks
    /// them.
    pub programs_left_out: u64,
    /// File size in bytes.
    pub bytes: u64,
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|error| error.to_string())
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Write the latest finalized endpoint to a new file at `path`. With
    /// `anchor`, the file also opens the boundary at that many chunks under
    /// the endpoint, for an importer whose trust boundary it is.
    ///
    /// # Errors
    /// Refuses an existing file, a node with no finalized History proof or an
    /// anchor it cannot open, and reports I/O and storage failures. A failed
    /// export leaves a partial file, which no import accepts as complete.
    pub fn export_snapshot(
        &self,
        path: &Path,
        anchor: Option<u64>,
    ) -> Result<SnapshotSummary, String> {
        let endpoint = self
            .with_engine(neutrin0_consensus_engine::Engine::latest_history_proof)
            .map_err(|error| error.to_string())?
            .ok_or("no finalized History proof to export")?
            .end_checkpoint();
        let data = self
            .serve_bootstrap(endpoint.hash())
            .map_err(|error| error.to_string())?;
        let end = *data.history.end();
        // The export reads every object under both roots; lease them first.
        let now = now()?;
        self.with_engine_mut(|engine| {
            engine.store_mut().pin_state_snapshot(end.state_root, now)?;
            engine
                .store_mut()
                .pin_state_snapshot(end.identity_sanctions_root, now)
        })
        .map_err(|error| error.to_string())?;
        let anchor = anchor
            .map(|anchor| {
                self.with_engine(|engine| engine.anchor_opening(anchor, end.next_chunk_id))
                    .map_err(|error| error.to_string())
            })
            .transpose()?
            .flatten();
        let programs = bootstrap_program_items(&data).map_err(|error| error.to_string())?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|error| error.to_string())?;
        let mut writer = Writer {
            out: BufWriter::new(file),
            objects: 0,
        };
        let header = borsh::to_vec(&Header { anchor, data }).map_err(|error| error.to_string())?;
        let length = u32::try_from(header.len())
            .ok()
            .filter(|length| *length <= MAX_HEADER_BYTES)
            .ok_or("snapshot manifest too large")?;
        writer
            .out
            .write_all(MAGIC)
            .map_err(|error| error.to_string())?;
        writer
            .out
            .write_all(&length.to_le_bytes())
            .map_err(|error| error.to_string())?;
        writer
            .out
            .write_all(&header)
            .map_err(|error| error.to_string())?;
        let mut programs_left_out = 0;
        for item in programs {
            match self.program_bytes(item)? {
                Some(bytes) => writer.object(item.kind, &item.hash, &bytes)?,
                None => programs_left_out += 1,
            }
        }
        for root in [end.state_root, end.identity_sanctions_root] {
            self.write_state(&mut writer, root)?;
        }
        writer
            .out
            .write_all(&[END])
            .map_err(|error| error.to_string())?;
        let file = writer.out.into_inner().map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        Ok(SnapshotSummary {
            endpoint: endpoint.hash(),
            chunks: end.next_chunk_id,
            objects: writer.objects,
            programs_left_out,
            bytes: file.metadata().map_err(|error| error.to_string())?.len(),
        })
    }

    /// The complete bytes of a program the manifest names, as a peer serves
    /// them fragment by fragment, or `None` when this node does not hold it.
    fn program_bytes(&self, item: StateItem) -> Result<Option<Vec<u8>>, String> {
        let mut bytes = Vec::new();
        loop {
            let fragment = match self.bootstrap_program_fragment(&StateItem {
                offset: bytes.len() as u64,
                ..item
            }) {
                Ok(fragment) => fragment,
                Err(SyncBackendError::NotAvailable(_)) if bytes.is_empty() => return Ok(None),
                Err(error) => return Err(error.to_string()),
            };
            bytes.extend_from_slice(fragment.bytes.as_slice());
            if bytes.len() as u64 >= fragment.total_len {
                return Ok(Some(bytes));
            }
        }
    }

    /// Write every object `root` reaches, depth first, renewing its lease so
    /// collection keeps it while the export runs.
    fn write_state(&self, writer: &mut Writer, root: Hash) -> Result<(), String> {
        let source = self.with_engine(|engine| engine.store().state_source());
        let mut pending = vec![root];
        let mut written = 0_u64;
        while let Some(hash) = pending.pop() {
            if hash == ZERO_HASH {
                continue;
            }
            let bytes = source.node(&hash).ok_or("snapshot state node is missing")?;
            match Node::decode(&bytes).map_err(|error| error.to_string())? {
                Node::Leaf { value_hash, .. } => {
                    let value = source
                        .value(&value_hash)
                        .ok_or("snapshot state value is missing")?;
                    writer.object(StateItemKind::Value, &value_hash, &value)?;
                }
                Node::Branch { left, right } => pending.extend([left, right]),
                Node::Extension { child, .. } => pending.push(child),
            }
            writer.object(StateItemKind::Node, &hash, &bytes)?;
            written += 1;
            if written.is_multiple_of(LEASE_RENEWAL) {
                let now = now()?;
                self.with_engine_mut(|engine| engine.store_mut().refresh_state_snapshot(root, now))
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    /// Bootstrap from the snapshot file at `path` and return whether it was
    /// installed; an endpoint local finality already reached is skipped.
    ///
    /// Under a hard fork's successor specification, a file of exactly the
    /// predecessor's endpoint the specification pins starts the successor
    /// there instead: the start is trusted as genesis is, so the file's
    /// predecessor History proof is not verified (it may need another SP1
    /// version), only its data against that start.
    ///
    /// # Errors
    /// Refuses a malformed file, a manifest that does not authenticate
    /// against the local trust boundary or the fork's start, objects that do
    /// not match their keys and a file lacking objects its manifest needs.
    pub async fn import_snapshot(&self, path: &Path) -> Result<bool, String> {
        let mut input = BufReader::new(File::open(path).map_err(|error| error.to_string())?);
        let mut magic = [0; 16];
        input
            .read_exact(&mut magic)
            .map_err(|error| error.to_string())?;
        if &magic != MAGIC {
            return Err("not a Neutrin0 snapshot file".into());
        }
        let length = read_u32(&mut input)?;
        if length > MAX_HEADER_BYTES {
            return Err("snapshot manifest too large".into());
        }
        let mut header = vec![0; length as usize];
        input
            .read_exact(&mut header)
            .map_err(|error| error.to_string())?;
        let Header { anchor, data } =
            borsh::from_slice(&header).map_err(|error| error.to_string())?;
        let count = data.history.end().next_chunk_id;
        if count <= self.with_engine(neutrin0_consensus_engine::Engine::finalized_next_chunk_id) {
            return Ok(false);
        }
        let fork_start = self.with_engine(|engine| {
            let spec = engine.chain_spec();
            spec.fork
                .as_deref()
                .filter(|_| spec.fork_endpoint() == Some(*data.history.end()))
                .map(|fork| fork.start)
        });
        if let Some(start) = fork_start {
            self.stage_file_objects(&mut input)?;
            self.start_fork(&data, &start)?;
            return Ok(true);
        }
        self.begin_offline_bootstrap(anchor, data)
            .await
            .map_err(|error| error.to_string())?;
        self.stage_file_objects(&mut input)?;
        if !self.bootstrap_pending() {
            return Ok(true);
        }
        if !self
            .bootstrap_downloads_complete()
            .map_err(|error| error.to_string())?
        {
            return Err("snapshot file lacks objects its manifest needs".into());
        }
        self.finish_bootstrap()
            .await
            .map_err(|error| error.to_string())?;
        Ok(true)
    }

    /// Stage every object of the file's stream, a bounded batch per
    /// engine-lock hold.
    fn stage_file_objects(&self, input: &mut impl Read) -> Result<(), String> {
        let mut batch = Vec::new();
        let mut held = 0;
        loop {
            let mut tag = [0];
            input
                .read_exact(&mut tag)
                .map_err(|error| error.to_string())?;
            if tag[0] == END {
                break;
            }
            let kind = tag_kind(tag[0]).ok_or("malformed snapshot object kind")?;
            let mut hash = [0; 32];
            input
                .read_exact(&mut hash)
                .map_err(|error| error.to_string())?;
            let length = read_u32(input)?;
            // Staging bounds each kind; this only keeps one read finite.
            if u64::from(length) > super::state_sync::MAX_ENTRY_BYTES {
                return Err("snapshot object too large".into());
            }
            let mut bytes = vec![0; length as usize];
            input
                .read_exact(&mut bytes)
                .map_err(|error| error.to_string())?;
            held += bytes.len();
            batch.push((kind, hash, bytes));
            if batch.len() >= STAGE_OBJECTS || held >= STAGE_BYTES {
                self.stage_objects(&batch)
                    .map_err(|error| error.to_string())?;
                batch.clear();
                held = 0;
            }
        }
        self.stage_objects(&batch)
            .map_err(|error| error.to_string())
    }

    /// Start a hard fork's successor at `start` from the predecessor's
    /// endpoint data and the staged objects.
    fn start_fork(&self, data: &BootstrapData, start: &ConsensusBoundary) -> Result<(), String> {
        let recent = validate_data(data).map_err(|error| error.to_string())?;
        let mut roots = vec![start.state_root, start.identity_sanctions_root];
        roots.dedup();
        for root in &roots {
            if !self
                .state_download_items(*root)
                .map_err(|error| error.to_string())?
                .is_empty()
            {
                return Err("snapshot file lacks objects its manifest needs".into());
            }
        }
        self.install_downloaded_state(&[start.state_root, start.identity_sanctions_root])
            .map_err(|error| error.to_string())?;
        self.with_engine_mut(|engine| {
            engine.install_fork_start(
                &data.anchor_header,
                &data.validators,
                &data.frontier,
                &recent,
            )
        })
        .map_err(|error| error.to_string())?;
        for root in roots {
            self.clear_state_download(root)
                .map_err(|error| error.to_string())?;
        }
        self.bootstrap_fetch(false);
        self.after_chunk_finality();
        Ok(())
    }
}
