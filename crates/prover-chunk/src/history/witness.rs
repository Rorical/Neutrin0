//! Bounded historical openings and the append frontier one chunk witness
//! authenticates against its incoming history root.

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrin0_consensus_types::evidence::commitment;
use neutrin0_consensus_types::history::{
    HISTORY_RETENTION_CHUNKS, HistoryFrontier, HistoryPath, is_recent_history_index,
};
use neutrin0_primitives::Hash;

use super::HistoryError;
use super::records::{HistoricalChunk, HistoricalContext};

/// Maximum distinct historical reads in one consensus witness.
pub const MAX_HISTORY_READS: usize = 8;
const _: () = assert!(MAX_HISTORY_READS as u64 == HISTORY_RETENTION_CHUNKS);
/// Maximum canonical bytes of one retained full historical source record.
pub const MAX_HISTORY_RECORD_BYTES: usize = 8 * 1024 * 1024;

/// One record authenticated against the incoming counted history root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalOpening {
    /// Canonical historical record. Certificate bytes are not part of its leaf.
    pub record: HistoricalChunk,
    /// Fixed-depth membership path for that record's chunk ID.
    pub path: HistoryPath,
}

impl BorshSerialize for HistoricalOpening {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        borsh::to_vec(&self.record)?.serialize(writer)?;
        self.path.serialize(writer)
    }
}

impl HistoricalOpening {
    fn read_bounded<R: io::Read>(reader: &mut R, budget: &mut usize) -> io::Result<Self> {
        let length = u32::deserialize_reader(reader)? as usize;
        *budget = budget.checked_sub(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "historical record byte budget")
        })?;
        let mut bytes = alloc::vec![0; length];
        reader.read_exact(&mut bytes)?;
        let record = borsh::from_slice(&bytes)?;
        let path = HistoryPath::deserialize_reader(reader)?;
        Ok(Self { record, path })
    }
}

impl BorshDeserialize for HistoricalOpening {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut budget = MAX_HISTORY_RECORD_BYTES;
        Self::read_bounded(reader, &mut budget)
    }
}

/// Aggregate canonical thin-context bytes admitted by one Chunk witness.
/// Eight maximum-size current validator vectors fit below this bound.
pub const MAX_HISTORY_CONTEXT_BYTES: usize = 256 * 1024;
/// Maximum canonical bytes of one thin historical context.
pub const MAX_HISTORY_CONTEXT_RECORD_BYTES: usize = 32 * 1024;

/// A slim consensus read authenticated against the incoming history root.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalContextOpening {
    /// Certificate-independent context; signed sources are retained separately.
    pub record: HistoricalContext,
    /// Fixed-depth membership path for that record's chunk ID.
    pub path: HistoryPath,
}

impl From<&HistoricalOpening> for HistoricalContextOpening {
    fn from(opening: &HistoricalOpening) -> Self {
        Self {
            record: HistoricalContext::from(&opening.record),
            path: opening.path.clone(),
        }
    }
}

impl From<HistoricalOpening> for HistoricalContextOpening {
    fn from(opening: HistoricalOpening) -> Self {
        let HistoricalOpening { record, path } = opening;
        Self {
            record: HistoricalContext {
                chunk: record.chunk,
                validators: record.validators,
                seed: record.seed,
                block_guest_vk_digest: record.block_guest_vk_digest,
                runtime_code_hash: record.runtime_code_hash,
                start_boundary: record.start_boundary,
            },
            path,
        }
    }
}

impl BorshSerialize for HistoricalContextOpening {
    fn serialize<W: io::Write>(&self, writer: &mut W) -> io::Result<()> {
        borsh::to_vec(&self.record)?.serialize(writer)?;
        self.path.serialize(writer)
    }
}

impl HistoricalContextOpening {
    fn read_bounded<R: io::Read>(reader: &mut R, budget: &mut usize) -> io::Result<Self> {
        let length = u32::deserialize_reader(reader)? as usize;
        if length > MAX_HISTORY_CONTEXT_RECORD_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "historical context record bytes",
            ));
        }
        *budget = budget.checked_sub(length).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "historical context byte budget")
        })?;
        let mut bytes = alloc::vec![0; length];
        reader.read_exact(&mut bytes)?;
        Ok(Self {
            record: borsh::from_slice(&bytes)?,
            path: HistoryPath::deserialize_reader(reader)?,
        })
    }
}

impl BorshDeserialize for HistoricalContextOpening {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let mut budget = MAX_HISTORY_CONTEXT_BYTES;
        Self::read_bounded(reader, &mut budget)
    }
}

/// Bounded append frontier and only the records actually read by this chunk.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize)]
pub struct HistoryWitness {
    /// Canonical prefix shape authenticated against the incoming history root.
    pub frontier: HistoryFrontier,
    /// Strictly increasing chunk IDs; no duplicate or unused openings.
    pub records: Vec<HistoricalContextOpening>,
}

impl BorshDeserialize for HistoryWitness {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let frontier = HistoryFrontier::deserialize_reader(reader)?;
        let length = u32::deserialize_reader(reader)? as usize;
        if length > MAX_HISTORY_READS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "historical read count",
            ));
        }
        let mut budget = MAX_HISTORY_CONTEXT_BYTES;
        let records = (0..length)
            .map(|_| HistoricalContextOpening::read_bounded(reader, &mut budget))
            .collect::<io::Result<Vec<_>>>()?;
        Ok(Self { frontier, records })
    }
}

impl HistoryWitness {
    /// Authenticate bounded contexts and the append position before using records.
    ///
    /// The incoming root must already be authenticated by the start boundary.
    /// Complete Chunk verification appended each source leaf after checking its
    /// finality; this membership read does not repeat that earlier certificate.
    pub fn authenticate(&self, chunk_id: u64, history_root: Hash) -> Result<(), HistoryError> {
        if self.frontier.count != chunk_id
            || self.frontier.root() != Some(history_root)
            || self.records.len() > MAX_HISTORY_READS
            || self
                .records
                .windows(2)
                .any(|pair| pair[0].record.chunk.chunk_id >= pair[1].record.chunk.chunk_id)
        {
            return Err(HistoryError::Anchor);
        }
        let mut budget = MAX_HISTORY_CONTEXT_BYTES;
        for opening in &self.records {
            let record = &opening.record;
            let context = record.evidence_context();
            let size = borsh::object_length(record).map_err(|_| HistoryError::Anchor)?;
            if size > MAX_HISTORY_CONTEXT_RECORD_BYTES {
                return Err(HistoryError::Anchor);
            }
            budget = budget.checked_sub(size).ok_or(HistoryError::Anchor)?;
            if !is_recent_history_index(record.chunk.chunk_id, chunk_id)
                || opening.path.index != record.chunk.chunk_id
                || opening.path.count != chunk_id
                || !opening.path.verify(commitment(&context), history_root)
                || record.chunk.active_validator_set_root != context.validators_root
                || !canonical_chunk_range(record)
            {
                return Err(HistoryError::Anchor);
            }
        }
        Ok(())
    }

    /// Construct selected openings from archive records (not a proving-time scan).
    pub fn from_history(history: &[HistoricalChunk], requested: &[u64]) -> Option<Self> {
        let count = u64::try_from(history.len()).ok()?;
        if requested.len() > MAX_HISTORY_READS
            || requested.windows(2).any(|pair| pair[0] >= pair[1])
            || requested
                .iter()
                .any(|id| !is_recent_history_index(*id, count))
        {
            return None;
        }
        let leaves: Vec<_> = history
            .iter()
            .map(|record| commitment(&record.evidence_context()))
            .collect();
        let frontier = HistoryFrontier::from_leaves(&leaves)?;
        let records = requested
            .iter()
            .map(|id| {
                let index = usize::try_from(*id).ok()?;
                let record = HistoricalContext::from(history.get(index)?);
                if record.chunk.chunk_id != *id {
                    return None;
                }
                Some(HistoricalContextOpening {
                    record,
                    path: HistoryPath::build(&leaves, index)?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        Some(Self { frontier, records })
    }

    /// Look up only authenticated requested historical membership.
    pub fn record(&self, chunk_id: u64) -> Result<&HistoricalContext, HistoryError> {
        if !is_recent_history_index(chunk_id, self.frontier.count) {
            return Err(HistoryError::Anchor);
        }
        self.records
            .binary_search_by_key(&chunk_id, |opening| opening.record.chunk.chunk_id)
            .ok()
            .and_then(|index| self.records.get(index))
            .map(|opening| &opening.record)
            .ok_or(HistoryError::Anchor)
    }
}

fn canonical_chunk_range(record: &HistoricalContext) -> bool {
    let Some(size) = record
        .chunk
        .end_height
        .checked_sub(record.chunk.start_height)
        .and_then(|difference| difference.checked_add(1))
    else {
        return false;
    };
    neutrin0_primitives::committee_size_valid(record.validators.len(), size)
        && record
            .chunk
            .chunk_id
            .checked_mul(size)
            .and_then(|height| height.checked_add(1))
            == Some(record.chunk.start_height)
}
