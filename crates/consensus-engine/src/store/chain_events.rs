//! Bounded, node-local canonical transition journal, atomic with chain publication.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::Header;
use neutrin0_primitives::Hash;
use neutrin0_storage::{Batch, BatchOp, Column, Database};

use super::{ChainStore, StoreError, pointers};

const STATE_KEY: &[u8] = b"local:chain-events";
const EVENT_PREFIX: &[u8] = b"local:chain-event:";
/// Maximum number of retained canonical transitions, independent of body retention.
pub const CHAIN_EVENT_WINDOW: u64 = 4096;
const MAX_ANCESTRY_READS: usize = 16_384;

/// One canonical block endpoint, requiring no historical transaction bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct ChainPoint {
    /// Canonical native block hash.
    pub hash: Hash,
    /// Block height, zero for genesis.
    pub height: u64,
}

/// Local stream identity and atomic current chain snapshot.
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct ChainEventState {
    /// Random database-local identity, retained through ordinary restart.
    pub stream_id: Hash,
    /// Full locally authenticated chain specification identity.
    pub chain_spec_hash: Hash,
    /// Trusted genesis hash.
    pub genesis: Hash,
    /// Selected canonical execution head.
    pub head: ChainPoint,
    /// Complete-chunk finalized endpoint.
    pub finalized: ChainPoint,
    /// Number of finalized chunks, zero at genesis.
    pub finalized_chunks: u64,
    /// First retained event sequence (inclusive).
    pub oldest: u64,
    /// Next unused event sequence; cursor zero predates initial snapshot.
    pub next: u64,
}

/// One durable transition. Missing ancestry explicitly requires snapshot recovery.
#[derive(Clone, Debug, Eq, PartialEq, BorshDeserialize, BorshSerialize)]
pub struct ChainEvent {
    /// Monotonically increasing local sequence.
    pub sequence: u64,
    /// Pre-transition head; absent only for stream initialization.
    pub previous_head: Option<ChainPoint>,
    /// New canonical head.
    pub head: ChainPoint,
    /// Common ancestor of both branches; absent for checkpoint jumps/initialization.
    pub common_ancestor: Option<ChainPoint>,
    /// Previous finalized endpoint.
    pub previous_finalized: ChainPoint,
    /// New finalized endpoint.
    pub finalized: ChainPoint,
    /// Previous finalized chunk count.
    pub previous_finalized_chunks: u64,
    /// New finalized chunk count.
    pub finalized_chunks: u64,
}

fn event_key(sequence: u64) -> Vec<u8> {
    let mut key = EVENT_PREFIX.to_vec();
    key.extend_from_slice(&sequence.to_be_bytes());
    key
}

fn staged_value<'a>(batch: &'a Batch, column: Column, key: &[u8]) -> Option<&'a [u8]> {
    batch.operations().iter().rev().find_map(|op| match op {
        BatchOp::Put {
            column: c,
            key: k,
            value,
        } if *c == column && k == key => Some(value.as_slice()),
        _ => None,
    })
}

impl<DB: Database> ChainStore<DB> {
    /// Load a journal snapshot; absent until the host enables the service.
    pub fn chain_event_state(&self) -> Result<Option<ChainEventState>, StoreError<DB::Error>> {
        let state: Option<ChainEventState> = self.get_decoded(Column::Meta, STATE_KEY)?;
        if state.as_ref().is_some_and(|s| {
            s.oldest == 0 || s.next <= s.oldest || s.next - s.oldest > CHAIN_EVENT_WINDOW
        }) {
            return Err(StoreError::Corrupt("invalid chain event retention bounds"));
        }
        Ok(state)
    }

    /// Enable a database-local stream before workers start, or validate its saved state.
    /// The supplied random identity is used only for a previously uninitialized stream.
    pub fn initialize_chain_events(
        &mut self,
        stream_id: Hash,
        chain_spec_hash: Hash,
        genesis: Hash,
    ) -> Result<(), StoreError<DB::Error>> {
        if let Some(state) = self.chain_event_state()? {
            if state.chain_spec_hash != chain_spec_hash || state.genesis != genesis {
                return Err(StoreError::Corrupt(
                    "chain event stream belongs to another chain",
                ));
            }
            self.validate_event_snapshot(&state)?;
            let mut previous: Option<ChainEvent> = None;
            for sequence in state.oldest..state.next {
                let event = self
                    .chain_event(sequence)?
                    .ok_or(StoreError::Corrupt("chain event journal has a gap"))?;
                if previous.as_ref().is_some_and(|prev| {
                    event.previous_head != Some(prev.head)
                        || event.previous_finalized != prev.finalized
                        || event.previous_finalized_chunks != prev.finalized_chunks
                }) {
                    return Err(StoreError::Corrupt("chain event journal is discontinuous"));
                }
                previous = Some(event);
            }
            if previous.is_none_or(|event| {
                event.head != state.head
                    || event.finalized != state.finalized
                    || event.finalized_chunks != state.finalized_chunks
            }) {
                return Err(StoreError::Corrupt(
                    "chain event tail disagrees with snapshot",
                ));
            }
            return Ok(());
        }
        let head = self.event_point(
            self.get_tip()?.ok_or(StoreError::Corrupt("missing tip"))?,
            genesis,
            &Batch::new(),
        )?;
        let finalized = self.event_point(
            self.get_finalized_head()?
                .ok_or(StoreError::Corrupt("missing finality"))?,
            genesis,
            &Batch::new(),
        )?;
        let count = self.finalized_count()?;
        let state = ChainEventState {
            stream_id,
            chain_spec_hash,
            genesis,
            head,
            finalized,
            finalized_chunks: count,
            oldest: 1,
            next: 2,
        };
        let event = ChainEvent {
            sequence: 1,
            previous_head: None,
            head,
            common_ancestor: None,
            previous_finalized: finalized,
            finalized,
            previous_finalized_chunks: count,
            finalized_chunks: count,
        };
        let mut batch = Batch::new();
        batch.put(Column::Meta, STATE_KEY, borsh::to_vec(&state)?);
        batch.put(Column::Meta, event_key(1), borsh::to_vec(&event)?);
        self.db
            .write_batch_durable(batch)
            .map_err(StoreError::Database)
    }

    /// Read one retained event with exact sequence validation.
    pub fn chain_event(&self, sequence: u64) -> Result<Option<ChainEvent>, StoreError<DB::Error>> {
        self.get_checked(
            Column::Meta,
            &event_key(sequence),
            |e: &ChainEvent| e.sequence == sequence,
            "chain event sequence mismatch",
        )
    }

    fn validate_event_snapshot(
        &self,
        state: &ChainEventState,
    ) -> Result<(), StoreError<DB::Error>> {
        if self.event_point(state.head.hash, state.genesis, &Batch::new())? != state.head
            || self.event_point(state.finalized.hash, state.genesis, &Batch::new())?
                != state.finalized
            || self.get_tip()? != Some(state.head.hash)
            || self.get_finalized_head()? != Some(state.finalized.hash)
            || self.finalized_count()? != state.finalized_chunks
        {
            return Err(StoreError::Corrupt(
                "chain event snapshot disagrees with durable chain",
            ));
        }
        Ok(())
    }

    fn event_header(
        &self,
        hash: Hash,
        batch: &Batch,
    ) -> Result<Option<Header>, StoreError<DB::Error>> {
        let header = staged_value(batch, Column::Headers, &hash).map_or_else(
            || self.get_header(&hash),
            |bytes| borsh::from_slice(bytes).map(Some).map_err(StoreError::from),
        )?;
        if header.as_ref().is_some_and(|header| header.hash() != hash) {
            return Err(StoreError::Corrupt("chain event header hash mismatch"));
        }
        Ok(header)
    }

    fn event_point(
        &self,
        hash: Hash,
        genesis: Hash,
        batch: &Batch,
    ) -> Result<ChainPoint, StoreError<DB::Error>> {
        let height = if hash == genesis {
            0
        } else {
            self.event_header(hash, batch)?
                .ok_or(StoreError::Corrupt("chain event header missing"))?
                .height
        };
        Ok(ChainPoint { hash, height })
    }

    fn event_ancestor(
        &self,
        state: &ChainEventState,
        mut point: ChainPoint,
        batch: &Batch,
    ) -> Result<Option<ChainPoint>, StoreError<DB::Error>> {
        for _ in 0..MAX_ANCESTRY_READS {
            if point.height <= state.head.height
                && self.get_block_hash_by_height(point.height)? == Some(point.hash)
            {
                return Ok(Some(point));
            }
            if point.height == 0 {
                return Ok(None);
            }
            let Some(header) = self.event_header(point.hash, batch)? else {
                return Ok(None);
            };
            if header.height != point.height {
                return Err(StoreError::Corrupt("chain event ancestry height mismatch"));
            }
            point = ChainPoint {
                hash: header.parent_hash,
                height: point.height - 1,
            };
        }
        Ok(None)
    }

    /// Append transitions to the same batch as canonical publication. No memory
    /// cache can advance ahead of a failed durable commit.
    pub(super) fn stage_chain_events(
        &self,
        batch: &mut Batch,
    ) -> Result<bool, StoreError<DB::Error>> {
        let relevant = batch.operations().iter().any(|op| matches!(op, BatchOp::Put { column: Column::Finalized, key, .. } if [pointers::TIP, pointers::FINALIZED_HEAD, pointers::LATEST_FINALIZED_CHUNK_ID].contains(&key.as_slice())));
        if !relevant {
            return Ok(false);
        }
        let Some(mut state) = self.chain_event_state()? else {
            return Ok(false);
        };
        self.validate_event_snapshot(&state)?;
        let hash = |key, default| -> Result<Hash, StoreError<DB::Error>> {
            staged_value(batch, Column::Finalized, key).map_or(Ok(default), |bytes| {
                bytes
                    .try_into()
                    .map_err(|_| StoreError::Corrupt("chain event pointer length"))
            })
        };
        let head = self.event_point(hash(pointers::TIP, state.head.hash)?, state.genesis, batch)?;
        let finalized = self.event_point(
            hash(pointers::FINALIZED_HEAD, state.finalized.hash)?,
            state.genesis,
            batch,
        )?;
        let count = staged_value(
            batch,
            Column::Finalized,
            pointers::LATEST_FINALIZED_CHUNK_ID,
        )
        .map_or(Ok(state.finalized_chunks), |bytes| {
            let bytes = bytes
                .try_into()
                .map_err(|_| StoreError::Corrupt("chain event chunk count length"))?;
            u64::from_be_bytes(bytes)
                .checked_add(1)
                .ok_or(StoreError::Corrupt("chain event chunk count overflow"))
        })?;
        if (head, finalized, count) == (state.head, state.finalized, state.finalized_chunks) {
            return Ok(false);
        }
        if count < state.finalized_chunks
            || finalized.height < state.finalized.height
            || (count == state.finalized_chunks && finalized != state.finalized)
        {
            return Err(StoreError::Corrupt("chain event finality regressed"));
        }
        let event = ChainEvent {
            sequence: state.next,
            previous_head: Some(state.head),
            head,
            common_ancestor: self.event_ancestor(&state, head, batch)?,
            previous_finalized: state.finalized,
            finalized,
            previous_finalized_chunks: state.finalized_chunks,
            finalized_chunks: count,
        };
        state.next = state
            .next
            .checked_add(1)
            .ok_or(StoreError::Corrupt("chain event sequence exhausted"))?;
        if state.next - state.oldest > CHAIN_EVENT_WINDOW {
            batch.delete(Column::Meta, event_key(state.oldest));
            state.oldest += 1;
        }
        state.head = head;
        state.finalized = finalized;
        state.finalized_chunks = count;
        batch.put(
            Column::Meta,
            event_key(event.sequence),
            borsh::to_vec(&event)?,
        );
        batch.put(Column::Meta, STATE_KEY, borsh::to_vec(&state)?);
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
