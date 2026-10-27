//! The signer's own slashing protection.
//!
//! Every request is reserved durably before it is signed, and a request that
//! could form an offence with one already signed is refused: a second header
//! at a used slot or an earlier slot, a second vote (value or nil) at a used
//! chunk, round and step, a second proposal or round change at a used round,
//! anything at a round below the highest one signed in the chunk, a prevote
//! for another value than the retained lock without a later unlock quorum and
//! a precommit without its own round's quorum. Quorums are checked by shape
//! only: the signer holds no validator sets, and the node verifies their
//! signatures before asking. Exactly repeated requests are signed again.
//!
//! Positions are kept for the last [`WINDOW`] chunks an identity signed in;
//! anything older is refused, so the journal stays bounded. Slots and chunks
//! never advance faster than one a second, so a request further ahead of the
//! highest one signed than that pace allows is refused: one buggy far-future
//! request cannot move the window past every real chunk.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_engine::SignRequest;
use neutrin0_consensus_types::{FinalityVoteData, FinalityVotePhase};
use neutrin0_primitives::{BlsPublicKey, Hash, Slot, blake3_256};
use neutrin0_storage::{Batch, Column, Database};

use crate::protocol::Refusal;

/// Chunks below an identity's highest signed chunk whose positions are kept.
pub const WINDOW: u64 = 64;

/// Slots a header may run ahead of the paced bound, for clock skew between
/// the node and the signer.
const SLOT_MARGIN: u64 = 600;

const HEADER: u8 = b'h';
const FLOOR: u8 = b'f';
const ROUND: u8 = b'w';
const VOTE: u8 = b'v';
const MESSAGE: u8 = b'm';
const SLOT_PACE: u8 = b's';
const CHUNK_PACE: u8 = b'c';
const PROPOSAL: u8 = 0;
const ROUND_CHANGE: u8 = 1;

/// Highest round signed in one chunk and the value precommitted there.
#[derive(BorshSerialize, BorshDeserialize, Default)]
struct Watermark {
    round: u32,
    lock: Option<FinalityVoteData>,
}

/// Durable reservations of one signer's identities.
#[derive(Debug)]
pub struct Journal<DB> {
    db: DB,
}

impl<DB: Database> Journal<DB>
where
    DB::Error: core::fmt::Display,
{
    /// A journal over `db`, whose `SigningJournal` column it owns.
    pub const fn new(db: DB) -> Self {
        Self { db }
    }

    /// Reserve `request` for `identity` at the current wall-clock time.
    ///
    /// # Errors
    /// Returns the refusal; storage failures refuse as well.
    pub fn reserve(
        &mut self,
        identity: &BlsPublicKey,
        request: &SignRequest,
    ) -> Result<(), Refusal> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_secs());
        self.reserve_at(identity, request, now)
    }

    /// Reserve `request` for `identity` at `now` (Unix seconds): record it
    /// durably and return `Ok` when it may be signed, or the reason it may not.
    ///
    /// # Errors
    /// Returns the refusal; storage failures refuse as well.
    pub fn reserve_at(
        &mut self,
        identity: &BlsPublicKey,
        request: &SignRequest,
        now: u64,
    ) -> Result<(), Refusal> {
        let digest = blake3_256(&borsh::to_vec(request).map_err(storage)?);
        let mut batch = Batch::new();
        match request {
            // Evaluating the VRF again yields the same proof; no offence exists.
            SignRequest::Vrf { .. } => return Ok(()),
            SignRequest::Header(header) => {
                self.pace(
                    &mut batch,
                    identity_key(SLOT_PACE, identity),
                    header.slot,
                    SLOT_MARGIN,
                    now,
                )?;
                self.reserve_header(&mut batch, identity, header.slot, header.hash())?;
            }
            SignRequest::Vote(claim) => {
                let data = &claim.vote;
                let mut watermark =
                    self.position(&mut batch, identity, data.chunk_id, data.round, now)?;
                self.claim(
                    &mut batch,
                    &vote_key(identity, data.chunk_id, data.round, data.phase),
                    digest,
                )?;
                match data.phase {
                    // Another value than the lock needs a quorum for it
                    // strictly between the lock's round and this one.
                    FinalityVotePhase::Prevote => {
                        if let Some(lock) = &watermark.lock
                            && !data.same_value(lock)
                            && !claim.unlock_quorum.as_ref().is_some_and(|unlock| {
                                lock.round < unlock.data.round
                                    && unlock.data.round < data.round
                                    && unlock.data.same_value(data)
                            })
                        {
                            return Err(Refusal::Conflict);
                        }
                    }
                    FinalityVotePhase::Precommit => {
                        let quorum = claim
                            .unlock_quorum
                            .as_ref()
                            .filter(|quorum| {
                                quorum.data.round == data.round && quorum.data.same_value(data)
                            })
                            .ok_or(Refusal::Conflict)?;
                        watermark.lock = Some(quorum.data.clone());
                    }
                }
                put_watermark(&mut batch, identity, data.chunk_id, &watermark)?;
            }
            SignRequest::NilVote(claim) => {
                let data = &claim.vote;
                let watermark =
                    self.position(&mut batch, identity, data.chunk_id, data.round, now)?;
                self.claim(
                    &mut batch,
                    &vote_key(identity, data.chunk_id, data.round, data.phase),
                    digest,
                )?;
                put_watermark(&mut batch, identity, data.chunk_id, &watermark)?;
            }
            SignRequest::Proposal(proposal) => {
                self.reserve_message(
                    &mut batch,
                    identity,
                    PROPOSAL,
                    (proposal.chunk.chunk_id, proposal.round),
                    digest,
                    now,
                )?;
            }
            SignRequest::RoundChange(report) => {
                self.reserve_message(
                    &mut batch,
                    identity,
                    ROUND_CHANGE,
                    (report.chunk_id, report.round),
                    digest,
                    now,
                )?;
            }
        }
        self.db.write_batch_durable(batch).map_err(storage)
    }

    fn reserve_header(
        &self,
        batch: &mut Batch,
        identity: &BlsPublicKey,
        slot: Slot,
        hash: Hash,
    ) -> Result<(), Refusal> {
        let key = identity_key(HEADER, identity);
        if let Some((prior_slot, prior_hash)) = self.read::<(Slot, Hash)>(&key)? {
            if slot < prior_slot {
                return Err(Refusal::Regression);
            }
            if slot == prior_slot && hash != prior_hash {
                return Err(Refusal::Conflict);
            }
        }
        batch.put(
            Column::SigningJournal,
            key,
            borsh::to_vec(&(slot, hash)).map_err(storage)?,
        );
        Ok(())
    }

    fn reserve_message(
        &self,
        batch: &mut Batch,
        identity: &BlsPublicKey,
        kind: u8,
        (chunk, round): (u64, u32),
        digest: Hash,
        now: u64,
    ) -> Result<(), Refusal> {
        let watermark = self.position(batch, identity, chunk, round, now)?;
        let mut key = chunk_key(MESSAGE, identity, chunk);
        key.extend_from_slice(&round.to_be_bytes());
        key.push(kind);
        self.claim(batch, &key, digest)?;
        put_watermark(batch, identity, chunk, &watermark)
    }

    /// Refuse `position` beyond the highest one recorded under `key` by more
    /// than `margin` plus one per second since that one was recorded, and
    /// record a new highest. Nothing bounds an identity's first request.
    fn pace(
        &self,
        batch: &mut Batch,
        key: Vec<u8>,
        position: u64,
        margin: u64,
        now: u64,
    ) -> Result<(), Refusal> {
        if let Some((highest, since)) = self.read::<(u64, u64)>(&key)? {
            if position <= highest {
                return Ok(());
            }
            let paced = highest
                .saturating_add(margin)
                .saturating_add(now.saturating_sub(since));
            if position > paced {
                return Err(Refusal::TooFarAhead);
            }
        }
        batch.put(
            Column::SigningJournal,
            key,
            borsh::to_vec(&(position, now)).map_err(storage)?,
        );
        Ok(())
    }

    /// The watermark of `chunk` advanced to `round`, refusing a chunk below
    /// the identity's window, one ahead of the pace or a round below the
    /// chunk's highest. Advancing the window drops the positions that leave it.
    fn position(
        &self,
        batch: &mut Batch,
        identity: &BlsPublicKey,
        chunk: u64,
        round: u32,
        now: u64,
    ) -> Result<Watermark, Refusal> {
        self.pace(
            batch,
            identity_key(CHUNK_PACE, identity),
            chunk,
            WINDOW,
            now,
        )?;
        let floor_key = identity_key(FLOOR, identity);
        let floor = self.read::<u64>(&floor_key)?.unwrap_or(0);
        if chunk < floor {
            return Err(Refusal::Expired);
        }
        let mut watermark: Watermark = self
            .read(&chunk_key(ROUND, identity, chunk))?
            .unwrap_or_default();
        if round < watermark.round {
            return Err(Refusal::Regression);
        }
        watermark.round = round;
        let next_floor = chunk.saturating_sub(WINDOW);
        if next_floor > floor {
            batch.put(
                Column::SigningJournal,
                floor_key,
                borsh::to_vec(&next_floor).map_err(storage)?,
            );
            for tag in [ROUND, VOTE, MESSAGE] {
                let start = chunk_key(tag, identity, floor);
                let end = chunk_key(tag, identity, next_floor);
                let mut from = start;
                loop {
                    let keys = self
                        .db
                        .keys_from(Column::SigningJournal, &from, 1024)
                        .map_err(storage)?;
                    let done = keys.len() < 1024;
                    let mut last = None;
                    for key in keys.into_iter().take_while(|key| *key < end) {
                        batch.delete(Column::SigningJournal, key.clone());
                        last = Some(key);
                    }
                    match last.filter(|_| !done) {
                        Some(mut key) => {
                            key.push(0);
                            from = key;
                        }
                        None => break,
                    }
                }
            }
        }
        Ok(watermark)
    }

    /// Record `digest` at `key`, refusing another request already there.
    fn claim(&self, batch: &mut Batch, key: &[u8], digest: Hash) -> Result<(), Refusal> {
        if self.read::<Hash>(key)?.is_some_and(|prior| prior != digest) {
            return Err(Refusal::Conflict);
        }
        batch.put(Column::SigningJournal, key.to_vec(), digest.to_vec());
        Ok(())
    }

    fn read<T: BorshDeserialize>(&self, key: &[u8]) -> Result<Option<T>, Refusal> {
        self.db
            .get(Column::SigningJournal, key)
            .map_err(storage)?
            .map(|bytes| borsh::from_slice(&bytes).map_err(storage))
            .transpose()
    }
}

fn put_watermark(
    batch: &mut Batch,
    identity: &BlsPublicKey,
    chunk: u64,
    watermark: &Watermark,
) -> Result<(), Refusal> {
    batch.put(
        Column::SigningJournal,
        chunk_key(ROUND, identity, chunk),
        borsh::to_vec(watermark).map_err(storage)?,
    );
    Ok(())
}

fn identity_key(tag: u8, identity: &BlsPublicKey) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 48 + 8 + 4 + 1);
    key.push(tag);
    key.extend_from_slice(identity);
    key
}

fn chunk_key(tag: u8, identity: &BlsPublicKey, chunk: u64) -> Vec<u8> {
    let mut key = identity_key(tag, identity);
    key.extend_from_slice(&chunk.to_be_bytes());
    key
}

fn vote_key(identity: &BlsPublicKey, chunk: u64, round: u32, phase: FinalityVotePhase) -> Vec<u8> {
    let mut key = chunk_key(VOTE, identity, chunk);
    key.extend_from_slice(&round.to_be_bytes());
    key.push(match phase {
        FinalityVotePhase::Prevote => 0,
        FinalityVotePhase::Precommit => 1,
    });
    key
}

fn storage(error: impl core::fmt::Display) -> Refusal {
    Refusal::Storage(error.to_string())
}

#[cfg(test)]
mod tests;
