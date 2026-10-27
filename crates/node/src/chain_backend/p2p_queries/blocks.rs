//! Block publications, receipts and witnesses along an advertised branch.

use std::collections::BTreeMap;

use neutrin0_consensus_engine::Engine;
use neutrin0_network::rpc::{self, BlocksByRangeResponse, WitnessByBlockResponse};
use neutrin0_primitives::{BlockHash, Height, ZERO_HASH};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;
use neutrin0_sync::SyncBackendError;

use super::{
    ChainBackend, bounded, check_count, not_available, query_error, rpc_queries, storage_error,
};

/// One page entry of `BlocksByRange`.
enum Entry {
    Proven(neutrin0_consensus_types::ProvenBlock),
    Candidate(neutrin0_consensus_types::CandidateBlock),
}

fn canonical_hash<DB: Database>(
    engine: &Engine<DB>,
    height: Height,
) -> Result<Option<BlockHash>, SyncBackendError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    engine
        .store()
        .get_block_hash_by_height(height)
        .map_err(storage_error)
}

/// The anchor's height, once the requested range can be served from it.
fn branch_tip_height<DB: Database>(
    engine: &Engine<DB>,
    anchor: BlockHash,
    start: Height,
    count: u64,
) -> Result<Height, SyncBackendError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    if count > 0 {
        rpc_queries::ensure_payload_height(engine, start).map_err(query_error)?;
    }
    let genesis = engine.chain_spec().genesis_block_hash;
    let tip_height = if anchor == genesis {
        0
    } else {
        rpc_queries::checked_header(engine, anchor)
            .map_err(query_error)?
            .ok_or_else(|| not_available("requested branch anchor is unavailable"))?
            .height
    };
    if count > 0 && (start == 0 || start > tip_height) {
        return Err(not_available(
            "requested block height is unavailable on this branch",
        ));
    }
    Ok(tip_height)
}

fn wanted_heights(
    start: Height,
    count: u64,
    step: u64,
    tip_height: Height,
) -> BTreeMap<Height, BlockHash> {
    let mut wanted = BTreeMap::new();
    for offset in 0..count {
        let Some(height) = offset
            .checked_mul(step)
            .and_then(|delta| start.checked_add(delta))
        else {
            break;
        };
        if height > tip_height {
            break;
        }
        wanted.insert(height, ZERO_HASH);
    }
    wanted
}

// Off the canonical chain, follow parents until the branch joins it. An
// unfinalized branch joins within a few chunks; a deeper anchor is refused
// rather than walked.
fn walk_off_canonical<DB: Database>(
    engine: &Engine<DB>,
    anchor: BlockHash,
    tip_height: Height,
    lowest: Height,
    wanted: &mut BTreeMap<Height, BlockHash>,
) -> Result<(Height, BlockHash), SyncBackendError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let limit = engine
        .chain_spec()
        .consensus
        .chunk_size
        .saturating_mul(4)
        .saturating_add(rpc::MAX_BLOCKS_PER_RESPONSE);
    let mut cursor = anchor;
    let mut height = tip_height;
    let mut walked = 0_u64;
    while height >= lowest && canonical_hash(engine, height)? != Some(cursor) {
        walked += 1;
        if walked > limit {
            return Err(SyncBackendError::InvalidRequest(
                "branch anchor lies too far off the canonical chain".to_owned(),
            ));
        }
        let header = rpc_queries::checked_header(engine, cursor)
            .map_err(query_error)?
            .ok_or_else(|| storage_error("branch ancestor is missing"))?;
        if header.height != height {
            return Err(storage_error("branch ancestry heights are inconsistent"));
        }
        if let Some(hash) = wanted.get_mut(&height) {
            *hash = cursor;
        }
        cursor = header.parent_hash;
        height -= 1;
    }
    Ok((height, cursor))
}

// Resolve a whole bounded range under one lock. Archived anchors remain readable
// after a reorg; a canonical anchor, and any branch once it joins the canonical
// chain, uses the height index, so a request never walks the whole chain.
fn branch_hashes<DB: Database>(
    engine: &Engine<DB>,
    anchor: BlockHash,
    start: Height,
    count: u64,
    step: u64,
) -> Result<Vec<(Height, BlockHash)>, SyncBackendError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let tip_height = branch_tip_height(engine, anchor, start, count)?;
    let genesis = engine.chain_spec().genesis_block_hash;
    let mut wanted = wanted_heights(start, count, step, tip_height);
    let Some((&lowest, _)) = wanted.first_key_value() else {
        return Ok(Vec::new());
    };
    let (height, cursor) = walk_off_canonical(engine, anchor, tip_height, lowest, &mut wanted)?;
    if height < lowest {
        if lowest == 1 && cursor != genesis {
            return Err(storage_error("branch does not reach genesis"));
        }
    } else {
        for (wanted_height, hash) in wanted.range_mut(..=height) {
            *hash = canonical_hash(engine, *wanted_height)?
                .ok_or_else(|| storage_error("canonical header is missing"))?;
        }
    }
    Ok(wanted.into_iter().collect())
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    /// Complete publications along the advertised branch, then the
    /// candidates that follow them (design 08). The proven page ends at the
    /// first block without a retained receipt; from there every block the
    /// node holds a write set for is served as a candidate, so a page never
    /// places a proven block after a candidate. The page also ends where the
    /// next entry would exceed the response byte cap; a short page is partial.
    pub(in crate::chain_backend) fn p2p_blocks_by_range(
        &self,
        start: Height,
        count: u64,
        anchor: BlockHash,
    ) -> Result<BlocksByRangeResponse, SyncBackendError> {
        self.with_engine(|engine| {
            let hashes = branch_hashes(
                engine,
                anchor,
                start,
                count.min(rpc::MAX_BLOCKS_PER_RESPONSE),
                1,
            )?;
            let mut blocks = Vec::new();
            let mut candidates: Vec<neutrin0_consensus_types::CandidateBlock> = Vec::new();
            let mut bytes = 0_u64;
            for (_, hash) in hashes {
                let proven = if candidates.is_empty() {
                    engine.proven_block(&hash).map_err(storage_error)?
                } else {
                    None
                };
                let (block, size) = if let Some(bundle) = proven {
                    let size = u64::try_from(borsh::object_length(&bundle).map_err(storage_error)?)
                        .unwrap_or(u64::MAX);
                    (Entry::Proven(bundle), size)
                } else {
                    let Some(candidate) = engine.candidate_block(&hash).map_err(storage_error)?
                    else {
                        break;
                    };
                    let size =
                        u64::try_from(borsh::object_length(&candidate).map_err(storage_error)?)
                            .unwrap_or(u64::MAX);
                    (Entry::Candidate(candidate), size)
                };
                let header = match &block {
                    Entry::Proven(bundle) => &bundle.block.header,
                    Entry::Candidate(candidate) => &candidate.block.header,
                };
                // Import verified the body against the header's roots, and
                // the requester verifies them again; only the cheap header
                // identity is checked under the engine lock.
                if header.hash() != hash {
                    return Err(storage_error("stored block does not match its header"));
                }
                if blocks.is_empty()
                    && candidates.is_empty()
                    && size >= rpc::DEFAULT_MAX_RESPONSE_SIZE
                {
                    return Err(SyncBackendError::NotAvailable(
                        "block publication exceeds the wire size limit".to_owned(),
                    ));
                }
                if bytes.saturating_add(size).saturating_add(64) >= rpc::DEFAULT_MAX_RESPONSE_SIZE {
                    break;
                }
                bytes = bytes.saturating_add(size);
                match block {
                    Entry::Proven(bundle) => blocks.push(bundle),
                    Entry::Candidate(candidate) => candidates.push(candidate),
                }
            }
            if blocks.is_empty() && candidates.is_empty() {
                return Err(not_available("no publication is available at that height"));
            }
            Ok::<_, SyncBackendError>(BlocksByRangeResponse { blocks, candidates })
        })
        .and_then(bounded)
    }

    /// Every retained receipt of the requested blocks, in request order and
    /// the canonical receipt of each block first, unknown or unproven blocks
    /// omitted; at most `MAX_RECEIPTS_PER_RESPONSE` receipts and bounded by
    /// the response byte cap (design 08).
    pub(in crate::chain_backend) fn p2p_receipts_by_hash(
        &self,
        block_hashes: &[BlockHash],
    ) -> Result<rpc::ReceiptsByHashResponse, SyncBackendError> {
        // Each requested hash costs a lookup whether or not it is known, so
        // the request itself is bounded, not only the response.
        check_count(block_hashes.len(), rpc::MAX_RECEIPTS_PER_RESPONSE)?;
        self.with_engine(|engine| {
            let limit = usize::try_from(rpc::MAX_RECEIPTS_PER_RESPONSE).unwrap_or(usize::MAX);
            let mut receipts = Vec::new();
            let mut bytes = 0_u64;
            'blocks: for hash in block_hashes {
                let Some(canonical) = engine.block_receipt(hash).map_err(storage_error)? else {
                    continue;
                };
                let alternatives: Vec<_> = engine
                    .store()
                    .block_receipts(hash)
                    .map_err(storage_error)?
                    .into_iter()
                    .filter(|held| held.proof.proof_bytes != canonical.proof_bytes)
                    .map(|held| neutrin0_consensus_types::BlockReceipt {
                        block_hash: *hash,
                        proof_bytes: held.proof.proof_bytes,
                    })
                    .collect();
                for receipt in core::iter::once(canonical).chain(alternatives) {
                    let size =
                        u64::try_from(borsh::object_length(&receipt).map_err(storage_error)?)
                            .unwrap_or(u64::MAX);
                    if receipts.len() >= limit
                        || bytes.saturating_add(size).saturating_add(64)
                            >= rpc::DEFAULT_MAX_RESPONSE_SIZE
                    {
                        break 'blocks;
                    }
                    bytes = bytes.saturating_add(size);
                    receipts.push(receipt);
                }
            }
            Ok::<_, SyncBackendError>(rpc::ReceiptsByHashResponse { receipts })
        })
        .and_then(bounded)
    }

    pub(in crate::chain_backend) fn p2p_witnesses_by_block(
        &self,
        hashes: &[BlockHash],
    ) -> Result<WitnessByBlockResponse, SyncBackendError> {
        check_count(hashes.len(), rpc::MAX_WITNESSES_PER_RESPONSE)?;
        self.with_engine(|engine| {
            let witnesses = hashes
                .iter()
                .map(|hash| {
                    if let Some(header) =
                        rpc_queries::checked_header(engine, *hash).map_err(query_error)?
                    {
                        rpc_queries::ensure_payload_height(engine, header.height)
                            .map_err(query_error)?;
                    }
                    engine
                        .store()
                        .get_witness(hash)
                        .map_err(storage_error)?
                        .ok_or_else(|| not_available("block witness is unavailable"))
                })
                .collect::<Result<_, _>>()?;
            Ok::<_, SyncBackendError>(WitnessByBlockResponse { witnesses })
        })
        .and_then(bounded)
    }
}
