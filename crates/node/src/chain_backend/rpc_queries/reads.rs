//! Checked reads of headers, bodies and committed state under the engine lock.

use neutrin0_consensus_engine::{Engine, RetentionPolicy};
use neutrin0_consensus_types::{Body, Header};
use neutrin0_primitives::{BlockHash, Hash, Height};
use neutrin0_rpc::{BlockId, FinalizedInfo, HistoryRetention, QueryError};
use neutrin0_storage::Database;
use neutrin0_trie::Trie;

pub(in crate::chain_backend) fn storage_error(error: impl core::fmt::Display) -> QueryError {
    QueryError::Storage(error.to_string())
}

/// A missing entry is state this node does not hold; any other read failure
/// is a corrupt store.
pub(super) fn state_read_error(error: neutrin0_trie::TrieError) -> QueryError {
    if error == neutrin0_trie::TrieError::MissingRetainedEntry {
        QueryError::StateUnavailable
    } else {
        storage_error(error)
    }
}

pub(in crate::chain_backend) fn retention_info<DB: Database>(
    engine: &Engine<DB>,
) -> Result<HistoryRetention, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let retention = engine.retention_info().map_err(storage_error)?;
    Ok(HistoryRetention {
        // Every source of this specification, from genesis or its fork's start.
        archive: retention.policy == RetentionPolicy::Archive
            && retention.pruned_before_chunk == engine.chain_spec().first_chunk(),
        retained_from_chunk: Some(retention.pruned_before_chunk),
        retained_from_height: Some(retention.first_retained_height),
        finalized_chunks: engine
            .latest_finalized_chunk_id()
            .map_or(0, |id| id.saturating_add(1)),
    })
}

pub(in crate::chain_backend) fn ensure_payload_height<DB: Database>(
    engine: &Engine<DB>,
    height: Height,
) -> Result<(), QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let retention = engine.retention_info().map_err(storage_error)?;
    if height > 0 && height < retention.first_retained_height {
        return Err(QueryError::Pruned {
            retained_from_chunk: retention.pruned_before_chunk,
            retained_from_height: retention.first_retained_height,
        });
    }
    Ok(())
}

pub(in crate::chain_backend) fn checked_header<DB: Database>(
    engine: &Engine<DB>,
    hash: BlockHash,
) -> Result<Option<Header>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let header = engine.store().get_header(&hash).map_err(storage_error)?;
    if header.as_ref().is_some_and(|header| header.hash() != hash) {
        return Err(storage_error("stored header does not match its block hash"));
    }
    Ok(header)
}

pub(super) fn required_header<DB: Database>(
    engine: &Engine<DB>,
    hash: BlockHash,
) -> Result<Header, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    checked_header(engine, hash)?.ok_or_else(|| storage_error("selected chain header is missing"))
}

pub(in crate::chain_backend) fn finalized_info<DB: Database>(
    engine: &Engine<DB>,
) -> Result<FinalizedInfo, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let block_hash = engine.fork_choice_finalized();
    let spec = engine.chain_spec();
    if block_hash == spec.genesis_block_hash {
        return Ok(FinalizedInfo {
            chunk_id: None,
            block_hash,
            height: 0,
            state_root: spec.genesis_state_root,
        });
    }
    let header = required_header(engine, block_hash)?;
    let chunk_id = engine
        .latest_finalized_chunk_id()
        .ok_or_else(|| storage_error("finalized boundary has no chunk ID"))?;
    Ok(FinalizedInfo {
        chunk_id: Some(chunk_id),
        block_hash,
        height: header.height,
        state_root: header.state_root,
    })
}

pub(super) fn resolve_id<DB: Database>(
    engine: &Engine<DB>,
    id: &BlockId,
) -> Result<Option<BlockHash>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    match id {
        BlockId::Latest => {
            let hash = engine.head_hash();
            if hash != engine.chain_spec().genesis_block_hash {
                let _ = required_header(engine, hash)?;
            }
            Ok(Some(hash))
        }
        BlockId::Safe => {
            let hash = engine.proven_head();
            if hash != engine.chain_spec().genesis_block_hash {
                let _ = required_header(engine, hash)?;
            }
            Ok(Some(hash))
        }
        BlockId::Finalized => Ok(Some(finalized_info(engine)?.block_hash)),
        BlockId::Hash(hash) => {
            if *hash == engine.chain_spec().genesis_block_hash {
                return Ok(Some(*hash));
            }
            Ok(checked_header(engine, *hash)?.map(|_| *hash))
        }
        BlockId::Height(height) => {
            if *height > engine.head_height() {
                return Ok(None);
            }
            let hash = engine
                .store()
                .get_block_hash_by_height(*height)
                .map_err(storage_error)?;
            let Some(hash) = hash else {
                ensure_payload_height(engine, *height)?;
                return Err(storage_error("canonical height is missing"));
            };
            if *height == 0 {
                if hash != engine.chain_spec().genesis_block_hash {
                    return Err(storage_error("canonical genesis anchor is inconsistent"));
                }
            } else if required_header(engine, hash)?.height != *height {
                return Err(storage_error("canonical height does not match its header"));
            }
            Ok(Some(hash))
        }
    }
}

/// Whether `body` reproduces every opaque payload commitment of `header`.
pub(super) fn body_matches_header(header: &Header, body: &Body) -> bool {
    let roots = neutrin0_consensus_engine::compute_body_roots(body);
    roots.da_root == header.da_root
        && roots.transactions_root == header.transactions_root
        && roots.votes_root == header.votes_root
        && body.artifacts.commitment() == header.receipts_root
}

/// The header of a block whose payload is still retained.
pub(super) fn readable_header<DB: Database>(
    engine: &Engine<DB>,
    hash: BlockHash,
) -> Result<Option<Header>, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let Some(header) = checked_header(engine, hash)? else {
        return Ok(None);
    };
    ensure_payload_height(engine, header.height)?;
    Ok(Some(header))
}

/// State committed by the block `at` selects, with that block's height.
pub(super) fn read_state<DB: Database>(
    engine: &Engine<DB>,
    at: &BlockId,
) -> Result<(Trie, Height), QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let hash = resolve_id(engine, at)?.ok_or(QueryError::BlockNotFound)?;
    let (root, height) = if hash == engine.chain_spec().genesis_block_hash {
        (engine.chain_spec().genesis_state_root, 0)
    } else {
        let header = required_header(engine, hash)?;
        (header.state_root, header.height)
    };
    let state = read_state_at(engine, root).or_else(|error| {
        if error == QueryError::StateUnavailable {
            ensure_payload_height(engine, height)?;
        }
        Err(error)
    })?;
    Ok((state, height))
}

/// The persisted state under `root`, read on demand: a query touches only the
/// paths it reads. A root this node does not retain is unavailable; a node
/// pruned while a query runs fails that query the same way, never reads as
/// absent.
pub(in crate::chain_backend) fn read_state_at<DB: Database>(
    engine: &Engine<DB>,
    root: Hash,
) -> Result<Trie, QueryError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    if !engine.store().has_state(root).map_err(storage_error)? {
        return Err(QueryError::StateUnavailable);
    }
    Ok(engine.store().state_at(root))
}
