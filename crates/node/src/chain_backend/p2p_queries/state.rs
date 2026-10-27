//! Snapshot state objects and program fragments served by content hash.

use neutrin0_consensus_engine::Engine;
use neutrin0_consensus_types::bootstrap::{
    MAX_STATE_FRAGMENT_BYTES, MAX_STATE_ITEMS, StateEntries, StateEntry, StateItem, StateItemKind,
};
use neutrin0_network::rpc::StateByRootResponse;
use neutrin0_primitives::{StateRoot, ZERO_HASH};
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::{Column, Database};
use neutrin0_sync::SyncBackendError;
use neutrin0_trie::{Hasher, Node, Poseidon2Hasher};

use super::{ChainBackend, bounded, check_count, not_available, storage_error};

// The retained root must exist and authenticate its own node. Object
// reachability is established by the receiver while following child
// hashes; serving each fragment does not traverse the complete tree.
fn authenticate_served_root<DB: Database>(
    engine: &Engine<DB>,
    root: StateRoot,
) -> Result<(), SyncBackendError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    if root != ZERO_HASH {
        let bytes = engine
            .store()
            .db()
            .get(Column::TrieNodes, &root)
            .map_err(storage_error)?
            .ok_or_else(|| not_available("requested state root is unavailable"))?;
        if Poseidon2Hasher::hash_node(&bytes) != root {
            return Err(storage_error("persisted state root content hash mismatch"));
        }
        Node::decode(&bytes).map_err(storage_error)?;
    }
    Ok(())
}

/// Keep `root` readable while a download reads it: renew its lease, or start
/// one when it is a root of the latest finalized endpoint, the only roots a
/// bootstrap manifest names.
fn lease_served_root<DB: Database>(
    engine: &mut Engine<DB>,
    root: StateRoot,
    now: u64,
) -> Result<(), SyncBackendError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    if engine
        .store_mut()
        .refresh_state_snapshot(root, now)
        .map_err(not_available)?
    {
        return Ok(());
    }
    let end = engine
        .canonical_boundary(engine.finalized_next_chunk_id())
        .map_err(not_available)?;
    if root == end.state_root || root == end.identity_sanctions_root {
        engine
            .store_mut()
            .pin_state_snapshot(root, now)
            .map_err(not_available)?;
    }
    Ok(())
}

/// One bounded fragment of a persisted trie node or value, checked against
/// its content hash.
fn state_object_entry<DB: Database>(
    engine: &Engine<DB>,
    item: &StateItem,
) -> Result<StateEntry, SyncBackendError>
where
    DB::Error: core::fmt::Debug + core::fmt::Display,
{
    let bytes = match item.kind {
        StateItemKind::Node | StateItemKind::Value => {
            let column = if item.kind == StateItemKind::Node {
                Column::TrieNodes
            } else {
                Column::StateValues
            };
            engine
                .store()
                .db()
                .get(column, &item.hash)
                .map_err(storage_error)?
                .ok_or_else(|| not_available("state object unavailable"))?
        }
        StateItemKind::Runtime | StateItemKind::Guest => {
            unreachable!("handled program fragment")
        }
    };
    let hash = match item.kind {
        StateItemKind::Node => Poseidon2Hasher::hash_node(&bytes),
        StateItemKind::Value => Poseidon2Hasher::hash_value(&bytes),
        StateItemKind::Runtime | StateItemKind::Guest => {
            unreachable!("handled program fragment")
        }
    };
    if hash != item.hash {
        return Err(storage_error("persisted state content hash mismatch"));
    }
    let offset = usize::try_from(item.offset).map_err(storage_error)?;
    if offset > bytes.len() || (offset == bytes.len() && offset != 0) {
        return Err(SyncBackendError::InvalidRequest(
            "state offset exceeds object".into(),
        ));
    }
    let end = offset
        .saturating_add(MAX_STATE_FRAGMENT_BYTES)
        .min(bytes.len());
    Ok(StateEntry {
        item: *item,
        total_len: u64::try_from(bytes.len()).map_err(storage_error)?,
        bytes: neutrin0_primitives::BoundedBytes::new(bytes[offset..end].to_vec())
            .map_err(storage_error)?,
    })
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(in crate::chain_backend) fn p2p_state_nodes(
        &self,
        root: StateRoot,
        items: &[StateItem],
    ) -> Result<StateByRootResponse, SyncBackendError> {
        check_count(
            items.len(),
            u64::try_from(MAX_STATE_ITEMS).expect("bounded item count"),
        )?;
        self.with_engine_mut(|engine| {
            authenticate_served_root(engine, root)?;
            let entries = items
                .iter()
                .map(|item| {
                    if matches!(item.kind, StateItemKind::Runtime | StateItemKind::Guest) {
                        return self.bootstrap_program_fragment(item);
                    }
                    state_object_entry(engine, item)
                })
                .collect::<Result<Vec<_>, SyncBackendError>>()?;
            let response = bounded(StateByRootResponse {
                entries: StateEntries::new(entries).map_err(storage_error)?,
            })?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(storage_error)?
                .as_secs();
            lease_served_root(engine, root, now)?;
            Ok(response)
        })
    }

    pub(in crate::chain_backend) fn bootstrap_program_fragment(
        &self,
        item: &StateItem,
    ) -> Result<StateEntry, SyncBackendError> {
        let fragment = match item.kind {
            StateItemKind::Runtime => self.block_executor_snapshot().and_then(|executor| {
                executor.runtime_fragment(&item.hash, item.offset, MAX_STATE_FRAGMENT_BYTES)
            }),
            StateItemKind::Guest => item.guest_digest().and_then(|digest| {
                self.proof_system
                    .guest_fragment(&digest, item.offset, MAX_STATE_FRAGMENT_BYTES)
            }),
            StateItemKind::Node | StateItemKind::Value => None,
        }
        .ok_or_else(|| not_available("bootstrap execution artifact fragment unavailable"))?;
        let (total_len, bytes) = fragment;
        if total_len == 0
            || total_len > u64::from(neutrin0_consensus_types::MAX_PROGRAM_BYTES)
            || item.offset >= total_len
            || bytes.is_empty()
        {
            return Err(SyncBackendError::InvalidRequest(
                "invalid bootstrap program fragment".into(),
            ));
        }
        let entry = StateEntry {
            item: *item,
            total_len,
            bytes: neutrin0_primitives::BoundedBytes::new(bytes).map_err(storage_error)?,
        };
        if !entry.validate_for(item) {
            return Err(storage_error(
                "installed program returned inconsistent fragment framing",
            ));
        }
        Ok(entry)
    }
}
