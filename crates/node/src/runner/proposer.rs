//! The validator key and the block production configuration derived from
//! the node configuration (design 19).

use std::sync::Arc;

use neutrin0_consensus_engine::ProposerKey;
use neutrin0_primitives::ChainSpec;
use tracing::{info, warn};

use super::NodeError;
use crate::chain_spec::decode_hex_exact;
use crate::config::{NodeConfig, NodeRole};
use crate::producer::BlockProducerConfig;

pub(super) fn build_block_producer_config(
    config: &NodeConfig,
    chain_spec: &ChainSpec,
) -> Result<Option<BlockProducerConfig>, NodeError> {
    if config.role != NodeRole::Validator {
        // A node that proves candidates it did not produce runs the proof
        // loop without a proposer key (design 08).
        if config.proving.prove_foreign_blocks && config.role != NodeRole::LightClient {
            return Ok(Some(BlockProducerConfig {
                proving: config.proving,
                proposer: None,
                standby: None,
                genesis_time_secs: chain_spec.genesis_time,
                slot_duration_secs: chain_spec.consensus.slot_duration_secs,
            }));
        }
        return Ok(None);
    }
    // The configured position is a hint. Engine signing resolves the key's
    // position in the authenticated live set after replay or checkpoint bootstrap.
    let (proposer, standby) = proposer_keys(config, config.proposer_index.unwrap_or(0))?;
    Ok(Some(BlockProducerConfig {
        proving: config.proving,
        proposer: Some(proposer),
        standby,
        genesis_time_secs: chain_spec.genesis_time,
        slot_duration_secs: chain_spec.consensus.slot_duration_secs,
    }))
}

/// The validator key from exactly one configured source: a remote signer, an
/// EIP-2335 keystore or an IKM (environment, file or inline); and the next
/// key a rotation will seat, from a signer or a keystore.
pub(super) fn proposer_keys(
    config: &NodeConfig,
    index: u32,
) -> Result<(ProposerKey, Option<ProposerKey>), NodeError> {
    let ikm = config
        .resolve_proposer_ikm_hex()
        .map_err(|err| NodeError::ProposerKey(err.to_string()))?;
    let sources = usize::from(config.remote_signer.is_some())
        + usize::from(config.proposer_keystore_path.is_some())
        + usize::from(ikm.is_some());
    if sources > 1 {
        return Err(NodeError::ProposerKey(
            "configure exactly one validator key: remote_signer, proposer_keystore_path or an IKM"
                .into(),
        ));
    }
    if let Some(remote) = &config.remote_signer {
        return remote_proposer_keys(remote, index);
    }
    if let Some(path) = &config.proposer_keystore_path {
        let password = config
            .resolve_keystore_password()
            .map_err(NodeError::ProposerKey)?;
        let decrypt = |path: &std::path::Path| {
            let secret = neutrin0_keystore::Keystore::from_file(path)
                .and_then(|keystore| {
                    keystore
                        .decrypt(&password)
                        .map_err(|err| format!("{}: {err}", path.display()))
                })
                .map_err(NodeError::ProposerKey)?;
            info!(keystore = %path.display(), "proposer key decrypted");
            Ok::<_, NodeError>(ProposerKey::new(secret, index))
        };
        let next = config
            .proposer_next_keystore_path
            .as_deref()
            .map(decrypt)
            .transpose()?;
        return Ok((decrypt(path)?, next));
    }
    if config.proposer_next_keystore_path.is_some() {
        return Err(NodeError::ProposerKey(
            "proposer_next_keystore_path needs proposer_keystore_path".into(),
        ));
    }
    let (ikm_hex, source) = required_proposer_key(ikm)?;
    match source {
        crate::config::ProposerIkmSource::Inline => warn!(
            "proposer key read inline from the config file; prefer {} or proposer_ikm_path",
            crate::config::PROPOSER_IKM_ENV
        ),
        other => info!(source = ?other, "proposer key loaded"),
    }
    let ikm = decode_hex_exact::<32>(&ikm_hex, "proposer key")?;
    let key = ProposerKey::from_ikm(&ikm, index)
        .map_err(|err| NodeError::ProposerKey(err.to_string()))?;
    Ok((key, None))
}

/// The key a `neutrin0-signer` holds: the configured one, or its only one;
/// and the configured next key, which it must hold too.
fn remote_proposer_keys(
    remote: &crate::config::RemoteSignerConfig,
    index: u32,
) -> Result<(ProposerKey, Option<ProposerKey>), NodeError> {
    let endpoint = remote.endpoint().map_err(NodeError::ProposerKey)?;
    let client = neutrin0_signer::Client::new(endpoint.clone());
    let held = client.identities().map_err(NodeError::ProposerKey)?;
    let held_key = |hex: &str, field: &str| {
        let key = decode_hex_exact::<48>(hex, field)?;
        if !held.contains(&key) {
            return Err(NodeError::ProposerKey(format!(
                "the signer does not hold {field}"
            )));
        }
        Ok(key)
    };
    let identity = match &remote.public_key_hex {
        Some(hex) => held_key(hex, "remote_signer.public_key_hex")?,
        None => match held.as_slice() {
            [key] => *key,
            _ => {
                return Err(NodeError::ProposerKey(format!(
                    "the signer holds {} keys; set remote_signer.public_key_hex",
                    held.len()
                )));
            }
        },
    };
    let next = remote
        .next_public_key_hex
        .as_deref()
        .map(|hex| held_key(hex, "remote_signer.next_public_key_hex"))
        .transpose()?;
    info!(key = %hex::encode(identity), signer = ?endpoint, "proposer key held by a remote signer");
    let client: Arc<dyn neutrin0_consensus_engine::RemoteSigner> = Arc::new(client);
    Ok((
        ProposerKey::remote(identity, Arc::clone(&client), index),
        next.map(|next| ProposerKey::remote(next, client, index)),
    ))
}

pub(super) fn required_proposer_key(
    resolved: Option<(String, crate::config::ProposerIkmSource)>,
) -> Result<(String, crate::config::ProposerIkmSource), NodeError> {
    resolved.ok_or_else(|| NodeError::ProposerKey(format!(
        "validator role requires a proposer key ({} / proposer_ikm_path, proposer_keystore_path or remote_signer); use role=full for a non-validator node",
        crate::config::PROPOSER_IKM_ENV
    )))
}
