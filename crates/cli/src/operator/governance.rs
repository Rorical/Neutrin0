//! Governance views and proposal calldata for the EVM runtime's 0x…0801 interface.

use alloy_primitives::U256;
use neutrin0_consensus_types::evidence::EvidenceAnchor;
use neutrin0_consensus_types::history_proof::ProgramArtifacts;
use neutrin0_primitives::{ProgramSet, ScheduledFork};
use neutrin0_rpc::client::{NodeApiClient, NodeClient};
use neutrin0_rpc::{BlockId, BlockIdJson, HashHex};
use neutrin0_runtime_host::package::{MAX_RUNTIME_PACKAGE_BYTES, RuntimePackage};
use neutrin0_runtime_system::governance::{
    UPGRADE_ACTIVATION_WINDOW_CHUNKS, UPGRADE_VOTING_PERIOD_CHUNKS, upgrade_min_lead_chunks,
};
use neutrin0_runtime_system::{ProposalAction, RuntimePolicy, UpgradeProposal, UpgradeStatus};
use serde_json::{Value, json};
use std::io::Read as _;

use super::{Arguments, Error};

/// Policy fields a `propose-policy` flag may override, in ABI tuple order.
pub(super) const POLICY_FLAGS: &[&str] = &[
    "min-validator-stake",
    "evidence-max-age-blocks",
    "evidence-max-pending",
    "evidence-admissions-per-block",
    "evidence-executions-per-block",
    "inactivity-leak-amount",
    "reporter-reward-bps",
    "chunk-prover-fee-bps",
    "annual-issuance-bps",
    "abandonment-penalty-amount",
];

/// Activation chunks a program switch proposed in the next block may name.
struct UpgradeWindow {
    chunk_size: u64,
    current_chunk: u64,
    min_lead_chunks: u64,
    earliest: u64,
    latest: u64,
}

impl UpgradeWindow {
    /// The runtime checks the window against the chunk of the block that
    /// includes the proposal; the next block's chunk is the closest estimate.
    async fn next_block(client: &NodeClient) -> Result<Self, Error> {
        let (head, diagnostics) =
            tokio::try_join!(client.rpc().head(), client.rpc().diagnostics())?;
        if diagnostics.chunk_size == 0 {
            return Err(Error::Local("node reports a zero chunk size".into()));
        }
        // Heights 1..=chunk_size form chunk 0, so the next block's chunk is head / size.
        let current_chunk = head.height / diagnostics.chunk_size;
        let min_lead_chunks = upgrade_min_lead_chunks(&EvidenceAnchor {
            chunk_size: diagnostics.chunk_size,
            unbonding_delay_blocks: diagnostics.unbonding_delay_blocks,
            ..EvidenceAnchor::default()
        });
        let earliest = current_chunk.saturating_add(min_lead_chunks);
        Ok(Self {
            chunk_size: diagnostics.chunk_size,
            current_chunk,
            min_lead_chunks,
            earliest,
            latest: earliest.saturating_add(UPGRADE_ACTIVATION_WINDOW_CHUNKS - 1),
        })
    }

    /// Refuse a chunk `--flag` names outside the window.
    fn check(&self, flag: &str, chunk: u64) -> Result<(), Error> {
        if (self.earliest..=self.latest).contains(&chunk) {
            return Ok(());
        }
        Err(Error::Usage(format!(
            "--{flag} must lie in {}..={} (current chunk {} plus the {}-chunk lead); \
             leave room for voting, since a proposal dies once it is closer than the lead",
            self.earliest, self.latest, self.current_chunk, self.min_lead_chunks
        )))
    }

    fn json(&self) -> Value {
        json!({"current_chunk": self.current_chunk, "min_lead_chunks": self.min_lead_chunks,
            "earliest_activation_chunk": self.earliest, "latest_activation_chunk": self.latest,
            "voting_period_chunks": UPGRADE_VOTING_PERIOD_CHUNKS})
    }
}

pub(super) async fn status(client: &NodeClient, options: &Arguments) -> Result<Value, Error> {
    let at = client.pin(options.at()?).await?;
    let status: UpgradeStatus = client.query("upgrade_status", vec![], at).await?;
    let window = UpgradeWindow::next_block(client).await?;
    // Stored proposals leave their slot only when it is next written; show
    // those a block after `at` could still vote on.
    let chunk = at.height / window.chunk_size;
    let live = |proposals: &[UpgradeProposal]| -> Vec<Value> {
        proposals
            .iter()
            .filter(|proposal| proposal.is_live(chunk, window.min_lead_chunks))
            .map(proposal_json)
            .collect()
    };
    let proposals = live(&status.proposals);
    let policy_proposals = live(&status.policy_proposals);
    let fork_proposals = live(&status.fork_proposals);
    let scheduled = status.scheduled.map(|scheduled| json!({"programs": programs_json(scheduled.programs), "artifacts": artifacts_json(scheduled.artifacts), "activate_at_chunk": scheduled.activate_at_chunk, "available": scheduled.available}));
    let pending_policy = status.pending_policy.map(|pending| json!({"policy": policy_json(pending.policy), "effective_height": pending.effective_height}));
    let scheduled_fork = status.scheduled_fork.map(fork_json);
    Ok(
        json!({"at": at, "proposals": proposals, "scheduled": scheduled, "policy_proposals": policy_proposals, "pending_policy": pending_policy, "fork_proposals": fork_proposals, "scheduled_fork": scheduled_fork, "upgrade_window": window.json()}),
    )
}

pub(super) async fn policy(client: &NodeClient, options: &Arguments) -> Result<Value, Error> {
    let at = client.pin(options.at()?).await?;
    let policy: RuntimePolicy = client.query("runtime_policy", vec![], at).await?;
    Ok(json!({"at": at, "policy": policy_json(policy)}))
}

/// Calldata for a proposal; checks locally what the runtime would refuse.
pub(super) async fn calldata(
    client: &NodeClient,
    operation: &str,
    options: &Arguments,
) -> Result<Vec<u8>, Error> {
    match operation {
        "propose-upgrade" => {
            let package = read_package(options.required("package")?)?;
            let activate_at_chunk = options
                .get("activate-at-chunk")
                .ok_or_else(|| Error::Usage("missing --activate-at-chunk".into()))
                .and_then(|_| options.number("activate-at-chunk", 0))?;
            UpgradeWindow::next_block(client)
                .await?
                .check("activate-at-chunk", activate_at_chunk)?;
            let artifacts = package
                .distribution_artifacts()
                .map_err(|error| Error::Local(error.to_string()))?;
            let mut words = program_words(package.programs);
            words.extend([
                artifacts.runtime,
                artifacts.fact,
                artifacts.evidence,
                artifacts.block,
            ]);
            words.push(U256::from(activate_at_chunk).to_be_bytes());
            Ok(encode(
                "proposeUpgrade(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,uint64)",
                &words,
            ))
        }
        "cancel-upgrade" => {
            let head = client.pin(BlockIdJson(BlockId::Latest)).await?;
            let status: UpgradeStatus = client.query("upgrade_status", vec![], head).await?;
            let scheduled = status.scheduled.ok_or_else(|| {
                Error::Usage("no enacted program switch is scheduled at the latest head".into())
            })?;
            let mut words = program_words(scheduled.programs);
            words.push(U256::from(scheduled.activate_at_chunk).to_be_bytes());
            Ok(encode(
                "cancelUpgrade(bytes32,bytes32,bytes32,bytes32,uint64)",
                &words,
            ))
        }
        "propose-fork" => {
            let count = options
                .get("fork-chunk")
                .ok_or_else(|| Error::Usage("missing --fork-chunk".into()))
                .and_then(|_| options.number("fork-chunk", 0))?;
            UpgradeWindow::next_block(client)
                .await?
                .check("fork-chunk", count)?;
            let successor = options.hash("successor")?.0;
            if successor == [0; 32] {
                return Err(Error::Usage("--successor must be nonzero".into()));
            }
            Ok(encode(
                "proposeFork(uint64,bytes32)",
                &[U256::from(count).to_be_bytes(), successor],
            ))
        }
        "cancel-fork" => {
            let head = client.pin(BlockIdJson(BlockId::Latest)).await?;
            let status: UpgradeStatus = client.query("upgrade_status", vec![], head).await?;
            let fork = status.scheduled_fork.ok_or_else(|| {
                Error::Usage("no enacted hard fork is scheduled at the latest head".into())
            })?;
            Ok(encode(
                "cancelFork(uint64,bytes32)",
                &[U256::from(fork.count).to_be_bytes(), fork.successor],
            ))
        }
        "propose-policy" => {
            let head = client.pin(BlockIdJson(BlockId::Latest)).await?;
            let current: RuntimePolicy = client.query("runtime_policy", vec![], head).await?;
            let policy = override_policy(current, options)?;
            if policy == current {
                return Err(Error::Usage(format!(
                    "propose-policy needs at least one changed field: --{}",
                    POLICY_FLAGS.join(" | --")
                )));
            }
            Ok(encode(
                "proposePolicy((uint128,uint64,uint32,uint32,uint32,uint128,uint16,uint16,uint16,uint128))",
                &policy_words(&policy),
            ))
        }
        _ => Err(Error::Usage("unsupported governance operation".into())),
    }
}

fn read_package(path: &str) -> Result<RuntimePackage, Error> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .and_then(|file| {
            file.take(MAX_RUNTIME_PACKAGE_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|error| Error::Local(format!("read {path}: {error}")))?;
    RuntimePackage::decode(&bytes)
        .map_err(|error| Error::Local(format!("invalid runtime package {path}: {error}")))
}

/// The policy in force with each given flag replacing its field.
fn override_policy(mut policy: RuntimePolicy, options: &Arguments) -> Result<RuntimePolicy, Error> {
    let wide = |flag: &str, current: u128| -> Result<u128, Error> {
        options.get(flag).map_or(Ok(current), |value| {
            value
                .parse()
                .map_err(|_| Error::Usage(format!("--{flag} must be a decimal integer in wei")))
        })
    };
    let narrow = |flag: &str, current: u64, limit: u64| -> Result<u64, Error> {
        let value = options.number(flag, current)?;
        if value > limit {
            return Err(Error::Usage(format!("--{flag} must not exceed {limit}")));
        }
        Ok(value)
    };
    let small = |flag: &str, current: u32| -> Result<u32, Error> {
        u32::try_from(narrow(flag, current.into(), u32::MAX.into())?)
            .map_err(|_| Error::Usage(format!("--{flag} exceeds uint32")))
    };
    let bps = |flag: &str, current: u16| -> Result<u16, Error> {
        u16::try_from(narrow(flag, current.into(), 10_000)?)
            .map_err(|_| Error::Usage(format!("--{flag} exceeds uint16")))
    };
    policy.min_validator_stake = wide("min-validator-stake", policy.min_validator_stake)?;
    policy.evidence_max_age_blocks = narrow(
        "evidence-max-age-blocks",
        policy.evidence_max_age_blocks,
        u64::MAX,
    )?;
    policy.evidence_max_pending = small("evidence-max-pending", policy.evidence_max_pending)?;
    policy.evidence_admissions_per_block = small(
        "evidence-admissions-per-block",
        policy.evidence_admissions_per_block,
    )?;
    policy.evidence_executions_per_block = small(
        "evidence-executions-per-block",
        policy.evidence_executions_per_block,
    )?;
    policy.inactivity_leak_amount = wide("inactivity-leak-amount", policy.inactivity_leak_amount)?;
    policy.reporter_reward_bps = bps("reporter-reward-bps", policy.reporter_reward_bps)?;
    policy.chunk_prover_fee_bps = bps("chunk-prover-fee-bps", policy.chunk_prover_fee_bps)?;
    policy.annual_issuance_bps = bps("annual-issuance-bps", policy.annual_issuance_bps)?;
    policy.abandonment_penalty_amount = wide(
        "abandonment-penalty-amount",
        policy.abandonment_penalty_amount,
    )?;
    Ok(policy)
}

/// Static tuple fields encode in place, one word each, in declaration order.
fn policy_words(policy: &RuntimePolicy) -> Vec<[u8; 32]> {
    [
        policy.min_validator_stake,
        u128::from(policy.evidence_max_age_blocks),
        u128::from(policy.evidence_max_pending),
        u128::from(policy.evidence_admissions_per_block),
        u128::from(policy.evidence_executions_per_block),
        policy.inactivity_leak_amount,
        u128::from(policy.reporter_reward_bps),
        u128::from(policy.chunk_prover_fee_bps),
        u128::from(policy.annual_issuance_bps),
        policy.abandonment_penalty_amount,
    ]
    .into_iter()
    .map(|value| U256::from(value).to_be_bytes())
    .collect()
}

fn program_words(programs: ProgramSet) -> Vec<[u8; 32]> {
    vec![
        programs.runtime_code_hash,
        vk_bytes(programs.execution.fact),
        vk_bytes(programs.execution.evidence),
        vk_bytes(programs.execution.block),
    ]
}

/// The interface packs the eight SP1 VK words little endian into a bytes32.
fn vk_bytes(words: [u32; 8]) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (chunk, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(words) {
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

fn encode(signature: &str, words: &[[u8; 32]]) -> Vec<u8> {
    let mut data = neutrin0_crypto::keccak256(signature.as_bytes())[..4].to_vec();
    for word in words {
        data.extend_from_slice(word);
    }
    data
}

fn policy_json(policy: RuntimePolicy) -> Value {
    json!({"min_validator_stake": policy.min_validator_stake.to_string(),
        "evidence_max_age_blocks": policy.evidence_max_age_blocks, "evidence_max_pending": policy.evidence_max_pending,
        "evidence_admissions_per_block": policy.evidence_admissions_per_block, "evidence_executions_per_block": policy.evidence_executions_per_block,
        "inactivity_leak_amount": policy.inactivity_leak_amount.to_string(), "reporter_reward_bps": policy.reporter_reward_bps,
        "chunk_prover_fee_bps": policy.chunk_prover_fee_bps, "annual_issuance_bps": policy.annual_issuance_bps,
        "abandonment_penalty_amount": policy.abandonment_penalty_amount.to_string()})
}

fn proposal_json(proposal: &UpgradeProposal) -> Value {
    let action = match proposal.action {
        ProposalAction::Policy(policy) => {
            json!({"kind": "policy", "policy": policy_json(policy)})
        }
        ProposalAction::Programs {
            programs,
            artifacts,
            activate_at_chunk,
        } => {
            json!({"kind": "programs", "programs": programs_json(programs), "artifacts": artifacts_json(artifacts), "activate_at_chunk": activate_at_chunk})
        }
        ProposalAction::Cancel {
            programs,
            activate_at_chunk,
        } => {
            json!({"kind": "cancel", "programs": programs_json(programs), "activate_at_chunk": activate_at_chunk})
        }
        ProposalAction::Fork(fork) => json!({"kind": "fork", "fork": fork_json(fork)}),
        ProposalAction::CancelFork(fork) => {
            json!({"kind": "cancel_fork", "fork": fork_json(fork)})
        }
    };
    json!({"id": HashHex(proposal.id()), "proposer": HashHex(proposal.proposer), "action": action, "proposed_at_chunk": proposal.proposed_at_chunk, "voters": proposal.voters.iter().copied().map(HashHex).collect::<Vec<_>>()})
}

/// VKs print as the bytes32 values the proposal interface takes.
fn programs_json(programs: ProgramSet) -> Value {
    json!({"runtime_code_hash": HashHex(programs.runtime_code_hash), "fact_vk": HashHex(vk_bytes(programs.execution.fact)),
        "evidence_vk": HashHex(vk_bytes(programs.execution.evidence)), "block_vk": HashHex(vk_bytes(programs.execution.block))})
}

fn fork_json(fork: ScheduledFork) -> Value {
    json!({"count": fork.count, "successor": HashHex(fork.successor)})
}

fn artifacts_json(artifacts: ProgramArtifacts) -> Value {
    json!({"runtime": HashHex(artifacts.runtime), "fact": HashHex(artifacts.fact), "evidence": HashHex(artifacts.evidence), "block": HashHex(artifacts.block)})
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The runtime unpacks each word little endian (`vk_digest`); a wrong
    /// order would name a program no node can derive.
    #[test]
    fn vk_words_pack_little_endian() {
        let bytes = vk_bytes([0x0403_0201, 0, 0, 0, 0, 0, 0, 0x0807_0605]);
        assert_eq!(&bytes[..4], &[1, 2, 3, 4]);
        assert_eq!(&bytes[28..], &[5, 6, 7, 8]);
    }
}
