//! Fixed runtime-to-consensus records, independent of account and staking layouts.

use crate::evidence::{EvidenceAnchor, SanctionKind};
use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::{Hash, StateRoot, Validator};

/// Consensus facts available to execution, authenticated again by the Chunk Guest.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ConsensusExecutionContext {
    /// Slot of the executing block.
    pub slot: u64,
    /// Timestamp committed by the block header.
    pub timestamp: u64,
    /// Parent header hash, used by runtime block-history storage.
    pub parent_block_hash: Hash,
    /// SHA-256 of the verified proposer BLS-VRF proof.
    pub proposer_vrf_output: Hash,
    /// Proven boundary entering the executing chunk; its seed is finalized.
    pub finalized: crate::history_proof::ConsensusBoundary,
}

impl Default for ConsensusExecutionContext {
    fn default() -> Self {
        use crate::history_proof::{ConsensusBoundary, ExecutionPrograms, ProgramSet};
        Self {
            slot: 0,
            timestamp: 0,
            parent_block_hash: [0; 32],
            proposer_vrf_output: [0; 32],
            finalized: ConsensusBoundary {
                identity_sanctions_root: [0; 32],

                next_chunk_id: 0,
                height: 0,
                block_hash: [0; 32],
                state_root: [0; 32],
                slot: 0,
                validators_root: crate::evidence::commitment(&Vec::<Validator>::new()),
                seed: [0; 32],
                history_root: [0; 32],
                programs: ProgramSet {
                    runtime_code_hash: [0; 32],
                    execution: ExecutionPrograms {
                        fact: [0; 8],
                        evidence: [0; 8],
                        block: [0; 8],
                    },
                },
                participation: [0; 32],
                proving: crate::proving::NO_PROVING,
                fork: None,
            },
        }
    }
}

/// Authenticated candidate record consumed by chunk rotation.
pub const CONSENSUS_CANDIDATES_KEY: &[u8] = b"consensus:candidates";
/// Authenticated execution-program schedule consumed at chunk boundaries.
pub const UPGRADE_KEY: &[u8] = b"upgrade:scheduled";
/// Authenticated hard-fork schedule ([`crate::history_proof::ScheduledFork`])
/// every boundary carries until its count, where the chain ends (design 20).
pub const FORK_KEY: &[u8] = b"fork:scheduled";
/// Domain of the candidate-record commitment.
pub const DOMAIN_CONSENSUS_CANDIDATES_ROOT: &[u8; 16] = b"NTRO/candidates\x00";

/// BLS identity a candidate offers to consensus.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlsIdentity {
    /// BLS12-381 G1 compressed public key (min-pk POP scheme).
    pub pubkey: neutrin0_primitives::BlsPublicKey,
    /// Proof of possession the chunk Guest verifies before seating the key,
    /// bound to the candidate's address; see
    /// [`neutrin0_primitives::registration_pop_message`].
    pub pop_signature: neutrin0_primitives::BlsSignature,
}

/// One address the runtime currently knows as a validator, with its slashable
/// stake and, once registered, the BLS identity consensus may seat.
///
/// An entry exists while the runtime holds a validator record or a
/// registration for the address, so a zero stake here is authenticated and a
/// missing entry means the runtime has fully withdrawn the validator.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Eq, PartialEq)]
pub struct ConsensusCandidate {
    /// Runtime address; doubles as the consensus `withdrawal_credentials`.
    pub address: Hash,
    /// Stake currently locked behind the validator.
    pub stake: u128,
    /// BLS identity, absent for genesis validators that never registered.
    pub identity: Option<BlsIdentity>,
}

/// Consensus-facing view of every candidate, sorted by address.
#[derive(BorshDeserialize, BorshSerialize, Clone, Debug, Default, Eq, PartialEq)]
pub struct ConsensusCandidates {
    /// Candidates sorted by address ascending.
    pub entries: Vec<ConsensusCandidate>,
}

impl ConsensusCandidates {
    /// Insert or replace the entry for `candidate.address`.
    pub fn upsert(&mut self, candidate: ConsensusCandidate) {
        match self
            .entries
            .binary_search_by(|entry| entry.address.cmp(&candidate.address))
        {
            Ok(index) => self.entries[index] = candidate,
            Err(index) => self.entries.insert(index, candidate),
        }
    }

    /// Remove `addr`; `true` when an entry was present.
    pub fn remove(&mut self, addr: &Hash) -> bool {
        match self
            .entries
            .binary_search_by(|entry| entry.address.cmp(addr))
        {
            Ok(index) => {
                self.entries.remove(index);
                true
            }
            Err(_) => false,
        }
    }

    /// The entry for `addr`, if any.
    #[must_use]
    pub fn get(&self, addr: &Hash) -> Option<&ConsensusCandidate> {
        self.entries
            .binary_search_by(|entry| entry.address.cmp(addr))
            .ok()
            .map(|index| &self.entries[index])
    }

    /// `true` when `addr` has an entry.
    #[must_use]
    pub fn contains(&self, addr: &Hash) -> bool {
        self.get(addr).is_some()
    }

    /// Canonical commitment: `BLAKE3(DOMAIN || borsh(self))`.
    #[must_use]
    pub fn root(&self) -> StateRoot {
        crate::hashing::borsh_commitment(DOMAIN_CONSENSUS_CANDIDATES_ROOT, self)
    }
}

/// Minimal proven sanction consumed by chunk validator rotation.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct Sanction {
    /// Encoding-independent offence identity.
    pub offence_id: Hash,
    /// Historical stable identity and withdrawal account.
    pub offender: Validator,
    /// Misconduct or certificate non-inclusion.
    pub kind: SanctionKind,
}

impl Sanction {
    /// Replay marker: a permanent safety identity tombstone or a liveness offence.
    #[must_use]
    pub fn marker_key(&self) -> Vec<u8> {
        let (prefix, identity): (&[u8], &[u8]) = match self.kind {
            SanctionKind::Slash => (b"accountability:slashed:", &self.offender.pubkey),
            SanctionKind::Inactivity | SanctionKind::Abandonment => {
                (b"accountability:event:", &self.offence_id)
            }
        };
        let mut key = Vec::from(prefix);
        key.extend_from_slice(identity);
        key
    }
}

/// Block-proven accountability transition. Raw evidence is never exposed here.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct AccountabilityOutput {
    /// Incoming context, authenticated by the containing chunk.
    pub anchor: EvidenceAnchor,
    /// Newly admitted offences; chunk rotation consumes these identities.
    pub admitted: Vec<Sanction>,
    /// Queue items executed in deterministic FIFO order.
    pub executed: Vec<Sanction>,
    /// Queue commitment before this block.
    pub queue_before: Hash,
    /// Queue commitment after this block.
    pub queue_after: Hash,
}

/// Runtime-owned execution data authenticated by the common receipt commitment.
#[derive(Clone, Debug, Default, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionArtifacts {
    /// Runtime transaction identifiers and their common body envelope positions.
    /// Ethereum runtimes supply Keccak hashes; hosts keep their payloads opaque.
    pub transaction_ids: Vec<(u32, Hash)>,
    /// Opaque receipts in execution order, including mandatory system operations.
    pub receipts: Vec<Vec<u8>>,
    /// Opaque per-block runtime metadata.
    pub metadata: Vec<u8>,
}

impl ExecutionArtifacts {
    /// Canonical BLAKE3 commitment shared by headers, execution proofs and storage.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        crate::hashing::borsh_commitment(b"NTRO/execution-artifacts", self)
    }
}

/// Commitment of the execution inputs a header declares (design 08).
///
/// It covers the execution context and the participation, acknowledgement,
/// proving, program-lane and evidence-anchor commitments the block's output
/// reproduces.
#[must_use]
pub fn execution_inputs_root(
    context: &ConsensusExecutionContext,
    participation: neutrin0_primitives::Hash,
    participation_acks: neutrin0_primitives::Hash,
    proving: neutrin0_primitives::Hash,
    program_pieces: neutrin0_primitives::Hash,
    anchor: &crate::evidence::EvidenceAnchor,
) -> neutrin0_primitives::Hash {
    crate::tagged_commitment(
        &neutrin0_primitives::DOMAIN_EXECUTION_INPUTS,
        &(
            context,
            participation,
            participation_acks,
            proving,
            program_pieces,
            anchor,
        ),
    )
}
