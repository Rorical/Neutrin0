//! The proof-system trait surface used by the consensus engine.
//!
//! The complete chunk interface binds authenticated consensus witnesses as well
//! as recursive block proofs. Each chunk receipt recursively verifies the
//! previous one, so the latest receipt doubles as the chain's History proof.
//!
//! [`MockProofSystem`]: super::mock::MockProofSystem

use borsh::{BorshDeserialize, BorshSerialize};
use core::fmt::Debug;

use crate::error::ProofError;

use neutrin0_consensus_types::BlockProofPublicInputs;
use neutrin0_consensus_types::history_proof::{GuestPrograms, HistoryProof, ProofDomain, VkDigest};
use neutrin0_primitives::ChainSpec;

/// Backend-agnostic proof system interface.
///
/// Implementations are stateless adapters: all data required to prove
/// or verify is passed by argument so the same instance can serve
/// many blocks concurrently. Proof types must be borsh-serializable
/// because consensus messages carry them across the wire.
pub trait ProofSystem {
    /// Pin all execution/recursive programs before queueing a proof job.
    /// The lease must be carried through completion or queued cancellation.
    fn lease_programs(
        &self,
        _guests: &GuestPrograms,
    ) -> Result<crate::artifacts::ProgramLease, ProofError> {
        Ok(alloc::sync::Arc::new(()))
    }

    /// Reconcile heavyweight proving sessions with authenticated retained dependencies.
    /// Existing proof jobs keep their own leases until completion.
    fn retain_programs(&self, _retention: &crate::artifacts::ProgramRetention) {}

    /// Install a locally authenticated, bounded archive reader for evicted sources.
    fn set_artifact_loader(&self, _loader: crate::artifacts::ProgramArtifactLoader) {}

    /// Derive a retained Guest identity without allocating a heavyweight proving session.
    fn authenticate_guest(
        &self,
        _elf: alloc::vec::Vec<u8>,
        _expected: &[neutrin0_consensus_types::history_proof::VkDigest],
    ) -> Result<neutrin0_consensus_types::history_proof::VkDigest, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Whether individual native submissions honor the host's scoped admission.
    /// Backends without that hook retain composite node resource admission.
    fn native_submission_admission(&self) -> bool {
        false
    }
    /// Whether native proving and setup share one serialized backend resource.
    /// This is local scheduling metadata and never a consensus or proof statement.
    fn serial_submission(&self) -> bool {
        false
    }

    /// Local CUDA resource identifier, independent of all consensus statements.
    fn submission_device(&self) -> Option<u32> {
        None
    }

    /// Proof attesting that one block's public inputs are correct.
    type BlockProof: BorshDeserialize + BorshSerialize + Clone + Debug + Eq + Send + Sync;

    /// Proof of the complete execution and consensus chunk statement.
    type ChunkProof: BorshDeserialize + BorshSerialize + Clone + Debug + Eq + Send + Sync;

    /// Produces a block proof from the execution witness and public
    /// inputs the engine has already validated.
    ///
    /// The `witness` payload is opaque to the trait: callers pass the
    /// backend-specific witness bytes and each backend interprets them
    /// according to its own proving program.
    /// Backends may pre-validate the witness and reject with
    /// [`ProofError::InvalidWitness`] before invoking the prover.
    fn prove_block(
        &self,
        witness: &[u8],
        public_inputs: &BlockProofPublicInputs,
        prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::BlockProof, ProofError>;

    /// Verifies a block proof against its public inputs.
    fn verify_block(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<(), ProofError>;

    /// Classify an exact signed artifact for objective slashing.
    ///
    /// `expected_block_program` is the block Guest the block's chunk boundary
    /// names, resolved by the caller from its own state; an artifact naming
    /// any other program is rejected as a public-input mismatch, so a signer
    /// can never make its own program the verifier's key.
    ///
    /// `Ok(None)` means valid, `Ok(Some(reason))` establishes rejection.
    /// An error means the backend could not make this determination and must
    /// never be converted into a slash. Operational proving/verification
    /// failures are not evidence of a validator's misconduct.
    fn classify_block_rejection(
        &self,
        _proof: &neutrin0_consensus_types::BlockProof,
        _expected_block_program: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<Option<neutrin0_consensus_types::ProofRejectionReason>, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// The Guest identities this backend embeds and can prove under: the three
    /// execution Guests and the chunk Guest. The engine
    /// binds them to the chain specification's runtime artifact for the genesis
    /// boundary. `None` denotes partial test backends; it must not authorize a
    /// production substitute for a missing complete proof.
    fn programs(&self) -> Option<GuestPrograms> {
        None
    }

    /// `true` when this backend holds every program of `guests` and can prove
    /// under it. Backends with a program registry (design 20) override this.
    fn can_prove(&self, guests: &GuestPrograms) -> bool {
        self.programs().as_ref() == Some(guests)
    }

    /// Install a governed Guest only after its locally derived key matches the
    /// authenticated expected identity. A mismatch must leave the registry unchanged.
    /// Backends without atomic checked installation refuse the operation.
    fn install_guest_checked(
        &self,
        _elf: alloc::vec::Vec<u8>,
        _expected: neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<neutrin0_consensus_types::history_proof::VkDigest, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Read an installed Guest's exact ELF for bounded artifact serving during
    /// bootstrap. This never installs or executes a program.
    fn guest_artifact(
        &self,
        _digest: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Option<alloc::vec::Vec<u8>> {
        None
    }

    /// Read at most 64 KiB of an installed Guest without cloning its entire ELF.
    /// Returns the complete byte length and the fragment at `offset`.
    fn guest_fragment(
        &self,
        digest: &neutrin0_consensus_types::history_proof::VkDigest,
        offset: u64,
        max_bytes: usize,
    ) -> Option<(u64, alloc::vec::Vec<u8>)> {
        crate::artifacts::artifact_fragment(&self.guest_artifact(digest)?, offset, max_bytes)
    }

    /// `(digest, ELF hash)` of every installed Guest.
    fn installed_guests(
        &self,
    ) -> alloc::vec::Vec<(
        neutrin0_consensus_types::history_proof::VkDigest,
        neutrin0_primitives::Hash,
    )> {
        alloc::vec::Vec::new()
    }
    /// `(covered, total)` signature checks of the most recently proven chunk,
    /// where `covered` were answered by fact receipts. `None` when the
    /// backend does not track coverage or has not proven a chunk yet.
    fn last_chunk_fact_coverage(&self) -> Option<(u64, u64)> {
        None
    }

    /// Compress observed signed artifacts before misconduct is discovered.
    /// Implementations retain a bounded cache of verified receipts for reuse.
    fn preprove_facts(
        &self,
        _fact_program: &neutrin0_consensus_types::history_proof::VkDigest,
        _requests: &[neutrin0_prover_chunk::facts::FactRequest],
    ) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Prove and verify a bounded batch. The returned attachments are verified
    /// against their exact statements and program identities; callers need not
    /// verify them again until they cross a storage/network trust boundary.
    fn prove_evidence_batch(
        &self,
        _witnesses: &[neutrin0_prover_chunk::evidence::EvidenceWitness],
        _execution: &neutrin0_consensus_types::history_proof::ExecutionPrograms,
    ) -> Result<alloc::vec::Vec<neutrin0_consensus_types::evidence::EvidenceArtifact>, ProofError>
    {
        Err(ProofError::Unsupported)
    }

    /// Verify a receipt against exact batch public values and the pinned fact program.
    fn verify_evidence(
        &self,
        _proof: &[u8],
        _batch: &neutrin0_consensus_types::evidence::EvidenceBatch,
        _evidence_program: &neutrin0_consensus_types::history_proof::VkDigest,
    ) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Decode the exact block public values for recursive aggregation: the
    /// runtime statement and the prover-chosen attribution (design 08).
    /// Callers must also verify this proof against the canonical block inputs.
    fn block_statement(
        &self,
        _proof: &Self::BlockProof,
    ) -> Result<neutrin0_runtime_abi::BlockReceiptStatement, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Verify and extract the exact public values in one decoding pass.
    fn verify_block_statement(
        &self,
        proof: &Self::BlockProof,
        public_inputs: &BlockProofPublicInputs,
    ) -> Result<neutrin0_runtime_abi::BlockReceiptStatement, ProofError> {
        self.verify_block(proof, public_inputs)?;
        self.block_statement(proof)
    }

    /// Prove execution and consensus including an already-collected
    /// certificate, crediting `chunk_prover_address` outside the consensus
    /// statement (design 08). `ratified` holds the chunk proof the
    /// certificate ratifies, whose public values are the witness's `ratified`
    /// statements; the chunk Guest verifies it recursively.
    fn prove_consensus_chunk(
        &self,
        _proofs: &[Self::BlockProof],
        _ratified: &[Self::ChunkProof],
        _witness: &neutrin0_prover_chunk::consensus::ConsensusWitness,
        _chunk_prover_address: neutrin0_primitives::Hash,
    ) -> Result<Self::ChunkProof, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// The account a chunk proof credits, read from its committed public
    /// values (design 08). Callers still verify the proof against the
    /// complete expected statement.
    fn chunk_prover_address(
        &self,
        _proof: &Self::ChunkProof,
    ) -> Result<neutrin0_primitives::Hash, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Verify a complete proof against independently authenticated public
    /// values: the consensus statement and the credited account.
    fn verify_consensus_chunk(
        &self,
        _proof: &Self::ChunkProof,
        _statement: &neutrin0_consensus_types::history_proof::ChunkReceiptStatement,
    ) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Derive the complete trusted profile from this backend and chain specification.
    fn history_domain(&self, _spec: &ChainSpec) -> Result<ProofDomain, ProofError> {
        Err(ProofError::Unsupported)
    }

    /// Authenticate a History proof: a compressed chunk receipt committing
    /// exactly the proof's statement, verified under `chunk`, the chunk Guest
    /// of the specification the caller trusts. The key is never taken from the
    /// receipt's own statement, and mock receipts never pass. Use
    /// `verify_history_proof` to obtain the token accepted by engine storage.
    fn verify_history(&self, _proof: &HistoryProof, _chunk: &VkDigest) -> Result<(), ProofError> {
        Err(ProofError::Unsupported)
    }
}
