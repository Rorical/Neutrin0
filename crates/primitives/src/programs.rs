//! Program identities a boundary carries and a specification pins.

use borsh::{BorshDeserialize, BorshSerialize};

use crate::hashing::tagged_commitment;
use crate::{DOMAIN_PINNED_PROGRAMS, Hash};

/// Programs recursively authenticated by every complete chunk.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ExecutionPrograms {
    /// Immutable Fact Guest identity, repeated from the chain binding.
    /// Every boundary and upgrade must preserve the genesis identity.
    pub fact: [u32; 8],
    /// Evidence Guest identity.
    pub evidence: [u32; 8],
    /// Block Guest identity.
    pub block: [u32; 8],
}

impl ExecutionPrograms {
    /// `true` when no identity is zero.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        ![self.fact, self.evidence, self.block].contains(&[0; 8])
    }
}

/// Programs active between two consensus boundaries: the runtime and the
/// execution Guests the chunk Guest verifies recursively.
///
/// Carried inside each consensus boundary, so a program switch is a chunk whose
/// end boundary names a different set; see design 20. The chunk Guest is not
/// here: it is pinned in the immutable chain binding. The Fact
/// identity is repeated here for the execution ABI but cannot change by governance.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct ProgramSet {
    /// Runtime artifact commitment used for ordinary execution.
    pub runtime_code_hash: Hash,
    /// Inner execution programs recursively verified by the chunk Guest.
    pub execution: ExecutionPrograms,
}

impl ProgramSet {
    /// `true` when every Guest identity is nonzero. The runtime hash follows
    /// the chain specification's own rules, which admit a zero commitment.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.execution.is_complete()
    }
}

/// Program-lane content hashes of a specification's starting artifacts.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct GenesisArtifacts {
    /// Runtime WASM.
    pub runtime: Hash,
    /// Fact Guest ELF.
    pub fact: Hash,
    /// Evidence Guest ELF.
    pub evidence: Hash,
    /// Block Guest ELF.
    pub block: Hash,
    /// Chunk Guest ELF.
    pub chunk: Hash,
}

impl GenesisArtifacts {
    /// Every nonzero content hash.
    pub fn named(&self) -> impl Iterator<Item = Hash> {
        [
            self.runtime,
            self.fact,
            self.evidence,
            self.block,
            self.chunk,
        ]
        .into_iter()
        .filter(|hash| *hash != [0; 32])
    }
}

/// The programs a specification pins at its start.
///
/// They are its starting runtime and execution Guests, its chunk Guest and
/// their artifacts. A scheduled fork names its successor by their
/// commitment, which the successor's endpoint repeats
/// ([`ChainSpec::fork_endpoint`](crate::ChainSpec::fork_endpoint)), so only the programs governance approved
/// can start from the predecessor's endpoint (design 20).
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PinnedPrograms {
    /// Starting runtime and execution Guest identities.
    pub programs: ProgramSet,
    /// Chunk Guest identity.
    pub chunk: [u32; 8],
    /// Program-lane content hashes of the five artifacts.
    pub artifacts: GenesisArtifacts,
}

impl PinnedPrograms {
    /// Domain-separated commitment a fork proposal names.
    #[must_use]
    pub fn commitment(&self) -> Hash {
        tagged_commitment(&DOMAIN_PINNED_PROGRAMS, self)
    }
}
