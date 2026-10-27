//! Exact block proof verdicts cached per program, chain specification and
//! bootstrap generation.

#[cfg(test)]
mod verdict_cache_tests;

use neutrin0_primitives::Hash;
use neutrin0_proof_system::ProofSystem;
use neutrin0_storage::Database;

use super::{ChainBackend, Rejection};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::redundant_pub_crate)] // The parent evidence gate consumes exact verdicts.
pub(in crate::chain_backend) enum ProofVerdict {
    Valid,
    Rejected(Rejection),
}

impl From<Option<Rejection>> for ProofVerdict {
    fn from(reason: Option<Rejection>) -> Self {
        reason.map_or(Self::Valid, Self::Rejected)
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
struct VerdictKey {
    program: [u32; 8],
    chain_spec: Hash,
    source: Hash,
}

#[derive(Clone, Copy)]
#[allow(clippy::redundant_pub_crate)] // Shared with the parent import/bootstrap modules.
pub(in crate::chain_backend) struct VerdictToken {
    program: Option<[u32; 8]>,
    chain_spec: Hash,
    pub(super) source: Hash,
    generation: u64,
}

#[derive(Default)]
#[allow(clippy::redundant_pub_crate)] // Stored by the parent backend, used by sibling modules.
pub(in crate::chain_backend) struct VerdictCache {
    generation: u64,
    entries: std::collections::BTreeMap<VerdictKey, ProofVerdict>,
}

impl VerdictCache {
    fn get(
        &self,
        token: VerdictToken,
        program: Option<[u32; 8]>,
        chain_spec: Hash,
    ) -> Option<ProofVerdict> {
        if !self.token_is_current(token, program, chain_spec) {
            return None;
        }
        self.entries
            .get(&VerdictKey {
                program: token.program?,
                chain_spec: token.chain_spec,
                source: token.source,
            })
            .copied()
    }

    fn remember(
        &mut self,
        token: VerdictToken,
        program: Option<[u32; 8]>,
        chain_spec: Hash,
        verdict: ProofVerdict,
    ) -> bool {
        if !self.token_is_current(token, program, chain_spec) {
            return false;
        }
        let Some(program) = token.program else {
            return true;
        };
        let key = VerdictKey {
            program,
            chain_spec,
            source: token.source,
        };
        if self.entries.len() >= 4096
            && let Some(oldest) = self.entries.keys().next().copied()
        {
            self.entries.remove(&oldest);
        }
        self.entries.insert(key, verdict);
        true
    }

    fn token_is_current(
        &self,
        token: VerdictToken,
        program: Option<[u32; 8]>,
        chain_spec: Hash,
    ) -> bool {
        token.generation == self.generation
            && token.program == program
            && token.chain_spec == chain_spec
    }

    fn reset(&mut self) {
        self.generation = self
            .generation
            .checked_add(1)
            .expect("proof verdict cache generation overflow");
        self.entries.clear();
    }
}

impl<DB, P> ChainBackend<DB, P>
where
    DB: Database + Send + 'static,
    DB::Error: core::fmt::Debug + core::fmt::Display + Send + Sync + 'static,
    P: ProofSystem + Send + Sync + 'static,
{
    pub(in crate::chain_backend) fn begin_block_verdict(&self, source: Hash) -> VerdictToken {
        let program = self.block_program();
        let generation = self
            .availability_verdicts
            .lock()
            .expect("availability verdict cache")
            .generation;
        VerdictToken {
            program,
            chain_spec: self.chain_spec_hash,
            source,
            generation,
        }
    }

    /// Current verdict for `source`, read under one cache lock.
    pub(super) fn cached_block_verdict(&self, source: Hash) -> Option<ProofVerdict> {
        let program = self.block_program();
        let cache = self
            .availability_verdicts
            .lock()
            .expect("availability verdict cache");
        let token = VerdictToken {
            program,
            chain_spec: self.chain_spec_hash,
            source,
            generation: cache.generation,
        };
        cache.get(token, program, self.chain_spec_hash)
    }

    pub(super) fn cached_block_verdict_at(&self, token: VerdictToken) -> Option<ProofVerdict> {
        let program = self.block_program();
        // Bootstrap invalidates this generation while holding the Engine lock,
        // so a reset between token creation and lookup cannot return a prior
        // trust verdict.
        self.availability_verdicts
            .lock()
            .expect("availability verdict cache")
            .get(token, program, self.chain_spec_hash)
    }

    pub(super) fn remember_block_verdict(
        &self,
        token: VerdictToken,
        verdict: ProofVerdict,
    ) -> bool {
        let program = self.block_program();
        self.availability_verdicts
            .lock()
            .expect("availability verdict cache")
            .remember(token, program, self.chain_spec_hash, verdict)
    }

    pub(in crate::chain_backend) fn reset_block_verdicts(&self) {
        self.availability_verdicts
            .lock()
            .expect("availability verdict cache")
            .reset();
    }
}
