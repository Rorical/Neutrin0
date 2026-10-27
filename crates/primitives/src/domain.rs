//! Consensus signing domains of the current specification and its predecessors.

use alloc::vec::Vec;

use borsh::{BorshDeserialize, BorshSerialize};

use crate::{ChainId, DomainTag, Hash};

/// Consensus signing context derived from the complete authenticated chain spec.
/// Equal numeric chain identifiers do not make distinct specifications equivalent.
///
/// After a hard fork the specification also carries its predecessors' domains
/// (design 20): a signature on an older chunk verifies under the domain in force
/// at that chunk, so pre-fork safety evidence stays punishable (except proof
/// rejections, which belong to the verifier a fork may replace), while every
/// new signature binds the current specification.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ConsensusDomain {
    /// Numeric chain identifier, encoded little-endian in every signed message.
    pub chain_id: ChainId,
    /// Canonical hash of the complete chain specification.
    pub chain_spec_hash: Hash,
    /// Domains of predecessor specifications, oldest first.
    pub prior: PriorDomains,
}

/// Most predecessor signing domains a specification retains.
///
/// The bound keeps [`ConsensusDomain`] small enough to pass by value.
/// Specification validation refuses more, and so does the fork tooling
/// before it writes a successor, so no era's signatures ever stop verifying.
pub const MAX_PRIOR_DOMAINS: usize = 4;

/// The signing domain of a predecessor specification and the chunks it signed.
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct PriorDomain {
    /// The predecessor's complete specification hash; a fork keeps the chain
    /// identifier.
    pub chain_spec_hash: Hash,
    /// First chunk its successor signs: this domain covers every chunk below
    /// it and at or above the preceding entry's `end_chunk`.
    pub end_chunk: u64,
    /// Last block height this domain covers, `end_chunk * chunk_size`.
    pub end_height: u64,
}

/// Bounded, ordered predecessor domains carried by value in [`ConsensusDomain`].
#[derive(BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct PriorDomains {
    len: u8,
    entries: [PriorDomain; MAX_PRIOR_DOMAINS],
}

impl PriorDomains {
    /// No predecessor: the chain starts at genesis.
    pub const NONE: Self = Self {
        len: 0,
        entries: [PriorDomain {
            chain_spec_hash: [0; 32],
            end_chunk: 0,
            end_height: 0,
        }; MAX_PRIOR_DOMAINS],
    };

    /// Copy at most [`MAX_PRIOR_DOMAINS`] entries; `None` beyond the bound.
    #[must_use]
    pub fn from_slice(domains: &[PriorDomain]) -> Option<Self> {
        let mut prior = Self::NONE;
        prior.len = u8::try_from(domains.len())
            .ok()
            .filter(|len| usize::from(*len) <= MAX_PRIOR_DOMAINS)?;
        prior.entries[..domains.len()].copy_from_slice(domains);
        Some(prior)
    }

    /// The retained entries, oldest first.
    #[must_use]
    pub fn as_slice(&self) -> &[PriorDomain] {
        &self.entries[..usize::from(self.len).min(MAX_PRIOR_DOMAINS)]
    }
}

impl ConsensusDomain {
    /// The domain of a specification without predecessors.
    #[must_use]
    pub const fn new(chain_id: ChainId, chain_spec_hash: Hash) -> Self {
        Self {
            chain_id,
            chain_spec_hash,
            prior: PriorDomains::NONE,
        }
    }

    /// First chunk the current specification signs; zero without a fork.
    #[must_use]
    pub fn first_chunk(&self) -> u64 {
        self.prior
            .as_slice()
            .last()
            .map_or(0, |prior| prior.end_chunk)
    }

    /// The chunk whose proof a certificate of `chunk_id` ratifies under the
    /// specification in force at `chunk_id`; `None` for that specification's
    /// first chunk (`ChainSpec::previous_chunk`). A carried pre-fork
    /// certificate is judged by its own specification's rule.
    #[must_use]
    pub fn previous_chunk(&self, chunk_id: u64) -> Option<u64> {
        let first = self
            .prior
            .as_slice()
            .iter()
            .map(|prior| prior.end_chunk)
            .rev()
            .find(|end| *end <= chunk_id)
            .unwrap_or(0);
        (chunk_id > first).then(|| chunk_id - 1)
    }

    /// The exact domain a signature on `chunk_id` was made under: a
    /// predecessor's for chunks before the fork, otherwise this one.
    #[must_use]
    pub fn at_chunk(self, chunk_id: u64) -> Self {
        self.prior
            .as_slice()
            .iter()
            .find(|prior| chunk_id < prior.end_chunk)
            .map_or(self, |prior| {
                Self::new(self.chain_id, prior.chain_spec_hash)
            })
    }

    /// [`Self::at_chunk`] for a block at `height`.
    #[must_use]
    pub fn at_height(self, height: u64) -> Self {
        self.prior
            .as_slice()
            .iter()
            .find(|prior| height <= prior.end_height)
            .map_or(self, |prior| {
                Self::new(self.chain_id, prior.chain_spec_hash)
            })
    }

    /// Encode `tag || chain_id LE8 || chain_spec_hash || payload` canonically.
    #[must_use]
    pub fn signing_message(self, tag: DomainTag, payload: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(16 + 8 + 32 + payload.len());
        message.extend_from_slice(&tag);
        message.extend_from_slice(&self.chain_id.to_le_bytes());
        message.extend_from_slice(&self.chain_spec_hash);
        message.extend_from_slice(payload);
        message
    }

    /// Encode `tag || chain_id LE8 || chain_spec_hash || borsh(payload)`, byte-for-byte
    /// equal to `signing_message(tag, &borsh::to_vec(payload).expect(..))` without
    /// the intermediate payload buffer.
    ///
    /// # Panics
    ///
    /// Panics if `payload` fails to serialize, exactly where the
    /// `borsh::to_vec(payload).expect(..)` form would.
    #[must_use]
    pub fn signing_message_borsh<T: BorshSerialize + ?Sized>(
        self,
        tag: DomainTag,
        payload: &T,
    ) -> Vec<u8> {
        let mut message = Vec::with_capacity(16 + 8 + 32);
        message.extend_from_slice(&tag);
        message.extend_from_slice(&self.chain_id.to_le_bytes());
        message.extend_from_slice(&self.chain_spec_hash);
        payload
            .serialize(&mut message)
            .expect("canonical signing payload serializes");
        message
    }
}
