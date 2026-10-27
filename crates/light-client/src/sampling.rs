//! Which advertised endpoint a light client may accept.
//!
//! A History proof shows that its endpoint follows from the specification's
//! start under the chain's rules, not that the network follows that chain:
//! validators that have since withdrawn could sign an alternative history. A
//! light client therefore advances only to an endpoint that a quorum of the
//! distinct peers it sampled advertise identically, and stops when two
//! endpoints differ at one chunk count, which takes more than a third of the
//! stake signing both.

use alloc::vec::Vec;
use neutrin0_primitives::Hash;

/// Largest sample window a client keeps.
pub const MAX_SAMPLE_PEERS: usize = 64;

/// A peer's advertised finalized endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Advertisement {
    /// Chunks finalized at the endpoint.
    pub chunks: u64,
    /// Checkpoint hash of the endpoint.
    pub checkpoint_hash: Hash,
}

/// How many distinct peers a client samples and how many must agree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SamplingPolicy {
    /// Distinct peers whose latest advertisements are kept.
    pub peers: usize,
    /// Identical advertisements needed to accept an endpoint.
    pub quorum: usize,
}

impl SamplingPolicy {
    /// Five sampled peers, three of which must agree.
    pub const DEFAULT: Self = Self {
        peers: 5,
        quorum: 3,
    };

    /// `true` when `1 <= quorum <= peers <= MAX_SAMPLE_PEERS`.
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.quorum >= 1 && self.quorum <= self.peers && self.peers <= MAX_SAMPLE_PEERS
    }
}

impl Default for SamplingPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What a client does with its current samples.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    /// The highest endpoint after the current one that a quorum advertises.
    Advance(Advertisement),
    /// Two different endpoints at one chunk count, or one different from the
    /// current endpoint at its own count, each side advertised by at least
    /// two samples. `first` is the current endpoint's hash when the conflict
    /// is with it.
    Conflict {
        /// The chunk count both endpoints claim.
        chunks: u64,
        /// One endpoint's checkpoint hash.
        first: Hash,
        /// The other endpoint's checkpoint hash.
        second: Hash,
    },
    /// No endpoint after the current one has a quorum yet.
    Wait,
}

/// One endpoint disagreeing with the best-supported one at its chunk count.
///
/// The best-supported endpoint is the current one at its own count, else the
/// one most samples advertise. `backed` once two samples advertise the
/// disagreeing endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Disagreement {
    /// The chunk count both endpoints claim.
    pub chunks: u64,
    /// The best-supported endpoint's checkpoint hash.
    pub first: Hash,
    /// The disagreeing endpoint's checkpoint hash.
    pub second: Hash,
    /// Whether at least two samples advertise `second`.
    pub backed: bool,
}

/// Every disagreement among the latest advertisement of each sampled peer,
/// highest count first. Genesis (`chunks == 0`) is never sampled.
#[must_use]
pub fn disagreements(current: Advertisement, samples: &[Advertisement]) -> Vec<Disagreement> {
    let support = |advert: &Advertisement| samples.iter().filter(|other| *other == advert).count();
    let mut counts: Vec<u64> = samples
        .iter()
        .map(|sample| sample.chunks)
        .filter(|chunks| *chunks != 0)
        .collect();
    counts.sort_unstable_by(|a, b| b.cmp(a));
    counts.dedup();
    let mut found = Vec::new();
    for chunks in counts {
        let mut endpoints: Vec<Advertisement> = samples
            .iter()
            .filter(|sample| sample.chunks == chunks)
            .copied()
            .collect();
        endpoints.sort_unstable_by_key(|endpoint| endpoint.checkpoint_hash);
        endpoints.dedup();
        // The verified current endpoint outranks any advertisement.
        let first = if chunks == current.chunks {
            current
        } else {
            *endpoints
                .iter()
                .max_by_key(|endpoint| {
                    (
                        support(endpoint),
                        core::cmp::Reverse(endpoint.checkpoint_hash),
                    )
                })
                .expect("a sampled count has an endpoint")
        };
        for endpoint in endpoints {
            if endpoint.checkpoint_hash != first.checkpoint_hash {
                found.push(Disagreement {
                    chunks,
                    first: first.checkpoint_hash,
                    second: endpoint.checkpoint_hash,
                    backed: support(&endpoint) >= 2,
                });
            }
        }
    }
    found
}

/// Decide from the latest advertisement of each sampled peer.
///
/// Genesis (`chunks == 0`) is never sampled: it is part of the trusted
/// specification. A backed conflict at the highest count wins over any
/// advancement. An endpoint only one peer advertises against the others
/// cannot hold the client back: it is checked alongside (see
/// [`disagreements`]) and halts the client only once verified.
#[must_use]
pub fn decide(current: Advertisement, samples: &[Advertisement], quorum: usize) -> Decision {
    if let Some(conflict) = disagreements(current, samples)
        .into_iter()
        .find(|disagreement| disagreement.backed)
    {
        return Decision::Conflict {
            chunks: conflict.chunks,
            first: conflict.first,
            second: conflict.second,
        };
    }
    let quorum = quorum.max(1);
    samples
        .iter()
        .filter(|sample| sample.chunks > current.chunks)
        .filter(|sample| samples.iter().filter(|other| other == sample).count() >= quorum)
        .max_by_key(|sample| sample.chunks)
        .map_or(Decision::Wait, |sample| Decision::Advance(*sample))
}
