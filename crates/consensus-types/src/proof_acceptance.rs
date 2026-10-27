//! Compact, independently signed acceptance of exact block-proof envelopes.

use alloc::{
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use borsh::{BorshDeserialize, BorshSerialize, io};
use neutrin0_primitives::{
    Hash, MAX_CONSENSUS_COMMITTEE_BLOCKS, MAX_CONSENSUS_VALIDATORS, blake3_256,
};

use crate::VoteAttestation;

const LEAF: &[u8; 16] = b"NEU_PROOF_LEAF__";
const EMPTY: &[u8; 16] = b"NEU_PROOF_EMPTY_";
const NODE: &[u8; 16] = b"NEU_PROOF_NODE__";
const ROOT: &[u8; 16] = b"NEU_PROOF_ROOT__";

/// Counted commitment to position-bound exact proof-envelope hashes.
///
/// Chain/spec/chunk/target binding comes from the containing signed attestation;
/// accepted execution programs come from authenticated consensus history.
#[derive(
    BorshDeserialize, BorshSerialize, Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd,
)]
pub struct ProofAcceptanceCommitment {
    /// Exact number of canonical block positions, positive and bounded.
    pub count: u64,
    /// Domain-separated count and padded Merkle-tree commitment. Padding uses
    /// a constant domain-separated empty leaf; real leaves bind their indices.
    pub root: Hash,
}

/// Ordered exact block-proof identities (`commitment(BlockProof)`), shared
/// between signers.
#[derive(BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProofManifest {
    /// One complete proof-envelope hash for each ascending block height.
    pub proof_hashes: Vec<Hash>,
}

/// Canonical opening of one logical block position in a proof manifest.
#[derive(BorshSerialize, Clone, Debug, Eq, Hash, PartialEq)]
pub struct ProofAcceptanceOpening {
    /// Zero-based offset from the source chunk's first canonical block height.
    pub index: u64,
    /// Bottom-up siblings; direction is derived exclusively from `index`.
    pub siblings: Vec<Hash>,
}

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "proof manifest exceeds canonical bounds",
    )
}

fn leaf(index: u64, hash: &Hash) -> Hash {
    let mut bytes = [0; 56];
    bytes[..16].copy_from_slice(LEAF);
    bytes[16..24].copy_from_slice(&index.to_le_bytes());
    bytes[24..].copy_from_slice(hash);
    blake3_256(&bytes)
}
fn empty() -> Hash {
    blake3_256(EMPTY)
}
fn parent(left: &Hash, right: &Hash) -> Hash {
    let mut bytes = [0; 80];
    bytes[..16].copy_from_slice(NODE);
    bytes[16..48].copy_from_slice(left);
    bytes[48..].copy_from_slice(right);
    blake3_256(&bytes)
}
fn counted(count: u64, tree: &Hash) -> Hash {
    let mut bytes = [0; 56];
    bytes[..16].copy_from_slice(ROOT);
    bytes[16..24].copy_from_slice(&count.to_le_bytes());
    bytes[24..].copy_from_slice(tree);
    blake3_256(&bytes)
}
fn width(count: u64) -> Option<usize> {
    (count > 0 && count <= MAX_CONSENSUS_COMMITTEE_BLOCKS)
        .then(|| usize::try_from(count).ok()?.checked_next_power_of_two())
        .flatten()
}
fn reduce(layer: &[Hash]) -> Vec<Hash> {
    layer
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| parent(&pair[0], &pair[1]))
        .collect()
}

impl ProofManifest {
    fn layer(&self) -> Option<Vec<Hash>> {
        let size = width(u64::try_from(self.proof_hashes.len()).ok()?)?;
        Some(
            (0..size)
                .map(|index| {
                    self.proof_hashes
                        .get(index)
                        .map_or_else(empty, |hash| leaf(index as u64, hash))
                })
                .collect(),
        )
    }
    /// Derive the canonical commitment. Empty/oversized manifests yield an
    /// invalid count/root pair which validation and opening verification reject.
    #[must_use]
    pub fn commitment(&self) -> ProofAcceptanceCommitment {
        let count = u64::try_from(self.proof_hashes.len()).unwrap_or(u64::MAX);
        let Some(mut layer) = self.layer() else {
            return ProofAcceptanceCommitment {
                count,
                root: [0; 32],
            };
        };
        while layer.len() > 1 {
            layer = reduce(&layer);
        }
        ProofAcceptanceCommitment {
            count,
            root: counted(count, &layer[0]),
        }
    }
    /// Open a real position; canonical padding cannot be opened as a proof.
    #[must_use]
    pub fn opening(&self, index: u64) -> Option<ProofAcceptanceOpening> {
        let mut position = usize::try_from(index).ok()?;
        if position >= self.proof_hashes.len() {
            return None;
        }
        let mut layer = self.layer()?;
        let mut siblings = Vec::new();
        while layer.len() > 1 {
            siblings.push(layer[position ^ 1]);
            position /= 2;
            layer = reduce(&layer);
        }
        Some(ProofAcceptanceOpening { index, siblings })
    }
}

impl ProofAcceptanceCommitment {
    /// Verify one exact envelope hash, rejecting count/index/depth substitutions.
    #[must_use]
    pub fn verify(&self, hash: &Hash, opening: &ProofAcceptanceOpening) -> bool {
        let Some(size) = width(self.count) else {
            return false;
        };
        if opening.index >= self.count || opening.siblings.len() != size.trailing_zeros() as usize {
            return false;
        }
        let mut position = opening.index;
        let mut node = leaf(position, hash);
        let mut padding = empty();
        for (level, sibling) in opening.siblings.iter().enumerate() {
            let sibling_start = ((opening.index >> level) ^ 1) << level;
            if sibling_start >= self.count && padding != *sibling {
                return false;
            }
            node = if position & 1 == 0 {
                parent(&node, sibling)
            } else {
                parent(sibling, &node)
            };
            position >>= 1;
            padding = parent(&padding, &padding);
        }
        counted(self.count, &node) == self.root
    }
}

impl BorshDeserialize for ProofManifest {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        read_manifest(reader, MAX_CONSENSUS_COMMITTEE_BLOCKS)
    }
}
impl BorshDeserialize for ProofAcceptanceOpening {
    fn deserialize_reader<R: io::Read>(reader: &mut R) -> io::Result<Self> {
        let index = u64::deserialize_reader(reader)?;
        let count = u32::deserialize_reader(reader)?;
        if count > MAX_CONSENSUS_COMMITTEE_BLOCKS.trailing_zeros() {
            return Err(invalid());
        }
        let mut siblings = Vec::with_capacity(count as usize);
        for _ in 0..count {
            siblings.push(Hash::deserialize_reader(reader)?);
        }
        Ok(Self { index, siblings })
    }
}
fn read_manifest<R: io::Read>(reader: &mut R, remaining: u64) -> io::Result<ProofManifest> {
    let count = u32::deserialize_reader(reader)?;
    if count == 0 || u64::from(count) > remaining {
        return Err(invalid());
    }
    let mut proof_hashes = Vec::with_capacity(count as usize);
    for _ in 0..count {
        proof_hashes.push(Hash::deserialize_reader(reader)?);
    }
    Ok(ProofManifest { proof_hashes })
}
/// Decode the shared dictionary with aggregate allocation bounds before each list.
pub(crate) fn read_manifests<R: io::Read>(reader: &mut R) -> io::Result<Vec<ProofManifest>> {
    let count = u32::deserialize_reader(reader)?;
    if count as usize > MAX_CONSENSUS_VALIDATORS {
        return Err(invalid());
    }
    let mut remaining = MAX_CONSENSUS_COMMITTEE_BLOCKS;
    let mut manifests = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let manifest = read_manifest(reader, remaining)?;
        remaining -= manifest.proof_hashes.len() as u64;
        manifests.push(manifest);
    }
    Ok(manifests)
}

/// One authenticated dictionary index; each manifest root is computed once.
#[derive(Debug)]
pub struct ProofManifestIndex<'a> {
    manifests: BTreeMap<ProofAcceptanceCommitment, &'a ProofManifest>,
}
impl<'a> ProofManifestIndex<'a> {
    /// Authenticate canonical order, uniqueness and aggregate allocation bounds.
    #[must_use]
    pub fn new(manifests: &'a [ProofManifest]) -> Option<Self> {
        if manifests.len() > MAX_CONSENSUS_VALIDATORS {
            return None;
        }
        let mut indexed = BTreeMap::new();
        let mut prior = None;
        let mut total = 0_u64;
        for manifest in manifests {
            let commitment = manifest.commitment();
            if width(commitment.count).is_none() || prior.is_some_and(|prior| prior >= commitment) {
                return None;
            }
            total = total.checked_add(commitment.count)?;
            if total > MAX_CONSENSUS_COMMITTEE_BLOCKS {
                return None;
            }
            indexed.insert(commitment, manifest);
            prior = Some(commitment);
        }
        Some(Self { manifests: indexed })
    }
    /// Resolve a signed commitment without rehashing the shared list.
    #[must_use]
    pub fn get(&self, commitment: &ProofAcceptanceCommitment) -> Option<&'a ProofManifest> {
        self.manifests.get(commitment).copied()
    }
    /// Computed commitment keys in canonical order, without rehashing lists.
    pub fn commitments(&self) -> impl Iterator<Item = ProofAcceptanceCommitment> + '_ {
        self.manifests.keys().copied()
    }
    /// Require exactly the referenced precommit lists, including no unused entry.
    #[must_use]
    pub fn covers_exact(&self, claims: &[VoteAttestation]) -> bool {
        let required: BTreeSet<_> = claims
            .iter()
            .filter_map(|claim| claim.proof_acceptance)
            .collect();
        required.len() == self.manifests.len()
            && required
                .iter()
                .all(|commitment| self.manifests.contains_key(commitment))
    }
}

/// Find one manifest by commitment. For multiple lookups, build a
/// [`ProofManifestIndex`] once instead of recomputing roots per signer.
#[must_use]
pub fn proof_manifest_for<'a>(
    manifests: &'a [ProofManifest],
    commitment: &ProofAcceptanceCommitment,
) -> Option<&'a ProofManifest> {
    ProofManifestIndex::new(manifests)?.get(commitment)
}

/// Require a sorted, unique, bounded dictionary covering exactly every signed
/// precommit commitment. Prevotes refer to no manifests.
#[must_use]
pub fn proof_manifests_valid(claims: &[VoteAttestation], manifests: &[ProofManifest]) -> bool {
    ProofManifestIndex::new(manifests).is_some_and(|index| index.covers_exact(claims))
}

/// Deduplicate full dictionaries, retain only selected claims' lists, and return
/// canonical commitment order. Conflicting/missing/oversized lists fail closed.
#[must_use]
pub fn proof_manifests_for<'a>(
    claims: &[VoteAttestation],
    dictionaries: impl IntoIterator<Item = &'a [ProofManifest]>,
) -> Option<Vec<ProofManifest>> {
    let required: BTreeSet<_> = claims
        .iter()
        .filter_map(|claim| claim.proof_acceptance)
        .collect();
    let mut selected: BTreeMap<ProofAcceptanceCommitment, &'a ProofManifest> = BTreeMap::new();
    let mut total = 0_u64;
    for dictionary in dictionaries {
        let index = ProofManifestIndex::new(dictionary)?;
        for commitment in &required {
            if let Some(manifest) = index.get(commitment) {
                if let Some(prior) = selected.get(commitment) {
                    if *prior != manifest {
                        return None;
                    }
                } else {
                    total = total.checked_add(commitment.count)?;
                    if total > MAX_CONSENSUS_COMMITTEE_BLOCKS {
                        return None;
                    }
                    selected.insert(*commitment, manifest);
                }
            }
        }
    }
    if selected.len() != required.len() || selected.len() > MAX_CONSENSUS_VALIDATORS {
        return None;
    }
    Some(selected.into_values().cloned().collect())
}

#[cfg(test)]
mod tests;
