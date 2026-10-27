//! Receipts that arrived before their block, kept for the orphan window.

#[cfg(test)]
mod tests;

/// Most orphan receipts kept at once.
const MAX_ORPHAN_RECEIPTS: usize = 256;
/// Most orphan receipt bytes kept at once.
const MAX_ORPHAN_RECEIPT_BYTES: usize = 32 * 1024 * 1024;
/// Most orphan receipts kept from one source, so no peer can flush the rest.
const MAX_ORPHANS_PER_SOURCE: usize = 16;
/// How long a source whose buffered receipt failed has its orphans refused.
const ORPHAN_DISTRUST: std::time::Duration = std::time::Duration::from_mins(30);

pub(super) type Source = neutrin0_network::PeerId;

/// Receipts for blocks this node does not hold yet, kept under entry and
/// byte caps until their block arrives or `proof_orphan_slots` pass. Each
/// receipt is kept with the source it came from: a block keeps one receipt
/// per source, so filling its slots takes as many sources, and none replaces
/// another; a source keeps a bounded share, the caps evict from the source
/// holding the most first, and a source whose receipt fails once its block
/// arrives has its orphans refused for a while.
#[derive(Debug, Default)]
pub(in crate::chain_backend) struct OrphanReceipts {
    entries: std::collections::VecDeque<(
        std::time::Instant,
        Source,
        neutrin0_consensus_types::BlockReceipt,
    )>,
    bytes: usize,
    distrusted: std::collections::BTreeMap<Source, std::time::Instant>,
}

impl OrphanReceipts {
    /// Keep `receipt` from `source`, at most `per_block` for its block,
    /// evicting the oldest entries past the caps. Returns whether it is kept.
    pub(super) fn push(
        &mut self,
        receipt: neutrin0_consensus_types::BlockReceipt,
        source: Source,
        now: std::time::Instant,
        ttl: std::time::Duration,
        per_block: usize,
    ) -> bool {
        self.expire(now, ttl);
        let size = receipt.proof_bytes.len();
        if size > MAX_ORPHAN_RECEIPT_BYTES
            || self
                .distrusted
                .get(&source)
                .is_some_and(|until| *until > now)
            || self
                .entries
                .iter()
                .filter(|(_, held_from, _)| *held_from == source)
                .count()
                >= MAX_ORPHANS_PER_SOURCE
        {
            return false;
        }
        let for_block: Vec<_> = self
            .entries
            .iter()
            .filter(|(_, _, held)| held.block_hash == receipt.block_hash)
            .collect();
        if for_block.len() >= per_block
            || for_block.iter().any(|(_, held_from, held)| {
                *held_from == source || held.proof_bytes == receipt.proof_bytes
            })
        {
            return false;
        }
        while self.entries.len() >= MAX_ORPHAN_RECEIPTS
            || self.bytes.saturating_add(size) > MAX_ORPHAN_RECEIPT_BYTES
        {
            let Some(evicted) = self.evict_from_busiest() else {
                break;
            };
            self.bytes -= evicted.proof_bytes.len();
        }
        self.bytes += size;
        self.entries.push_back((now, source, receipt));
        true
    }

    /// Remove and return the receipts kept for `block_hash`, with their sources.
    pub(super) fn take(
        &mut self,
        block_hash: &neutrin0_primitives::BlockHash,
    ) -> Vec<(Source, neutrin0_consensus_types::BlockReceipt)> {
        let mut taken = Vec::new();
        self.entries.retain(|(_, source, receipt)| {
            if receipt.block_hash == *block_hash {
                taken.push((*source, receipt.clone()));
                false
            } else {
                true
            }
        });
        self.bytes -= taken
            .iter()
            .map(|(_, receipt)| receipt.proof_bytes.len())
            .sum::<usize>();
        taken
    }

    /// Remove the oldest receipt of the source holding the most.
    fn evict_from_busiest(&mut self) -> Option<neutrin0_consensus_types::BlockReceipt> {
        let mut held = std::collections::BTreeMap::<Source, usize>::new();
        for (_, source, _) in &self.entries {
            *held.entry(*source).or_default() += 1;
        }
        let busiest = held
            .into_iter()
            .max_by_key(|(_, count)| *count)
            .map(|(source, _)| source)?;
        let position = self
            .entries
            .iter()
            .position(|(_, source, _)| *source == busiest)?;
        self.entries.remove(position).map(|(_, _, receipt)| receipt)
    }

    /// Refuse `source`'s orphans for a while: one of its receipts failed
    /// once its block arrived. A full set forgets the entry ending soonest
    /// rather than refusing to distrust.
    pub(super) fn distrust(&mut self, source: Source, now: std::time::Instant) {
        self.distrusted.retain(|_, until| *until > now);
        if self.distrusted.len() >= MAX_ORPHAN_RECEIPTS
            && !self.distrusted.contains_key(&source)
            && let Some(soonest) = self
                .distrusted
                .iter()
                .min_by_key(|(_, until)| **until)
                .map(|(source, _)| *source)
        {
            self.distrusted.remove(&soonest);
        }
        self.distrusted.insert(source, now + ORPHAN_DISTRUST);
    }

    fn expire(&mut self, now: std::time::Instant, ttl: std::time::Duration) {
        while let Some((kept_at, _, receipt)) = self.entries.front()
            && now.duration_since(*kept_at) >= ttl
        {
            self.bytes -= receipt.proof_bytes.len();
            self.entries.pop_front();
        }
    }

    /// Number of receipts currently kept.
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }
}
