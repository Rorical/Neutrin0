//! Provider choice by measured service, with a backoff no peer can reset.
//!
//! A peer's own advertisement says nothing about how it serves. Providers are
//! asked in order of measured latency, a peer never asked before first, and a
//! failure backs a provider off for longer each time it repeats. Neither a
//! notice, a changed status nor a reconnect clears that; only a served
//! request does.

use alloc::{collections::BTreeMap, vec::Vec};
use core::time::Duration;
use neutrin0_network::PeerId;
use tokio::time::Instant;

const BASE_BACKOFF: Duration = Duration::from_secs(30);
/// Latency charged for a request that made no progress, as if it had timed
/// out, so a peer cannot hold first place by answering quickly with nothing.
const UNPRODUCTIVE: Duration = Duration::from_secs(30);
const MAX_BACKOFF: Duration = Duration::from_mins(30);
/// Providers remembered at once, so churned identities cannot grow either map.
const CAPACITY: usize = 256;

#[derive(Default)]
pub(super) struct Providers {
    /// Running mean latency of served requests, the newest weighted a quarter.
    latency: BTreeMap<PeerId, Duration>,
    /// When a failed provider may be asked again, and its consecutive failures.
    backoff: BTreeMap<PeerId, (Instant, u32)>,
}

impl Providers {
    /// `peer` served a request in `elapsed`.
    pub(super) fn served(&mut self, peer: PeerId, elapsed: Duration) {
        self.backoff.remove(&peer);
        self.sample(peer, elapsed);
    }

    /// `peer` answered without progress, or left with a request in flight.
    /// Honest peers do this too, so it lowers the peer's rank without
    /// backing it off.
    pub(super) fn unproductive(&mut self, peer: PeerId) {
        self.sample(peer, UNPRODUCTIVE);
    }

    fn sample(&mut self, peer: PeerId, elapsed: Duration) {
        let mean = self
            .latency
            .get(&peer)
            .map_or(elapsed, |mean| (*mean * 3 + elapsed) / 4);
        if self.latency.len() >= CAPACITY && !self.latency.contains_key(&peer) {
            // Forget the slowest measurement: it would be asked last anyway.
            if let Some(slowest) = self
                .latency
                .iter()
                .max_by_key(|(_, latency)| **latency)
                .map(|(peer, _)| *peer)
            {
                self.latency.remove(&slowest);
            }
        }
        self.latency.insert(peer, mean);
    }

    /// `peer` failed a request or never answered it.
    pub(super) fn failed(&mut self, peer: PeerId, now: Instant) {
        let strikes = self
            .backoff
            .get(&peer)
            .map_or(0, |(_, strikes)| strikes.saturating_add(1));
        let delay = BASE_BACKOFF
            .saturating_mul(1 << strikes.min(6))
            .min(MAX_BACKOFF);
        if self.backoff.len() >= CAPACITY && !self.backoff.contains_key(&peer) {
            // Forget the backoff that would end soonest.
            if let Some(soonest) = self
                .backoff
                .iter()
                .min_by_key(|(_, (until, _))| *until)
                .map(|(peer, _)| *peer)
            {
                self.backoff.remove(&soonest);
            }
        }
        self.backoff.insert(peer, (now + delay, strikes));
    }

    /// Whether `peer` is backed off at `now`.
    pub(super) fn cooling(&self, peer: &PeerId, now: Instant) -> bool {
        self.backoff
            .get(peer)
            .is_some_and(|(until, _)| *until > now)
    }

    /// `candidates` not backed off, in the order to ask them.
    pub(super) fn ranked(
        &self,
        candidates: impl IntoIterator<Item = PeerId>,
        now: Instant,
    ) -> Vec<PeerId> {
        let mut ranked: Vec<_> = candidates
            .into_iter()
            .filter(|peer| !self.cooling(peer, now))
            .collect();
        self.order(&mut ranked);
        ranked
    }

    /// Order `peers` to ask them: never asked first, then fastest.
    pub(super) fn order(&self, peers: &mut [PeerId]) {
        peers.sort_by_key(|peer| {
            (
                self.latency.get(peer).copied().unwrap_or(Duration::ZERO),
                *peer,
            )
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer() -> PeerId {
        PeerId::from(neutrin0_network::libp2p::identity::Keypair::generate_ed25519().public())
    }

    #[test]
    fn repeated_failures_back_off_longer_and_only_service_clears_them() {
        let mut providers = Providers::default();
        let (slow, fast, fresh) = (peer(), peer(), peer());
        let start = Instant::now();
        providers.served(slow, Duration::from_secs(20));
        providers.served(fast, Duration::from_millis(200));
        assert_eq!(
            providers.ranked([slow, fast, fresh], start),
            vec![fresh, fast, slow]
        );
        // A quick answer with nothing in it costs a never-asked peer its lead.
        providers.unproductive(fresh);
        assert_eq!(
            providers.ranked([slow, fast, fresh], start),
            vec![fast, slow, fresh]
        );
        providers.failed(fast, start);
        assert!(providers.cooling(&fast, start + BASE_BACKOFF - Duration::from_secs(1)));
        assert!(!providers.cooling(&fast, start + BASE_BACKOFF));
        providers.failed(fast, start + BASE_BACKOFF);
        assert!(providers.cooling(&fast, start + BASE_BACKOFF * 2));
        assert_eq!(
            providers.ranked([slow, fast], start + BASE_BACKOFF * 2),
            vec![slow]
        );
        for _ in 0..16 {
            providers.failed(fast, start);
        }
        assert!(!providers.cooling(&fast, start + MAX_BACKOFF));
        providers.served(fast, Duration::from_millis(200));
        assert!(!providers.cooling(&fast, start));
    }
}
