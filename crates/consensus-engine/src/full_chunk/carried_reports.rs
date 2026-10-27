//! The participation and proving reports a block consumes from its branch's
//! carried certificate (design 08).

extern crate alloc;

use alloc::borrow::Cow;
use neutrin0_consensus_types::QuorumCertificate;
use neutrin0_primitives::Hash;
use neutrin0_storage::Database;

use super::CarriedReports;
use crate::Engine;

impl<DB: Database> Engine<DB> {
    /// Participation selected by a retained canonical block's first ancestor
    /// in its chunk. Historical reads never substitute the head's certificate.
    ///
    /// # Errors
    /// Returns an unavailable/pruned-block error or a malformed selection.
    pub fn participation_for_height(
        &self,
        height: u64,
    ) -> Result<
        Option<neutrin0_consensus_types::participation::ParticipationReport>,
        alloc::string::String,
    > {
        let unavailable = || alloc::string::String::from(crate::import::PARTICIPATION_UNAVAILABLE);
        let hash = self
            .store()
            .get_block_hash_by_height(height)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let header = self
            .store()
            .get_header(&hash)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let body = self
            .store()
            .get_body(&hash)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        self.participation_for_block(&header, &body)
    }

    /// Participation for a disposable local simulation extending the head.
    /// The carrier carries a locally held valid previous certificate; later
    /// blocks inherit the exact selection on the head's ancestry.
    ///
    /// # Errors
    /// Returns unavailable history, ancestry or an invalid certificate.
    pub fn participation_for_next_block(
        &self,
    ) -> Result<
        Option<neutrin0_consensus_types::participation::ParticipationReport>,
        alloc::string::String,
    > {
        Ok(self
            .reports_for_next_block()?
            .map(|(participation, _)| participation))
    }

    /// Both reports the next head block consumes (design 08).
    ///
    /// # Errors
    /// Returns unavailable history, ancestry or an invalid certificate.
    pub fn reports_for_next_block(&self) -> Result<Option<CarriedReports>, alloc::string::String> {
        let height = self
            .head_height()
            .checked_add(1)
            .ok_or_else(|| alloc::string::String::from("participation height overflow"))?;
        let certificate = self.production_participation_certificate(height)?;
        self.participation_on_branch(height, self.head_hash(), certificate.as_ref())
    }

    /// Exact previous certificate carried by the canonical following chunk.
    /// The carrier is the first block its proposer produced while holding the
    /// certificate (design 08), so the canonical range is scanned up to it.
    /// Missing selection data never falls back to a locally collected subset.
    ///
    /// # Errors
    /// Returns an overflowing source range, an unavailable/pruned body before
    /// the carrier, or a complete canonical range without one.
    pub fn selected_participation_certificate(
        &self,
        source_chunk: u64,
    ) -> Result<Option<QuorumCertificate>, alloc::string::String> {
        let chunk_id = source_chunk
            .checked_add(1)
            .ok_or_else(|| alloc::string::String::from("participation source overflow"))?;
        let (start, end) = self
            .chunk_heights(chunk_id)
            .ok_or_else(|| alloc::string::String::from("invalid participation range"))?;
        let unavailable = || alloc::string::String::from(crate::import::PARTICIPATION_UNAVAILABLE);
        for height in start..=end {
            let Some(hash) = self
                .store()
                .get_block_hash_by_height(height)
                .map_err(|_| unavailable())?
            else {
                return Ok(None);
            };
            let body = self
                .store()
                .get_body(&hash)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if let Some(carried) = body.participation {
                return Ok(Some(carried.quorum));
            }
        }
        Err(alloc::string::String::from(
            "invalid committed participation selection",
        ))
    }

    /// Authenticate the report selected in this block's exact branch data.
    /// Only one block of each chunk after chunk 0, the carrier, carries the
    /// previous certificate.
    ///
    /// # Errors
    /// Returns unavailable history/ancestry or an invalid selection.
    pub fn participation_for_block(
        &self,
        header: &neutrin0_consensus_types::Header,
        body: &neutrin0_consensus_types::Body,
    ) -> Result<
        Option<neutrin0_consensus_types::participation::ParticipationReport>,
        alloc::string::String,
    > {
        Ok(self
            .reports_for_block(header, body)?
            .map(|(participation, _)| participation))
    }

    /// Both reports this block consumes from its branch's carried certificate
    /// (design 08).
    ///
    /// # Errors
    /// Returns unavailable history/ancestry or an invalid selection.
    pub fn reports_for_block(
        &self,
        header: &neutrin0_consensus_types::Header,
        body: &neutrin0_consensus_types::Body,
    ) -> Result<Option<CarriedReports>, alloc::string::String> {
        self.participation_on_branch(
            header.height,
            header.parent_hash,
            body.participation.as_ref(),
        )
    }

    pub(crate) fn production_participation_certificate(
        &self,
        height: u64,
    ) -> Result<Option<neutrin0_consensus_types::proving::CarriedCertificate>, alloc::string::String>
    {
        if self.programs.is_none() {
            return Ok(None);
        }
        let chunk_id = self
            .chunk_of_height(height)
            .ok_or_else(|| alloc::string::String::from("invalid participation height"))?;
        let (start, end) = self
            .chunk_heights(chunk_id)
            .ok_or_else(|| alloc::string::String::from("invalid participation range"))?;
        let Some(previous) = self.chain_spec().carried_chunk(chunk_id) else {
            return Ok(None);
        };
        // Design 08: the first block produced while holding the previous
        // certificate carries it; none after a carrier on this branch.
        if self
            .branch_carrier(height, self.head_hash(), start)?
            .is_some()
        {
            return Ok(None);
        }
        let record = self
            .execution_history_chunk(previous, chunk_id)
            .map_err(|_| alloc::string::String::from(crate::import::PARTICIPATION_UNAVAILABLE))?;
        match record {
            Some(record) => Ok(Some(record.finality.carried_certificate())),
            // The chunk's last block cannot close the range without one.
            None if height == end => Err(alloc::string::String::from(
                crate::import::PARTICIPATION_UNAVAILABLE,
            )),
            None => Ok(None),
        }
    }

    /// The certificate an earlier block of `height`'s chunk carried on the
    /// branch ending at `parent_hash`, walking back to the chunk's `start`.
    fn branch_carrier(
        &self,
        height: u64,
        parent_hash: Hash,
        start: u64,
    ) -> Result<Option<neutrin0_consensus_types::proving::CarriedCertificate>, alloc::string::String>
    {
        let unavailable = || alloc::string::String::from(crate::import::PARTICIPATION_UNAVAILABLE);
        let invalid = || alloc::string::String::from("invalid committed participation selection");
        if height <= start {
            return Ok(None);
        }
        let mut cursor = parent_hash;
        let mut expected = height.checked_sub(1).ok_or_else(invalid)?;
        loop {
            let header = self
                .store()
                .get_header(&cursor)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if header.height != expected || header.hash() != cursor {
                return Err(invalid());
            }
            let body = self
                .store()
                .get_body(&cursor)
                .map_err(|_| unavailable())?
                .ok_or_else(unavailable)?;
            if let Some(carried) = body.participation {
                return Ok(Some(carried));
            }
            if expected == start {
                return Ok(None);
            }
            cursor = header.parent_hash;
            expected = expected.checked_sub(1).ok_or_else(invalid)?;
        }
    }

    fn participation_on_branch(
        &self,
        height: u64,
        parent_hash: Hash,
        certificate: Option<&neutrin0_consensus_types::proving::CarriedCertificate>,
    ) -> Result<Option<CarriedReports>, alloc::string::String> {
        if self.programs.is_none() {
            return Ok(None);
        }
        let unavailable = || alloc::string::String::from(crate::import::PARTICIPATION_UNAVAILABLE);
        let invalid = || alloc::string::String::from("invalid committed participation selection");
        let chunk_id = self.chunk_of_height(height).ok_or_else(invalid)?;
        let Some(previous) = self.chain_spec().carried_chunk(chunk_id) else {
            return if certificate.is_none() {
                Ok(None)
            } else {
                Err(invalid())
            };
        };
        let (start, end) = self.chunk_heights(chunk_id).ok_or_else(invalid)?;
        // Design 08 carrier rule: exactly one block of the chunk carries the
        // previous certificate; blocks before it consume no new report, the
        // carrier and later blocks consume the derived ones, and the chunk's
        // last block cannot close the range without a carrier.
        let inherited = self.branch_carrier(height, parent_hash, start)?;
        let certificate = match (certificate, inherited) {
            (Some(_), Some(_)) => return Err(invalid()),
            (Some(carried), None) => Cow::Borrowed(carried),
            (None, Some(carried)) => Cow::Owned(carried),
            (None, None) if height == end => return Err(invalid()),
            (None, None) => return Ok(None),
        };
        let record = self
            .execution_history_chunk(previous, chunk_id)
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        neutrin0_prover_chunk::history::verify_carried(self.chain_spec(), &record, &certificate)
            .map(Some)
            .map_err(|_| invalid())
    }
}
