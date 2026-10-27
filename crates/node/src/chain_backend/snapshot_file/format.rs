//! Byte layout of a snapshot file: magic, length-prefixed manifest, then
//! tagged objects ended by [`END`].

use std::fs::File;
use std::io::{BufWriter, Read, Write};

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_consensus_types::bootstrap::{BootstrapData, StateItemKind};
use neutrin0_consensus_types::history_proof::AnchorOpening;
use neutrin0_primitives::Hash;

/// Leading bytes of every snapshot file.
pub(super) const MAGIC: &[u8; 16] = b"NEUTRIN0-SNAPSHT";
/// Tag ending the object stream.
pub(super) const END: u8 = 0xff;
/// Bound on the encoded manifest, as on a saved pending download.
pub(super) const MAX_HEADER_BYTES: u32 = 32 * 1024 * 1024;

#[derive(BorshSerialize, BorshDeserialize)]
pub(super) struct Header {
    /// Opening of the importer's trust boundary under the endpoint, when the
    /// exporter was asked for one.
    pub(super) anchor: Option<AnchorOpening>,
    pub(super) data: BootstrapData,
}

/// Wire tag of an object kind.
const fn kind_tag(kind: StateItemKind) -> u8 {
    match kind {
        StateItemKind::Node => 0,
        StateItemKind::Value => 1,
        StateItemKind::Runtime => 2,
        StateItemKind::Guest => 3,
    }
}

pub(super) const fn tag_kind(tag: u8) -> Option<StateItemKind> {
    match tag {
        0 => Some(StateItemKind::Node),
        1 => Some(StateItemKind::Value),
        2 => Some(StateItemKind::Runtime),
        3 => Some(StateItemKind::Guest),
        _ => None,
    }
}

pub(super) struct Writer {
    pub(super) out: BufWriter<File>,
    pub(super) objects: u64,
}

impl Writer {
    pub(super) fn object(
        &mut self,
        kind: StateItemKind,
        hash: &Hash,
        bytes: &[u8],
    ) -> Result<(), String> {
        let length = u32::try_from(bytes.len()).map_err(|_| "snapshot object too large")?;
        self.out
            .write_all(&[kind_tag(kind)])
            .map_err(|error| error.to_string())?;
        self.out
            .write_all(hash)
            .map_err(|error| error.to_string())?;
        self.out
            .write_all(&length.to_le_bytes())
            .map_err(|error| error.to_string())?;
        self.out
            .write_all(bytes)
            .map_err(|error| error.to_string())?;
        self.objects += 1;
        Ok(())
    }
}

pub(super) fn read_u32(input: &mut impl Read) -> Result<u32, String> {
    let mut bytes = [0; 4];
    input
        .read_exact(&mut bytes)
        .map_err(|error| error.to_string())?;
    Ok(u32::from_le_bytes(bytes))
}
