//! Serde-friendly JSON DTOs for the RPC layer.
//!
//! Internal consensus types use borsh for the wire and operate on raw
//! byte arrays. The DTOs here re-encode hashes as `0x..` hex strings,
//! produce decimal integers for heights/slots, and expose only the
//! fields a JSON-RPC client actually needs. Conversion is one-way
//! (consensus → JSON): clients submitting transactions send hex
//! strings directly through the method parameter shapes in
//! `server.rs`.

mod chain;
mod consensus;
mod encoding;
mod operational;
mod system;
#[cfg(test)]
mod tests;

pub use chain::{
    BlockJson, BodyJson, FinalizedInfoJson, GenesisInfoJson, HeadInfoJson, HeaderJson,
};
pub use consensus::*;
pub use encoding::{BlockIdJson, BytesHex, HashHex, Wei};
pub use operational::{BftSessionJson, DiagnosticsJson, ProofWorkJson, SyncProgressJson};
pub use system::{
    ArtifactProgressJson, HealthJson, InstalledGuestJson, PersistedArtifactJson,
    ProgramsStatusJson, ProvingStatusJson, RuntimeCallResultJson, SubmitResultJson, SystemInfoJson,
    ValidatorJson,
};
