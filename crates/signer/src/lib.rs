//! `neutrin0-signer`: a validator's BLS keys held apart from its node.
//!
//! The node asks for typed signatures ([`neutrin0_consensus_engine::SignRequest`])
//! over a Unix socket or mutually authenticated TLS. The signer rebuilds each
//! exact message for the chain it is configured for, refuses any that could
//! form an offence with one it already signed ([`journal`]) and answers with
//! the signatures, which the node verifies before use. The node keeps its own
//! signing journal; the signer's is a second, independent protection that
//! also covers two nodes mistakenly sharing one key.

#![deny(unsafe_code)]

pub mod client;
pub mod journal;
pub mod protocol;
pub mod server;
pub mod tls;

pub use client::{Client, Endpoint};
pub use protocol::{Refusal, Request, Response};
pub use server::{Access, Signer, TlsClients};
