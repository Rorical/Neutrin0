#![deny(unsafe_code)]
//! Independent PostgreSQL indexing and GraphQL queries over a full node's public RPC.

pub mod config;
mod error;
pub use error::{Error, Result};
pub mod api;
pub mod db;
pub mod extract;
pub mod ingest;
pub mod model;
pub mod source;
