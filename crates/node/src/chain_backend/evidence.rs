//! Background evidence proving and persistent receipt admission.

mod abandonment;
mod body;
mod jobs;
mod policy;
mod reports;
mod worker;

use super::ChainBackend;

pub(super) use body::selected_body;
