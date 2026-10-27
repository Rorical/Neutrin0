//! Moving a validator's signing protection to another data directory.
//!
//! The signing journal (exact vote, proposal and nil reservations and the
//! proposer slot watermark), the unfinalized BFT sessions with their locks
//! and the local signing policy keep a restarted validator from signing a
//! second, conflicting message, which forfeits its whole slashable balance.
//! A validator moved to a fresh data directory without them starts unprotected
//! above finality. Export reads them from a stopped node's database; import
//! writes them into a target that holds no journal of its own and belongs to
//! the same chain, so journals are never merged.

use borsh::{BorshDeserialize, BorshSerialize};
use neutrin0_primitives::Hash;
use neutrin0_storage::{Batch, Column, ColumnSnapshot, Database};

use crate::local_control::POLICY_KEY;
use crate::store::pointers::{CHAIN_SPEC_HASH, SIGNING_TRANSFER_SPEC};

/// Everything a validator's signing protection consists of, exactly as stored.
#[derive(Clone, Debug, Eq, PartialEq, BorshSerialize, BorshDeserialize)]
pub struct SigningTransfer {
    /// Chain specification hash of the source database.
    pub chain_spec_hash: Hash,
    /// `signing_journal` column entries.
    pub journal: ColumnSnapshot,
    /// `bft_sessions` column entries.
    pub sessions: ColumnSnapshot,
    /// Encoded local signing policy, if one was saved.
    pub policy: Option<Vec<u8>>,
}

impl SigningTransfer {
    /// Read the signing protection of an initialized database.
    ///
    /// # Errors
    /// Returns storage failures, or refuses a database that never stored a
    /// chain specification (it has signed nothing).
    pub fn export<DB: Database>(db: &DB) -> Result<Self, String>
    where
        DB::Error: core::fmt::Display,
    {
        let chain_spec_hash = chain_spec_hash(db)?
            .ok_or_else(|| String::from("source database was never initialized"))?;
        Ok(Self {
            chain_spec_hash,
            journal: db
                .iter_column(Column::SigningJournal)
                .map_err(|error| error.to_string())?,
            sessions: db
                .iter_column(Column::BftSessions)
                .map_err(|error| error.to_string())?,
            policy: db
                .get(Column::Meta, POLICY_KEY)
                .map_err(|error| error.to_string())?,
        })
    }

    /// This protection as the successor of a hard fork from its source
    /// specification needs it: the proposer slot watermarks rebound to the
    /// successor and the local policy. Votes, messages and sessions stay
    /// behind, since the successor signs no chunk below its fork and signs
    /// later ones only under its own domain.
    ///
    /// # Errors
    /// Refuses a specification that is not a fork of this transfer's source.
    pub fn for_successor(
        &self,
        successor: &neutrin0_primitives::ChainSpec,
    ) -> Result<Self, String> {
        let fork = successor
            .fork
            .as_deref()
            .ok_or("the specification is not a hard fork")?;
        if fork.predecessor != self.chain_spec_hash {
            return Err("the transfer is not from this fork's predecessor".into());
        }
        let successor_hash = successor.hash();
        Ok(Self {
            chain_spec_hash: successor_hash,
            journal: crate::signing::successor_journal(
                &self.journal,
                self.chain_spec_hash,
                successor_hash,
            )?,
            sessions: Vec::new(),
            policy: self.policy.clone(),
        })
    }

    /// Write this protection into `db` in one durable batch. A target not
    /// yet initialized records the source chain, which genesis requires to
    /// be its own.
    ///
    /// # Errors
    /// Refuses a target initialized for another chain or holding any journal
    /// or session entry; returns storage failures.
    pub fn import<DB: Database>(&self, db: &mut DB) -> Result<(), String>
    where
        DB::Error: core::fmt::Display,
    {
        let initialized = match chain_spec_hash(db)? {
            Some(target) if target != self.chain_spec_hash => {
                return Err("target database belongs to another chain specification".into());
            }
            target => target.is_some(),
        };
        for column in [Column::SigningJournal, Column::BftSessions] {
            if !db
                .iter_keys(column)
                .map_err(|error| error.to_string())?
                .is_empty()
            {
                return Err(format!(
                    "target database already holds {} entries; journals are never merged",
                    column.name()
                ));
            }
        }
        let mut batch = Batch::new();
        for (key, value) in &self.journal {
            batch.put(Column::SigningJournal, key.clone(), value.clone());
        }
        for (key, value) in &self.sessions {
            batch.put(Column::BftSessions, key.clone(), value.clone());
        }
        if let Some(policy) = &self.policy {
            batch.put(Column::Meta, POLICY_KEY, policy.clone());
        }
        if !initialized {
            batch.put(Column::Meta, SIGNING_TRANSFER_SPEC, self.chain_spec_hash);
        }
        db.write_batch_durable(batch)
            .map_err(|error| error.to_string())
    }
}

impl SigningTransfer {
    /// The chain `db` belongs to: the specification it was initialized for,
    /// or the one an imported transfer recorded before its first start.
    ///
    /// # Errors
    /// Returns storage failures and malformed records.
    pub fn recorded_chain<DB: Database>(db: &DB) -> Result<Option<Hash>, String>
    where
        DB::Error: core::fmt::Display,
    {
        if let Some(hash) = chain_spec_hash(db)? {
            return Ok(Some(hash));
        }
        db.get(Column::Meta, SIGNING_TRANSFER_SPEC)
            .map_err(|error| error.to_string())?
            .map(|bytes| {
                Hash::try_from(bytes.as_slice())
                    .map_err(|_| String::from("recorded transfer specification is malformed"))
            })
            .transpose()
    }
}

fn chain_spec_hash<DB: Database>(db: &DB) -> Result<Option<Hash>, String>
where
    DB::Error: core::fmt::Display,
{
    db.get(Column::Meta, CHAIN_SPEC_HASH)
        .map_err(|error| error.to_string())?
        .map(|bytes| {
            Hash::try_from(bytes.as_slice())
                .map_err(|_| String::from("stored chain specification hash is malformed"))
        })
        .transpose()
}

#[cfg(test)]
mod tests;
