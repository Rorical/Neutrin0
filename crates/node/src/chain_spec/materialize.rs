//! Materialising the canonical [`ChainSpec`] from a file, with its hard-fork
//! anchor, and pinning a derived genesis root back into the file text.

use neutrin0_primitives::{
    BoundedBytes, ChainSpec, ConsensusParams, Hash, LightClientParams, ProofParams,
};

use super::{
    ChainSpecError, ChainSpecFile, ForkFile, GenesisPrograms, decode_hash_or_zero, decode_hex_exact,
};

impl ChainSpecFile {
    /// Materialise a canonical [`ChainSpec`] from this file.
    ///
    /// # Errors
    ///
    /// Returns [`ChainSpecError`] when any hex field is invalid or the
    /// resulting spec fails canonical validation.
    pub fn to_chain_spec(&self) -> Result<ChainSpec, ChainSpecError> {
        self.to_chain_spec_with(&self.genesis_programs(None)?)
    }

    /// [`Self::to_chain_spec`] over already resolved genesis programs.
    ///
    /// # Errors
    ///
    /// As [`Self::to_chain_spec`].
    pub fn to_chain_spec_with(
        &self,
        programs: &GenesisPrograms,
    ) -> Result<ChainSpec, ChainSpecError> {
        let name_bytes = self.name.as_bytes().to_vec();
        let name = BoundedBytes::new(name_bytes)
            .map_err(|err| ChainSpecError::NameTooLong { len: err.actual })?;

        let metadata_bytes = self
            .metadata
            .as_deref()
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        let metadata = BoundedBytes::new(metadata_bytes)
            .map_err(|err| ChainSpecError::MetadataTooLong { len: err.actual })?;

        let genesis_seed: Hash =
            decode_hash_or_zero(self.genesis_seed_hex.as_deref(), "genesis_seed_hex")?;
        let genesis = crate::genesis::build_genesis_state_with(self, &programs.package)?;
        let genesis_state_root = self.genesis_state_root(genesis.root)?;
        let genesis_block_hash: Hash = decode_hash_or_zero(
            self.genesis_block_hash_hex.as_deref(),
            "genesis_block_hash_hex",
        )?;
        // Bind the exact package which produced this root. Re-reading a mutable
        // package file here could pair one genesis state with another program set.
        let runtime_code_hash = genesis.programs.runtime_code_hash;
        let validators = self.genesis_validators()?;

        let (consensus, proof_params) = self.consensus_and_proof_params();
        let light_client = LightClientParams::default();
        let runtime = self.runtime_params();
        let runtime_info = genesis.runtime_info;

        let genesis_validator_set_root =
            neutrin0_consensus_engine::validator_set::validator_set_root(&validators);

        let mut spec = ChainSpec {
            name,
            chain_id: self.chain_id,
            genesis_time: self.genesis_time,
            genesis_gas_limit: self.genesis_gas_limit,
            runtime_info,
            runtime_code_hash,
            genesis_execution: genesis.programs.execution,
            genesis_chunk: programs.chunk,
            genesis_artifacts: programs.artifacts,
            fork: None,
            genesis_seed,
            genesis_state_root,
            genesis_block_hash,
            genesis_validator_set_root,
            consensus,
            proof: proof_params,
            light_client,
            runtime,
            initial_validators: validators,
            metadata,
        };

        self.attach_fork_anchor(&mut spec)?;
        spec.validate()
            .map_err(|err| ChainSpecError::Validation(err.to_string()))?;
        Ok(spec)
    }

    /// The root the specification commits: the derived one, which a declared
    /// `genesis_state_root_hex` must equal, or a fork's declared one.
    fn genesis_state_root(&self, derived: Hash) -> Result<Hash, ChainSpecError> {
        let mut genesis_state_root = derived;
        if let Some(declared) = self.genesis_state_root_hex.as_deref() {
            let declared = decode_hex_exact::<32>(declared, "genesis_state_root_hex")?;
            // A fork keeps its predecessor's genesis, which other programs
            // than this file's produced.
            if self.fork.is_some() {
                genesis_state_root = declared;
            } else if declared != genesis_state_root {
                return Err(ChainSpecError::Validation(format!(
                    "genesis_state_root_hex {} does not match the root derived from the \
                     genesis allocation {}",
                    hex::encode(declared),
                    hex::encode(genesis_state_root)
                )));
            }
        }
        Ok(genesis_state_root)
    }

    /// Canonical consensus and proof parameters under this file's overrides.
    fn consensus_and_proof_params(&self) -> (ConsensusParams, ProofParams) {
        let mut proof_params = ProofParams::default();
        let mut consensus = ConsensusParams::default();
        if let Some(slot_duration_secs) = self.slot_duration_secs {
            consensus.slot_duration_secs = slot_duration_secs;
        }
        if let Some(chunk_size) = self.chunk_size {
            consensus.chunk_size = chunk_size;
        }
        if let Some(bytes) = self.max_block_proving_input_bytes {
            proof_params.max_block_proving_input_bytes = bytes;
        }
        (consensus, proof_params)
    }

    /// Anchor a fork's specification at its predecessor's endpoint.
    fn attach_fork_anchor(&self, spec: &mut ChainSpec) -> Result<(), ChainSpecError> {
        if let Some(fork) = &self.fork {
            if self.genesis_state_root_hex.is_none() {
                return Err(ChainSpecError::Validation(
                    "a fork pins its predecessor's genesis_state_root_hex".into(),
                ));
            }
            let (anchor, endpoint) = fork.anchor(spec)?;
            spec.fork = Some(Box::new(anchor));
            // Only the programs governance scheduled start from the
            // predecessor's endpoint (design 20).
            if spec.fork_endpoint() != Some(endpoint) {
                return Err(ChainSpecError::Validation(
                    "the predecessor's endpoint schedules no fork to these programs".into(),
                ));
            }
        }
        Ok(())
    }
}

impl ForkFile {
    /// The anchor of `spec`, the specification this file belongs to, and the
    /// predecessor's endpoint: the fork starts at the endpoint with `spec`'s
    /// starting programs.
    fn anchor(
        &self,
        spec: &ChainSpec,
    ) -> Result<
        (
            neutrin0_primitives::ForkAnchor,
            neutrin0_primitives::ConsensusBoundary,
        ),
        ChainSpecError,
    > {
        let endpoint_bytes = hex::decode(&self.endpoint_hex)
            .map_err(|err| ChainSpecError::Validation(format!("endpoint_hex: {err}")))?;
        let endpoint: neutrin0_primitives::ConsensusBoundary =
            borsh::from_slice(&endpoint_bytes)
                .map_err(|err| ChainSpecError::Validation(format!("endpoint_hex: {err}")))?;
        let prior_domains = self
            .prior_domains
            .iter()
            .map(|prior| {
                Ok(neutrin0_primitives::PriorDomain {
                    chain_spec_hash: decode_hex_exact::<32>(
                        &prior.chain_spec_hash_hex,
                        "prior_domains.chain_spec_hash_hex",
                    )?,
                    end_chunk: prior.end_chunk,
                    end_height: prior.end_height,
                })
            })
            .collect::<Result<_, ChainSpecError>>()?;
        let anchor = neutrin0_primitives::ForkAnchor {
            predecessor: decode_hex_exact::<32>(&self.predecessor_hex, "predecessor_hex")?,
            count: endpoint.next_chunk_id,
            endpoint_programs: endpoint.programs,
            start: neutrin0_primitives::ConsensusBoundary::fork_start(&endpoint, spec),
            endpoint_prover: decode_hex_exact::<32>(
                &self.endpoint_prover_hex,
                "endpoint_prover_hex",
            )?,
            prior_domains,
        };
        Ok((anchor, endpoint))
    }
}

/// `raw`, a specification file, with its `genesis_state_root_hex` line
/// replaced or inserted ahead of the first table, the rest untouched.
#[must_use]
pub fn pin_genesis_root(raw: &str, root_hex: &str) -> String {
    let line = format!("genesis_state_root_hex = \"{root_hex}\"");
    let mut out = Vec::new();
    let mut replaced = false;
    for existing in raw.lines() {
        if existing.trim_start().starts_with("genesis_state_root_hex") {
            out.push(line.clone());
            replaced = true;
        } else {
            out.push(existing.to_owned());
        }
    }
    if !replaced {
        // Keep top-level keys ahead of the first table.
        let at = out
            .iter()
            .position(|l| l.trim_start().starts_with('['))
            .unwrap_or(out.len());
        out.insert(at, line);
    }
    let mut text = out.join("\n");
    text.push('\n');
    text
}
