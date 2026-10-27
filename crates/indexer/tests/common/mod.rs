#![allow(
    clippy::redundant_pub_crate,
    reason = "Fixtures are scoped to this integration test, not exported as a library"
)]
#![allow(
    clippy::unused_async,
    clippy::unused_async_trait_impl,
    reason = "Async source fixtures deliberately return deterministic observations"
)]
use async_trait::async_trait;
use neutrin0_indexer::{
    Error, Result,
    config::Config,
    model::{Binding, hex},
    source::Source,
};
use neutrin0_rpc::{HashHex, types::*};
use neutrin0_runtime_abi::{ExecutionArtifacts, RuntimeTransaction};
use serde_json::{Value, json};
use std::{collections::BTreeMap, sync::Mutex};

pub(super) fn config() -> Config {
    toml::from_str(&format!("rpc_url='http://127.0.0.1:1'\nchain_spec_hash='{}'\nruntime='evm'\nbatch_blocks=2\nproof_refresh_blocks=2",hex(&[9;32]))).unwrap()
}
pub(super) const fn genesis() -> GenesisInfoJson {
    GenesisInfoJson {
        hash: HashHex([6; 32]),
        state_root: HashHex([1; 32]),
        timestamp: 0,
        gas_limit: 1_000_000,
        seed: HashHex([8; 32]),
    }
}
pub(super) fn binding(config: &Config) -> Binding {
    Binding {
        chain_spec_hash: hex(&[9; 32]),
        chain_id: "7".into(),
        genesis: genesis(),
        chunk_size: 2,
        decoder_hash: config.decoder_hash().unwrap(),
    }
}
#[derive(Clone)]
pub(super) struct Input {
    pub(super) block: BlockJson,
    pub(super) artifacts: BlockArtifactsJson,
    pub(super) projection: Value,
    pub(super) receipt: neutrin0_rpc::client::EthereumReceiptJson,
}
pub(super) fn input(height: u64, parent: HashHex, branch: u8) -> Input {
    let payload = vec![branch, u8::try_from(height).unwrap(), 7];
    let raw = borsh::to_vec(&RuntimeTransaction::User(payload.clone())).unwrap();
    let id = neutrin0_crypto::keccak256(&payload);
    let artifacts = ExecutionArtifacts {
        transaction_ids: vec![(0, id)],
        receipts: vec![vec![3, 4]],
        metadata: vec![],
    };
    let hash = HashHex(neutrin0_primitives::blake3_256(&[
        branch,
        u8::try_from(height).unwrap(),
    ]));
    let block = BlockJson {
        header: HeaderJson {
            height,
            slot: height,
            parent_hash: parent,
            block_hash: hash,
            proposer_index: 0,
            state_root: HashHex([1; 32]),
            transactions_root: HashHex(neutrin0_primitives::transactions_root_of_blobs(
                std::slice::from_ref(&raw),
            )),
            votes_root: HashHex([0; 32]),
            da_root: HashHex([0; 32]),
            runtime_extra: HashHex([0; 32]),
            receipts_root: HashHex(artifacts.commitment()),
            gas_used: 21_000,
            gas_limit: 1_000_000,
            timestamp: height * 12,
        },
        body: BodyJson {
            transactions: vec![BytesHex(raw)],
            ..BodyJson::default()
        },
    };
    let topic = hex(&neutrin0_crypto::keccak256(
        b"Transfer(address,address,uint256)",
    ));
    let log = json!({"address":hex(&[3;20]),"topics":[topic,hex(&[0;32]),format!("0x{}{}","00".repeat(12),"02".repeat(20))],"data":hex(&[255;32]),"blockHash":hash,"transactionHash":hex(&id),"logIndex":"0x0","removed":false});
    let receipt = serde_json::from_value(json!({"transactionHash":hex(&id),"blockHash":hash,"blockNumber":format!("0x{height:x}"),"status":"0x1","transactionIndex":"0x0","gasUsed":"0x5208","contractAddress":null,"logs":[log]})).unwrap();
    let projection = json!({"hash":hash,"number":format!("0x{height:x}"),"transactions":[{"hash":hex(&id),"blockHash":hash,"transactionIndex":"0x0","from":hex(&[1;20]),"to":hex(&[2;20]),"nonce":format!("0x{height:x}"),"value":format!("0x{}","f".repeat(64)),"input":"0x"}]});
    Input {
        block,
        artifacts: BlockArtifactsJson {
            block_hash: hash,
            runtime_code_hash: HashHex([5; 32]),
            artifacts: BytesHex(borsh::to_vec(&artifacts).unwrap()),
        },
        projection,
        receipt,
    }
}
pub(super) struct State {
    pub(super) inputs: BTreeMap<u64, Input>,
    pub(super) finalized_chunks: u64,
    pub(super) sequence: u64,
    pub(super) stream: HashHex,
    pub(super) expire: bool,
    pub(super) missing: Option<u64>,
    pub(super) corrupt: Option<u64>,
    pub(super) wrong_spec: bool,
    pub(super) delayed_proofs: bool,
}
pub(super) struct Fixture {
    pub(super) state: Mutex<State>,
}
impl Fixture {
    pub(super) fn new(count: u64, finalized_chunks: u64) -> Self {
        let mut parent = genesis().hash;
        let inputs = (1..=count)
            .map(|height| {
                let input = input(height, parent, 1);
                parent = input.block.header.block_hash;
                (height, input)
            })
            .collect();
        Self {
            state: Mutex::new(State {
                inputs,
                finalized_chunks,
                sequence: 1,
                stream: HashHex([10; 32]),
                expire: false,
                missing: None,
                corrupt: None,
                wrong_spec: false,
                delayed_proofs: false,
            }),
        }
    }
    pub(super) fn fork(&self, ancestor: u64, count: u64) {
        let mut state = self.state.lock().unwrap();
        state.inputs.retain(|height, _| *height <= ancestor);
        let mut parent = if ancestor == 0 {
            genesis().hash
        } else {
            state.inputs[&ancestor].block.header.block_hash
        };
        for height in ancestor + 1..=count {
            let input = input(height, parent, 2);
            parent = input.block.header.block_hash;
            state.inputs.insert(height, input);
        }
        state.sequence += 1;
    }
}
#[async_trait]
impl Source for Fixture {
    async fn binding(&self, config: &Config) -> Result<Binding> {
        Ok(binding(config))
    }
    async fn events(&self, after: Option<ChainCursorJson>) -> Result<ChainEventPageJson> {
        let state = self.state.lock().unwrap();
        if state.expire && after.is_some() {
            return Err(Error::Rpc(jsonrpsee::core::client::Error::Call(
                jsonrpsee::types::ErrorObjectOwned::owned(-32028, "expired", None::<()>),
            )));
        }
        let point = |height| ChainPointJson {
            height,
            hash: if height == 0 {
                genesis().hash
            } else {
                state.inputs[&height].block.header.block_hash
            },
        };
        let latest = ChainCursorJson {
            stream_id: state.stream,
            sequence: state.sequence.to_string(),
        };
        let status = ChainEventStatusJson {
            chain_spec_hash: HashHex(if state.wrong_spec { [11; 32] } else { [9; 32] }),
            head: point(*state.inputs.last_key_value().unwrap().0),
            finalized: point(state.finalized_chunks * 2),
            finalized_chunks: state.finalized_chunks,
            latest: latest.clone(),
            replay_from: ChainCursorJson {
                stream_id: state.stream,
                sequence: "0".into(),
            },
            retention_events: 8,
        };
        Ok(ChainEventPageJson {
            status,
            events: vec![],
            next: latest,
            has_more: false,
        })
    }
    async fn header(&self, height: u64) -> Result<Option<HeaderJson>> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .inputs
            .get(&height)
            .map(|input| input.block.header.clone()))
    }
    async fn block(&self, height: u64) -> Result<Option<BlockJson>> {
        let state = self.state.lock().unwrap();
        Ok((state.missing != Some(height))
            .then(|| state.inputs.get(&height).map(|input| input.block.clone()))
            .flatten())
    }
    async fn artifacts(&self, hash: HashHex) -> Result<Option<BlockArtifactsJson>> {
        let state = self.state.lock().unwrap();
        Ok(state
            .inputs
            .values()
            .find(|input| input.block.header.block_hash == hash)
            .map(|input| {
                let mut result = input.artifacts.clone();
                if state.corrupt == Some(input.block.header.height) {
                    result.artifacts.0.push(0);
                }
                result
            }))
    }
    async fn ethereum(
        &self,
        hash: HashHex,
    ) -> Result<(Value, Vec<neutrin0_rpc::client::EthereumReceiptJson>)> {
        let state = self.state.lock().unwrap();
        let input = state
            .inputs
            .values()
            .find(|input| input.block.header.block_hash == hash)
            .ok_or(Error::BranchChanged)?;
        let result = (input.projection.clone(), vec![input.receipt.clone()]);
        drop(state);
        Ok(result)
    }
    async fn chunk(&self, id: u64) -> Result<Option<ChunkJson>> {
        let state = self.state.lock().unwrap();
        if id >= state.finalized_chunks {
            return Ok(None);
        }
        let start = id * 2 + 1;
        let end = start + 1;
        Ok(Some(ChunkJson {
            hash: HashHex([20; 32]),
            chunk_id: id,
            start_height: start,
            end_height: end,
            start_state_root: HashHex([1; 32]),
            end_state_root: HashHex([1; 32]),
            start_block_hash: state.inputs[&start].block.header.block_hash,
            end_block_hash: state.inputs[&end].block.header.block_hash,
            block_hash_root: HashHex([0; 32]),
            block_proof_root: HashHex([0; 32]),
            vrf_proof_root: HashHex([0; 32]),
            active_validator_set_root: HashHex([0; 32]),
            next_validator_set_root: HashHex([0; 32]),
            next_identity_sanctions_root: HashHex([0; 32]),
            da_root: HashHex([0; 32]),
            proof_available: true,
            certificate_available: true,
        }))
    }
    async fn certificate(&self, id: u64) -> Result<Option<CertificateJson>> {
        Ok(Some(CertificateJson {
            chunk_id: id,
            chunk_hash: HashHex([20; 32]),
            round: 0,
            active_validator_set_root: HashHex([0; 32]),
            leader_index: 0,
            proposal: BytesHex(vec![1]),
            prevote_signers: vec![0],
            precommit_signers: vec![0],
            prevote_signature: BytesHex(vec![1]),
            precommit_signature: BytesHex(vec![1]),
            prevote_attestations: 1,
            precommit_attestations: 1,
            proof_manifests: vec![],
            artifact: ArtifactInfoJson {
                id: ArtifactIdJson::Certificate { chunk: id },
                artifact_hash: HashHex([20; 32]),
                encoded_bytes: 1,
                proof_bytes: 0,
                public_values: None,
            },
        }))
    }
    async fn proof(&self, id: ArtifactIdJson) -> Result<Option<ArtifactInfoJson>> {
        if self.state.lock().unwrap().delayed_proofs {
            return Err(Error::Rpc(jsonrpsee::core::client::Error::Call(
                jsonrpsee::types::ErrorObjectOwned::owned(-32026, "not ready", None::<()>),
            )));
        }
        Ok(Some(ArtifactInfoJson {
            id,
            artifact_hash: HashHex([21; 32]),
            encoded_bytes: 100,
            proof_bytes: 90,
            public_values: None,
        }))
    }
    async fn validators(&self) -> Result<Vec<ValidatorJson>> {
        Ok(vec![ValidatorJson {
            effective_stake: Wei(u128::MAX),
            exit_epoch: u64::MAX,
            ..ValidatorJson::default()
        }])
    }
}
pub(super) async fn store() -> neutrin0_indexer::db::Store {
    let url = std::env::var("NEUTRIN0_INDEXER_TEST_DATABASE_URL")
        .expect("Set a disposable PostgreSQL URL; this test creates isolated schemas");
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).unwrap();
    neutrin0_indexer::db::Store::open(&url, &format!("test_{}", hex::encode(random)))
        .await
        .unwrap()
}
