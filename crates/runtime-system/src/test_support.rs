//! Fixtures shared by the crate's unit tests.
//!
//! The runtime that embeds these modules authenticates one caller per
//! system call and drives a fixed block sequence: the mandatory phase, the
//! callers' actions under the block-start policy, then candidate pruning.
//! [`run_block`] is that engine in miniature over any backend.

#![allow(
    clippy::redundant_pub_crate,
    reason = "Test fixtures stay explicitly crate-scoped inside this private module."
)]

extern crate std;

use alloc::vec::Vec;

use neutrin0_consensus_types::evidence::EvidenceAnchor;
use neutrin0_primitives::Hash;
use neutrin0_runtime_abi::RuntimeBlockInput;
use neutrin0_runtime_core::{
    StateBackend, WitnessState,
    host::{LiveTrie, TracingState},
    overlay::OverlayState,
};

use crate::system::{SystemAction, SystemBlock, begin_block, dispatch_with_policy};
use crate::{
    Account, Address, RUNTIME_POLICY_KEY, ReceiptStatus, RuntimePolicy, Validator, account_key,
    encode_account, encode_validator, load_runtime_policy, prune_consensus_candidates,
    validator_key,
};

/// Chain identifier of the test blocks.
pub(crate) const CHAIN_ID: u64 = 42;
/// Generous block gas limit for unit tests.
pub(crate) const TEST_BLOCK_GAS_LIMIT: u64 = 30_000_000;
/// Default block height, comfortably above the unbonding delay arithmetic
/// of the happy paths; queue tests override it per call.
pub(crate) const TEST_BLOCK_HEIGHT: u64 = 100;

/// Deterministic test address for `seed`: a zero-padded 20-byte account
/// whose last byte is `seed`, as the EVM runtime derives system addresses.
pub(crate) fn address(seed: u8) -> Address {
    let mut address = [0; 32];
    address[12] = 0xA0;
    address[31] = seed;
    address
}

/// Backend view whose authenticated caller is `caller`, as the EVM
/// precompile journal presents the transaction sender.
pub(crate) struct Caller<'a, B: StateBackend> {
    pub(crate) inner: &'a mut B,
    pub(crate) caller: Address,
}

impl<B: StateBackend> StateBackend for Caller<'_, B> {
    fn authenticated_caller(&self) -> Option<Hash> {
        Some(self.caller)
    }
    fn credit_system_tokens(&mut self, address: &Hash, amount: u128) -> Option<u128> {
        self.inner.credit_system_tokens(address, amount)
    }
    fn burn_system_tokens(&mut self, amount: u128) {
        self.inner.burn_system_tokens(amount);
    }
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.read(key)
    }
    fn write(&mut self, key: &[u8], value: Vec<u8>) {
        self.inner.write(key, value);
    }
    fn delete(&mut self, key: &[u8]) {
        self.inner.delete(key);
    }
    fn pre_state_root(&self) -> Hash {
        self.inner.pre_state_root()
    }
    fn post_state_root(&self) -> Hash {
        self.inner.post_state_root()
    }
}

/// Outcome of one block run.
pub(crate) struct BlockRun {
    /// Mandatory phase: admissions, deductions and their receipts.
    pub(crate) system: SystemBlock,
    /// Each action's verdict, in order.
    pub(crate) results: Vec<Result<(), ReceiptStatus>>,
    /// Consensus candidate commitment after pruning.
    pub(crate) consensus_candidates_root: Hash,
    /// State root the backend reports once the block ran.
    pub(crate) post_state_root: Hash,
}

impl BlockRun {
    /// Number of actions that applied.
    pub(crate) fn applied(&self) -> u32 {
        u32::try_from(self.results.iter().filter(|result| result.is_ok()).count()).unwrap()
    }
    /// Number of actions that were refused.
    pub(crate) fn failed(&self) -> u32 {
        u32::try_from(self.results.iter().filter(|result| result.is_err()).count()).unwrap()
    }
    /// `(applied, failed)`.
    pub(crate) fn counts(&self) -> (u32, u32) {
        (self.applied(), self.failed())
    }
}

/// Drive the block sequence the embedding runtime runs: the mandatory
/// phase, each action on behalf of its caller under the block-start policy,
/// then candidate pruning. A refused action leaves no writes behind, as the
/// engine's transaction rollback guarantees.
pub(crate) fn run_block<B: StateBackend>(
    state: &mut B,
    input: &RuntimeBlockInput,
    actions: &[(Address, SystemAction)],
) -> BlockRun {
    // The embedding runtime executes the whole block in a disposable journal:
    // an invariant violation anywhere aborts the block and commits nothing.
    let mut block = OverlayState::new(state);
    let system = begin_block(input, &mut block);
    let policy = load_runtime_policy(&mut block);
    let mut results = Vec::with_capacity(actions.len());
    for (caller, action) in actions {
        let mut overlay = OverlayState::new(&mut block);
        let result = dispatch_with_policy(
            &mut Caller {
                inner: &mut overlay,
                caller: *caller,
            },
            input,
            action,
            &policy,
        );
        if result.is_ok() {
            overlay.flush();
        }
        results.push(result);
    }
    let consensus_candidates_root =
        prune_consensus_candidates(&mut block, &input.active_validators).root();
    block.flush();
    BlockRun {
        system,
        results,
        consensus_candidates_root,
        post_state_root: state.post_state_root(),
    }
}

/// Run `input` and `actions` against a tracing view of `live` and return
/// the run with the committed post-state.
pub(crate) fn apply_against(
    live: &LiveTrie,
    input: &RuntimeBlockInput,
    actions: &[(Address, SystemAction)],
) -> (BlockRun, LiveTrie) {
    let mut tracer = TracingState::new(live);
    let run = run_block(&mut tracer, input, actions);
    let (post, _witness) = tracer.into_committed_and_witness().unwrap();
    (run, LiveTrie::from_trie(post))
}

/// Run on the host, then replay the recorded witness in the Guest's
/// backend and require the same verdicts, receipts and post-state root,
/// mirroring the consensus engine's host-then-guest flow.
pub(crate) fn replay(
    live: &LiveTrie,
    input: &RuntimeBlockInput,
    actions: &[(Address, SystemAction)],
) -> (BlockRun, LiveTrie) {
    let mut tracer = TracingState::new(live);
    let host = run_block(&mut tracer, input, actions);
    let (post, witness) = tracer.into_committed_and_witness().unwrap();
    let mut guest = WitnessState::new(&witness).expect("witness round-trips");
    let replayed = run_block(&mut guest, input, actions);
    assert_eq!(replayed.results, host.results);
    assert_eq!(replayed.system.receipts, host.system.receipts);
    assert_eq!(replayed.system.accountability, host.system.accountability);
    assert_eq!(replayed.system.gas, host.system.gas);
    assert_eq!(
        replayed.consensus_candidates_root,
        host.consensus_candidates_root
    );
    assert_eq!(replayed.post_state_root, host.post_state_root);
    assert_eq!(guest.post_state_root(), host.post_state_root);
    (host, LiveTrie::from_trie(post))
}

/// Empty block at `height` with the test chain's defaults.
pub(crate) fn block_input(height: u64) -> RuntimeBlockInput {
    RuntimeBlockInput {
        active_validators: Vec::new(),
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),
        context: neutrin0_consensus_types::runtime::ConsensusExecutionContext::default(),
        evidence_anchor: EvidenceAnchor::default(),
        chain_id: CHAIN_ID,
        block_height: height,
        block_gas_limit: TEST_BLOCK_GAS_LIMIT,
        proposer_address: [0; 32],
        participation: None,
        proving: None,
        transactions: Vec::new(),
    }
}

/// The governable policy lives in state; seed the test trie with `policy`.
pub(crate) fn seed_policy(live: &mut LiveTrie, policy: &RuntimePolicy) {
    live.insert(RUNTIME_POLICY_KEY, borsh::to_vec(policy).unwrap());
}

/// Seed a runtime validator record, active exactly when it holds stake.
pub(crate) fn seed_validator(live: &mut LiveTrie, address: &Address, stake: u128) {
    live.insert(
        &validator_key(address),
        encode_validator(&Validator { stake }),
    );
}

/// Seed staked validators as the runtime leaves them: each validator record
/// and its consensus candidate, the only other copy of a stake.
pub(crate) fn seed_staked(live: &mut LiveTrie, validators: &[(Address, u128)]) {
    use neutrin0_consensus_types::runtime::{
        CONSENSUS_CANDIDATES_KEY, ConsensusCandidate, ConsensusCandidates,
    };
    let mut candidates: ConsensusCandidates = live
        .get(CONSENSUS_CANDIDATES_KEY)
        .unwrap()
        .map(|bytes| borsh::from_slice(&bytes).unwrap())
        .unwrap_or_default();
    for (address, stake) in validators {
        seed_validator(live, address, *stake);
        candidates.upsert(ConsensusCandidate {
            address: *address,
            stake: *stake,
            identity: None,
        });
    }
    live.insert(
        CONSENSUS_CANDIDATES_KEY,
        borsh::to_vec(&candidates).unwrap(),
    );
}

/// Seed `address`'s system account with `balance`.
pub(crate) fn fund(live: &mut LiveTrie, address: &Address, balance: u128) {
    live.insert(&account_key(address), encode_account(&Account { balance }));
}

/// Empty block at height 2 for the evidence-admission tests.
pub(crate) fn evidence_input() -> RuntimeBlockInput {
    RuntimeBlockInput {
        active_validators: Vec::new(),
        participation_acks: Vec::new(),
        program_pieces: Vec::new(),

        context: neutrin0_consensus_types::runtime::ConsensusExecutionContext::default(),
        evidence_anchor: EvidenceAnchor::default(),
        chain_id: 7,
        block_height: 2,
        block_gas_limit: 1_000_000,
        proposer_address: [0; 32],
        participation: None,
        proving: None,
        transactions: Vec::new(),
    }
}
