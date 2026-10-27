// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// Runtime-owned interfaces. Send zero value; amounts debit the caller's native balance.
/// Every amount is wei of the 18-decimal native token, the same unit as balances and msg.value.
/// Active stake plus all unclaimed withdrawals per validator account must fit uint128, and
/// a bond fails if the validator set's total stake would exceed uint128 max / 2.
interface INeutrin0Staking {
    event SystemOperation(address indexed caller, uint8 kind);
    function validator(address account) external view returns (uint256 stake, bool active);
    /// Matured funds remain unclaimable while held. nextMaturity is zero if none remain immature.
    function withdrawalStatus(address account) external view returns
        (uint256 queued, uint256 matured, bool held, uint64 nextMaturity);
    function registerValidator(bytes calldata blsPublicKey, bytes calldata proofOfPossession, uint256 amount) external;
    /// Replace the caller's BLS key; consensus seats it in the caller's seat at the next chunk
    /// boundary. The proof binds the new key to the caller's account, as registration's does.
    function rotateKey(bytes calldata blsPublicKey, bytes calldata proofOfPossession) external;
    function stake(uint256 amount) external;
    function unstake(uint256 amount) external;
    function exit() external;
    function withdraw() external;
}

interface INeutrin0Governance {
    struct RuntimePolicy {
        uint128 minValidatorStake;
        uint64 evidenceMaxAgeBlocks;
        uint32 evidenceMaxPending;
        uint32 evidenceAdmissionsPerBlock;
        uint32 evidenceExecutionsPerBlock;
        uint128 inactivityLeakAmount;
        uint16 reporterRewardBps;
        /// Share of each block's base fee escrowed for the chunk prover; the rest pays the committee.
        uint16 chunkProverFeeBps;
        /// Yearly issuance on total stake, half to block provers and half to chunk provers.
        uint16 annualIssuanceBps;
        /// Deduction for a signed block the chain replaced after its exclusive proof window.
        uint128 abandonmentPenaltyAmount;
    }
    event SystemOperation(address indexed caller, uint8 kind);
    event ProposalSubmitted(address indexed caller, bytes32 indexed proposalId);
    /// VK bytes pack the eight SP1 u32 words in little endian order.
    /// factVk must equal the chain's genesis Fact identity; changing it requires a hard fork.
    function proposeUpgrade(bytes32 runtimeCodeHash, bytes32 factVk, bytes32 evidenceVk,
        bytes32 blockVk, bytes32 runtimeArtifact, bytes32 factArtifact,
        bytes32 evidenceArtifact, bytes32 blockArtifact, uint64 activateAtChunk)
        external returns (bytes32 proposalId);
    /// Canonical Borsh RuntimePolicy bytes, described by the installed runtime.
    function proposePolicy(bytes calldata policy) external returns (bytes32 proposalId);
    /// Tuple encoding avoids requiring Solidity callers to construct Borsh bytes.
    function proposePolicy(RuntimePolicy calldata policy) external returns (bytes32 proposalId);
    /// Cancel the enacted, not yet activated switch with this program set and activation chunk.
    function cancelUpgrade(bytes32 runtimeCodeHash, bytes32 factVk, bytes32 evidenceVk,
        bytes32 blockVk, uint64 activateAtChunk) external returns (bytes32 proposalId);
    /// End this chain at chunk `count`: from there the successor whose pinned programs
    /// (starting runtime and Guests, chunk Guest and their artifacts) `successor` commits
    /// takes over. `count` obeys the program switch's lead and window.
    function proposeFork(uint64 count, bytes32 successor) external returns (bytes32 proposalId);
    /// Cancel the enacted fork with this count and successor before its count.
    function cancelFork(uint64 count, bytes32 successor) external returns (bytes32 proposalId);
    /// Policy in force. An enacted policy waits in pendingPolicy for its delay.
    function policy() external view returns (RuntimePolicy memory);
    /// Live program-slot proposals, at most one per proposer; whichever reaches
    /// two thirds of the counted stake enacts and closes the others.
    function proposalCount() external view returns (uint256);
    /// Live program-slot proposal at index; kind is 0 for a program switch and
    /// 2 for a cancellation. exists is false past the last index.
    function proposalAt(uint256 index) external view returns (bool exists, bytes32 proposalId,
        address proposer, uint8 kind, uint64 proposedAtChunk, uint64 activateAtChunk);
    /// Live policy-slot proposals, at most one per proposer.
    function policyProposalCount() external view returns (uint256);
    /// Live policy-slot proposal at index; kind is 1.
    function policyProposalAt(uint256 index) external view returns (bool exists, bytes32 proposalId,
        address proposer, uint8 kind, uint64 proposedAtChunk, uint64 activateAtChunk);
    /// Live fork-slot proposals, at most one per proposer.
    function forkProposalCount() external view returns (uint256);
    /// Live fork-slot proposal at index; kind is 3 for a fork and 4 for a fork
    /// cancellation, and activateAtChunk is the fork's count.
    function forkProposalAt(uint256 index) external view returns (bool exists, bytes32 proposalId,
        address proposer, uint8 kind, uint64 proposedAtChunk, uint64 activateAtChunk);
    /// Enacted policy and the first block executed under it.
    function pendingPolicy() external view returns (bool exists, uint64 effectiveHeight,
        RuntimePolicy memory policy);
    /// True if the account supports a live proposal in any slot.
    function hasVoted(address account) external view returns (bool);
    /// available is true once every changed program's artifact is published in full;
    /// an unavailable switch is void at its activation boundary.
    function scheduledUpgrade() external view returns (bool exists, uint64 activateAtChunk,
        bytes32 runtimeCodeHash, bytes32 factVk, bytes32 evidenceVk, bytes32 blockVk,
        bytes32 runtimeArtifact, bytes32 factArtifact, bytes32 evidenceArtifact, bytes32 blockArtifact,
        bool available);
    /// Enacted fork: this chain proves no chunk from `count` on.
    function scheduledFork() external view returns (bool exists, uint64 count, bytes32 successor);
    /// Support a live proposal; the caller's support leaves any other proposal of its slot.
    function vote(bytes32 proposalId) external;
}

interface INeutrin0Consensus {
    function finalizedSeed() external view returns (bytes32);
    function producerVrf() external view returns (bytes32);
    /// Incoming boundary count; also the currently executing chunk ID.
    function chunkId() external view returns (uint64);
    function finalizedHeight() external view returns (uint64);
    function validatorsRoot() external view returns (bytes32);
    function historyRoot() external view returns (bytes32);
    function slot() external view returns (uint64);
    function nativeParentHash() external view returns (bytes32);
}

interface INeutrin0Randomness {
    /// Reverts explicitly when this source has not finalized or has left the eight-seed window.
    /// Commit inputs before commitBeforeChunk; consume from availableFromChunk.
    function randomness(uint64 sourceChunk) external view returns
        (bytes32 seed, uint64 source, uint64 commitBeforeChunk, uint64 availableFromChunk);
}

library Neutrin0System {
    INeutrin0Staking internal constant STAKING = INeutrin0Staking(address(0x0800));
    INeutrin0Governance internal constant GOVERNANCE = INeutrin0Governance(address(0x0801));
    INeutrin0Consensus internal constant CONSENSUS = INeutrin0Consensus(address(0x0802));
    INeutrin0Randomness internal constant RANDOMNESS = INeutrin0Randomness(address(0x0803));
}
