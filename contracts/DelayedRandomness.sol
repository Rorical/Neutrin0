// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {Neutrin0System} from "./INeutrin0System.sol";

/// Delayed consumption limits adaptive participation. It does not remove producer
/// withholding bias or establish BABE-equivalent beacon guarantees.
contract DelayedRandomness {
    struct Request {
        uint64 createdChunk;
        uint64 sourceChunk;
        bytes32 inputs;
        bytes32 result;
        bool settled;
    }
    uint256 public nextRequest;
    mapping(uint256 => Request) public requests;
    mapping(uint256 => address[]) private participants;
    event Requested(uint256 indexed requestId, uint64 sourceChunk, bytes32 inputs);
    event Settled(uint256 indexed requestId, bytes32 result);
    error SourceUnavailable(uint64 sourceChunk);

    /// Freeze all participants and application inputs now in chunk k. No later
    /// operation can add a participant or change the commitment for this request.
    function request(address[] calldata initialParticipants, bytes32 applicationInputs)
        external returns (uint256 id)
    {
        require(initialParticipants.length > 0 && initialParticipants.length <= 64, "participant count");
        for (uint256 i; i < initialParticipants.length; ++i) {
            require(initialParticipants[i] != address(0), "zero participant");
            for (uint256 j; j < i; ++j) require(initialParticipants[i] != initialParticipants[j], "duplicate participant");
        }
        uint64 chunk = Neutrin0System.CONSENSUS.chunkId();
        id = nextRequest++;
        bytes32 inputs = keccak256(abi.encode(block.chainid, address(this), id, msg.sender, initialParticipants, applicationInputs));
        requests[id] = Request(chunk, chunk + 2, inputs, bytes32(0), false);
        participants[id] = initialParticipants;
        emit Requested(id, chunk + 2, inputs);
    }

    /// Source k+2 becomes consumable in chunk k+3, after finalization. Persist the
    /// consumed result so pruning the source seed cannot change a settled outcome.
    function settle(uint256 id) external returns (bytes32 result) {
        Request storage pending = requests[id];
        require(id < nextRequest && !pending.settled, "invalid request");
        require(Neutrin0System.CONSENSUS.chunkId() >= pending.sourceChunk + 1, "source not finalized");
        try Neutrin0System.RANDOMNESS.randomness(pending.sourceChunk)
            returns (bytes32 seed, uint64 source, uint64 commitBefore, uint64 availableFrom)
        {
            require(source == pending.sourceChunk && pending.createdChunk < commitBefore, "source binding");
            require(Neutrin0System.CONSENSUS.chunkId() >= availableFrom, "consumption timing");
            result = keccak256(abi.encode(seed, source, pending.inputs));
            pending.result = result;
            pending.settled = true;
            emit Settled(id, result);
        } catch { revert SourceUnavailable(pending.sourceChunk); }
    }

    function fixedParticipants(uint256 id) external view returns (address[] memory) {
        return participants[id];
    }
}
