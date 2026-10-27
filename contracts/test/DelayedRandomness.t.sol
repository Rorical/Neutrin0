// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
import {DelayedRandomness} from "../DelayedRandomness.sol";
interface Vm {
    function etch(address target, bytes calldata code) external;
    function store(address target, bytes32 slot, bytes32 value) external;
    function expectRevert() external;
}
contract ConsensusMock {
    uint64 public chunkId;
}
contract RandomnessMock {
    function randomness(uint64 source) external pure returns(bytes32, uint64, uint64, uint64) {
        require(source == 7, "unavailable");
        return (bytes32(uint256(123)), source, source - 1, source + 1);
    }
}
contract DelayedRandomnessTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    DelayedRandomness example;
    function setUp() public {
        vm.etch(address(0x0802), type(ConsensusMock).runtimeCode);
        vm.etch(address(0x0803), type(RandomnessMock).runtimeCode);
        vm.store(address(0x0802), bytes32(0), bytes32(uint256(5)));
        example = new DelayedRandomness();
    }
    function testFreezeInputsDelaySettlementAndPersistResult() public {
        address[] memory people = new address[](2);
        people[0] = address(1); people[1] = address(2);
        uint256 id = example.request(people, bytes32(uint256(42)));
        people[0] = address(3);
        require(example.fixedParticipants(id)[0] == address(1));
        vm.expectRevert(); example.settle(id);
        vm.store(address(0x0802), bytes32(0), bytes32(uint256(8)));
        bytes32 result = example.settle(id);
        (,,,bytes32 saved,bool settled) = example.requests(id);
        require(settled && saved == result && result != bytes32(0));
        vm.expectRevert(); example.settle(id);
    }
    function testRejectDuplicateParticipants() public {
        address[] memory people = new address[](2);
        people[0] = address(1); people[1] = address(1);
        vm.expectRevert(); example.request(people, bytes32(0));
    }
    function testUnavailableSourceIsExplicit() public {
        vm.store(address(0x0802), bytes32(0), bytes32(uint256(6)));
        address[] memory people = new address[](1); people[0] = address(1);
        uint256 id = example.request(people, bytes32(0));
        vm.store(address(0x0802), bytes32(0), bytes32(uint256(9)));
        vm.expectRevert(); example.settle(id);
    }
}
