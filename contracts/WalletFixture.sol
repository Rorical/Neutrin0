// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;
contract WalletFixture {
    uint256 public value;
    event Changed(uint256 indexed value, address indexed caller);
    function set(uint256 next) external { value = next; emit Changed(next, msg.sender); }
    function rollback(uint256 next) external { value = next; emit Changed(next, msg.sender); revert("rollback"); }
    function transient(uint256 next) external returns(uint256 result) {
        assembly { tstore(0, next) result := tload(0) }
    }
    function context() external view returns(uint256, uint256, address, uint256, uint256, bytes32) {
        return (block.number, block.timestamp, block.coinbase, block.chainid, block.prevrandao, blockhash(block.number - 1));
    }
}
