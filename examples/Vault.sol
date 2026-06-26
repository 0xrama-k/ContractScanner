// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

// Intentionally vulnerable sample for testing the scanner.
// Has a classic reentrancy: external call before the state update.
contract Vault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }
}
