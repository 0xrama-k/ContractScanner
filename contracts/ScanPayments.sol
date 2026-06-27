// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ScanPayments
/// @notice Fixed-price payment gate for ContractScanner on Monad testnet.
/// @dev Price is immutable (10 MON). There is no fee admin and no `setPrice`;
///      the only privileged action is `withdraw`. Self-contained (no imports)
///      for simple single-file deployment/verification. MON is the 18-decimal
///      native token, so 10 MON == 10 * 10**18 wei.
contract ScanPayments {
    /// @notice Required payment per scan, in wei. 10 MON, fixed for the MVP.
    uint256 public constant PRICE = 10 * (10 ** 18);

    address public owner;
    address public pendingOwner;

    /// @notice scanId (UUID v4 left-padded to bytes32) => paid.
    mapping(bytes32 => bool) public paid;

    event ScanPaid(bytes32 indexed scanId, address indexed payer, uint256 amount);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    error NotOwner();
    error NotPendingOwner();
    error Underpaid();
    error AlreadyPaid();
    error WithdrawFailed();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    /// @notice Pay for a single scan. Reverts on underpayment or replay.
    /// @param scanId The backend scan id encoded as bytes32.
    function pay(bytes32 scanId) external payable {
        if (msg.value < PRICE) revert Underpaid();
        if (paid[scanId]) revert AlreadyPaid();
        paid[scanId] = true;
        emit ScanPaid(scanId, msg.sender, msg.value);
    }

    /// @notice Withdraw the full balance to `to`. Owner only.
    function withdraw(address payable to) external onlyOwner {
        (bool ok, ) = to.call{value: address(this).balance}("");
        if (!ok) revert WithdrawFailed();
    }

    // --- Two-step ownership transfer (Ownable2Step-style) ---

    function transferOwnership(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();
        address prev = owner;
        owner = pendingOwner;
        pendingOwner = address(0);
        emit OwnershipTransferred(prev, owner);
    }
}
