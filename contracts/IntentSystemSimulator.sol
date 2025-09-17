// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title IntentSystemSimulator
 * @dev Simulator contract that implements the IntentSystem interface with empty functions
 * This is used for testing the filler bot against the IntentSystem interface
 */
contract IntentSystemSimulator {
    // Events for tracking function calls
    event BlobStored(bytes32 indexed blobHash, uint256 expiryTime);
    event BlobProlonged(bytes32 indexed blobHash);
    event IntentCreated(bytes32 indexed intentId, uint256 nonce);
    event IntentFromBlobCreated(bytes32 indexed intentId, bytes32 indexed blobHash, uint256 nonce);
    event IntentCancelled(bytes32 indexed intentId);
    event IntentLocked(bytes32 indexed intentId, address indexed locker);
    event IntentSolved(bytes32 indexed intentId);
    event IntentLockCancelled(bytes32 indexed intentId);

    // Storage for testing
    mapping(bytes32 => bool) public blobStoredMap;
    mapping(bytes32 => uint256) public blobExpiry;
    mapping(bytes32 => address) public intentLockerMap;
    mapping(bytes32 => bool) public intentSolved;
    mapping(bytes32 => uint256) public valueStoredInIntentMap;
    mapping(bytes32 => bytes) public intentDataMap;

    // Blob storage functions
    function storeBlob(bytes calldata data, uint256 expiryTime) external payable {
        bytes32 blobHash = keccak256(data);
        blobStoredMap[blobHash] = true;
        blobExpiry[blobHash] = expiryTime;
        emit BlobStored(blobHash, expiryTime);
    }

    function prolongBlob(bytes32 blobHash) external payable {
        require(blobStoredMap[blobHash], "Blob not stored");
        blobExpiry[blobHash] = block.timestamp + 86400; // Extend by 1 day
        emit BlobProlonged(blobHash);
    }

    function blobStored(bytes32 blobHash) external view returns (bool) {
        return blobStoredMap[blobHash] && blobExpiry[blobHash] > block.timestamp;
    }

    // Intent creation functions
    function intent(bytes calldata intentDataParam, uint256 nonce) external payable returns (bytes32 intentId) {
        intentId = keccak256(abi.encodePacked(msg.sender, nonce, intentDataParam, block.timestamp));
        valueStoredInIntentMap[intentId] = msg.value;
        intentDataMap[intentId] = intentDataParam;
        emit IntentCreated(intentId, nonce);
    }

    function intentFromBlob(bytes32 blobHash, uint256 nonce, bytes calldata extraData) external payable returns (bytes32 intentId) {
        require(blobStoredMap[blobHash], "Blob not stored");
        intentId = keccak256(abi.encodePacked(msg.sender, blobHash, nonce, extraData, block.timestamp));
        valueStoredInIntentMap[intentId] = msg.value;
        intentDataMap[intentId] = extraData;
        emit IntentFromBlobCreated(intentId, blobHash, nonce);
    }

    // Intent management functions
    function cancelIntent(bytes32 intentId, bytes calldata data) external payable {
        require(valueStoredInIntentMap[intentId] > 0, "Intent not found");
        require(intentLockerMap[intentId] == address(0) || intentLockerMap[intentId] == msg.sender, "Not authorized to cancel");

        // Refund the value
        payable(msg.sender).transfer(valueStoredInIntentMap[intentId]);
        valueStoredInIntentMap[intentId] = 0;

        emit IntentCancelled(intentId);
    }

    function lockIntentForSolving(bytes32 intentId, bytes calldata data) external payable {
        require(valueStoredInIntentMap[intentId] > 0, "Intent not found");
        require(intentLockerMap[intentId] == address(0), "Intent already locked");
        require(!intentSolved[intentId], "Intent already solved");

        intentLockerMap[intentId] = msg.sender;
        emit IntentLocked(intentId, msg.sender);
    }

    function solveIntent(bytes32 intentId, bytes calldata data) external payable {
        require(valueStoredInIntentMap[intentId] > 0, "Intent not found");
        require(intentLockerMap[intentId] == msg.sender, "Not the locker");
        require(!intentSolved[intentId], "Intent already solved");

        intentSolved[intentId] = true;
        emit IntentSolved(intentId);
    }

    function cancelIntentLock(bytes32 intentId, bytes calldata data) external payable {
        require(intentLockerMap[intentId] == msg.sender, "Not the locker");

        intentLockerMap[intentId] = address(0);
        emit IntentLockCancelled(intentId);
    }

    // Query functions
    function isIntentSolved(bytes32 intentId) external view returns (bool) {
        return intentSolved[intentId];
    }

    function intentLocker(bytes32 intentId) external view returns (address) {
        return intentLockerMap[intentId];
    }

    function valueStoredInIntent(bytes32 intentId) external view returns (uint256) {
        return valueStoredInIntentMap[intentId];
    }

    // Helper function to get contract balance
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // Fallback function to receive ETH
    receive() external payable {}
}
