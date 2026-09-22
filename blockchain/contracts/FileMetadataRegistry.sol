// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title FileMetadataRegistry
 * @dev Phase 5 — Solidity Smart Contract for Immutable File Metadata & Integrity Records.
 *
 * Security Principles:
 * - Stores METADATA ONLY (fileId, ownerId, ipfsCid, sha256Hash, timestamp, active).
 * - NEVER stores plaintext files, encrypted file bytes, AES keys, passwords, or secrets.
 * - Immutability: Once registered, metadata fields cannot be modified or updated.
 * - Deactivation flips active = false while preserving historical on-chain metadata.
 */
contract FileMetadataRegistry is Ownable {

    struct FileRecord {
        uint256 fileId;
        string ownerId;
        string ipfsCid;
        string sha256Hash;
        uint256 timestamp;
        bool active;
    }

    // Mapping from file ID to its immutable FileRecord
    mapping(uint256 => FileRecord) private _fileRecords;

    // List of registered file IDs for enumeration
    uint256[] private _registeredFileIds;

    // Events
    event FileRegistered(
        uint256 indexed fileId,
        string ownerId,
        string ipfsCid,
        string sha256Hash,
        uint256 timestamp
    );

    event FileDeactivated(
        uint256 indexed fileId,
        uint256 timestamp
    );

    /**
     * @dev Initializes contract setting deployer as the initial owner.
     */
    constructor() Ownable(msg.sender) {}

    /**
     * @dev Registers a new immutable file metadata record on the blockchain.
     * @param fileId Unique application file ID from MySQL
     * @param ownerId Non-sensitive owner identifier (e.g., MySQL user ID as string)
     * @param ipfsCid Real IPFS Content Identifier (CID) generated in Phase 4
     * @param sha256Hash 64-character hex SHA-256 digest computed over encrypted payload
     */
    function registerFile(
        uint256 fileId,
        string calldata ownerId,
        string calldata ipfsCid,
        string calldata sha256Hash
    ) external {
        require(fileId > 0, "Invalid file ID: must be greater than zero");
        require(bytes(ownerId).length > 0, "Invalid owner ID: cannot be empty");
        require(bytes(ipfsCid).length > 0, "Invalid IPFS CID: cannot be empty");
        require(bytes(sha256Hash).length == 64, "Invalid SHA-256 hash: must be exactly 64 hex characters");
        require(_fileRecords[fileId].timestamp == 0, "Duplicate registration: file ID already registered");

        _fileRecords[fileId] = FileRecord({
            fileId: fileId,
            ownerId: ownerId,
            ipfsCid: ipfsCid,
            sha256Hash: sha256Hash,
            timestamp: block.timestamp,
            active: true
        });

        _registeredFileIds.push(fileId);

        emit FileRegistered(fileId, ownerId, ipfsCid, sha256Hash, block.timestamp);
    }

    /**
     * @dev Retrieves an existing file metadata record by file ID.
     * @param fileId Unique application file ID
     */
    function getFile(uint256 fileId)
        external
        view
        returns (
            uint256 recordFileId,
            string memory ownerId,
            string memory ipfsCid,
            string memory sha256Hash,
            uint256 timestamp,
            bool active
        )
    {
        require(_fileRecords[fileId].timestamp > 0, "File record not found");
        FileRecord memory rec = _fileRecords[fileId];
        return (
            rec.fileId,
            rec.ownerId,
            rec.ipfsCid,
            rec.sha256Hash,
            rec.timestamp,
            rec.active
        );
    }

    /**
     * @dev Deactivates a file record. Restricted to contract owner.
     * Preserves historical metadata record while marking active = false.
     * @param fileId Unique application file ID
     */
    function deactivateFile(uint256 fileId) external onlyOwner {
        require(_fileRecords[fileId].timestamp > 0, "File record not found");
        require(_fileRecords[fileId].active, "File record is already inactive");

        _fileRecords[fileId].active = false;

        emit FileDeactivated(fileId, block.timestamp);
    }

    /**
     * @dev Checks if a file ID is registered on the blockchain.
     * @param fileId Unique application file ID
     */
    function isFileRegistered(uint256 fileId) external view returns (bool) {
        return _fileRecords[fileId].timestamp > 0;
    }

    /**
     * @dev Returns total number of file records registered.
     */
    function getRegisteredFileCount() external view returns (uint256) {
        return _registeredFileIds.length;
    }
}
