# Phase 5 — Blockchain Metadata Registry (Solidity & Hardhat)

This directory contains **Phase 5** of the B.Tech final-year major project: **Secure File Sharing Using AES Encryption and Blockchain Technology**.

---

## 🎯 Phase 5 Overview

Phase 5 implements a **Solidity smart contract (`FileMetadataRegistry.sol`)** deployed on a local Ethereum-compatible development blockchain using **Hardhat**.

The smart contract maintains an **immutable on-chain registry** of file metadata and SHA-256 integrity checksums.

---

## 🔒 Data Separation Architecture

| Layer | Responsibility | Data Stored |
|---|---|---|
| **IPFS** | Decentralized Binary Storage | Encrypted `.enc` file bytes only |
| **MySQL** | Application Database | User profiles, JWT sessions, encrypted per-file AES keys, nonces, CIDs, hashes |
| **Blockchain** | Immutable Registry | Metadata only: `fileId`, `ownerId`, `ipfsCid`, `sha256Hash`, `timestamp`, `active` |
| **Server Env** | Cryptographic Key Protection | `ENCRYPTION_MASTER_KEY` (32 bytes) |

> [!CAUTION]
> **Data Privacy on Blockchain**:
> The blockchain **NEVER** stores plaintext files, encrypted file bytes, AES keys, master keys, passwords, JWT tokens, database credentials, or personal user information.

---

## 📜 Smart Contract Architecture (`FileMetadataRegistry.sol`)

- **Solidity Version**: `^0.8.20`
- **Inheritance**: OpenZeppelin `Ownable` (contract owner administration)

### Struct Definition:
```solidity
struct FileRecord {
    uint256 fileId;
    string ownerId;
    string ipfsCid;
    string sha256Hash;
    uint256 timestamp;
    bool active;
}
```

### Core Methods:
1. `registerFile(fileId, ownerId, ipfsCid, sha256Hash)`: Registers immutable file metadata on-chain. Validates file ID > 0, non-empty CID, 64-char SHA-256 hex string, and prevents duplicate file ID registration. Generates `timestamp` via `block.timestamp`.
2. `getFile(fileId)`: Read-only lookup returning full metadata record.
3. `deactivateFile(fileId)`: Restricted to contract owner. Flips `active = false` while preserving historical metadata.
4. `isFileRegistered(fileId)`: Returns boolean check.
5. `getRegisteredFileCount()`: Returns total registered records count.

---

## 🚀 Commands & Execution Guide

### 1. Install Dependencies
```powershell
cd blockchain
npm install
```

### 2. Compile Smart Contracts
```powershell
npx hardhat compile
```

### 3. Run Automated Smart Contract Tests
```powershell
npx hardhat test
```

### 4. Start Local Hardhat Node
```powershell
npx hardhat node
```

### 5. Deploy Contract to Local Node
In a separate terminal window:
```powershell
cd blockchain
npx hardhat run scripts/deploy.js --network localhost
```

---

## 📋 Security Features Roadmap

- [x] Secure user authentication (Bcrypt & JWT)
- [x] AES-256-GCM encryption & master key protection
- [x] SHA-256 integrity verification (64-char hex digest over encrypted bytes)
- [x] IPFS decentralized encrypted storage (Zero Local Fallback)
- [x] Blockchain metadata registry (`FileMetadataRegistry.sol`)
- [ ] Blockchain application integration (Flask + Web3.py) — Phase 6
- [ ] File sharing permissions — Later Phase
- [ ] ECC-based secure key sharing — Later Phase
