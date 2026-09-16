# Demonstration Guide — Secure File Sharing Using AES Encryption and Blockchain Technology

## B.Tech Major Project Final Demonstration Guide

This guide outlines the step-by-step workflow for demonstrating the complete end-to-end system during final project evaluations and viva presentations.

---

## 1. System Initialization & Service Setup

Before initiating the demonstration, launch all underlying infrastructure services in separate terminal windows:

### Terminal 1: Database Setup (MySQL)
Ensure MySQL daemon is running on port `3306` with the `secure_file_sharing` database initialized using `database/schema.sql` and `database/phase7_schema.sql`.

### Terminal 2: Decentralized Storage (IPFS Kubo Node)
```powershell
ipfs daemon
```
*Listens on `http://127.0.0.1:5001`.*

### Terminal 3: Blockchain Local Network (Hardhat Node)
```powershell
cd blockchain
npx hardhat node
```
*Listens on `http://127.0.0.1:8545` (Chain ID: `31337`).*

### Terminal 4: Deploy Solidity Smart Contract
```powershell
cd blockchain
npx hardhat run scripts/deploy.js --network localhost
```
*Deploys `FileMetadataRegistry.sol` and outputs contract address.*

### Terminal 5: Flask Backend REST API
```powershell
cd backend
.\venv\Scripts\Activate.ps1
python run.py
```
*Runs Flask server on `http://127.0.0.1:5000`.*

### Terminal 6: React + Vite Frontend
```powershell
cd frontend
npm run dev
```
*Launches application UI at `http://localhost:5173`.*

---

## 2. Step-by-Step Demonstration Workflow Script

Follow this sequence to demonstrate all core security, decentralized storage, blockchain, and cryptographic key sharing features:

### Step 1: User Registration & ECC Keypair Generation
1. Open web browser to `http://localhost:5173`.
2. Navigate to **Register**.
3. Register User 1:
   - **Username**: `alice`
   - **Email**: `alice@example.com`
   - **Password**: `Password123`
4. Register User 2:
   - **Username**: `bob`
   - **Email**: `bob@example.com`
   - **Password**: `Password123`
5. *Explanation*: Upon registration, the backend automatically generates a persistent **NIST P-256 (secp256r1)** asymmetric keypair for each user. The long-term private key is encrypted with the server `ENCRYPTION_MASTER_KEY` via AES-256-GCM before database storage.

### Step 2: Login as Alice (File Owner)
1. Navigate to **Login**.
2. Log in using `alice@example.com` / `Password123`.
3. View the **Dashboard** displaying Alice's user profile, security feature status, and empty file list.

### Step 3: Encrypted File Upload & IPFS/Blockchain Storage
1. Click **Choose File** and select a document (e.g., `research_report.pdf` or `sample.txt`).
2. Click **Encrypt & Store File**.
3. Observe real-time execution:
   - **AES-256-GCM Encryption**: Generates a random 256-bit AES file key and encrypts the file payload in memory.
   - **SHA-256 Integrity Digest**: Calculates a 64-character hex hash over the encrypted payload bytes.
   - **IPFS Storage**: Uploads encrypted `.enc` payload to local IPFS Kubo node and receives a real Content Identifier (CID).
   - **MySQL Storage**: Persists file metadata, CID, hash, and master-key-protected AES key in MySQL.
   - **Blockchain Registration**: Submits Web3.py transaction to `FileMetadataRegistry.sol` contract on Hardhat network, returning a 32-byte transaction hash.
4. Verify success notification and inspect the file row in **My Encrypted Files** showing CID and `Recorded` blockchain badge.

### Step 4: Verify Cross-System Blockchain & IPFS Integrity
1. Click **Verify Chain** next to `research_report.pdf`.
2. Modal displays 4-way cross-system verification results:
   - MySQL Record ↔ Hardhat Blockchain Smart Contract ↔ IPFS Encrypted Content SHA-256 Digest.
3. Confirm status displays **OVERALL VERIFIED ✓**.

### Step 5: Secure File Sharing to Bob (P-256 ECDH + HKDF)
1. On `research_report.pdf`, click **Share**.
2. Select receiver **bob (bob@example.com)** from dropdown menu.
3. Click **Share File**.
4. *Explanation*: Backend retrieves Bob's persistent P-256 public key, recovers original Phase 2 AES file key, generates a fresh sender ephemeral P-256 keypair, derives a 32-byte shared key using **ECDH** and **HKDF-SHA256** (`info=b"secure-file-sharing-phase7-key-wrap"`), and wraps the AES file key using AES-256-GCM with canonical AAD (`phase7-key-share-v1|{file_id}|{sender_id}|{receiver_id}`).

### Step 6: Login as Bob (Receiver) & Download Shared File
1. Log out as Alice.
2. Log in as **bob@example.com** / `Password123`.
3. Switch tab to **Shared With Me**.
4. Observe `research_report.pdf` listed with owner `alice (alice@example.com)`.
5. Click **Decrypt & Download**.
6. Observe download execution order:
   - **JWT Auth & Active Share Check**: Validates active share record.
   - **IPFS Retrieval**: Fetches encrypted payload strictly from IPFS CID (Zero local fallback).
   - **SHA-256 Integrity Verification**: Validates IPFS bytes against database hash BEFORE key unwrapping.
   - **ECC Key Unwrapping**: Decrypts Bob's private key, computes ECDH + HKDF, unwraps original AES file key.
   - **AES Decryption**: Decrypts payload and streams decrypted file.
7. Open downloaded file and verify plaintext matches original upload.

### Step 7: Revoke Bob's Share Access (Alice)
1. Log out as Bob and log in back as **alice@example.com**.
2. Click **Manage Shares** on `research_report.pdf`.
3. View active share row for Bob and click **Revoke Access**.
4. Confirm status changes to `Revoked`.

### Step 8: Verify Access Rejection for Revoked User
1. Log out as Alice and log in as **bob@example.com**.
2. Attempt to download `research_report.pdf`.
3. Confirm application rejects download with **HTTP 403 Forbidden** error message (*"You do not have active authorized access to this shared file."*).

### Step 9: Re-Share File with Bob (Fresh Ephemeral Material)
1. Log out as Bob and log in as **alice@example.com**.
2. Click **Share** on `research_report.pdf`, select **bob**, and click **Share File**.
3. *Explanation*: Re-sharing generates a **fresh** ephemeral P-256 keypair, fresh ECDH shared secret, fresh HKDF key, fresh 12-byte nonce, and fresh wrapped AES key.

### Step 10: Second Receiver Download & Plaintext Verification
1. Log out as Alice and log in as **bob@example.com**.
2. Switch to **Shared With Me** tab.
3. Click **Decrypt & Download**.
4. Confirm download succeeds and plaintext matches original uploaded file exactly.

---

## 3. Key Defensive Security Summary

| Threat Model | Defensive Architecture |
| :--- | :--- |
| **IPFS Data Leakage** | Only encrypted `.enc` bytes stored on IPFS. Plaintext is NEVER uploaded to IPFS. |
| **Blockchain Privacy** | Blockchain stores metadata reference only (`fileId`, `ownerId`, `ipfsCid`, `sha256Hash`). Keys, files, and secrets are NEVER on-chain. |
| **Key-Share Copy Attack** | Canonical AAD (`phase7-key-share-v1|{file_id}|{sender_id}|{receiver_id}`) binds key-wrapping to exact file and users. Reusing wrapped key for another file fails AES-GCM tag validation. |
| **Tampered IPFS Data** | SHA-256 integrity check runs BEFORE ECC private key decryption or unwrapping. Returns HTTP 409 and halts immediately if tampered. |
| **Revoked Access Bypass** | Server checks `file_key_shares.active == True` before retrieving IPFS content or performing unwrapping. Revoked users receive HTTP 403. |
