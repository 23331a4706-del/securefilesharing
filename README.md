# Secure File Sharing Using AES Encryption and Blockchain Technology

## B.Tech Major Project — Production Implementation & Audit Trail

This repository contains the complete implementation of **Secure File Sharing Using AES Encryption and Blockchain Technology**.

> [!NOTE]
> **Project Status**: **Completed & Fully Verified**.
> Features client-independent **AES-256-GCM file encryption**, **SHA-256 pre-decryption integrity verification**, **decentralized IPFS storage with Base58 CIDs (`Qm...`)**, **Solidity smart contract metadata ledger (`FileMetadataRegistry.sol`)**, **MetaMask EIP-712 structured data audit logging**, **real-time Web3 wallet account switching**, **NIST P-256 ECC + ECDH + HKDF key wrapping for secure multi-recipient sharing & revocation**, **2-step gatekeeping access control**, and **full automated regression test suites**.

---

## 🛠️ Technology Stack

- **Frontend**: React 18, Vite, React Router v6, Vanilla CSS (Cyber Dark System), Ethers.js / Web3 Provider
- **Backend**: Python 3, Flask, Flask-CORS, PyMySQL, Bcrypt, PyJWT, Cryptography (AES-256-GCM, P-256 ECC, ECDH, HKDF-SHA256), Requests (IPFS REST API), Web3.py (Ethereum JSON-RPC)
- **Smart Contracts & Blockchain**: Solidity `^0.8.20`, OpenZeppelin `Ownable`, Hardhat Development Network (`http://127.0.0.1:8545`, `Chain ID: 31337`)
- **Web3 Wallet Integration**: MetaMask browser extension (`eth_signTypedData_v4` EIP-712 structured signing & `accountsChanged` real-time account sync)
- **Decentralized Storage**: Local IPFS Kubo Node (`http://127.0.0.1:5001`) with Base58 v0 multihash CIDs
- **Database**: MySQL / SQLite fallback (`secure_file_sharing`)

---

## 🔐 Core System Architecture & Features

### 1. File Upload & Encryption Workflow
```text
User Selects File → AES-256-GCM Encryption → SHA-256 Hash Digest → IPFS Kubo HTTP API → Base58 CID (Qm...) → Store Record in Database → Hardhat Smart Contract Metadata Registration → MetaMask EIP-712 Structured Data Confirmation → Signature Hash in Activity Audit Log
```

### 2. MetaMask EIP-712 Structured Data Payload
When uploading a file, MetaMask prompts the user to sign a structured data payload anchored directly into the Web3 wallet audit history:
```json
{
  "action": "REGISTER_FILE_SHA256",
  "fileId": 15,
  "filename": "confidential_document.pdf",
  "ownerAddress": "0x69782ce2fd528c6856fbc0fce3091da5ef3eede1",
  "fileStatus": "Active (blockchain_recorded)",
  "accessPermissions": "Private Owner Only (AES-256-GCM Encrypted)",
  "ipfsCid": "QmfJN2yebbJULDyWyk9MbUpxTqchesBGTdxkMPyFzJF5Qm",
  "sha256": "fc00a97c6047fd9ef42d520e5278d7b984438b3e17cc256e5ecd313730587c52",
  "transactionHistory": "Registered at 8:40:52 PM (Confirmed on Blockchain)",
  "timestamp": "8:40:52 PM"
}
```

### 3. Receiver Shared File Access & 2-Step Gatekeeping Workflow
```text
Receiver Navigates to 'Shared With Me' → Active Share Authorization Check (403 if Revoked) → Download Encrypted Bytes from IPFS CID → Gate 1: SHA-256 Hash Match Check (Download Access) → P-256 ECDH + HKDF Key Unwrapping → Gate 2: Decryption Key Match Check (Decryption Access) → AES-256-GCM File Decryption → Browser Download
```

---

## 🛡️ Security Guarantees & Data Separation Rules

1. **IPFS**: Stores encrypted `.enc` file payload bytes only. Plaintext files are **NEVER** stored on or uploaded to IPFS.
2. **Database**: Stores user profiles, JWT sessions, encrypted per-file AES keys, nonces, CIDs, hashes, encrypted ECC private keys, wrapped recipient keys, and transaction hashes.
3. **Blockchain**: Stores immutable metadata reference: `fileId`, `ownerId`, `ipfsCid`, `sha256Hash`, `timestamp`, `active`.
   - **Privacy Guarantee**: Plaintext files, ciphertext, AES keys, master keys, passwords, JWT tokens, wrapped keys, and DB credentials are **NEVER** stored on-chain.
4. **Canonical AAD Key-Wrapping Security**: Key wrapping binds `phase7-key-share-v1|{file_id}|{sender_id}|{receiver_id}` to prevent AAD copy and key-share hijacking attacks.

---

## 📁 Project Structure

```text
securefilesharing/
│
├── blockchain/                   # Hardhat Smart Contract Directory
│   ├── contracts/
│   │   └── FileMetadataRegistry.sol # Solidity ^0.8.20 Smart Contract
│   ├── scripts/
│   │   └── deploy.js             # Deployment script for local network
│   ├── test/
│   │   └── FileMetadataRegistry.test.js # Smart contract test suite (14/14 Passing)
│   ├── hardhat.config.js         # Hardhat network configuration (Chain ID: 31337)
│   └── package.json              # Hardhat & OpenZeppelin dependencies
│
├── frontend/                     # React + Vite Frontend
│   ├── src/
│   │   ├── components/           # Navbar, ProtectedRoute
│   │   ├── context/              # AuthContext (JWT & session state)
│   │   ├── pages/                # Home, Register, Login, Dashboard, Profile
│   │   ├── services/             # API Service layer (with Web3 & Share helpers)
│   │   ├── App.jsx               # Main Router
│   │   ├── index.css             # Cyber Dark Design System
│   │   └── main.jsx              # React Entrypoint
│   ├── index.html
│   ├── package.json
│   └── vite.config.js            # API proxy to Flask backend
│
├── backend/                      # Flask REST API Backend
│   ├── app/
│   │   ├── models/               # user.py (P-256 ECC Keypair support)
│   │   ├── routes/               # auth.py, health.py, file.py, share.py
│   │   ├── services/             # encryption_service.py, file_service.py, integrity_service.py, ipfs_service.py, blockchain_service.py, share_service.py
│   │   ├── config.py             # Security configuration & env audit helper
│   │   ├── db.py                 # MySQL connection & SQLite test wrapper
│   │   └── __init__.py           # Flask app factory, CORS, Security Headers, Error Handlers
│   ├── run.py                    # Server startup script (Port 5000)
│   ├── test_phase1_automated.py  # Phase 1 test suite
│   ├── test_phase2_automated.py  # Phase 2 test suite
│   ├── test_phase3_automated.py  # Phase 3 SHA-256 test suite
│   ├── test_phase4_automated.py  # Phase 4 IPFS test suite
│   ├── test_phase6_automated.py  # Phase 6 Web3.py integration test suite
│   ├── test_phase7_automated.py  # Phase 7 ECC Key Sharing test suite
│   ├── test_phase8_security_e2e.py # Phase 8 Security Hardening & E2E suite
│   ├── test_phase9_final_verification.py # Phase 9 Final Verification test suite
│   ├── requirements.txt          # Python dependencies
│   └── .env.example              # Environment variables template
│
├── database/
│   ├── schema.sql                # Complete Database schema (Phases 1-4)
│   ├── phase5_schema.sql         # Phase 5 blockchain columns migration
│   └── phase7_schema.sql         # Phase 7 ECC keys & file_key_shares migration
│
├── docs/
│   ├── CLOUD_DEPLOYMENT_GUIDE.md # Free Cloud Deployment Guide (Vercel + Render)
│   └── DEMO_GUIDE.md             # Final B.Tech Demonstration Script
│
├── START_APP.bat                 # One-click Windows startup script
├── STOP_APP.bat                  # One-click Windows shutdown script
├── SETUP_NEW_MACHINE.bat         # Dependency installer
└── README.md
```

---

## 🚀 Setup & Execution Guide

### Option A: One-Click Batch Script (Windows)
Double-click `START_APP.bat` in the root folder to launch the local application servers.

---

### Option B: Manual Setup (Windows PowerShell)

#### 1. Start Hardhat Blockchain Node
```powershell
cd blockchain
npm install
npx hardhat node
```

#### 2. Deploy Solidity Smart Contract
In a second terminal window:
```powershell
cd blockchain
npx hardhat run scripts/deploy.js --network localhost
```

#### 3. Start IPFS Kubo Daemon
In a third terminal window:
```powershell
ipfs daemon
```

#### 4. Backend Startup
In a fourth terminal window:
```powershell
cd backend
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

#### 5. Frontend Startup
In a fifth terminal window:
```powershell
cd frontend
npm install
npm run dev
```

---

## ☁️ Cloud Deployment (Free Vercel + Render Hosting)

For a complete step-by-step guide to hosting this application live on the web for 100% free, see **[`docs/CLOUD_DEPLOYMENT_GUIDE.md`](file:///c:/Users/bojja_raj9umt/OneDrive/Desktop/securefilesharing/docs/CLOUD_DEPLOYMENT_GUIDE.md)**:
- **Frontend UI (Vite + React)**: Deployed to **Vercel** (Free CDN Hosting).
- **Backend API (Flask + Cryptography)**: Deployed to **Render** (Free Web Service).

---

## 🧪 Automated Test Execution Matrix

### 1. Smart Contract Tests (`FileMetadataRegistry.test.js`)
```powershell
cd blockchain
npx hardhat test
```

### 2. Complete Backend Automated Test Suite
```powershell
cd backend
.\venv\Scripts\python.exe test_phase9_final_verification.py
```

### 3. Frontend Production Build
```powershell
cd frontend
npm run build
```
