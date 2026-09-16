# Secure File Sharing Using AES Encryption and Blockchain Technology

## B.Tech Major Project — Complete 9-Phase Production Implementation

This repository contains the complete **Phases 1 through 9** of the B.Tech final-year major project: **Secure File Sharing Using AES Encryption and Blockchain Technology**.

> [!NOTE]
> **Project Status**: **Completed & Fully Verified (Phases 1–9)**.
> Features secure user authentication (Bcrypt & JWT), client-independent **AES-256-GCM file encryption**, server-side master key protection, **SHA-256 pre-decryption integrity verification**, **decentralized IPFS Kubo storage with zero local fallback**, **Solidity smart contract metadata registry (`FileMetadataRegistry.sol`)**, **Flask-Web3.py application-level blockchain integration on local Hardhat**, **ECC P-256 + ECDH + HKDF-SHA256 secure key wrapping for multi-recipient sharing & revocation**, **modern security headers & CORS hardening**, and **full automated regression test suites**.

---

## 🛠️ Technology Stack

- **Frontend**: React 18, Vite, React Router v6, Vanilla CSS (Cyber Dark System)
- **Backend**: Python 3, Flask, Flask-CORS, PyMySQL, Bcrypt, PyJWT, Cryptography (AES-256-GCM, P-256 ECC, ECDH, HKDF-SHA256), Requests (IPFS REST API), Web3.py (Ethereum JSON-RPC)
- **Smart Contracts & Blockchain**: Solidity `^0.8.20`, OpenZeppelin `Ownable`, Hardhat Development Network (`http://127.0.0.1:8545`, `Chain ID: 31337`)
- **Decentralized Storage**: Local IPFS Kubo Node (`http://127.0.0.1:5001`)
- **Database**: MySQL (`secure_file_sharing`)

---

## 🔐 End-to-End System Architecture

### 1. File Upload & Encryption Workflow
```text
User Uploads File → AES-256-GCM Encryption → SHA-256 Hash of Encrypted Bytes → IPFS Kubo HTTP API → Real Content Identifier (CID) → Store CID + SHA-256 + Protected Key in MySQL → Web3.py registerFile(fileId, ownerId, ipfsCid, sha256Hash) → Local Hardhat Blockchain → Real 32-Byte Transaction Receipt → Store Transaction Hash in MySQL
```

### 2. Owner Download Workflow
```text
Download Request → JWT Auth → Ownership Authorization (403 if Non-Owner) → Retrieve Encrypted (.enc) Bytes strictly from IPFS Kubo Node (503 if IPFS Offline) → SHA-256 Hash Verification (409 if Mismatch; STOPS before Decryption) → AES-256-GCM Unprotect Key & Decrypt → Stream Plaintext File
```

### 3. Receiver Shared File Download Workflow
```text
Shared Download Request → JWT Auth → Active Share Verification (403 if Unshared or Revoked) → Retrieve Encrypted Bytes strictly from IPFS → SHA-256 Hash Verification (409 if Mismatch; STOPS before Key Unwrapping) → Decrypt Receiver ECC Private Key → P-256 ECDH + HKDF-SHA256 Key Unwrap (with Canonical AAD) → Recover Original AES File Key → AES-256-GCM Decrypt → Stream Plaintext File
```

---

## 🛡️ Security Guarantees & Data Separation Rules

1. **IPFS**: Stores encrypted `.enc` file payload bytes only. Plaintext files are **NEVER** stored on or uploaded to IPFS.
2. **MySQL**: Stores user profiles, JWT sessions, encrypted per-file AES keys, nonces, CIDs, hashes, encrypted ECC private keys, wrapped recipient keys, and transaction hashes.
3. **Blockchain**: Stores immutable metadata reference only: `fileId`, `ownerId`, `ipfsCid`, `sha256Hash`, `timestamp`, `active`.
   - **Privacy Guarantee**: Plaintext files, ciphertext, AES keys, master key, passwords, JWT tokens, wrapped keys, and DB credentials are **NEVER** stored on-chain.
4. **Canonical AAD Key-Wrapping Security**: Key wrapping binds `phase7-key-share-v1|{file_id}|{sender_id}|{receiver_id}` to prevent AAD copy and key-share hijacking attacks.

---

## 📁 Project Structure

```text
securefilesharing/
│
├── blockchain/                   # Hardhat Smart Contract Directory (Phases 5 & 6)
│   ├── contracts/
│   │   └── FileMetadataRegistry.sol # Solidity ^0.8.20 Smart Contract
│   ├── scripts/
│   │   └── deploy.js             # Deployment script for local network
│   ├── test/
│   │   └── FileMetadataRegistry.test.js # Smart contract test suite (14/14 Passing)
│   ├── hardhat.config.js         # Hardhat network configuration (Chain ID: 31337)
│   └── package.json              # Hardhat & OpenZeppelin dependencies
│
├── frontend/                     # React + Vite Frontend (Phases 1–8)
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
├── backend/                      # Flask REST API Backend (Phases 1–9)
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
│   └── DEMO_GUIDE.md             # Final B.Tech Demonstration Script
└── README.md
```

---

## 🔑 Environment Variables Reference

Configure environment variables in `backend/.env` (use `backend/.env.example` as template):

```text
ENCRYPTION_MASTER_KEY=<base64-encoded-32-byte-master-key>
JWT_SECRET_KEY=<secure-random-jwt-signing-secret>
DATABASE_HOST=localhost
DATABASE_PORT=3306
DATABASE_NAME=secure_file_sharing
DATABASE_USER=root
DATABASE_PASSWORD=<your-mysql-password>
IPFS_API_URL=http://127.0.0.1:5001
BLOCKCHAIN_RPC_URL=http://127.0.0.1:8545
BLOCKCHAIN_CHAIN_ID=31337
BLOCKCHAIN_CONTRACT_ADDRESS=<deployed-contract-address>
BLOCKCHAIN_PRIVATE_KEY=<hardhat-signer-private-key>
FRONTEND_ORIGIN=http://localhost:5173
```

> **Security Note**: Never commit `.env` or expose raw keys in public repositories.

---

## 🚀 Setup & Execution Guide (Windows PowerShell)

### Step 1: Start Local Hardhat Blockchain Node
```powershell
cd blockchain
npm install
npx hardhat node
```

### Step 2: Deploy Solidity Smart Contract
In a second terminal window:
```powershell
cd blockchain
npx hardhat run scripts/deploy.js --network localhost
```

### Step 3: Start IPFS Kubo Daemon
In a third terminal window:
```powershell
ipfs daemon
```

### Step 4: Backend Startup
In a fourth terminal window:
```powershell
cd backend
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

### Step 5: Frontend Startup
In a fifth terminal window:
```powershell
cd frontend
npm install
npm run dev
```

---

## 🧪 Automated Test Execution Matrix (Phases 1–9)

### 1. Smart Contract Tests (`FileMetadataRegistry.test.js`)
```powershell
cd blockchain
npx hardhat test
```
*Executes 14 automated smart contract test cases (14/14 Passing).*

### 2. Complete Backend Automated Test Suite (Phases 1–9)
```powershell
cd backend
.\venv\Scripts\python.exe test_phase1_automated.py
.\venv\Scripts\python.exe test_phase2_automated.py
.\venv\Scripts\python.exe test_phase3_automated.py
.\venv\Scripts\python.exe test_phase4_automated.py
.\venv\Scripts\python.exe test_phase6_automated.py
.\venv\Scripts\python.exe test_phase7_automated.py
.\venv\Scripts\python.exe test_phase8_security_e2e.py
.\venv\Scripts\python.exe test_phase9_final_verification.py
```

### 3. Frontend Production Build
```powershell
cd frontend
npm run build
```
*Builds production dist bundle with zero errors.*
