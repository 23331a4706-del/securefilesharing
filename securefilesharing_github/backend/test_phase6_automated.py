import os
import unittest
import base64
from unittest.mock import patch, MagicMock

# Enable SQLite test database fallback before loading app
os.environ["USE_SQLITE"] = "true"
os.environ["SQLITE_DB_PATH"] = "test_phase6_secure_share.db"

# Ensure master key is present in environment for testing
if not os.getenv("ENCRYPTION_MASTER_KEY"):
    os.environ["ENCRYPTION_MASTER_KEY"] = "wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM="

# Configure default local Hardhat parameters
if not os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS"):
    os.environ["BLOCKCHAIN_CONTRACT_ADDRESS"] = "0x5FbDB2315678afecb367f032d93F642f64180aa3"
if not os.getenv("BLOCKCHAIN_PRIVATE_KEY"):
    os.environ["BLOCKCHAIN_PRIVATE_KEY"] = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

from app import create_app
from app.config import Config
from app.db import get_db_connection
from app.services.encryption_service import (
    generate_file_key,
    generate_nonce,
    encrypt_file_data,
    decrypt_file_data,
    protect_file_key
)
from app.services.integrity_service import calculate_bytes_sha256
from app.services.blockchain_service import (
    verify_blockchain_connection,
    get_contract,
    is_file_registered,
    get_file_metadata,
    register_file_metadata,
    BlockchainUnavailableError,
    BlockchainConfigurationError,
    BlockchainMetadataMismatchError,
    BlockchainRegistrationError
)


class TestPhase6Automated(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Set up Flask test client and reset test database tables."""
        cls.app = create_app()
        cls.client = cls.app.test_client()

        # Reset DB tables
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("DROP TABLE IF EXISTS files;")
                cursor.execute("DROP TABLE IF EXISTS users;")
                cursor.execute("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username VARCHAR(50) NOT NULL UNIQUE,
                        email VARCHAR(100) NOT NULL UNIQUE,
                        password_hash VARCHAR(255) NOT NULL,
                        wallet_address VARCHAR(100) DEFAULT NULL,
                        ecc_public_key TEXT DEFAULT NULL,
                        ecc_private_key_encrypted TEXT DEFAULT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                cursor.execute("""
                    CREATE TABLE files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        owner_id INTEGER NOT NULL,
                        original_filename VARCHAR(255) NOT NULL,
                        stored_filename VARCHAR(255) NOT NULL UNIQUE,
                        file_size BIGINT NOT NULL,
                        mime_type VARCHAR(100) DEFAULT 'application/octet-stream',
                        encryption_algorithm VARCHAR(50) DEFAULT 'AES-256-GCM',
                        nonce VARCHAR(255) NOT NULL,
                        encrypted_key TEXT NOT NULL,
                        storage_path VARCHAR(255) NOT NULL,
                        sha256_hash CHAR(64) DEFAULT NULL,
                        ipfs_cid VARCHAR(100) DEFAULT NULL,
                        blockchain_recorded BOOLEAN DEFAULT 0,
                        blockchain_tx_hash VARCHAR(100) DEFAULT NULL,
                        status VARCHAR(50) DEFAULT 'encrypted',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
                    );
                """)
                cursor.execute("INSERT OR REPLACE INTO sqlite_sequence (name, seq) VALUES ('files', 5000);")
        finally:
            conn.close()

        # Register User A (Alice)
        cls.client.post('/api/auth/register', json={
            "username": "phase6_alice",
            "email": "alice_p6@example.com",
            "password": "Password123!"
        })
        login_a = cls.client.post('/api/auth/login', json={
            "email": "alice_p6@example.com",
            "password": "Password123!"
        }).get_json()
        cls.user_a_token = login_a["token"]
        cls.user_a_id = login_a["user"]["id"]

        # Register User B (Bob)
        cls.client.post('/api/auth/register', json={
            "username": "phase6_bob",
            "email": "bob_p6@example.com",
            "password": "Password123!"
        })
        login_b = cls.client.post('/api/auth/login', json={
            "email": "bob_p6@example.com",
            "password": "Password123!"
        }).get_json()
        cls.user_b_token = login_b["token"]
        cls.user_b_id = login_b["user"]["id"]

        # Check if local Hardhat node is running
        try:
            cls.blockchain_active = verify_blockchain_connection()["connected"]
        except Exception:
            cls.blockchain_active = False

    def test_01_web3_connection_and_signer_verification(self):
        """TEST A-F: Verify Web3 connection, Chain ID 31337, Contract bytecode, and Signer Owner match."""
        if not self.blockchain_active:
            self.skipTest("Local Hardhat node is not running on port 8545.")

        info = verify_blockchain_connection()
        self.assertTrue(info["connected"])
        self.assertEqual(info["chain_id"], 31337)
        self.assertIsNotNone(info["contract_address"])
        self.assertEqual(info["signer_address"].lower(), info["contract_owner"].lower())
        print(f"\n[PASS] TEST A-F: Web3 connected to Hardhat node. Contract owner: {info['contract_owner']}")

    def test_02_register_file_metadata_transaction(self):
        """TEST G-I: Register real metadata on Hardhat node, verify 32-byte transaction hash and getFile query."""
        if not self.blockchain_active:
            self.skipTest("Local Hardhat node is not running on port 8545.")

        test_file_id = 9001
        test_owner_id = "101"
        test_cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco"
        test_hash = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"

        res = register_file_metadata(test_file_id, test_owner_id, test_cid, test_hash)
        self.assertTrue(res["success"])

        if not res.get("already_registered"):
            self.assertTrue(res["transaction_hash"].startswith("0x"))
            self.assertEqual(len(res["transaction_hash"]), 66)

        # Retrieve on-chain metadata via getFile
        metadata = get_file_metadata(test_file_id)
        self.assertEqual(metadata["file_id"], test_file_id)
        self.assertEqual(metadata["owner_id"], test_owner_id)
        self.assertEqual(metadata["ipfs_cid"], test_cid)
        self.assertEqual(metadata["sha256_hash"].lower(), test_hash.lower())
        self.assertTrue(metadata["active"])
        self.assertGreater(metadata["timestamp"], 0)
        print("\n[PASS] TEST G-I: On-chain registration succeeded and getFile returned matching metadata.")

    def test_03_duplicate_registration_idempotency_and_mismatch(self):
        """TEST J-K: Identical metadata registration returns existing state; conflicting metadata reverts."""
        if not self.blockchain_active:
            self.skipTest("Local Hardhat node is not running on port 8545.")

        test_file_id = 9002
        test_owner_id = "102"
        test_cid = "QmCID11111111111111111111111111111111111111111"
        test_hash = "1" * 64

        # First registration
        res1 = register_file_metadata(test_file_id, test_owner_id, test_cid, test_hash)
        self.assertTrue(res1["success"])

        # Second registration with IDENTICAL metadata -> idempotent success
        res2 = register_file_metadata(test_file_id, test_owner_id, test_cid, test_hash)
        self.assertTrue(res2["success"])
        self.assertTrue(res2["already_registered"])

        # Third registration with CONFLICTING metadata -> raises BlockchainMetadataMismatchError
        with self.assertRaises(BlockchainMetadataMismatchError):
            register_file_metadata(test_file_id, test_owner_id, "QmDifferentCID", test_hash)

        print("\n[PASS] TEST J-K: Idempotent matching registration succeeded; conflicting metadata rejected.")

    @patch("app.services.file_service.add_bytes_to_ipfs")
    def test_04_full_file_upload_with_automatic_blockchain_registration(self, mock_ipfs):
        """TEST L-N: Upload file -> AES -> SHA-256 -> IPFS -> MySQL -> Blockchain registration & verification API."""
        mock_cid = "QmPhase6UploadTestCID1234567890123456789012"
        mock_ipfs.return_value = mock_cid

        file_content = b"Phase 6 Blockchain Application Integration Content"
        response = self.client.post(
            '/api/files/upload',
            headers={"Authorization": f"Bearer {self.user_a_token}"},
            data={'file': (io.BytesIO(file_content), 'blockchain_test.txt')},
            content_type='multipart/form-data'
        )

        self.assertEqual(response.status_code, 201)
        data = response.get_json()["file"]
        file_id = data["id"]

        self.assertEqual(data["ipfs_cid"], mock_cid)
        self.assertIsNotNone(data["sha256_hash"])

        if self.blockchain_active:
            self.assertTrue(data["blockchain_recorded"])
            self.assertIsNotNone(data["blockchain_tx_hash"])

            # Query GET /api/files/<file_id>/blockchain
            bc_res = self.client.get(
                f'/api/files/{file_id}/blockchain',
                headers={"Authorization": f"Bearer {self.user_a_token}"}
            )
            self.assertEqual(bc_res.status_code, 200)
            bc_data = bc_res.get_json()["blockchain"]
            self.assertTrue(bc_data["recorded"])
            self.assertTrue(bc_data["matches_database"])

            # Query GET /api/files/<file_id>/verify (with IPFS mock for 4-way check)
            with patch("app.services.file_service.get_bytes_from_ipfs") as mock_get_ipfs:
                master_key = Config.get_master_key_bytes()
                file_rec = get_file_record(file_id)
                file_key = unprotect_file_key(file_rec["encrypted_key"], master_key)
                nonce = base64.b64decode(file_rec["nonce"])
                ciphertext = encrypt_file_data(file_content, file_key, nonce)
                mock_get_ipfs.return_value = ciphertext

                ver_res = self.client.get(
                    f'/api/files/{file_id}/verify',
                    headers={"Authorization": f"Bearer {self.user_a_token}"}
                )
                self.assertEqual(ver_res.status_code, 200)
                ver_data = ver_res.get_json()
                self.assertTrue(ver_data["verified"])
                self.assertTrue(ver_data["checks"]["ipfs_content_integrity"])

        print("\n[PASS] TEST L-N: Full file upload automatically registered on blockchain and verified via API.")

    def test_05_non_owner_authorization_rejection(self):
        """TEST Q: User B attempting to access Alice's blockchain record receives HTTP 403 Forbidden."""
        # Create file for User A
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("""
                    INSERT INTO files (owner_id, original_filename, stored_filename, file_size, mime_type, nonce, encrypted_key, storage_path, sha256_hash, ipfs_cid, status)
                    VALUES (%s, 'alice_secret.txt', 'alice_secret.enc', 100, 'text/plain', 'nonce', 'key', 'ipfs://cid', %s, 'QmAliceCID', 'ipfs_stored')
                """, (self.user_a_id, "a" * 64))
                file_id = cursor.lastrowid
        finally:
            conn.close()

        # User B attempts to access Alice's blockchain endpoint
        res = self.client.get(
            f'/api/files/{file_id}/blockchain',
            headers={"Authorization": f"Bearer {self.user_b_token}"}
        )
        self.assertEqual(res.status_code, 403)

        # User B attempts to verify Alice's file
        res_v = self.client.get(
            f'/api/files/{file_id}/verify',
            headers={"Authorization": f"Bearer {self.user_b_token}"}
        )
        self.assertEqual(res_v.status_code, 403)

        print("\n[PASS] TEST Q: Non-owner access to blockchain endpoints rejected with HTTP 403 Forbidden.")

    @patch("app.services.file_service.register_file_metadata")
    def test_06_blockchain_unavailable_resilience(self, mock_bc_register):
        """TEST R: When blockchain node is offline, upload completes with blockchain_recorded = False (no crash)."""
        mock_bc_register.side_effect = BlockchainUnavailableError("Node offline")

        with patch("app.services.file_service.add_bytes_to_ipfs") as mock_ipfs:
            mock_ipfs.return_value = "QmOfflineTestCID1234567890"

            response = self.client.post(
                '/api/files/upload',
                headers={"Authorization": f"Bearer {self.user_a_token}"},
                data={'file': (io.BytesIO(b"Offline test data"), 'offline_test.txt')},
                content_type='multipart/form-data'
            )

            self.assertEqual(response.status_code, 201)
            data = response.get_json()["file"]
            self.assertFalse(data["blockchain_recorded"])
            self.assertIsNone(data["blockchain_tx_hash"])
            self.assertEqual(data["status"], "ipfs_stored")

        print("\n[PASS] TEST R: Upload handles offline blockchain gracefully without destroying IPFS file.")


import io
from app.services.file_service import get_file_record, unprotect_file_key

if __name__ == "__main__":
    unittest.main()
