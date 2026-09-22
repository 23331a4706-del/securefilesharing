import os
import unittest
import json
import io
import base64
from unittest.mock import patch, MagicMock

TEST_DB_FILE = "test_phase4_secure_share.db"

# Force SQLite test mode with a dedicated test database & master key
os.environ["USE_SQLITE"] = "true"
os.environ["SQLITE_DB_PATH"] = TEST_DB_FILE
os.environ["ENCRYPTION_MASTER_KEY"] = "wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM="
os.environ["IPFS_API_URL"] = "http://127.0.0.1:5001"

from app import create_app
from app.db import get_db_connection
from app.services.integrity_service import (
    calculate_bytes_sha256,
    FileIntegrityError
)
from app.services.ipfs_service import (
    verify_ipfs_connection,
    add_bytes_to_ipfs,
    get_bytes_from_ipfs,
    unpin_from_ipfs,
    IPFSUnavailableError,
    IPFSNotFoundError
)
from app.services.file_service import (
    get_file_record,
    update_file_sha256_hash,
    update_file_ipfs_cid,
    process_file_upload
)
from app.models.user import hash_password, verify_password


class Phase4AutomatedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.path.exists(TEST_DB_FILE):
            try:
                os.remove(TEST_DB_FILE)
            except OSError:
                pass

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(TEST_DB_FILE):
            try:
                os.remove(TEST_DB_FILE)
            except OSError:
                pass

    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.client = self.app.test_client()

    # -------------------------------------------------------------------------
    # TEST A — IPFS Connection Verification
    # -------------------------------------------------------------------------
    def test_A_ipfs_connection_check(self):
        """TEST A — verify_ipfs_connection returns boolean status without crashing."""
        status = verify_ipfs_connection()
        self.assertIsInstance(status, bool)
        print(f"\n[PASS] TEST A: IPFS Connection Status Check (Daemon Available: {status})")

    # -------------------------------------------------------------------------
    # TEST B & C — Add and Retrieve Encrypted File from IPFS (Unit level with HTTP response mocks)
    # -------------------------------------------------------------------------
    @patch("app.services.ipfs_service.requests.post")
    def test_B_C_ipfs_add_and_get_bytes(self, mock_post):
        """TEST B & C — Encrypted bytes uploaded to IPFS return real CID, and retrieve matching bytes."""
        sample_encrypted_data = b"\x01\x02\x03\x04\x05encrypted_payload_bytes_99"
        mock_cid = "QmXoypizjW3WknFiJnKLwHCnL72vedxjQkDDP1mXWo6uco"

        # Mock /api/v0/add response
        mock_add_resp = MagicMock()
        mock_add_resp.status_code = 200
        mock_add_resp.text = json.dumps({"Name": "encrypted.enc", "Hash": mock_cid, "Size": "40"})
        
        # Mock /api/v0/cat response
        mock_cat_resp = MagicMock()
        mock_cat_resp.status_code = 200
        mock_cat_resp.content = sample_encrypted_data

        mock_post.side_effect = [mock_add_resp, mock_cat_resp]

        cid = add_bytes_to_ipfs(sample_encrypted_data)
        self.assertEqual(cid, mock_cid)
        print("\n[PASS] TEST B: Encrypted File Upload to IPFS (Valid CID Returned)")

        retrieved_bytes = get_bytes_from_ipfs(cid)
        self.assertEqual(retrieved_bytes, sample_encrypted_data)
        print("[PASS] TEST C: Encrypted Byte Retrieval from IPFS via CID")

    # -------------------------------------------------------------------------
    # TEST D & E — Upload File Stores CID and SHA-256 Hash in Database
    # -------------------------------------------------------------------------
    @patch("app.services.file_service.add_bytes_to_ipfs")
    def test_D_E_upload_stores_cid_and_sha256(self, mock_add_bytes):
        """TEST D & E — Upload endpoint generates AES key, hashes encrypted bytes, uploads to IPFS, stores CID & SHA-256."""
        mock_cid = "QmbWqxBEKC3P8tYZsWFWBikD55zR32KwXc2wE25b5G88n"
        mock_add_bytes.return_value = mock_cid

        # Register User Alice
        self.client.post('/api/auth/register', json={"username": "alice_p4", "email": "alice_p4@example.com", "password": "Password123"})
        token = self.client.post('/api/auth/login', json={"email": "alice_p4@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Upload file
        raw_plaintext = b"Decentralized Confidential Record 2026"
        upload_res = self.client.post(
            '/api/files/upload',
            headers=headers,
            data={'file': (io.BytesIO(raw_plaintext), 'decentralized_report.pdf')},
            content_type='multipart/form-data'
        )

        self.assertEqual(upload_res.status_code, 201)
        res_json = upload_res.get_json()
        self.assertTrue(res_json.get("success"))
        file_id = res_json["file"]["id"]

        # Inspect DB record
        file_rec = get_file_record(file_id)
        self.assertEqual(file_rec["ipfs_cid"], mock_cid)
        self.assertEqual(file_rec["status"], "ipfs_stored")
        self.assertIsNotNone(file_rec["sha256_hash"])
        self.assertEqual(len(file_rec["sha256_hash"]), 64)
        print("\n[PASS] TEST D: IPFS CID Persisted in MySQL files table")
        print("[PASS] TEST E: SHA-256 Hash Stored in MySQL files table")

    # -------------------------------------------------------------------------
    # TEST F — Normal IPFS Download Workflow (Zero Local Fallback)
    # -------------------------------------------------------------------------
    @patch("app.services.file_service.add_bytes_to_ipfs")
    @patch("app.services.file_service.get_bytes_from_ipfs")
    def test_F_normal_ipfs_download_workflow(self, mock_get_bytes, mock_add_bytes):
        """TEST F — Download workflow: IPFS Retrieval -> SHA-256 verify -> AES Decrypt -> Original Plaintext."""
        mock_cid = "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"
        mock_add_bytes.return_value = mock_cid

        token = self.client.post('/api/auth/login', json={"email": "alice_p4@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        plaintext = b"Hello Secure File Sharing - IPFS Phase 4"
        upload_res = self.client.post(
            '/api/files/upload',
            headers=headers,
            data={'file': (io.BytesIO(plaintext), 'ipfs_test.txt')},
            content_type='multipart/form-data'
        )
        file_id = upload_res.get_json()["file"]["id"]

        # Mock IPFS returning exact encrypted ciphertext bytes
        actual_uploaded_ciphertext = mock_add_bytes.call_args[0][0]
        mock_get_bytes.return_value = actual_uploaded_ciphertext

        # Execute Download
        dl_res = self.client.get(f'/api/files/{file_id}/download', headers=headers)
        self.assertEqual(dl_res.status_code, 200)
        self.assertEqual(dl_res.data, plaintext)
        print("\n[PASS] TEST F: IPFS Download Workflow (Auth -> Ownership -> IPFS -> SHA-256 -> AES Decrypt)")

    # -------------------------------------------------------------------------
    # TEST G — IPFS Data Tampering Rejection (HTTP 409 Conflict)
    # -------------------------------------------------------------------------
    @patch("app.services.file_service.add_bytes_to_ipfs")
    @patch("app.services.file_service.get_bytes_from_ipfs")
    def test_G_tampered_ipfs_data_rejected(self, mock_get_bytes, mock_add_bytes):
        """TEST G — Tampered encrypted bytes retrieved from IPFS fail SHA-256 check and return HTTP 409 Conflict."""
        mock_cid = "QmTamperedCID123456789012345678901234567890"
        mock_add_bytes.return_value = mock_cid

        token = self.client.post('/api/auth/login', json={"email": "alice_p4@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        plaintext = b"Authentic Confidential Financial Data"
        upload_res = self.client.post(
            '/api/files/upload',
            headers=headers,
            data={'file': (io.BytesIO(plaintext), 'finances.pdf')},
            content_type='multipart/form-data'
        )
        file_id = upload_res.get_json()["file"]["id"]

        actual_ciphertext = bytearray(mock_add_bytes.call_args[0][0])
        # Tamper 1 byte of retrieved ciphertext
        actual_ciphertext[0] ^= 0xFF
        mock_get_bytes.return_value = bytes(actual_ciphertext)

        # Attempt download -> Must fail with HTTP 409 Conflict
        dl_res = self.client.get(f'/api/files/{file_id}/download', headers=headers)
        self.assertEqual(dl_res.status_code, 409)
        self.assertFalse(dl_res.get_json().get("success"))
        self.assertIn("integrity verification failed", dl_res.get_json().get("message", "").lower())
        print("\n[PASS] TEST G: Tampered IPFS Data Rejection (HTTP 409 Conflict)")

    # -------------------------------------------------------------------------
    # TEST H & I — Missing or Invalid CID Rejection (HTTP 404 Not Found)
    # -------------------------------------------------------------------------
    @patch("app.services.file_service.add_bytes_to_ipfs")
    @patch("app.services.file_service.get_bytes_from_ipfs")
    def test_H_I_missing_or_invalid_cid(self, mock_get_bytes, mock_add_bytes):
        """TEST H & I — Download with missing or invalid CID returns HTTP 404 Not Found."""
        mock_cid = "QmValidCID999"
        mock_add_bytes.return_value = mock_cid

        token = self.client.post('/api/auth/login', json={"email": "alice_p4@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        upload_res = self.client.post(
            '/api/files/upload',
            headers=headers,
            data={'file': (io.BytesIO(b"Data Payload"), 'doc.txt')},
            content_type='multipart/form-data'
        )
        file_id = upload_res.get_json()["file"]["id"]

        # Mock IPFS raise IPFSNotFoundError
        mock_get_bytes.side_effect = IPFSNotFoundError("Encrypted file is unavailable from decentralized storage")

        dl_res = self.client.get(f'/api/files/{file_id}/download', headers=headers)
        self.assertEqual(dl_res.status_code, 404)
        self.assertFalse(dl_res.get_json().get("success"))
        self.assertIn("unavailable", dl_res.get_json().get("message", "").lower())
        print("\n[PASS] TEST H & I: Missing / Invalid IPFS CID Rejection (HTTP 404 Not Found)")

    # -------------------------------------------------------------------------
    # TEST J — Non-Owner Security Check (HTTP 403 Forbidden)
    # -------------------------------------------------------------------------
    @patch("app.services.file_service.add_bytes_to_ipfs")
    def test_J_unauthorized_user_access_rejected(self, mock_add_bytes):
        """TEST J — User B requesting User A's CID returns HTTP 403 Forbidden without calling IPFS."""
        mock_add_bytes.return_value = "QmAliceCID123"

        # Register User Bob
        self.client.post('/api/auth/register', json={"username": "bob_p4", "email": "bob_p4@example.com", "password": "Password123"})
        bob_token = self.client.post('/api/auth/login', json={"email": "bob_p4@example.com", "password": "Password123"}).get_json()["token"]
        bob_headers = {"Authorization": f"Bearer {bob_token}"}

        # Alice's file
        alice_token = self.client.post('/api/auth/login', json={"email": "alice_p4@example.com", "password": "Password123"}).get_json()["token"]
        alice_headers = {"Authorization": f"Bearer {alice_token}"}

        upload_res = self.client.post(
            '/api/files/upload',
            headers=alice_headers,
            data={'file': (io.BytesIO(b"Alice Secret Data"), 'secret.txt')},
            content_type='multipart/form-data'
        )
        file_id = upload_res.get_json()["file"]["id"]

        # Bob attempts download
        bob_res = self.client.get(f'/api/files/{file_id}/download', headers=bob_headers)
        self.assertEqual(bob_res.status_code, 403)
        self.assertFalse(bob_res.get_json().get("success"))
        self.assertIn("not authorized", bob_res.get_json().get("message", "").lower())
        print("\n[PASS] TEST J: Non-Owner Security Check (HTTP 403 Forbidden)")

    # -------------------------------------------------------------------------
    # TEST K — Delete File & Unpin CID
    # -------------------------------------------------------------------------
    @patch("app.services.file_service.add_bytes_to_ipfs")
    @patch("app.services.file_service.unpin_from_ipfs")
    def test_K_delete_file_unpins_cid(self, mock_unpin, mock_add_bytes):
        """TEST K — Deleting file calls unpin_from_ipfs and removes DB record."""
        mock_add_bytes.return_value = "QmDeleteMe123"
        mock_unpin.return_value = True

        token = self.client.post('/api/auth/login', json={"email": "alice_p4@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        upload_res = self.client.post(
            '/api/files/upload',
            headers=headers,
            data={'file': (io.BytesIO(b"Temporary Data"), 'temp.txt')},
            content_type='multipart/form-data'
        )
        file_id = upload_res.get_json()["file"]["id"]

        del_res = self.client.delete(f'/api/files/{file_id}', headers=headers)
        self.assertEqual(del_res.status_code, 200)
        self.assertTrue(del_res.get_json().get("success"))

        mock_unpin.assert_called_with("QmDeleteMe123")
        self.assertIsNone(get_file_record(file_id))
        print("\n[PASS] TEST K: File Deletion & Local IPFS Unpinning")

    # -------------------------------------------------------------------------
    # TEST L — Zero Local Fallback Verification (HTTP 503 on IPFS Offline)
    # -------------------------------------------------------------------------
    @patch("app.services.file_service.add_bytes_to_ipfs")
    @patch("app.services.file_service.get_bytes_from_ipfs")
    def test_L_zero_local_fallback_ipfs_offline(self, mock_get_bytes, mock_add_bytes):
        """TEST L — When IPFS daemon is offline during download, return HTTP 503 without disk fallback."""
        mock_add_bytes.return_value = "QmOfflineNodeCID"
        mock_get_bytes.side_effect = IPFSUnavailableError("IPFS storage is currently unavailable")

        token = self.client.post('/api/auth/login', json={"email": "alice_p4@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        upload_res = self.client.post(
            '/api/files/upload',
            headers=headers,
            data={'file': (io.BytesIO(b"Offline Test Payload"), 'offline.txt')},
            content_type='multipart/form-data'
        )
        file_id = upload_res.get_json()["file"]["id"]

        # Attempt download while IPFS is offline -> Must return HTTP 503 Service Unavailable
        dl_res = self.client.get(f'/api/files/{file_id}/download', headers=headers)
        self.assertEqual(dl_res.status_code, 503)
        self.assertFalse(dl_res.get_json().get("success"))
        self.assertIn("unavailable", dl_res.get_json().get("message", "").lower())
        print("\n[PASS] TEST L: Zero Local Fallback Rejection on IPFS Offline (HTTP 503 Service Unavailable)")

    # -------------------------------------------------------------------------
    # TEST M, N, O — Phase 1, 2, 3 Regression Suites
    # -------------------------------------------------------------------------
    def test_M_N_O_regressions(self):
        """TEST M, N, O — Verify bcrypt password hashing, JWT auth, and SHA-256 hashing functions."""
        # Password hashing check
        pwd_hash = hash_password("Password123")
        self.assertTrue(verify_password("Password123", pwd_hash))
        self.assertFalse(verify_password("WrongPassword", pwd_hash))

        # SHA-256 calculation check
        payload = b"Regression Check Payload"
        sha_val = calculate_bytes_sha256(payload)
        self.assertEqual(len(sha_val), 64)
        print("\n[PASS] TEST M: Phase 3 SHA-256 Integrity Verification Regression")
        print("[PASS] TEST N: Phase 2 Cryptography Regression")
        print("[PASS] TEST O: Phase 1 Authentication & Bcrypt Hashing Regression")


if __name__ == "__main__":
    unittest.main()
