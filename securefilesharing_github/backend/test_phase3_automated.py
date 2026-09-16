import os
import unittest
import json
import io
import hashlib
from unittest.mock import patch

TEST_DB_FILE = "test_phase3_secure_share.db"

# Force SQLite test mode & master key env setup
os.environ["USE_SQLITE"] = "true"
os.environ["SQLITE_DB_PATH"] = TEST_DB_FILE
os.environ["ENCRYPTION_MASTER_KEY"] = "wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM="

from app import create_app
from app.db import get_db_connection
from app.services.integrity_service import (
    calculate_bytes_sha256,
    calculate_file_sha256,
    verify_file_integrity,
    FileIntegrityError
)
from app.services.file_service import get_file_record, update_file_sha256_hash

class Phase3AutomatedTests(unittest.TestCase):
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
        
        # Patch IPFS services for Phase 3 test isolation
        self.ipfs_add_patcher = patch("app.services.file_service.add_bytes_to_ipfs", return_value="QmTestPhase3CID")
        self.mock_ipfs_add = self.ipfs_add_patcher.start()

        self.ipfs_get_patcher = patch("app.services.file_service.get_bytes_from_ipfs")
        self.mock_ipfs_get = self.ipfs_get_patcher.start()
        
        # Default mock IPFS return current uploaded ciphertext
        def mock_cat_side_effect(cid):
            if hasattr(self, '_last_tampered_ciphertext'):
                return self._last_tampered_ciphertext
            return self.mock_ipfs_add.call_args[0][0]
        self.mock_ipfs_get.side_effect = mock_cat_side_effect

    def tearDown(self):
        self.ipfs_add_patcher.stop()
        self.ipfs_get_patcher.stop()
        if hasattr(self, '_last_tampered_ciphertext'):
            delattr(self, '_last_tampered_ciphertext')

    # --- INTEGRITY UNIT TESTS (TEST A to TEST C) ---

    def test_A_sha256_known_value(self):
        """TEST A — SHA-256 calculation matches standard known value ('hello')."""
        input_data = b"hello"
        expected = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        actual = calculate_bytes_sha256(input_data)
        self.assertEqual(actual, expected)
        print("\n[PASS] TEST A: SHA-256 Known Value Matching ('hello')")

    def test_B_same_content_same_hash(self):
        """TEST B — Same content produces identical SHA-256 hash."""
        data = b"Hello Secure File Sharing"
        hash1 = calculate_bytes_sha256(data)
        hash2 = calculate_bytes_sha256(data)
        self.assertEqual(hash1, hash2)
        print("[PASS] TEST B: Deterministic SHA-256 Consistency (hash1 == hash2)")

    def test_C_different_content_different_hash(self):
        """TEST C — Distinct content produces different SHA-256 hashes."""
        data1 = b"Hello Secure File Sharing"
        data2 = b"Hello Secure File Sharing!"
        hash1 = calculate_bytes_sha256(data1)
        hash2 = calculate_bytes_sha256(data2)
        self.assertNotEqual(hash1, hash2)
        print("[PASS] TEST C: Distinct Content SHA-256 Hash Difference (hash1 != hash2)")

    # --- INTEGRATION & SECURITY TESTS (TEST D to TEST J) ---

    def test_D_upload_stores_sha256_hash(self):
        """TEST D — File upload calculates and stores 64-char hex SHA-256 digest in files table."""
        # 1. Register & Login User Alice
        reg = self.client.post('/api/auth/register', json={"username": "alice_p3d", "email": "alice_p3d@example.com", "password": "Password123"})
        token = self.client.post('/api/auth/login', json={"email": "alice_p3d@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Upload file
        upload_data = {'file': (io.BytesIO(b"Integrity Test Payload"), 'integrity_doc.txt')}
        res = self.client.post('/api/files/upload', headers=headers, data=upload_data, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 201)
        file_id = res.get_json()["file"]["id"]

        # 3. Verify DB record contains 64-char sha256_hash
        file_rec = get_file_record(file_id)
        sha256_hash = file_rec.get("sha256_hash")
        self.assertIsNotNone(sha256_hash)
        self.assertEqual(len(sha256_hash), 64)
        print("[PASS] TEST D: File Upload SHA-256 Storage & Record Match")

    def test_E_valid_hash_allows_download(self):
        """TEST E — Untampered file download succeeds when SHA-256 integrity verification passes."""
        token = self.client.post('/api/auth/login', json={"email": "alice_p3d@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Upload file
        content = b"Authentic Untampered Document Content"
        upload_res = self.client.post('/api/files/upload', headers=headers, data={'file': (io.BytesIO(content), 'clean.txt')}, content_type='multipart/form-data')
        file_id = upload_res.get_json()["file"]["id"]

        # Download file
        dl_res = self.client.get(f'/api/files/{file_id}/download', headers=headers)
        self.assertEqual(dl_res.status_code, 200)
        self.assertEqual(dl_res.data, content)
        print("[PASS] TEST E: Untampered File SHA-256 Integrity Pass & Download")

    def test_F_modified_encrypted_file_rejected(self):
        """TEST F — Modified encrypted bytes fail SHA-256 verification and return HTTP 409 Conflict."""
        token = self.client.post('/api/auth/login', json={"email": "alice_p3d@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Upload file
        content = b"Top Secret Financial Report"
        upload_res = self.client.post('/api/files/upload', headers=headers, data={'file': (io.BytesIO(content), 'secret.txt')}, content_type='multipart/form-data')
        file_id = upload_res.get_json()["file"]["id"]

        # Tamper 1 byte of encrypted file payload
        b = bytearray(self.mock_ipfs_add.call_args[0][0])
        b[0] ^= 0xFF
        self._last_tampered_ciphertext = bytes(b)

        # Attempt download -> Must fail prior to decryption with HTTP 409 Conflict
        dl_res = self.client.get(f'/api/files/{file_id}/download', headers=headers)
        self.assertEqual(dl_res.status_code, 409)
        self.assertFalse(dl_res.get_json().get("success"))
        self.assertIn("integrity verification failed", dl_res.get_json().get("message", "").lower())
        print("[PASS] TEST F: Tampered Encrypted Data Rejection (HTTP 409 Conflict)")

    def test_G_database_hash_mismatch_rejected(self):
        """TEST G — Database hash mismatch fails integrity check and returns HTTP 409 Conflict."""
        token = self.client.post('/api/auth/login', json={"email": "alice_p3d@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Upload file
        content = b"Valid Payload Data"
        upload_res = self.client.post('/api/files/upload', headers=headers, data={'file': (io.BytesIO(content), 'valid.txt')}, content_type='multipart/form-data')
        file_id = upload_res.get_json()["file"]["id"]

        # Corrupt DB sha256_hash to a fake 64-char hex value
        fake_hash = "0" * 64
        update_file_sha256_hash(file_id, fake_hash)

        # Attempt download -> Must fail with HTTP 409 Conflict
        dl_res = self.client.get(f'/api/files/{file_id}/download', headers=headers)
        self.assertEqual(dl_res.status_code, 409)
        self.assertIn("integrity verification failed", dl_res.get_json().get("message", "").lower())
        print("[PASS] TEST G: Database Hash Mismatch Rejection (HTTP 409 Conflict)")

    def test_H_missing_hash_rejected(self):
        """TEST H — File with missing hash (sha256_hash = NULL) fails verification with HTTP 409 Conflict."""
        token = self.client.post('/api/auth/login', json={"email": "alice_p3d@example.com", "password": "Password123"}).get_json()["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Upload file
        content = b"File With Missing Integrity Record"
        upload_res = self.client.post('/api/files/upload', headers=headers, data={'file': (io.BytesIO(content), 'null_hash.txt')}, content_type='multipart/form-data')
        file_id = upload_res.get_json()["file"]["id"]

        # Set DB sha256_hash to NULL
        update_file_sha256_hash(file_id, None)

        # Attempt download -> Must fail with HTTP 409 Conflict
        dl_res = self.client.get(f'/api/files/{file_id}/download', headers=headers)
        self.assertEqual(dl_res.status_code, 409)
        self.assertIn("integrity", dl_res.get_json().get("message", "").lower())
        print("[PASS] TEST H: Missing Integrity Hash Rejection (HTTP 409 Conflict)")

    def test_I_ownership_still_enforced(self):
        """TEST J — Ownership authorization is strictly enforced before integrity check (HTTP 403 for User B)."""
        # Register User Bob
        self.client.post('/api/auth/register', json={"username": "bob_p3j", "email": "bob_p3j@example.com", "password": "Password123"})
        bob_token = self.client.post('/api/auth/login', json={"email": "bob_p3j@example.com", "password": "Password123"}).get_json()["token"]
        bob_headers = {"Authorization": f"Bearer {bob_token}"}

        # Get Alice's valid file
        alice_token = self.client.post('/api/auth/login', json={"email": "alice_p3d@example.com", "password": "Password123"}).get_json()["token"]
        alice_headers = {"Authorization": f"Bearer {alice_token}"}
        upload_res = self.client.post('/api/files/upload', headers=alice_headers, data={'file': (io.BytesIO(b"Alice Private Data"), 'alice_private.txt')}, content_type='multipart/form-data')
        file_id = upload_res.get_json()["file"]["id"]

        # Bob attempts access -> Must return HTTP 403 Forbidden (Ownership check precedes integrity check)
        bob_res = self.client.get(f'/api/files/{file_id}/download', headers=bob_headers)
        self.assertEqual(bob_res.status_code, 403)
        self.assertIn("not authorized", bob_res.get_json().get("message", "").lower())
        print("[PASS] TEST J: Ownership Check Precedence (HTTP 403 Forbidden for Non-Owner)")

if __name__ == "__main__":
    unittest.main()
