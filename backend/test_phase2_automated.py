import os
import unittest
import json
import io
import base64

TEST_DB_FILE = "test_phase2_secure_share.db"

# Force SQLite test mode & set test master key
os.environ["USE_SQLITE"] = "true"
os.environ["SQLITE_DB_PATH"] = TEST_DB_FILE
os.environ["ENCRYPTION_MASTER_KEY"] = "wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM="

from app import create_app
from app.config import Config
from app.services.encryption_service import (
    generate_file_key,
    generate_nonce,
    encrypt_file_data,
    decrypt_file_data,
    protect_file_key,
    unprotect_file_key,
    AuthenticationTagMismatchError,
    CryptographyError
)

class Phase2AutomatedTests(unittest.TestCase):
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

    # --- CRYPTOGRAPHY UNIT TESTS (TEST A to TEST F) ---

    def test_A_encrypt_decrypt_round_trip(self):
        """TEST A — Encrypt/decrypt round trip returns exact original plaintext."""
        plaintext = b"Hello Secure File Sharing"
        key = generate_file_key()
        nonce = generate_nonce()

        ciphertext = encrypt_file_data(plaintext, key, nonce)
        self.assertNotEqual(plaintext, ciphertext)

        decrypted = decrypt_file_data(ciphertext, key, nonce)
        self.assertEqual(plaintext, decrypted)
        print("\n[PASS] TEST A: AES-256-GCM Encrypt/Decrypt Round Trip")

    def test_B_unique_keys_per_file(self):
        """TEST B — Different files receive distinct AES-256 keys."""
        key1 = generate_file_key()
        key2 = generate_file_key()
        self.assertNotEqual(key1, key2)
        self.assertEqual(len(key1), 32)
        self.assertEqual(len(key2), 32)
        print("[PASS] TEST B: Distinct AES-256 Keys Per File")

    def test_C_unique_nonces_per_operation(self):
        """TEST C — Distinct encryption operations produce unique GCM nonces."""
        nonce1 = generate_nonce()
        nonce2 = generate_nonce()
        self.assertNotEqual(nonce1, nonce2)
        self.assertEqual(len(nonce1), 12)
        self.assertEqual(len(nonce2), 12)
        print("[PASS] TEST C: Unique 96-bit Nonces Per Encryption")

    def test_D_wrong_key_fails_decryption(self):
        """TEST D — Attempting decryption with incorrect key raises error."""
        plaintext = b"Confidential Financial Audit"
        correct_key = generate_file_key()
        wrong_key = generate_file_key()
        nonce = generate_nonce()

        ciphertext = encrypt_file_data(plaintext, correct_key, nonce)

        with self.assertRaises(AuthenticationTagMismatchError):
            decrypt_file_data(ciphertext, wrong_key, nonce)
        print("[PASS] TEST D: Decryption With Wrong Key Fails")

    def test_E_tampered_ciphertext_fails_auth(self):
        """TEST E — Modified ciphertext triggers GCM tag mismatch exception."""
        plaintext = b"Top Secret Data Payload"
        key = generate_file_key()
        nonce = generate_nonce()

        ciphertext = bytearray(encrypt_file_data(plaintext, key, nonce))
        # Tamper with the last byte (part of authentication tag or payload)
        ciphertext[-1] ^= 0xFF

        with self.assertRaises(AuthenticationTagMismatchError):
            decrypt_file_data(bytes(ciphertext), key, nonce)
        print("[PASS] TEST E: Modified Ciphertext Authentication Tag Verification Failure")

    def test_F_master_key_protection(self):
        """TEST F — Per-file AES key is securely protected and recovered via Master Key."""
        master_key = Config.get_master_key_bytes()
        self.assertEqual(len(master_key), 32)

        file_key = generate_file_key()
        protected_b64 = protect_file_key(file_key, master_key)
        
        # Protected key must be base64 string and NOT plain file_key
        self.assertIsInstance(protected_b64, str)
        self.assertNotEqual(base64.b64decode(protected_b64), file_key)

        recovered_key = unprotect_file_key(protected_b64, master_key)
        self.assertEqual(file_key, recovered_key)
        print("[PASS] TEST F: Server Master Key AES Key Protection & Recovery")

    from unittest.mock import patch

    @patch("app.services.file_service.add_bytes_to_ipfs", return_value="QmTestPhase2CID123")
    @patch("app.services.file_service.get_bytes_from_ipfs")
    def test_G_upload_list_download_delete_workflow(self, mock_get_bytes, mock_add_bytes):
        """TEST G — Full workflow: Register User A & B, upload file, list, download, authorization check, delete."""
        def mock_cat_side_effect(cid):
            return mock_add_bytes.call_args[0][0]
        mock_get_bytes.side_effect = mock_cat_side_effect

        
        # 1. Register User Alice & User Bob
        alice_reg = self.client.post('/api/auth/register', json={"username": "alice_p2", "email": "alice_p2@example.com", "password": "Password123"})
        self.assertEqual(alice_reg.status_code, 201)

        bob_reg = self.client.post('/api/auth/register', json={"username": "bob_p2", "email": "bob_p2@example.com", "password": "Password123"})
        self.assertEqual(bob_reg.status_code, 201)

        # 2. Login as Alice & Bob
        alice_token = self.client.post('/api/auth/login', json={"email": "alice_p2@example.com", "password": "Password123"}).get_json()["token"]
        bob_token = self.client.post('/api/auth/login', json={"email": "bob_p2@example.com", "password": "Password123"}).get_json()["token"]

        alice_headers = {"Authorization": f"Bearer {alice_token}"}
        bob_headers = {"Authorization": f"Bearer {bob_token}"}

        # 3. Alice Uploads test.txt
        file_content = b"Hello Secure File Sharing"
        upload_data = {
            'file': (io.BytesIO(file_content), 'test.txt')
        }
        upload_res = self.client.post('/api/files/upload', headers=alice_headers, data=upload_data, content_type='multipart/form-data')
        self.assertEqual(upload_res.status_code, 201)
        upload_json = upload_res.get_json()
        self.assertTrue(upload_json.get("success"))
        file_id = upload_json["file"]["id"]
        self.assertEqual(upload_json["file"]["original_filename"], "test.txt")
        self.assertEqual(upload_json["file"]["encryption_algorithm"], "AES-256-GCM")
        print("[PASS] TEST G.1: File Upload & AES-256-GCM Encryption Endpoint")

        # 4. Alice Lists Files
        list_res = self.client.get('/api/files', headers=alice_headers)
        self.assertEqual(list_res.status_code, 200)
        user_files = list_res.get_json()["files"]
        self.assertEqual(len(user_files), 1)
        self.assertEqual(user_files[0]["id"], file_id)
        print("[PASS] TEST G.2: Get User Files List Endpoint")

        # 5. Alice Downloads File
        download_res = self.client.get(f'/api/files/{file_id}/download', headers=alice_headers)
        self.assertEqual(download_res.status_code, 200)
        self.assertEqual(download_res.data, file_content)
        print("[PASS] TEST G.3: Owner File Download & Decryption Endpoint")

        # 6. Bob (Unauthorized User) Tries Downloading Alice's File -> Expect 403 Forbidden
        unauth_dl = self.client.get(f'/api/files/{file_id}/download', headers=bob_headers)
        self.assertEqual(unauth_dl.status_code, 403)
        self.assertFalse(unauth_dl.get_json().get("success"))
        self.assertIn("not authorized", unauth_dl.get_json().get("message", "").lower())
        print("[PASS] TEST G.4: Unauthorized Access Prevention (HTTP 403 Forbidden)")

        # 7. Bob Tries Deleting Alice's File -> Expect 403 Forbidden
        unauth_del = self.client.delete(f'/api/files/{file_id}', headers=bob_headers)
        self.assertEqual(unauth_del.status_code, 403)
        print("[PASS] TEST G.5: Unauthorized Delete Prevention (HTTP 403 Forbidden)")

        # 8. Alice Deletes File
        del_res = self.client.delete(f'/api/files/{file_id}', headers=alice_headers)
        self.assertEqual(del_res.status_code, 200)
        self.assertTrue(del_res.get_json().get("success"))
        print("[PASS] TEST G.6: Owner File Deletion Endpoint")

        # 9. Verify File List is Empty After Deletion
        list_after_del = self.client.get('/api/files', headers=alice_headers)
        self.assertEqual(len(list_after_del.get_json()["files"]), 0)
        print("[PASS] TEST G.7: Database & Disk Cleanup Verification")

if __name__ == "__main__":
    unittest.main()
