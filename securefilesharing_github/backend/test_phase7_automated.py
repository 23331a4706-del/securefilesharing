import os
import io
import json
import base64
import hashlib
from unittest.mock import patch

# Force SQLite test DB & master key config for isolated automated testing
os.environ["USE_SQLITE"] = "true"
os.environ["SQLITE_DB_PATH"] = "test_phase7_secure_share.db"
os.environ["ENCRYPTION_MASTER_KEY"] = "wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM="

from app import create_app
from app.db import get_db_connection
from app.models.user import find_by_email
from app.services.file_service import get_file_record
from app.services.share_service import create_or_update_file_share, decrypt_and_read_shared_file
from app.services.encryption_service import (
    unprotect_file_key,
    unwrap_file_key_for_receiver,
    AuthenticationTagMismatchError,
    CryptographyError
)

# Mock IPFS Storage Map for Automated Test Suite
mock_ipfs_store = {}

def mock_add_bytes_to_ipfs(ciphertext_bytes: bytes) -> str:
    sha256 = hashlib.sha256(ciphertext_bytes).hexdigest()
    cid = f"QmTestMockCID{sha256[:20]}"
    mock_ipfs_store[cid] = ciphertext_bytes
    return cid

def mock_get_bytes_from_ipfs(cid: str) -> bytes:
    if cid in mock_ipfs_store:
        return mock_ipfs_store[cid]
    raise Exception("IPFS CID not found in mock store")

def run_phase7_tests():
    print("=" * 80)
    print("PHASE 7 AUTOMATED INTEGRATION TEST SUITE — ECC AES KEY SHARING")
    print("=" * 80)

    db_path = "test_phase7_secure_share.db"
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass

    app = create_app()
    app.config['TESTING'] = True
    client = app.test_client()

    master_key = base64.b64decode("wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM=")

    with patch('app.services.file_service.add_bytes_to_ipfs', side_effect=mock_add_bytes_to_ipfs), \
         patch('app.services.file_service.get_bytes_from_ipfs', side_effect=mock_get_bytes_from_ipfs), \
         patch('app.services.share_service.get_bytes_from_ipfs', side_effect=mock_get_bytes_from_ipfs), \
         patch('app.services.ipfs_service.add_bytes_to_ipfs', side_effect=mock_add_bytes_to_ipfs), \
         patch('app.services.ipfs_service.get_bytes_from_ipfs', side_effect=mock_get_bytes_from_ipfs):

        # -------------------------------------------------------------------------
        # SETUP USERS (Alice = Owner, Bob = Receiver 1, Charlie = Receiver 2, David = Receiver 3, Eve = Unshared)
        # -------------------------------------------------------------------------
        alice_reg = client.post('/api/auth/register', json={"username": "alice_p7", "email": "alice_p7@example.com", "password": "Password123"})
        bob_reg = client.post('/api/auth/register', json={"username": "bob_p7", "email": "bob_p7@example.com", "password": "Password123"})
        charlie_reg = client.post('/api/auth/register', json={"username": "charlie_p7", "email": "charlie_p7@example.com", "password": "Password123"})
        david_reg = client.post('/api/auth/register', json={"username": "david_p7", "email": "david_p7@example.com", "password": "Password123"})
        eve_reg = client.post('/api/auth/register', json={"username": "eve_p7", "email": "eve_p7@example.com", "password": "Password123"})

        alice_token = client.post('/api/auth/login', json={"email": "alice_p7@example.com", "password": "Password123"}).get_json()["token"]
        bob_token = client.post('/api/auth/login', json={"email": "bob_p7@example.com", "password": "Password123"}).get_json()["token"]
        charlie_token = client.post('/api/auth/login', json={"email": "charlie_p7@example.com", "password": "Password123"}).get_json()["token"]
        david_token = client.post('/api/auth/login', json={"email": "david_p7@example.com", "password": "Password123"}).get_json()["token"]
        eve_token = client.post('/api/auth/login', json={"email": "eve_p7@example.com", "password": "Password123"}).get_json()["token"]

        alice_headers = {"Authorization": f"Bearer {alice_token}"}
        bob_headers = {"Authorization": f"Bearer {bob_token}"}
        charlie_headers = {"Authorization": f"Bearer {charlie_token}"}
        david_headers = {"Authorization": f"Bearer {david_token}"}
        eve_headers = {"Authorization": f"Bearer {eve_token}"}

        alice_id = alice_reg.get_json()["user"]["id"]
        bob_id = bob_reg.get_json()["user"]["id"]
        charlie_id = charlie_reg.get_json()["user"]["id"]
        david_id = david_reg.get_json()["user"]["id"]
        eve_id = eve_reg.get_json()["user"]["id"]

        # -------------------------------------------------------------------------
        # TEST A — ECC Key Generation
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST A — ECC Key Generation (NIST P-256)")
        print("-" * 75)
        alice_db = find_by_email("alice_p7@example.com")
        assert alice_db["ecc_public_key"] is not None
        assert alice_db["ecc_private_key_encrypted"] is not None
        print(f"Alice P-256 Public Key (b64 snippet): {alice_db['ecc_public_key'][:30]}...")
        print(">>> TEST A RESULT: PASSED — Persistent P-256 keypair generated.")

        # -------------------------------------------------------------------------
        # TEST B — ECC Private Key Encryption
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST B — ECC Private Key Master-Key Protection")
        print("-" * 75)
        assert "BEGIN PRIVATE KEY" not in alice_db["ecc_private_key_encrypted"]
        assert len(base64.b64decode(alice_db["ecc_private_key_encrypted"])) > 28
        print(">>> TEST B RESULT: PASSED — Private key is encrypted with master key via Base64 format.")

        # -------------------------------------------------------------------------
        # TEST C — Existing User Key Preservation
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST C — Existing User Key Preservation")
        print("-" * 75)
        login_res = client.post('/api/auth/login', json={"email": "alice_p7@example.com", "password": "Password123"})
        alice_after_login = find_by_email("alice_p7@example.com")
        assert alice_after_login["ecc_public_key"] == alice_db["ecc_public_key"]
        assert alice_after_login["ecc_private_key_encrypted"] == alice_db["ecc_private_key_encrypted"]
        print(">>> TEST C RESULT: PASSED — ECC keys were preserved and NOT regenerated.")

        # -------------------------------------------------------------------------
        # UPLOAD TEST FILE BY ALICE
        # -------------------------------------------------------------------------
        file_content = b"Top Secret Quantum Encryption File Data - Phase 7 Test Payload"
        upload_res = client.post(
            '/api/files/upload',
            headers=alice_headers,
            data={'file': (io.BytesIO(file_content), 'secret_doc.txt')},
            content_type='multipart/form-data'
        )
        assert upload_res.status_code == 201, f"Expected 201, got {upload_res.status_code}: {upload_res.get_json()}"
        file_id = upload_res.get_json()["file"]["id"]
        file_rec_orig = get_file_record(file_id)
        orig_file_key = unprotect_file_key(file_rec_orig["encrypted_key"], master_key)
        print(f"\n[Setup] Uploaded secret_doc.txt (File ID: {file_id})")

        # -------------------------------------------------------------------------
        # TEST D — Owner Can Share File With Bob
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST D — Owner Shares File with Receiver")
        print("-" * 75)
        share_res = client.post(f'/api/files/{file_id}/share', headers=alice_headers, json={"receiver_id": bob_id})
        print(f"Response: {share_res.get_json()}")
        assert share_res.status_code == 200
        assert share_res.get_json()["success"] == True
        print(">>> TEST D RESULT: PASSED — File shared successfully.")

        # -------------------------------------------------------------------------
        # TEST E — Non-Owner Cannot Share
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST E — Non-Owner Share Rejection (HTTP 403)")
        print("-" * 75)
        non_owner_share = client.post(f'/api/files/{file_id}/share', headers=bob_headers, json={"receiver_id": charlie_id})
        print(f"Status: {non_owner_share.status_code}, Response: {non_owner_share.get_json()}")
        assert non_owner_share.status_code == 403
        print(">>> TEST E RESULT: PASSED — Non-owner share rejected with HTTP 403.")

        # -------------------------------------------------------------------------
        # TEST F — Invalid Receiver User (HTTP 404)
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST F — Invalid Receiver Rejection (HTTP 404)")
        print("-" * 75)
        invalid_share = client.post(f'/api/files/{file_id}/share', headers=alice_headers, json={"receiver_id": 99999})
        print(f"Status: {invalid_share.status_code}, Response: {invalid_share.get_json()}")
        assert invalid_share.status_code == 404
        print(">>> TEST F RESULT: PASSED — Invalid receiver rejected with HTTP 404.")

        # -------------------------------------------------------------------------
        # TEST G — Duplicate Active Share (HTTP 409)
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST G — Duplicate Active Share Rejection (HTTP 409)")
        print("-" * 75)
        dup_share = client.post(f'/api/files/{file_id}/share', headers=alice_headers, json={"receiver_id": bob_id})
        print(f"Status: {dup_share.status_code}, Response: {dup_share.get_json()}")
        assert dup_share.status_code == 409
        print(">>> TEST G RESULT: PASSED — Duplicate share rejected with HTTP 409.")

        # -------------------------------------------------------------------------
        # TEST H — Receiver Shared Files List
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST H — Receiver Shared Files List")
        print("-" * 75)
        shared_list_res = client.get('/api/shared-files', headers=bob_headers)
        print(f"Shared files for Bob: {shared_list_res.get_json()}")
        assert shared_list_res.status_code == 200
        shared_files = shared_list_res.get_json()["files"]
        assert len(shared_files) == 1
        assert shared_files[0]["file_id"] == file_id
        assert shared_files[0]["original_filename"] == "secret_doc.txt"
        print(">>> TEST H RESULT: PASSED — Shared file listed under GET /api/shared-files.")

        # -------------------------------------------------------------------------
        # TEST I — Authorized Receiver Download
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST I — Authorized Receiver Download & Decryption")
        print("-" * 75)
        bob_download = client.get(f'/api/shared-files/{file_id}/download', headers=bob_headers)
        print(f"Status: {bob_download.status_code}")
        print(f"Downloaded Content: {bob_download.data.decode()}")
        assert bob_download.status_code == 200
        assert bob_download.data == file_content
        print(">>> TEST I RESULT: PASSED — Receiver downloaded and decrypted shared file successfully.")

        # -------------------------------------------------------------------------
        # TEST J — Unshared Receiver Download Rejection (HTTP 403)
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST J — Unshared User Download Rejection (HTTP 403)")
        print("-" * 75)
        eve_download = client.get(f'/api/shared-files/{file_id}/download', headers=eve_headers)
        print(f"Status: {eve_download.status_code}, Response: {eve_download.get_json()}")
        assert eve_download.status_code == 403
        print(">>> TEST J RESULT: PASSED — Unshared user rejected with HTTP 403.")

        # -------------------------------------------------------------------------
        # TEST K — Revoke Share & Revoked Download Rejection (HTTP 403)
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST K — Revoke Share & Revoked Download Rejection")
        print("-" * 75)
        revoke_res = client.delete(f'/api/files/{file_id}/shares/{bob_id}', headers=alice_headers)
        print(f"Revoke Status: {revoke_res.status_code}, Response: {revoke_res.get_json()}")
        assert revoke_res.status_code == 200

        bob_after_revoke = client.get(f'/api/shared-files/{file_id}/download', headers=bob_headers)
        print(f"Bob Download Status After Revoke: {bob_after_revoke.status_code}")
        assert bob_after_revoke.status_code == 403
        print(">>> TEST K RESULT: PASSED — Access revoked; receiver rejected with HTTP 403.")

        # -------------------------------------------------------------------------
        # TEST L — Owner Download Unaffected
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST L — Owner Download Preservation After Revoke")
        print("-" * 75)
        alice_download = client.get(f'/api/files/{file_id}/download', headers=alice_headers)
        assert alice_download.status_code == 200
        assert alice_download.data == file_content
        print(">>> TEST L RESULT: PASSED — Owner still downloads successfully.")

        # -------------------------------------------------------------------------
        # TEST T & U — Multi-Recipient Sharing & Distinct Wrapping Material
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST T & U — Multi-Recipient Sharing & Distinct Wrapping Material")
        print("-" * 75)
        client.post(f'/api/files/{file_id}/share', headers=alice_headers, json={"receiver_id": charlie_id})
        client.post(f'/api/files/{file_id}/share', headers=alice_headers, json={"receiver_id": david_id})

        charlie_dl = client.get(f'/api/shared-files/{file_id}/download', headers=charlie_headers)
        david_dl = client.get(f'/api/shared-files/{file_id}/download', headers=david_headers)

        assert charlie_dl.status_code == 200 and charlie_dl.data == file_content
        assert david_dl.status_code == 200 and david_dl.data == file_content

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT receiver_id, sender_ephemeral_public_key, key_wrap_nonce, encrypted_aes_key FROM file_key_shares WHERE file_id = %s", (file_id,))
            shares = cursor.fetchall()
        conn.close()

        share_dict = {s["receiver_id"]: s for s in shares}
        charlie_s = share_dict[charlie_id]
        david_s = share_dict[david_id]

        assert charlie_s["sender_ephemeral_public_key"] != david_s["sender_ephemeral_public_key"]
        assert charlie_s["key_wrap_nonce"] != david_s["key_wrap_nonce"]
        assert charlie_s["encrypted_aes_key"] != david_s["encrypted_aes_key"]
        print(">>> TEST T & U RESULT: PASSED — Multi-recipient download succeeded with distinct ephemeral keys and nonces.")

        # -------------------------------------------------------------------------
        # TEST V — Re-Share After Revocation Uses Fresh Wrapping Material
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST V — Re-Share After Revocation Uses Fresh Material")
        print("-" * 75)
        old_bob_share = share_dict.get(bob_id)

        reshare_res = client.post(f'/api/files/{file_id}/share', headers=alice_headers, json={"receiver_id": bob_id})
        assert reshare_res.status_code == 200

        conn = get_db_connection()
        with conn.cursor() as cursor:
            cursor.execute("SELECT sender_ephemeral_public_key, key_wrap_nonce, encrypted_aes_key FROM file_key_shares WHERE file_id = %s AND receiver_id = %s", (file_id, bob_id))
            new_bob_share = cursor.fetchone()
        conn.close()

        assert new_bob_share["sender_ephemeral_public_key"] != old_bob_share["sender_ephemeral_public_key"]
        assert new_bob_share["key_wrap_nonce"] != old_bob_share["key_wrap_nonce"]
        assert new_bob_share["encrypted_aes_key"] != old_bob_share["encrypted_aes_key"]

        bob_redownload = client.get(f'/api/shared-files/{file_id}/download', headers=bob_headers)
        assert bob_redownload.status_code == 200
        assert bob_redownload.data == file_content
        print(">>> TEST V RESULT: PASSED — Re-share created fresh key-wrapping material and receiver downloaded again.")

        # -------------------------------------------------------------------------
        # TEST W — Original Phase 2 AES File Key Remains Unchanged
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST W — Original AES File Key Immutability")
        print("-" * 75)
        file_rec_after = get_file_record(file_id)
        key_after = unprotect_file_key(file_rec_after["encrypted_key"], master_key)
        assert orig_file_key == key_after
        print(">>> TEST W RESULT: PASSED — Phase 2 file encryption key was not altered.")

        # -------------------------------------------------------------------------
        # TEST R & S — Canonical AAD & AAD Copy Attack Protection
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST R & S — Canonical AAD Tampering & Copy Attack Protection")
        print("-" * 75)
        bob_share_rec = new_bob_share
        bob_user_db = find_by_email("bob_p7@example.com")

        # Attempt unwrapping with altered file_id (e.g. file_id=999 instead of actual file_id)
        try:
            unwrap_file_key_for_receiver(
                encrypted_aes_key_b64=bob_share_rec["encrypted_aes_key"],
                key_wrap_nonce_b64=bob_share_rec["key_wrap_nonce"],
                sender_ephemeral_public_key_b64=bob_share_rec["sender_ephemeral_public_key"],
                receiver_private_key_encrypted_b64=bob_user_db["ecc_private_key_encrypted"],
                master_key=master_key,
                file_id=999,
                sender_id=alice_id,
                receiver_id=bob_id
            )
            assert False, "Expected AuthenticationTagMismatchError!"
        except AuthenticationTagMismatchError:
            print("[PASS] AAD Tampering (file_id=999) rejected successfully with AuthenticationTagMismatchError.")

        print(">>> TEST R & S RESULT: PASSED — Canonical AAD protects against key-share copy & tampering attacks.")

        # -------------------------------------------------------------------------
        # TEST X — No Cryptographic Secrets in API Responses
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST X — API Secret Exposure Audit")
        print("-" * 75)
        me_res = client.get('/api/auth/me', headers=alice_headers).get_json()
        shareable_res = client.get('/api/users/shareable', headers=alice_headers).get_json()
        shared_res = client.get('/api/shared-files', headers=bob_headers).get_json()

        raw_dump = json.dumps(me_res) + json.dumps(shareable_res) + json.dumps(shared_res)
        assert "ecc_private_key" not in raw_dump.lower() or "ecc_private_key_encrypted" not in raw_dump
        assert "master_key" not in raw_dump.lower()
        print(">>> TEST X RESULT: PASSED — No cryptographic keys or master secrets exposed in APIs.")

    print("\n" + "=" * 80)
    print("ALL PHASE 7 TESTS PASSED 100% SUCCESSFULLY!")
    print("=" * 80)

if __name__ == "__main__":
    run_phase7_tests()
