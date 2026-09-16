import os
import io
import json
import base64
import hashlib
from unittest.mock import patch

# Force SQLite test DB & master key config for isolated automated testing
os.environ["USE_SQLITE"] = "true"
os.environ["SQLITE_DB_PATH"] = "test_phase9_final.db"
os.environ["ENCRYPTION_MASTER_KEY"] = "wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM="

from app import create_app
from app.db import get_db_connection

# Mock IPFS Storage Map for Phase 9 Test Suite
mock_ipfs_store = {}

def mock_add_bytes_to_ipfs(ciphertext_bytes: bytes) -> str:
    sha256 = hashlib.sha256(ciphertext_bytes).hexdigest()
    cid = f"QmPhase9E2EMockCID{sha256[:20]}"
    mock_ipfs_store[cid] = ciphertext_bytes
    return cid

def mock_get_bytes_from_ipfs(cid: str) -> bytes:
    if cid in mock_ipfs_store:
        return mock_ipfs_store[cid]
    raise Exception("IPFS CID not found in mock store")

def run_phase9_tests():
    print("=" * 80)
    print("PHASE 9 FINAL SYSTEM VERIFICATION & END-TO-END VALIDATION SUITE")
    print("=" * 80)

    db_path = "test_phase9_final.db"
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass

    app = create_app()
    app.config['TESTING'] = True
    client = app.test_client()

    with patch('app.services.file_service.add_bytes_to_ipfs', side_effect=mock_add_bytes_to_ipfs), \
         patch('app.services.file_service.get_bytes_from_ipfs', side_effect=mock_get_bytes_from_ipfs), \
         patch('app.services.share_service.get_bytes_from_ipfs', side_effect=mock_get_bytes_from_ipfs), \
         patch('app.services.ipfs_service.add_bytes_to_ipfs', side_effect=mock_add_bytes_to_ipfs), \
         patch('app.services.ipfs_service.get_bytes_from_ipfs', side_effect=mock_get_bytes_from_ipfs):

        # -------------------------------------------------------------------------
        # TEST 1 — Health Check and Security Headers
        # -------------------------------------------------------------------------
        print("\n[TEST 1] Verifying Health Check & Modern Security Headers...")
        health_res = client.get('/api/health')
        assert health_res.status_code == 200, f"Health check failed: {health_res.status_code}"
        headers = health_res.headers

        assert headers.get("X-Content-Type-Options") == "nosniff", "Missing X-Content-Type-Options"
        assert headers.get("X-Frame-Options") == "DENY", "Missing X-Frame-Options"
        assert headers.get("Referrer-Policy") == "no-referrer", "Missing Referrer-Policy"
        assert "Content-Security-Policy" in headers, "Missing Content-Security-Policy"
        assert "Permissions-Policy" in headers, "Missing Permissions-Policy"
        assert "X-XSS-Protection" not in headers, "X-XSS-Protection should not be present"
        print("[PASS] Test 1: Health check and modern security headers verified.")

        # -------------------------------------------------------------------------
        # TEST 2 — Complete E2E Workflow (Upload -> Share -> Download -> Revoke -> Re-share -> Download)
        # -------------------------------------------------------------------------
        print("\n[TEST 2] Verifying Complete E2E Key Sharing & Revocation Lifecycle...")
        
        # 1. Register Alice & Bob
        alice_payload = {"username": "alice_p9", "email": "alice_p9@example.com", "password": "Password123!"}
        bob_payload = {"username": "bob_p9", "email": "bob_p9@example.com", "password": "Password123!"}

        reg_a = client.post('/api/auth/register', json=alice_payload)
        assert reg_a.status_code == 201, f"Alice registration failed: {reg_a.data}"

        reg_b = client.post('/api/auth/register', json=bob_payload)
        assert reg_b.status_code == 201, f"Bob registration failed: {reg_b.data}"

        # 2. Login Alice & Bob
        log_a = client.post('/api/auth/login', json={"email": "alice_p9@example.com", "password": "Password123!"})
        assert log_a.status_code == 200, "Alice login failed"
        alice_token = log_a.get_json()['token']
        alice_id = log_a.get_json()['user']['id']

        log_b = client.post('/api/auth/login', json={"email": "bob_p9@example.com", "password": "Password123!"})
        assert log_b.status_code == 200, "Bob login failed"
        bob_token = log_b.get_json()['token']
        bob_id = log_b.get_json()['user']['id']

        alice_headers = {"Authorization": f"Bearer {alice_token}"}
        bob_headers = {"Authorization": f"Bearer {bob_token}"}

        # 3. Upload File as Alice
        test_content = b"PHASE 9 CONFIDENTIAL DATA - ECC P-256 SYSTEM VALIDATION"
        upload_data = {
            'file': (io.BytesIO(test_content), 'phase9_secret.txt')
        }
        res_upload = client.post('/api/files/upload', data=upload_data, headers=alice_headers, content_type='multipart/form-data')
        assert res_upload.status_code == 201, f"File upload failed: {res_upload.data}"
        upload_json = res_upload.get_json()
        file_id = upload_json['file']['id']

        # 4. Alice shares file with Bob (ECC P-256 ECDH automatic key wrapping)
        res_share = client.post(f'/api/files/{file_id}/share', json={"receiver_id": bob_id}, headers=alice_headers)
        assert res_share.status_code == 200, f"File share failed: {res_share.data}"
        assert res_share.get_json()["success"] == True

        # 5. Bob views shared files list
        shared_list = client.get('/api/shared-files', headers=bob_headers)
        assert shared_list.status_code == 200
        assert len(shared_list.get_json()["files"]) == 1

        # 6. Bob downloads & decrypts file
        res_dl_bob = client.get(f'/api/shared-files/{file_id}/download', headers=bob_headers)
        assert res_dl_bob.status_code == 200, f"Bob download failed: {res_dl_bob.status_code}"
        assert res_dl_bob.data == test_content, "Decrypted content does not match original plaintext!"

        # 7. Alice revokes Bob's access
        res_revoke = client.delete(f'/api/files/{file_id}/shares/{bob_id}', headers=alice_headers)
        assert res_revoke.status_code == 200, "File revocation failed"

        # 8. Bob download rejected (HTTP 403 Forbidden)
        res_dl_revoked = client.get(f'/api/shared-files/{file_id}/download', headers=bob_headers)
        assert res_dl_revoked.status_code == 403, f"Expected 403 for revoked user, got {res_dl_revoked.status_code}"

        # 9. Alice re-shares file with Bob
        res_reshare = client.post(f'/api/files/{file_id}/share', json={"receiver_id": bob_id}, headers=alice_headers)
        assert res_reshare.status_code == 200, "File re-share failed"

        # 10. Bob downloads again & verifies matching plaintext
        res_dl_reshared = client.get(f'/api/shared-files/{file_id}/download', headers=bob_headers)
        assert res_dl_reshared.status_code == 200, f"Bob re-shared download failed: {res_dl_reshared.status_code}"
        assert res_dl_reshared.data == test_content, "Re-shared decrypted content does not match original plaintext!"

        print("[PASS] Test 2: Complete E2E key sharing, download, revocation, 403 check, re-share, and second download verification passed.")

        # -------------------------------------------------------------------------
        # TEST 3 — Security & Authorization Boundaries
        # -------------------------------------------------------------------------
        print("\n[TEST 3] Verifying Security & Authorization Boundaries...")
        
        # Unauthenticated access check
        res_unauth = client.get('/api/files')
        assert res_unauth.status_code == 401, f"Expected 401 for unauthenticated request, got {res_unauth.status_code}"

        # Missing file check
        res_404 = client.get('/api/files/99999/download', headers=alice_headers)
        assert res_404.status_code == 404, f"Expected 404 for missing file, got {res_404.status_code}"

        print("[PASS] Test 3: Security & authorization boundaries verified.")

    print("\n" + "=" * 80)
    print("ALL PHASE 9 VERIFICATION CHECKS PASSED SUCCESSFULLY (100% PASS)")
    print("=" * 80)

if __name__ == '__main__':
    run_phase9_tests()
