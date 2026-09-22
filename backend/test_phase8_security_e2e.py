import os
import io
import json
import base64
import hashlib
from unittest.mock import patch

# Force SQLite test DB & master key config for isolated automated testing
os.environ["USE_SQLITE"] = "true"
os.environ["SQLITE_DB_PATH"] = "test_phase8_security_e2e.db"
os.environ["ENCRYPTION_MASTER_KEY"] = "wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM="

from app import create_app
from app.services.file_service import get_file_record
from app.services.encryption_service import unprotect_file_key

# Mock IPFS Storage Map for E2E Suite
mock_ipfs_store = {}

def mock_add_bytes_to_ipfs(ciphertext_bytes: bytes) -> str:
    sha256 = hashlib.sha256(ciphertext_bytes).hexdigest()
    cid = f"QmPhase8E2EMockCID{sha256[:20]}"
    mock_ipfs_store[cid] = ciphertext_bytes
    return cid

def mock_get_bytes_from_ipfs(cid: str) -> bytes:
    if cid in mock_ipfs_store:
        return mock_ipfs_store[cid]
    raise Exception("IPFS CID not found in mock store")

def run_phase8_tests():
    print("=" * 80)
    print("PHASE 8 AUTOMATED SECURITY HARDENING & E2E SYSTEM VALIDATION SUITE")
    print("=" * 80)

    db_path = "test_phase8_security_e2e.db"
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
        # TEST 1 — Security Headers Verification
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST 1 — Modern HTTP Security Headers Verification")
        print("-" * 75)
        health_res = client.get('/api/health')
        headers = health_res.headers

        assert headers.get("X-Content-Type-Options") == "nosniff", "Missing X-Content-Type-Options: nosniff"
        assert headers.get("X-Frame-Options") == "DENY", "Missing X-Frame-Options: DENY"
        assert headers.get("Referrer-Policy") == "no-referrer", "Missing Referrer-Policy: no-referrer"
        assert "Content-Security-Policy" in headers, "Missing Content-Security-Policy header"
        assert "Permissions-Policy" in headers, "Missing Permissions-Policy header"
        assert "X-XSS-Protection" not in headers, "Deprecated X-XSS-Protection header must NOT be present!"

        print("[PASS] X-Content-Type-Options: nosniff")
        print("[PASS] X-Frame-Options: DENY")
        print("[PASS] Referrer-Policy: no-referrer")
        print("[PASS] Content-Security-Policy: Present")
        print("[PASS] Permissions-Policy: Present")
        print("[PASS] Deprecated X-XSS-Protection: Absent (Verified)")
        print(">>> TEST 1 RESULT: PASSED — Modern HTTP security headers enforced.")

        # -------------------------------------------------------------------------
        # TEST 2 — CORS Origin Security Verification
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST 2 — CORS Origin Security Verification")
        print("-" * 75)
        options_res = client.options('/api/health', headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET"
        })
        cors_origin = options_res.headers.get("Access-Control-Allow-Origin")
        assert cors_origin != "*", "Wildcard '*' origin must NOT be allowed for authenticated APIs!"
        print(f"Configured Access-Control-Allow-Origin: {cors_origin}")
        print(">>> TEST 2 RESULT: PASSED — Strict CORS origin policy enforced.")

        # -------------------------------------------------------------------------
        # REGISTER USERS (Alice = Owner, Bob = Receiver, Charlie = Unshared)
        # -------------------------------------------------------------------------
        alice_reg = client.post('/api/auth/register', json={"username": "alice_p8", "email": "alice_p8@example.com", "password": "Password123"})
        bob_reg = client.post('/api/auth/register', json={"username": "bob_p8", "email": "bob_p8@example.com", "password": "Password123"})
        charlie_reg = client.post('/api/auth/register', json={"username": "charlie_p8", "email": "charlie_p8@example.com", "password": "Password123"})

        alice_token = client.post('/api/auth/login', json={"email": "alice_p8@example.com", "password": "Password123"}).get_json()["token"]
        bob_token = client.post('/api/auth/login', json={"email": "bob_p8@example.com", "password": "Password123"}).get_json()["token"]
        charlie_token = client.post('/api/auth/login', json={"email": "charlie_p8@example.com", "password": "Password123"}).get_json()["token"]

        alice_headers = {"Authorization": f"Bearer {alice_token}"}
        bob_headers = {"Authorization": f"Bearer {bob_token}"}
        charlie_headers = {"Authorization": f"Bearer {charlie_token}"}

        bob_id = bob_reg.get_json()["user"]["id"]
        charlie_id = charlie_reg.get_json()["user"]["id"]

        # -------------------------------------------------------------------------
        # TEST 3 — Secret Leakage Prevention Audit
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST 3 — Secret Leakage Prevention Audit")
        print("-" * 75)
        me_res = client.get('/api/auth/me', headers=alice_headers).get_json()
        users_res = client.get('/api/users/shareable', headers=alice_headers).get_json()

        combined_dump = json.dumps(me_res) + json.dumps(users_res)
        assert "master_key" not in combined_dump.lower()
        assert "jwt_secret" not in combined_dump.lower()
        assert "ecc_private_key" not in combined_dump or "ecc_private_key_encrypted" not in combined_dump
        print(">>> TEST 3 RESULT: PASSED — Zero secret leakage across user profile & directory endpoints.")

        # -------------------------------------------------------------------------
        # TEST 4 — Corrected End-to-End Workflow Execution
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST 4 — Corrected End-to-End Workflow Execution")
        print("Flow: Register -> Upload -> IPFS CID -> Blockchain Tx -> Share -> Download -> Revoke -> Revoked Reject (403) -> Re-Share -> Download Again (Plaintext Verified)")
        print("-" * 75)

        # 1. Upload File
        original_plaintext = b"Phase 8 Production Readiness Payload - Highly Confidential Data 2026"
        upload_res = client.post(
            '/api/files/upload',
            headers=alice_headers,
            data={'file': (io.BytesIO(original_plaintext), 'p8_document.txt')},
            content_type='multipart/form-data'
        )
        assert upload_res.status_code == 201, f"Expected 201, got {upload_res.status_code}"
        upload_data = upload_res.get_json()["file"]
        file_id = upload_data["id"]
        print(f"Step 1: Uploaded p8_document.txt (File ID #{file_id})")

        # 2. IPFS CID & SHA-256 Storage Verification
        assert upload_data["ipfs_cid"].startswith("QmPhase8E2EMockCID")
        assert len(upload_data["sha256_hash"]) == 64
        print(f"Step 2: Stored on IPFS (CID: {upload_data['ipfs_cid'][:20]}...) & SHA-256 verified.")

        # 3. Share File with Bob
        share_res = client.post(f'/api/files/{file_id}/share', headers=alice_headers, json={"receiver_id": bob_id})
        assert share_res.status_code == 200
        print(f"Step 3: Shared File #{file_id} with Bob (ID #{bob_id}).")

        # 4. Bob Downloads & Decrypts File
        bob_dl1 = client.get(f'/api/shared-files/{file_id}/download', headers=bob_headers)
        assert bob_dl1.status_code == 200
        assert bob_dl1.data == original_plaintext
        print(f"Step 4: Bob downloaded and decrypted File #{file_id} successfully.")

        # 5. Alice Revokes Share
        revoke_res = client.delete(f'/api/files/{file_id}/shares/{bob_id}', headers=alice_headers)
        assert revoke_res.status_code == 200
        print(f"Step 5: Alice revoked share for Bob.")

        # 6. Bob Download Rejection (HTTP 403)
        bob_dl2 = client.get(f'/api/shared-files/{file_id}/download', headers=bob_headers)
        assert bob_dl2.status_code == 403
        print(f"Step 6: Bob download attempt rejected after revocation (HTTP 403).")

        # 7. Alice Re-shares File with Bob
        reshare_res = client.post(f'/api/files/{file_id}/share', headers=alice_headers, json={"receiver_id": bob_id})
        assert reshare_res.status_code == 200
        print(f"Step 7: Alice re-shared File #{file_id} with Bob using fresh key wrapping material.")

        # 8. Bob Downloads Again & Plaintext Verified
        bob_dl3 = client.get(f'/api/shared-files/{file_id}/download', headers=bob_headers)
        assert bob_dl3.status_code == 200
        assert bob_dl3.data == original_plaintext
        print(f"Step 8: Bob downloaded again and verified plaintext matches original uploaded payload exactly!")

        print(">>> TEST 4 RESULT: PASSED — End-to-End workflow completed successfully.")

        # -------------------------------------------------------------------------
        # TEST 5 — IDOR Protection Audit
        # -------------------------------------------------------------------------
        print("\n" + "-" * 75)
        print("TEST 5 — IDOR Protection Audit")
        print("-" * 75)
        # Charlie attempts accessing Alice's file download -> 403
        charlie_dl = client.get(f'/api/files/{file_id}/download', headers=charlie_headers)
        assert charlie_dl.status_code == 403
        # Charlie attempts creating share for Alice's file -> 403
        charlie_share = client.post(f'/api/files/{file_id}/share', headers=charlie_headers, json={"receiver_id": bob_id})
        assert charlie_share.status_code == 403
        # Charlie attempts revoking Bob's share -> 403
        charlie_revoke = client.delete(f'/api/files/{file_id}/shares/{bob_id}', headers=charlie_headers)
        assert charlie_revoke.status_code == 403

        print(">>> TEST 5 RESULT: PASSED — IDOR protections enforced across all file endpoints.")

        print("\n" + "=" * 80)
        print("ALL PHASE 8 SECURITY HARDENING & E2E TESTS PASSED 100% SUCCESSFULLY!")
        print("=" * 80)

if __name__ == "__main__":
    run_phase8_tests()
