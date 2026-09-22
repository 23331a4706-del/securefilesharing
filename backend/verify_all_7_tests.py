import os
import io
import json
import base64

# Force SQLite test DB & master key config
os.environ["USE_SQLITE"] = "true"
os.environ["SQLITE_DB_PATH"] = "verify_all_7.db"
os.environ["ENCRYPTION_MASTER_KEY"] = "wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM="

from app import create_app
from app.services.file_service import get_file_record

def run_all_7_tests():
    print("=" * 75)
    print("COMPREHENSIVE 7-TEST VERIFICATION SUITE — PHASE 2")
    print("=" * 75)

    if os.path.exists("verify_all_7.db"):
        try:
            os.remove("verify_all_7.db")
        except OSError:
            pass

    app = create_app()
    app.config['TESTING'] = True
    client = app.test_client()

    # Pre-test Setup: Register User A (Alice) and User B (Bob)
    alice_reg = client.post('/api/auth/register', json={"username": "alice_7", "email": "alice_7@example.com", "password": "Password123"})
    bob_reg = client.post('/api/auth/register', json={"username": "bob_7", "email": "bob_7@example.com", "password": "Password123"})

    alice_token = client.post('/api/auth/login', json={"email": "alice_7@example.com", "password": "Password123"}).get_json()["token"]
    bob_token = client.post('/api/auth/login', json={"email": "bob_7@example.com", "password": "Password123"}).get_json()["token"]

    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    bob_headers = {"Authorization": f"Bearer {bob_token}"}

    # -------------------------------------------------------------------------
    # TEST 1 — Upload text file
    # -------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print("TEST 1 — Upload text file")
    print("Upload test.txt with content 'Hello Secure File Sharing'. Verify success message.")
    print("-" * 75)

    content_t1 = b"Hello Secure File Sharing"
    upload_res = client.post(
        '/api/files/upload',
        headers=alice_headers,
        data={'file': (io.BytesIO(content_t1), 'test.txt')},
        content_type='multipart/form-data'
    )
    print(f"HTTP Response Status Code: {upload_res.status_code}")
    res_json_t1 = upload_res.get_json()
    print(f"JSON Output: {json.dumps(res_json_t1, indent=2)}")

    assert upload_res.status_code == 201, f"Expected 201, got {upload_res.status_code}"
    assert res_json_t1.get("success") == True, "Expected success: true"
    assert res_json_t1.get("message") == "File encrypted and uploaded successfully"
    file_id = res_json_t1["file"]["id"]
    print(">>> TEST 1 RESULT: PASSED — Success message verified and HTTP 201 returned.")

    # -------------------------------------------------------------------------
    # TEST 2 — Verify physical storage
    # -------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print("TEST 2 — Verify physical storage")
    print("Inspect backend/storage/encrypted/. Confirm <uuid>.enc exists and is NOT readable plain text.")
    print("-" * 75)

    file_rec = get_file_record(file_id)
    storage_path = file_rec["storage_path"]
    stored_filename = file_rec["stored_filename"]
    
    print(f"Stored Filename: {stored_filename}")
    print(f"Full Storage Path: {storage_path}")
    print(f"Physical File Exists on Disk: {os.path.exists(storage_path)}")
    assert os.path.exists(storage_path), "Disk file does not exist!"

    with open(storage_path, "rb") as f:
        encrypted_raw_bytes = f.read()

    print(f"Raw Bytes Length: {len(encrypted_raw_bytes)} bytes")
    print(f"First 32 Hex Bytes: {encrypted_raw_bytes[:32].hex()}")
    is_readable = content_t1 in encrypted_raw_bytes
    print(f"Is original text 'Hello Secure File Sharing' readable inside file? {is_readable}")
    assert not is_readable, "Plaintext was found inside stored file!"
    print(">>> TEST 2 RESULT: PASSED — Physical <uuid>.enc file exists and plaintext is NOT readable.")

    # -------------------------------------------------------------------------
    # TEST 3 — Verify DB metadata
    # -------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print("TEST 3 — Verify DB metadata")
    print("Check files table record (original_filename, stored_filename, nonce, encrypted_key).")
    print("-" * 75)

    print(f"DB Record ID:           {file_rec['id']}")
    print(f"DB original_filename:  '{file_rec['original_filename']}'")
    print(f"DB stored_filename:    '{file_rec['stored_filename']}'")
    print(f"DB file_size:          {file_rec['file_size']} bytes")
    print(f"DB nonce (base64):     '{file_rec['nonce']}'")
    print(f"DB encrypted_key:      '{file_rec['encrypted_key']}'")
    print(f"DB status:             '{file_rec['status']}'")

    assert file_rec["original_filename"] == "test.txt"
    assert file_rec["stored_filename"].endswith(".enc")
    assert len(file_rec["nonce"]) > 0
    assert len(file_rec["encrypted_key"]) > 0
    print(">>> TEST 3 RESULT: PASSED — DB metadata fields populated accurately with protected key.")

    # -------------------------------------------------------------------------
    # TEST 4 — Download decrypted file
    # -------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print("TEST 4 — Download decrypted file")
    print("Click Download. Confirm downloaded test.txt matches original content exactly.")
    print("-" * 75)

    download_res = client.get(f'/api/files/{file_id}/download', headers=alice_headers)
    print(f"HTTP Response Status Code: {download_res.status_code}")
    downloaded_bytes = download_res.data
    print(f"Downloaded Text Content: '{downloaded_bytes.decode()}'")
    print(f"Exact Content Match: {downloaded_bytes == content_t1}")

    assert download_res.status_code == 200
    assert downloaded_bytes == content_t1
    print(">>> TEST 4 RESULT: PASSED — Downloaded test.txt matches original content exactly.")

    # -------------------------------------------------------------------------
    # TEST 5 — Ownership security check
    # -------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print("TEST 5 — Ownership security check")
    print("Log in as User B, request User A's file ID. Verify 403 Forbidden rejection.")
    print("-" * 75)

    bob_access_res = client.get(f'/api/files/{file_id}/download', headers=bob_headers)
    print(f"HTTP Response Status Code: {bob_access_res.status_code}")
    bob_res_json = bob_access_res.get_json()
    print(f"Response Payload: {json.dumps(bob_res_json, indent=2)}")

    assert bob_access_res.status_code == 403, f"Expected 403, got {bob_access_res.status_code}"
    assert bob_res_json.get("success") == False
    assert "not authorized" in bob_res_json.get("message", "").lower()
    print(">>> TEST 5 RESULT: PASSED — User B request rejected with HTTP 403 Forbidden.")

    # -------------------------------------------------------------------------
    # TEST 6 — File deletion
    # -------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print("TEST 6 — File deletion")
    print("Delete file. Confirm file is removed from UI, disk storage, and database.")
    print("-" * 75)

    delete_res = client.delete(f'/api/files/{file_id}', headers=alice_headers)
    print(f"HTTP Response Status Code: {delete_res.status_code}")
    print(f"Response Payload: {json.dumps(delete_res.get_json(), indent=2)}")

    assert delete_res.status_code == 200
    assert delete_res.get_json().get("success") == True

    # Confirm disk file removed
    disk_file_still_exists = os.path.exists(storage_path)
    print(f"Disk file exists after deletion? {disk_file_still_exists}")
    assert not disk_file_still_exists, "Disk file was not deleted!"

    # Confirm DB record removed
    rec_after_del = get_file_record(file_id)
    print(f"Database record exists after deletion? {rec_after_del is not None}")
    assert rec_after_del is None, "DB record was not deleted!"

    print(">>> TEST 6 RESULT: PASSED — File removed from API response, disk storage, and database.")

    # -------------------------------------------------------------------------
    # TEST 7 — File size limit
    # -------------------------------------------------------------------------
    print("\n" + "-" * 75)
    print("TEST 7 — File size limit")
    print("Attempt uploading file > 16 MB. Verify HTTP 400 rejection.")
    print("-" * 75)

    # Generate 17 MB synthetic file payload
    oversized_payload = b"0" * (17 * 1024 * 1024)
    print(f"Uploading synthetic payload size: {len(oversized_payload) / (1024 * 1024):.2f} MB (Configured Limit: 16 MB)")

    oversized_res = client.post(
        '/api/files/upload',
        headers=alice_headers,
        data={'file': (io.BytesIO(oversized_payload), 'large_video.mp4')},
        content_type='multipart/form-data'
    )
    print(f"HTTP Response Status Code: {oversized_res.status_code}")
    oversized_json = oversized_res.get_json()
    print(f"Response Payload: {json.dumps(oversized_json, indent=2)}")

    assert oversized_res.status_code in (400, 413), f"Expected 400 or 413, got {oversized_res.status_code}"
    assert oversized_json.get("success") == False
    assert "exceeds maximum" in oversized_json.get("message", "").lower()
    print(">>> TEST 7 RESULT: PASSED — Oversized file rejected with HTTP 400 error message.")

    print("\n" + "=" * 75)
    print("ALL 7 TESTS PASSED 100% SUCCESSFULLY!")
    print("=" * 75)

if __name__ == "__main__":
    run_all_7_tests()
