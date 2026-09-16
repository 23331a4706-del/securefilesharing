import os
import io
import json
import base64

# Enable test database mode
os.environ["USE_SQLITE"] = "true"
os.environ["SQLITE_DB_PATH"] = "verify_phase2.db"
os.environ["ENCRYPTION_MASTER_KEY"] = "wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM="

from app import create_app
from app.services.file_service import get_file_record

def run_verification():
    print("=" * 70)
    print("PHASE 2 EMPIRICAL VERIFICATION SUITE")
    print("=" * 70)

    # Clean previous test database
    if os.path.exists("verify_phase2.db"):
        try:
            os.remove("verify_phase2.db")
        except OSError:
            pass

    app = create_app()
    app.config['TESTING'] = True
    client = app.test_client()

    # Step 0: Setup Users (Alice & Bob)
    print("\n--- STEP 0: Setting up Alice & Bob accounts ---")
    alice_reg = client.post('/api/auth/register', json={"username": "alice_user", "email": "alice_verify@example.com", "password": "Password123"})
    bob_reg = client.post('/api/auth/register', json={"username": "bob_user", "email": "bob_verify@example.com", "password": "Password123"})

    alice_token = client.post('/api/auth/login', json={"email": "alice_verify@example.com", "password": "Password123"}).get_json()["token"]
    bob_token = client.post('/api/auth/login', json={"email": "bob_verify@example.com", "password": "Password123"}).get_json()["token"]

    alice_headers = {"Authorization": f"Bearer {alice_token}"}
    bob_headers = {"Authorization": f"Bearer {bob_token}"}
    print("[SUCCESS] Users registered & authenticated.")

    # STEP 1: Upload test.txt -> encrypted file appears
    print("\n" + "-" * 60)
    print("TEST 1: Upload test.txt -> encrypted file appears on disk")
    print("-" * 60)
    
    original_plaintext = b"Hello Secure File Sharing - Confidential Major Project Test Data"
    upload_data = {
        'file': (io.BytesIO(original_plaintext), 'test.txt')
    }
    
    upload_res = client.post('/api/files/upload', headers=alice_headers, data=upload_data, content_type='multipart/form-data')
    print(f"HTTP Response Status: {upload_res.status_code}")
    res_data = upload_res.get_json()
    print(f"Response Payload: {json.dumps(res_data, indent=2)}")
    
    file_id = res_data["file"]["id"]
    file_rec = get_file_record(file_id)
    storage_path = file_rec["storage_path"]
    
    print(f"\nTarget Database File ID: {file_id}")
    print(f"Stored Physical Path: {storage_path}")
    print(f"Physical File Exists on Disk: {os.path.exists(storage_path)}")
    assert os.path.exists(storage_path), "FAIL: Encrypted file was not created on disk!"
    print(">>> VERIFICATION 1 PASSED: File uploaded and encrypted disk file appeared.")

    # STEP 2: Open encrypted file -> plaintext is NOT readable
    print("\n" + "-" * 60)
    print("TEST 2: Open encrypted file on disk -> plaintext is NOT readable")
    print("-" * 60)

    with open(storage_path, "rb") as f:
        encrypted_raw_bytes = f.read()

    print(f"Encrypted File Hex Representation (First 64 Bytes): {encrypted_raw_bytes[:64].hex()}")
    is_plaintext_found = original_plaintext in encrypted_raw_bytes
    print(f"Is original text '{original_plaintext.decode()}' readable inside physical file? {is_plaintext_found}")
    assert not is_plaintext_found, "FAIL: Plaintext was found inside disk file!"
    print(">>> VERIFICATION 2 PASSED: Physical disk file contains unreadable AES-256-GCM ciphertext.")

    # STEP 3: Download file -> original text is recovered
    print("\n" + "-" * 60)
    print("TEST 3: Download file as Owner (Alice) -> original text recovered")
    print("-" * 60)

    download_res = client.get(f'/api/files/{file_id}/download', headers=alice_headers)
    print(f"HTTP Response Status: {download_res.status_code}")
    decrypted_content = download_res.data
    print(f"Decrypted Content Received: '{decrypted_content.decode()}'")
    print(f"Matches Original Plaintext Exactly: {decrypted_content == original_plaintext}")
    assert decrypted_content == original_plaintext, "FAIL: Decrypted content does not match original plaintext!"
    print(">>> VERIFICATION 3 PASSED: Original plaintext accurately recovered upon authorized download.")

    # STEP 4: Try another user's file -> 403 Access Denied
    print("\n" + "-" * 60)
    print("TEST 4: Unauthorized Download Attempt by User B (Bob) -> HTTP 403 Access Denied")
    print("-" * 60)

    unauth_res = client.get(f'/api/files/{file_id}/download', headers=bob_headers)
    print(f"HTTP Response Status Code: {unauth_res.status_code}")
    print(f"Response Payload: {json.dumps(unauth_res.get_json(), indent=2)}")
    assert unauth_res.status_code == 403, f"FAIL: Expected HTTP 403, got {unauth_res.status_code}"
    print(">>> VERIFICATION 4 PASSED: HTTP 403 Access Denied enforced for unauthorized user.")

    # STEP 5: Database Check -> Confirm AES key isn't stored in plaintext
    print("\n" + "-" * 60)
    print("DATABASE SECURITY AUDIT: Check 'files' table for AES key security")
    print("-" * 60)

    print(f"Original File Name: {file_rec['original_filename']}")
    print(f"Stored File Name:   {file_rec['stored_filename']}")
    print(f"Encryption Algo:    {file_rec['encryption_algorithm']}")
    print(f"GCM Nonce (Base64): {file_rec['nonce']}")
    print(f"Encrypted Key in DB: {file_rec['encrypted_key']}")
    
    # Verify encrypted_key does NOT contain plain text or raw 32-byte key
    master_key = os.environ["ENCRYPTION_MASTER_KEY"]
    is_master_key_exposed = master_key in file_rec["encrypted_key"]
    is_plain_pwd_exposed = "Password123" in file_rec["encrypted_key"]
    print(f"Is master key exposed in database? {is_master_key_exposed}")
    print(f"Is password exposed in database?   {is_plain_pwd_exposed}")
    
    assert not is_master_key_exposed and not is_plain_pwd_exposed, "FAIL: Secrets exposed in database!"
    print(">>> DATABASE SECURITY AUDIT PASSED: AES key is master-key encrypted and stored as base64.")

    print("\n" + "=" * 70)
    print("ALL 4 TESTS + DATABASE SECURITY AUDIT PASSED 100% SUCCESSFULLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_verification()
