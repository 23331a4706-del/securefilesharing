import os
import uuid
import base64
import logging
from werkzeug.utils import secure_filename
from app.config import Config
from app.db import get_db_connection
from app.services.encryption_service import (
    generate_file_key,
    generate_nonce,
    encrypt_file_data,
    decrypt_file_data,
    protect_file_key,
    unprotect_file_key
)
from app.services.integrity_service import (
    calculate_bytes_sha256,
    calculate_file_sha256,
    verify_file_integrity,
    FileIntegrityError
)
from app.services.ipfs_service import (
    add_bytes_to_ipfs,
    get_bytes_from_ipfs,
    unpin_from_ipfs,
    IPFSUnavailableError,
    IPFSNotFoundError
)
from app.services.blockchain_service import (
    register_file_metadata,
    get_file_metadata as get_blockchain_metadata,
    is_file_registered,
    BlockchainException,
    BlockchainUnavailableError,
    BlockchainMetadataMismatchError
)

logger = logging.getLogger(__name__)

def ensure_storage_dir():
    """Ensures backend/storage/encrypted directory exists."""
    os.makedirs(Config.ENCRYPTED_STORAGE_DIR, exist_ok=True)

def process_file_upload(file_storage, owner_id: int):
    """
    Handles file validation, AES-256-GCM encryption in memory, SHA-256 integrity calculation,
    uploading encrypted binary payload to IPFS, saving metadata in MySQL, and registering
    immutable metadata on local Hardhat blockchain via Web3.py.
    """
    if not file_storage or not file_storage.filename or file_storage.filename.strip() == "":
        raise ValueError("No valid file provided.")

    raw_filename = file_storage.filename.strip()
    original_filename = secure_filename(raw_filename) or f"file_{uuid.uuid4().hex[:8]}"

    # Read plaintext content into memory
    plaintext_bytes = file_storage.read()
    file_size = len(plaintext_bytes)

    if file_size == 0:
        raise ValueError("Uploaded file is empty.")

    if file_size > Config.MAX_CONTENT_LENGTH:
        raise ValueError(f"File size ({file_size / (1024*1024):.2f} MB) exceeds maximum limit of {Config.MAX_FILE_SIZE_MB} MB.")

    mime_type = file_storage.content_type or 'application/octet-stream'

    # Cryptography Operations
    master_key = Config.get_master_key_bytes()
    file_key = generate_file_key()
    nonce = generate_nonce()

    # Encrypt plaintext file bytes with AES-256-GCM
    ciphertext_bytes = encrypt_file_data(plaintext_bytes, file_key, nonce)

    # Calculate SHA-256 checksum over encrypted binary bytes
    sha256_hash = calculate_bytes_sha256(ciphertext_bytes)

    # Upload encrypted payload to IPFS Kubo node -> returns real CID
    ipfs_cid = add_bytes_to_ipfs(ciphertext_bytes)

    # Protect per-file AES key with master key
    protected_key_b64 = protect_file_key(file_key, master_key)
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')

    stored_filename = f"{uuid.uuid4().hex}.enc"
    storage_path = f"ipfs://{ipfs_cid}"

    # 1. Database Persistence
    conn = get_db_connection()
    file_id = None
    try:
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO files 
                (owner_id, original_filename, stored_filename, file_size, mime_type, encryption_algorithm, nonce, encrypted_key, storage_path, sha256_hash, ipfs_cid, blockchain_recorded, blockchain_tx_hash, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 0, NULL, 'ipfs_stored')
            """
            cursor.execute(sql, (
                owner_id,
                original_filename,
                stored_filename,
                file_size,
                mime_type,
                "AES-256-GCM",
                nonce_b64,
                protected_key_b64,
                storage_path,
                sha256_hash,
                ipfs_cid
            ))
            file_id = cursor.lastrowid

        # 2. Blockchain Registration (Phase 6)
        blockchain_recorded = False
        blockchain_tx_hash = None
        try:
            bc_result = register_file_metadata(file_id, str(owner_id), ipfs_cid, sha256_hash)
            if bc_result.get("success"):
                blockchain_recorded = True
                blockchain_tx_hash = bc_result.get("transaction_hash")
                with conn.cursor() as cursor:
                    cursor.execute("""
                        UPDATE files 
                        SET blockchain_recorded = 1, blockchain_tx_hash = %s, status = 'blockchain_recorded'
                        WHERE id = %s
                    """, (blockchain_tx_hash, file_id))
        except Exception as e:
            logger.warning(f"Automatic blockchain registration pending for file ID {file_id}: {e}")

        return {
            "id": file_id,
            "original_filename": original_filename,
            "file_size": file_size,
            "mime_type": mime_type,
            "encryption_algorithm": "AES-256-GCM",
            "sha256_hash": sha256_hash,
            "ipfs_cid": ipfs_cid,
            "blockchain_recorded": blockchain_recorded,
            "blockchain_tx_hash": blockchain_tx_hash,
            "status": "blockchain_recorded" if blockchain_recorded else "ipfs_stored"
        }
    finally:
        conn.close()


def get_user_files(owner_id: int):
    """Retrieves all encrypted file records owned by the specified user."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT id, original_filename, file_size, mime_type, encryption_algorithm, sha256_hash, ipfs_cid, blockchain_recorded, blockchain_tx_hash, status, created_at
                FROM files
                WHERE owner_id = %s
                ORDER BY created_at DESC
            """
            cursor.execute(sql, (owner_id,))
            rows = cursor.fetchall()
            for r in rows:
                if "blockchain_recorded" in r:
                    r["blockchain_recorded"] = bool(r["blockchain_recorded"])
            return rows
    finally:
        conn.close()


def get_file_record(file_id: int):
    """Retrieves a single file database record by ID."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM files WHERE id = %s"
            cursor.execute(sql, (file_id,))
            row = cursor.fetchone()
            if row and "blockchain_recorded" in row:
                row["blockchain_recorded"] = bool(row["blockchain_recorded"])
            return row
    finally:
        conn.close()


def update_file_sha256_hash(file_id: int, new_hash: str):
    """Updates sha256_hash in database for migration/backfill scenarios."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE files SET sha256_hash = %s WHERE id = %s"
            cursor.execute(sql, (new_hash, file_id))
    finally:
        conn.close()


def update_file_ipfs_cid(file_id: int, new_cid: str):
    """Updates ipfs_cid in database for testing/migration scenarios."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE files SET ipfs_cid = %s WHERE id = %s"
            cursor.execute(sql, (new_cid, file_id))
    finally:
        conn.close()


def get_file_blockchain_record(file_id: int, request_user_id: int) -> dict:
    """
    Retrieves the on-chain metadata record for a file ID and compares against MySQL.
    Requires ownership authorization.
    """
    file_record = get_file_record(file_id)
    if not file_record:
        raise FileNotFoundError("File not found.")

    if file_record["owner_id"] != request_user_id:
        raise PermissionError("You are not authorized to access this file's blockchain record.")

    bc_record = get_blockchain_metadata(file_id)
    db_cid = file_record.get("ipfs_cid", "")
    db_hash = file_record.get("sha256_hash", "")

    cid_match = (db_cid == bc_record["ipfs_cid"])
    hash_match = (db_hash.lower() == bc_record["sha256_hash"].lower())

    return {
        "success": True,
        "blockchain": {
            "recorded": True,
            "file_id": bc_record["file_id"],
            "owner_id": bc_record["owner_id"],
            "ipfs_cid": bc_record["ipfs_cid"],
            "sha256_hash": bc_record["sha256_hash"],
            "timestamp": bc_record["timestamp"],
            "active": bc_record["active"],
            "transaction_hash": file_record.get("blockchain_tx_hash"),
            "matches_database": cid_match and hash_match
        }
    }


def verify_file_full_integrity(file_id: int, request_user_id: int) -> dict:
    """
    Performs non-decrypting 4-way cross-system integrity verification:
    MySQL Record ↔ Blockchain Metadata ↔ IPFS Encrypted Bytes SHA-256 Digest.
    Requires owner authorization. Does NOT decrypt ciphertext.
    """
    file_record = get_file_record(file_id)
    if not file_record:
        raise FileNotFoundError("File not found.")

    if file_record["owner_id"] != request_user_id:
        raise PermissionError("You are not authorized to verify this file.")

    db_cid = file_record.get("ipfs_cid")
    db_hash = file_record.get("sha256_hash")

    if not db_cid or not db_hash:
        raise FileIntegrityError("Missing database CID or SHA-256 integrity hash.")

    # 1. Fetch Blockchain Metadata
    bc_metadata = get_blockchain_metadata(file_id)

    # 2. Retrieve Encrypted Data from IPFS (Zero Local Fallback)
    ciphertext_bytes = get_bytes_from_ipfs(db_cid)
    current_ipfs_hash = calculate_bytes_sha256(ciphertext_bytes)

    # 3. Perform 4-way Cross-Verification
    db_vs_bc = (db_cid == bc_metadata["ipfs_cid"]) and (db_hash.lower() == bc_metadata["sha256_hash"].lower())
    ipfs_cid_match = (db_cid == bc_metadata["ipfs_cid"])
    sha256_match = (db_hash.lower() == bc_metadata["sha256_hash"].lower())
    ipfs_content_integrity = (current_ipfs_hash.lower() == db_hash.lower() == bc_metadata["sha256_hash"].lower())

    overall_verified = db_vs_bc and ipfs_content_integrity

    if not overall_verified:
        raise FileIntegrityError("File integrity or blockchain metadata verification failed.")

    return {
        "success": True,
        "verified": True,
        "file_id": file_id,
        "checks": {
            "database_record": True,
            "blockchain_record": True,
            "database_vs_blockchain": db_vs_bc,
            "ipfs_cid_match": ipfs_cid_match,
            "sha256_match": sha256_match,
            "ipfs_content_integrity": ipfs_content_integrity
        },
        "blockchain": {
            "recorded": True,
            "transaction_hash": file_record.get("blockchain_tx_hash"),
            "timestamp": bc_metadata["timestamp"]
        },
        "message": "File metadata and encrypted content integrity verified successfully across MySQL, IPFS, and Blockchain."
    }


def retry_blockchain_registration(file_id: int, request_user_id: int) -> dict:
    """
    Manually retries blockchain registration for an IPFS-stored file whose
    initial registration was pending or failed. Requires owner authorization.
    """
    file_record = get_file_record(file_id)
    if not file_record:
        raise FileNotFoundError("File not found.")

    if file_record["owner_id"] != request_user_id:
        raise PermissionError("You are not authorized to register this file.")

    ipfs_cid = file_record.get("ipfs_cid")
    db_hash = file_record.get("sha256_hash")

    if not ipfs_cid or not db_hash:
        raise ValueError("File lacks IPFS CID or SHA-256 hash.")

    # Integrity verification over IPFS content before submitting transaction
    ciphertext_bytes = get_bytes_from_ipfs(ipfs_cid)
    current_hash = calculate_bytes_sha256(ciphertext_bytes)
    if current_hash.lower() != db_hash.lower():
        raise FileIntegrityError("Cannot register file on blockchain: IPFS integrity verification failed.")

    # Submit transaction
    bc_result = register_file_metadata(file_id, str(request_user_id), ipfs_cid, db_hash)
    tx_hash = bc_result.get("transaction_hash")

    # Update MySQL Database
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                UPDATE files 
                SET blockchain_recorded = 1, blockchain_tx_hash = %s, status = 'blockchain_recorded'
                WHERE id = %s
            """
            cursor.execute(sql, (tx_hash, file_id))
        return {
            "success": True,
            "message": "File metadata successfully recorded on blockchain.",
            "blockchain": {
                "file_id": file_id,
                "transaction_hash": tx_hash,
                "already_registered": bc_result.get("already_registered", False)
            }
        }
    finally:
        conn.close()


def decrypt_and_read_file(file_id: int, request_user_id: int):
    """
    Enforces Strict Zero-Fallback Security Order:
    1. Authentication (handled via JWT route)
    2. Ownership Authorization (403 if non-owner)
    3. Retrieve encrypted binary .enc bytes strictly from IPFS using CID (NO LOCAL DISK FALLBACK for IPFS files)
       - Raises IPFSUnavailableError if daemon is offline (HTTP 503)
       - Raises IPFSNotFoundError if CID is missing/invalid (HTTP 404)
    4. SHA-256 Integrity Verification over retrieved IPFS encrypted bytes (409 if tampered / hash mismatch)
    5. AES-256-GCM Decryption (executed ONLY after integrity verification succeeds)
    Returns tuple: (plaintext_bytes, original_filename, mime_type)
    """
    file_record = get_file_record(file_id)
    if not file_record:
        raise FileNotFoundError("File not found.")

    # 1. Ownership Authorization Check
    if file_record["owner_id"] != request_user_id:
        raise PermissionError("You are not authorized to access this file.")

    ipfs_cid = file_record.get("ipfs_cid")
    stored_hash = file_record.get("sha256_hash")

    if not stored_hash:
        raise FileIntegrityError("File integrity information is unavailable (SHA-256 hash missing from database).")

    # 2. Retrieve Encrypted Data (STRICT ZERO LOCAL FALLBACK for IPFS files)
    if ipfs_cid and ipfs_cid.strip():
        ciphertext_bytes = get_bytes_from_ipfs(ipfs_cid)
    else:
        storage_path = file_record.get("storage_path", "")
        if storage_path and os.path.exists(storage_path):
            with open(storage_path, "rb") as f:
                ciphertext_bytes = f.read()
        else:
            raise IPFSNotFoundError("Encrypted file is unavailable from decentralized storage")

    # 3. SHA-256 File Integrity Verification over retrieved ciphertext_bytes (Pre-Decryption)
    retrieved_hash = calculate_bytes_sha256(ciphertext_bytes)
    if retrieved_hash != stored_hash:
        raise FileIntegrityError("File integrity verification failed")

    # 4. AES-256-GCM Decryption (Executed ONLY after integrity verification succeeds)
    master_key = Config.get_master_key_bytes()
    nonce = base64.b64decode(file_record["nonce"])
    file_key = unprotect_file_key(file_record["encrypted_key"], master_key)

    plaintext_bytes = decrypt_file_data(ciphertext_bytes, file_key, nonce)
    return plaintext_bytes, file_record["original_filename"], file_record["mime_type"]


def delete_user_file(file_id: int, request_user_id: int):
    """
    Verifies ownership, unpins CID from local IPFS node, removes local disk file if present,
    and deletes database record. (Preserves immutable historical record on-chain).
    """
    file_record = get_file_record(file_id)
    if not file_record:
        raise FileNotFoundError("File not found.")

    if file_record["owner_id"] != request_user_id:
        raise PermissionError("You are not authorized to delete this file.")

    # 1. Unpin CID from local IPFS node if present
    ipfs_cid = file_record.get("ipfs_cid")
    if ipfs_cid:
        try:
            unpin_from_ipfs(ipfs_cid)
        except Exception as e:
            logger.warning(f"IPFS unpin failed for CID {ipfs_cid}: {e}")

    # 2. Remove local disk file if present
    storage_path = file_record.get("storage_path", "")
    if storage_path and os.path.exists(storage_path):
        try:
            os.remove(storage_path)
        except OSError as e:
            logger.warning(f"Failed to delete disk file {storage_path}: {e}")

    # 3. Delete database record
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "DELETE FROM files WHERE id = %s"
            cursor.execute(sql, (file_id,))
        return True
    finally:
        conn.close()
