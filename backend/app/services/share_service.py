import base64
import logging
from app.db import get_db_connection
from app.config import Config
from app.models.user import find_by_id, ensure_user_ecc_keys
from app.services.encryption_service import (
    unprotect_file_key,
    wrap_file_key_for_receiver,
    unwrap_file_key_for_receiver,
    decrypt_file_data,
    CryptographyError,
    AuthenticationTagMismatchError
)
from app.services.file_service import get_file_record
from app.services.integrity_service import calculate_bytes_sha256, FileIntegrityError
from app.services.ipfs_service import get_bytes_from_ipfs, IPFSUnavailableError, IPFSNotFoundError

logger = logging.getLogger(__name__)


def create_or_update_file_share(file_id: int, sender_id: int, receiver_id: int) -> dict:
    """
    Creates or re-activates a file share for a receiver.
    Enforces owner authorization, retrieves original Phase 2 AES file key,
    performs P-256 ECDH + HKDF-SHA256 + AES-256-GCM key wrapping,
    and persists share record in file_key_shares.
    """
    if sender_id == receiver_id:
        raise ValueError("Cannot share a file with yourself.")

    file_record = get_file_record(file_id)
    if not file_record:
        raise FileNotFoundError("File not found.")

    if file_record["owner_id"] != sender_id:
        raise PermissionError("Only the file owner can share this file.")

    receiver = find_by_id(receiver_id)
    if not receiver:
        raise FileNotFoundError("Receiver user not found.")

    # Ensure persistent ECC keys exist for sender and receiver
    sender_user = ensure_user_ecc_keys(sender_id)
    receiver_user = ensure_user_ecc_keys(receiver_id)

    receiver_public_key_b64 = receiver_user["ecc_public_key"]

    conn = get_db_connection()
    try:
        # Check existing share record
        existing_share = None
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT id, active FROM file_key_shares WHERE file_id = %s AND receiver_id = %s",
                (file_id, receiver_id)
            )
            existing_share = cursor.fetchone()

        if existing_share and existing_share.get("active"):
            raise ValueError("File is already actively shared with this user.")

        # Recover original Phase 2 AES file key using master key
        master_key = Config.get_master_key_bytes()
        file_key = unprotect_file_key(file_record["encrypted_key"], master_key)

        # Wrap original Phase 2 AES key for receiver
        sender_ephemeral_pub_b64, encrypted_aes_key_b64, key_wrap_nonce_b64 = wrap_file_key_for_receiver(
            file_key=file_key,
            receiver_public_key_b64=receiver_public_key_b64,
            file_id=file_id,
            sender_id=sender_id,
            receiver_id=receiver_id
        )

        with conn.cursor() as cursor:
            if existing_share:
                sql = """
                    UPDATE file_key_shares
                    SET sender_id = %s,
                        sender_ephemeral_public_key = %s,
                        encrypted_aes_key = %s,
                        key_wrap_nonce = %s,
                        active = TRUE,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = %s
                """
                cursor.execute(sql, (sender_id, sender_ephemeral_pub_b64, encrypted_aes_key_b64, key_wrap_nonce_b64, existing_share["id"]))
                share_id = existing_share["id"]
            else:
                sql = """
                    INSERT INTO file_key_shares
                    (file_id, sender_id, receiver_id, sender_ephemeral_public_key, encrypted_aes_key, key_wrap_nonce, active)
                    VALUES (%s, %s, %s, %s, %s, %s, TRUE)
                """
                cursor.execute(sql, (file_id, sender_id, receiver_id, sender_ephemeral_pub_b64, encrypted_aes_key_b64, key_wrap_nonce_b64))
                share_id = cursor.lastrowid

        logger.info(f"File ID {file_id} shared successfully with user ID {receiver_id} by owner ID {sender_id}")
        return {
            "success": True,
            "message": f"File shared successfully with {receiver['username']}",
            "share_id": share_id,
            "file_id": file_id,
            "receiver_id": receiver_id,
            "receiver_username": receiver["username"],
            "active": True
        }
    finally:
        conn.close()


def revoke_file_share(file_id: int, owner_id: int, receiver_id: int) -> dict:
    """
    Revokes access for a receiver by setting active = FALSE in file_key_shares.
    Restricted strictly to the file owner.
    """
    file_record = get_file_record(file_id)
    if not file_record:
        raise FileNotFoundError("File not found.")

    if file_record["owner_id"] != owner_id:
        raise PermissionError("Only the file owner can revoke file access.")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE file_key_shares SET active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE file_id = %s AND receiver_id = %s AND active = TRUE"
            cursor.execute(sql, (file_id, receiver_id))
            affected = cursor.rowcount

        if affected == 0:
            raise FileNotFoundError("Active share record not found.")

        return {
            "success": True,
            "message": "File share revoked successfully",
            "file_id": file_id,
            "receiver_id": receiver_id,
            "active": False
        }
    finally:
        conn.close()


def get_file_shares_for_owner(file_id: int, owner_id: int) -> list:
    """
    Retrieves all share records (active and revoked) for a specific file owned by owner_id.
    """
    file_record = get_file_record(file_id)
    if not file_record:
        raise FileNotFoundError("File not found.")

    if file_record["owner_id"] != owner_id:
        raise PermissionError("Only the file owner can view file shares.")

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT s.id, s.file_id, s.receiver_id, u.username AS receiver_username, u.email AS receiver_email, s.encrypted_aes_key, s.active, s.created_at, s.updated_at
                FROM file_key_shares s
                JOIN users u ON s.receiver_id = u.id
                WHERE s.file_id = %s
                ORDER BY s.created_at DESC
            """
            cursor.execute(sql, (file_id,))
            rows = cursor.fetchall()
            for r in rows:
                r["active"] = bool(r["active"])
                if r.get("created_at"):
                    r["created_at"] = str(r["created_at"])
                if r.get("updated_at"):
                    r["updated_at"] = str(r["updated_at"])
            return rows
    finally:
        conn.close()


def get_all_shares_by_sender(sender_id: int) -> list:
    """
    Retrieves all files shared by the sender across all recipients for the 'Shared By Me' view.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT s.id AS share_id, s.file_id, f.original_filename, f.file_size, f.sha256_hash, f.ipfs_cid, f.encrypted_key AS sender_key,
                       s.receiver_id, u.username AS receiver_username, u.email AS receiver_email,
                       s.encrypted_aes_key, s.active, s.created_at AS shared_at
                FROM file_key_shares s
                JOIN files f ON s.file_id = f.id
                JOIN users u ON s.receiver_id = u.id
                WHERE s.sender_id = %s OR f.owner_id = %s
                ORDER BY s.created_at DESC
            """
            cursor.execute(sql, (sender_id, sender_id))
            rows = cursor.fetchall()
            for r in rows:
                r["active"] = bool(r["active"])
                if r.get("shared_at"):
                    r["shared_at"] = str(r["shared_at"])
            return rows
    finally:
        conn.close()


def get_shared_files_for_receiver(receiver_id: int) -> list:
    """
    Retrieves metadata list of files actively shared with the specified receiver user.
    Enforces authorization check.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                SELECT f.id AS file_id, f.original_filename, f.file_size, f.mime_type, f.encryption_algorithm,
                       f.sha256_hash, f.ipfs_cid, f.blockchain_recorded, f.blockchain_tx_hash, f.encrypted_key AS sender_key,
                       f.owner_id, u.username AS owner_name, u.email AS owner_email,
                       s.created_at AS shared_at, s.active, s.encrypted_aes_key, s.sender_ephemeral_public_key
                FROM file_key_shares s
                JOIN files f ON s.file_id = f.id
                JOIN users u ON f.owner_id = u.id
                WHERE s.receiver_id = %s AND s.active = TRUE
                ORDER BY s.created_at DESC
            """
            cursor.execute(sql, (receiver_id,))
            rows = cursor.fetchall()
            for r in rows:
                r["active"] = bool(r["active"])
                r["blockchain_recorded"] = bool(r.get("blockchain_recorded"))
                if r.get("shared_at"):
                    r["shared_at"] = str(r["shared_at"])
            return rows
    finally:
        conn.close()


def inspect_file_payload(file_id: int, user_id: int) -> dict:
    """
    Performs real-time payload hash calculation and comparison for manual inspection.
    Retrieves the file payload from IPFS, calculates the SHA-256 hash immediately,
    and compares it with the sender's stored hash.
    """
    file_record = get_file_record(file_id)
    if not file_record:
        raise FileNotFoundError("File not found.")

    sender_hash = (file_record.get("sha256_hash") or "").lower()
    sender_key = file_record.get("encrypted_key") or ""
    ipfs_cid = file_record.get("ipfs_cid") or ""

    # Check authorization (Must be owner or receiver with an active share)
    is_authorized = (file_record["owner_id"] == user_id)
    wrapped_key = None
    sender_ephemeral_public_key = None

    if not is_authorized:
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT encrypted_aes_key, sender_ephemeral_public_key FROM file_key_shares WHERE file_id = %s AND receiver_id = %s AND active = TRUE",
                    (file_id, user_id)
                )
                share = cursor.fetchone()
                if share:
                    is_authorized = True
                    wrapped_key = share.get("encrypted_aes_key")
                    sender_ephemeral_public_key = share.get("sender_ephemeral_public_key")
        finally:
            conn.close()

    if not is_authorized:
        raise PermissionError("Unauthorized access to file payload inspection.")

    # Retrieve ciphertext payload from IPFS and generate real-time SHA-256 hash
    ciphertext_bytes = get_bytes_from_ipfs(ipfs_cid)
    generated_hash = calculate_bytes_sha256(ciphertext_bytes)

    hashes_match = (sender_hash != "" and sender_hash == generated_hash)

    return {
        "success": True,
        "file_id": file_id,
        "original_filename": file_record["original_filename"],
        "sender_hash": sender_hash,
        "generated_hash": generated_hash,
        "hashes_match": hashes_match,
        "sender_key": sender_key,
        "wrapped_key": wrapped_key,
        "sender_ephemeral_public_key": sender_ephemeral_public_key,
        "ipfs_cid": ipfs_cid
    }



def get_shareable_users(current_user_id: int) -> list:
    """
    Retrieves candidate users available for sharing (excluding the logged-in user).
    Excludes passwords and cryptographic secrets.
    """
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id, username, email FROM users WHERE id != %s ORDER BY username ASC"
            cursor.execute(sql, (current_user_id,))
            return cursor.fetchall()
    finally:
        conn.close()


def decrypt_and_read_shared_file(file_id: int, receiver_id: int):
    """
    Mandatory Receiver Download Flow:
    1. JWT Authentication (handled via blueprint decorator/authenticator)
    2. Active Share Authorization Check (file_key_shares.file_id == file_id AND receiver_id == receiver_id AND active == True)
       - Returns HTTP 403 (PermissionError) if missing or inactive.
    3. Retrieve encrypted binary bytes strictly from IPFS using CID
    4. SHA-256 Pre-Unwrap Integrity Check over retrieved IPFS bytes
       - Returns HTTP 409 (FileIntegrityError) if hash mismatch.
       - STOPS IMMEDIATELY before ECC private key decryption or key unwrapping!
    5. Receiver ECC Private Key Decryption using ENCRYPTION_MASTER_KEY.
    6. P-256 ECDH + HKDF-SHA256 + AES-256-GCM Key Unwrapping with Canonical AAD.
    7. Recover Original Phase 2 AES File Key.
    8. Execute Phase 2 AES-256-GCM File Decryption over ciphertext bytes.
    Returns tuple: (plaintext_bytes, original_filename, mime_type)
    """
    # 1. Retrieve Share Record & Enforce Authorization
    conn = get_db_connection()
    share_record = None
    try:
        with conn.cursor() as cursor:
            sql = "SELECT * FROM file_key_shares WHERE file_id = %s AND receiver_id = %s AND active = TRUE"
            cursor.execute(sql, (file_id, receiver_id))
            share_record = cursor.fetchone()
    finally:
        conn.close()

    if not share_record:
        raise PermissionError("You do not have active authorized access to this shared file.")

    file_record = get_file_record(file_id)
    if not file_record:
        raise FileNotFoundError("File not found.")

    sender_id = share_record["sender_id"]
    ipfs_cid = file_record.get("ipfs_cid")
    stored_hash = file_record.get("sha256_hash")

    if not stored_hash:
        raise FileIntegrityError("File integrity information is missing.")

    # 2. Retrieve Encrypted Payload from IPFS
    if ipfs_cid and ipfs_cid.strip():
        ciphertext_bytes = get_bytes_from_ipfs(ipfs_cid)
    else:
        raise IPFSNotFoundError("Encrypted file payload is unavailable on IPFS.")

    # 3. SHA-256 Integrity Verification (Executed BEFORE ECC unwrapping)
    retrieved_hash = calculate_bytes_sha256(ciphertext_bytes)
    if retrieved_hash.lower() != stored_hash.lower():
        raise FileIntegrityError("File integrity verification failed")

    # 4. ECC Key Unwrapping
    master_key = Config.get_master_key_bytes()
    receiver_user = ensure_user_ecc_keys(receiver_id)
    receiver_private_key_encrypted_b64 = receiver_user["ecc_private_key_encrypted"]

    # Unwrap original Phase 2 AES file key
    file_key = unwrap_file_key_for_receiver(
        encrypted_aes_key_b64=share_record["encrypted_aes_key"],
        key_wrap_nonce_b64=share_record["key_wrap_nonce"],
        sender_ephemeral_public_key_b64=share_record["sender_ephemeral_public_key"],
        receiver_private_key_encrypted_b64=receiver_private_key_encrypted_b64,
        master_key=master_key,
        file_id=file_id,
        sender_id=sender_id,
        receiver_id=receiver_id
    )

    # 5. Phase 2 AES-256-GCM File Decryption
    file_nonce = base64.b64decode(file_record["nonce"])
    plaintext_bytes = decrypt_file_data(ciphertext_bytes, file_key, file_nonce)

    return plaintext_bytes, file_record["original_filename"], file_record["mime_type"]
