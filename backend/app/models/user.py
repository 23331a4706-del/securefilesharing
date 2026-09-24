import bcrypt
from app.db import get_db_connection

def hash_password(password: str) -> str:
    """Hashes a plain-text password using bcrypt."""
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    """Verifies a plain-text password against a bcrypt hash."""
    if not password or not password_hash:
        return False
    return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))

from app.db import get_db_connection, save_user_to_persistent_backup, rehydrate_persistent_users

def find_by_email(email: str):
    """Finds a user by email, auto-rehydrating from persistent backup if needed."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id, username, email, password_hash, wallet_address, ecc_public_key, ecc_private_key_encrypted, created_at FROM users WHERE email = %s"
            cursor.execute(sql, (email.strip().lower(),))
            res = cursor.fetchone()
            if res:
                return res
        
        # Auto-rehydrate from JSON backup if missing (e.g. server restart)
        rehydrate_persistent_users(conn)
        with conn.cursor() as cursor:
            cursor.execute(sql, (email.strip().lower(),))
            return cursor.fetchone()
    finally:
        conn.close()

def find_by_username(username: str):
    """Finds a user by username, auto-rehydrating from persistent backup if needed."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id, username, email, password_hash, wallet_address, ecc_public_key, ecc_private_key_encrypted, created_at FROM users WHERE username = %s"
            cursor.execute(sql, (username.strip(),))
            res = cursor.fetchone()
            if res:
                return res
        
        # Auto-rehydrate from JSON backup if missing
        rehydrate_persistent_users(conn)
        with conn.cursor() as cursor:
            cursor.execute(sql, (username.strip(),))
            return cursor.fetchone()
    finally:
        conn.close()

def find_by_id(user_id: int):
    """Finds a user by ID."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id, username, email, wallet_address, ecc_public_key, ecc_private_key_encrypted, created_at FROM users WHERE id = %s"
            cursor.execute(sql, (user_id,))
            res = cursor.fetchone()
            if res:
                return res

        rehydrate_persistent_users(conn)
        with conn.cursor() as cursor:
            cursor.execute(sql, (user_id,))
            return cursor.fetchone()
    finally:
        conn.close()

def create_user(username: str, email: str, password_hash: str) -> int:
    """
    Creates a new user record in the database, generates persistent NIST P-256 (secp256r1)
    ECC keypair protected by ENCRYPTION_MASTER_KEY, and returns the new user ID.
    """
    from app.config import Config
    from app.services.encryption_service import generate_user_ecc_keypair

    master_key = Config.get_master_key_bytes()
    public_key_b64, private_key_encrypted_b64 = generate_user_ecc_keypair(master_key)

    conn = get_db_connection()
    try:
        clean_username = username.strip()
        clean_email = email.strip().lower()

        with conn.cursor() as cursor:
            sql = """
                INSERT INTO users (username, email, password_hash, wallet_address, ecc_public_key, ecc_private_key_encrypted)
                VALUES (%s, %s, %s, NULL, %s, %s)
            """
            cursor.execute(sql, (clean_username, clean_email, password_hash, public_key_b64, private_key_encrypted_b64))
            row_id = cursor.lastrowid
        conn.commit()

        # Save record permanently to persistent JSON backup engine
        save_user_to_persistent_backup({
            "id": row_id,
            "username": clean_username,
            "email": clean_email,
            "password_hash": password_hash,
            "wallet_address": None,
            "ecc_public_key": public_key_b64,
            "ecc_private_key_encrypted": private_key_encrypted_b64
        })

        return row_id
    finally:
        conn.close()

def update_user_wallet(user_id: int, wallet_address: str):
    """Updates a user's connected Ethereum wallet address."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE users SET wallet_address = %s WHERE id = %s"
            cursor.execute(sql, (wallet_address.strip(), user_id))
        conn.commit()

        # Sync update to persistent backup
        user_rec = find_by_id(user_id)
        if user_rec:
            save_user_to_persistent_backup(user_rec)
    finally:
        conn.close()

def ensure_user_ecc_keys(user_id: int) -> dict:
    """
    Ensures that a user has a persistent ECC keypair.
    If missing (e.g. legacy users), generates once and updates database.
    If keys already exist, returns existing keys without regenerating.
    """
    user = find_by_id(user_id)
    if not user:
        raise ValueError("User not found.")

    if user.get("ecc_public_key") and user.get("ecc_private_key_encrypted"):
        return user

    from app.config import Config
    from app.services.encryption_service import generate_user_ecc_keypair

    master_key = Config.get_master_key_bytes()
    public_key_b64, private_key_encrypted_b64 = generate_user_ecc_keypair(master_key)

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = """
                UPDATE users 
                SET ecc_public_key = %s, ecc_private_key_encrypted = %s 
                WHERE id = %s
            """
            cursor.execute(sql, (public_key_b64, private_key_encrypted_b64, user_id))
        conn.commit()
        user["ecc_public_key"] = public_key_b64
        user["ecc_private_key_encrypted"] = private_key_encrypted_b64
        return user
    finally:
        conn.close()
