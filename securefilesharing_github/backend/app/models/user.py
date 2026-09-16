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

def find_by_email(email: str):
    """Finds a user by email."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id, username, email, password_hash, wallet_address, ecc_public_key, ecc_private_key_encrypted, created_at FROM users WHERE email = %s"
            cursor.execute(sql, (email.strip().lower(),))
            return cursor.fetchone()
    finally:
        conn.close()

def find_by_username(username: str):
    """Finds a user by username."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "SELECT id, username, email, password_hash, wallet_address, ecc_public_key, ecc_private_key_encrypted, created_at FROM users WHERE username = %s"
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
        with conn.cursor() as cursor:
            sql = """
                INSERT INTO users (username, email, password_hash, wallet_address, ecc_public_key, ecc_private_key_encrypted)
                VALUES (%s, %s, %s, NULL, %s, %s)
            """
            cursor.execute(sql, (username.strip(), email.strip().lower(), password_hash, public_key_b64, private_key_encrypted_b64))
            return cursor.lastrowid
    finally:
        conn.close()

def update_user_wallet(user_id: int, wallet_address: str):
    """Updates a user's connected Ethereum wallet address."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            sql = "UPDATE users SET wallet_address = %s WHERE id = %s"
            cursor.execute(sql, (wallet_address.strip(), user_id))
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
        user["ecc_public_key"] = public_key_b64
        user["ecc_private_key_encrypted"] = private_key_encrypted_b64
        return user
    finally:
        conn.close()
