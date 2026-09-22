import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag
from app.config import Config

class CryptographyError(Exception):
    """Base exception for cryptographic operation failures."""
    pass

class AuthenticationTagMismatchError(CryptographyError):
    """Raised when AES-GCM authentication tag validation fails (tampered or wrong key)."""
    pass


def generate_file_key() -> bytes:
    """Generates a cryptographically random 256-bit (32-byte) AES key."""
    return os.urandom(32)


def generate_nonce() -> bytes:
    """Generates a cryptographically random 96-bit (12-byte) AES-GCM nonce."""
    return os.urandom(12)


def encrypt_file_data(plaintext_bytes: bytes, file_key: bytes, nonce: bytes) -> bytes:
    """
    Encrypts plaintext bytes using AES-256-GCM.
    Returns ciphertext with appended 128-bit authentication tag.
    """
    if len(file_key) != 32:
        raise CryptographyError("AES-256 key must be exactly 32 bytes.")
    if len(nonce) != 12:
        raise CryptographyError("AES-GCM nonce must be exactly 12 bytes.")

    try:
        aesgcm = AESGCM(file_key)
        return aesgcm.encrypt(nonce, plaintext_bytes, None)
    except Exception as e:
        raise CryptographyError(f"Encryption failed: {str(e)}")


def decrypt_file_data(ciphertext_bytes: bytes, file_key: bytes, nonce: bytes) -> bytes:
    """
    Decrypts ciphertext bytes using AES-256-GCM.
    Verifies authentication tag and raises AuthenticationTagMismatchError if corrupted.
    """
    if len(file_key) != 32:
        raise CryptographyError("AES-256 key must be exactly 32 bytes.")
    if len(nonce) != 12:
        raise CryptographyError("AES-GCM nonce must be exactly 12 bytes.")

    try:
        aesgcm = AESGCM(file_key)
        return aesgcm.decrypt(nonce, ciphertext_bytes, None)
    except InvalidTag:
        raise AuthenticationTagMismatchError("AES-GCM authentication tag verification failed. Data is corrupted or key is incorrect.")
    except Exception as e:
        raise CryptographyError(f"Decryption failed: {str(e)}")


def protect_file_key(file_key: bytes, master_key: bytes) -> str:
    """
    Encrypts the per-file AES key using the server-side master key.
    Format: Base64( key_nonce [12 bytes] + ciphertext_with_tag )
    """
    key_nonce = generate_nonce()
    aesgcm = AESGCM(master_key)
    encrypted_key_bytes = aesgcm.encrypt(key_nonce, file_key, None)
    combined = key_nonce + encrypted_key_bytes
    return base64.b64encode(combined).decode('utf-8')


def unprotect_file_key(protected_key_b64: str, master_key: bytes) -> bytes:
    """
    Decrypts the protected per-file AES key using the server-side master key.
    """
    try:
        combined = base64.b64decode(protected_key_b64)
        if len(combined) < 13:
            raise CryptographyError("Protected key payload is invalid.")
        
        key_nonce = combined[:12]
        ciphertext_bytes = combined[12:]
        
        aesgcm = AESGCM(master_key)
        return aesgcm.decrypt(key_nonce, ciphertext_bytes, None)
    except InvalidTag:
        raise AuthenticationTagMismatchError("Master key failed to decrypt protected AES key.")
    except Exception as e:
        raise CryptographyError(f"Failed to unprotect AES key: {str(e)}")


# -----------------------------------------------------------------------------
# PHASE 7 — ECC P-256 / ECDH / HKDF-SHA256 / AES-256-GCM KEY WRAPPING IMPLEMENTATION
# -----------------------------------------------------------------------------

def build_phase7_aad(file_id: int, sender_id: int, receiver_id: int) -> bytes:
    """
    Constructs the canonical AAD for Phase 7 key wrapping/unwrapping:
    Format: phase7-key-share-v1|{file_id}|{sender_id}|{receiver_id}
    Binds file ID, sender ID, and receiver ID to prevent key-share copy attacks.
    """
    return f"phase7-key-share-v1|{file_id}|{sender_id}|{receiver_id}".encode('utf-8')


def serialize_ecc_public_key(public_key: ec.EllipticCurvePublicKey) -> str:
    """
    Serializes a P-256 public key to Base64-encoded uncompressed point bytes.
    """
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return base64.b64encode(raw_bytes).decode('utf-8')


def deserialize_ecc_public_key(public_key_b64: str) -> ec.EllipticCurvePublicKey:
    """
    Deserializes a Base64-encoded uncompressed P-256 public key point.
    """
    try:
        raw_bytes = base64.b64decode(public_key_b64)
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw_bytes)
    except Exception as e:
        raise CryptographyError(f"Failed to deserialize ECC public key: {str(e)}")


def generate_user_ecc_keypair(master_key: bytes) -> tuple:
    """
    Generates a persistent long-term NIST P-256 (secp256r1) keypair for a user.
    Protects the private key using ENCRYPTION_MASTER_KEY via AES-256-GCM.
    Returns tuple: (ecc_public_key_b64, ecc_private_key_encrypted_b64)
    Format of ecc_private_key_encrypted_b64: Base64( nonce [12b] + ciphertext_with_tag )
    """
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    public_key_b64 = serialize_ecc_public_key(public_key)

    # Serialize private key to PKCS8 DER format
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Encrypt private key with master key using AES-256-GCM
    nonce = generate_nonce()
    aesgcm = AESGCM(master_key)
    encrypted_priv = aesgcm.encrypt(nonce, private_key_bytes, None)

    combined = nonce + encrypted_priv
    private_key_encrypted_b64 = base64.b64encode(combined).decode('utf-8')

    return public_key_b64, private_key_encrypted_b64


def decrypt_user_ecc_private_key(private_key_encrypted_b64: str, master_key: bytes) -> ec.EllipticCurvePrivateKey:
    """
    Decrypts user's master-key-encrypted ECC private key.
    """
    try:
        combined = base64.b64decode(private_key_encrypted_b64)
        if len(combined) < 13:
            raise CryptographyError("Invalid encrypted private key payload.")

        nonce = combined[:12]
        ciphertext_bytes = combined[12:]

        aesgcm = AESGCM(master_key)
        private_key_bytes = aesgcm.decrypt(nonce, ciphertext_bytes, None)

        return serialization.load_der_private_key(private_key_bytes, password=None)
    except InvalidTag:
        raise AuthenticationTagMismatchError("Failed to decrypt user ECC private key: tag mismatch or wrong master key.")
    except Exception as e:
        raise CryptographyError(f"Failed to decrypt ECC private key: {str(e)}")


def wrap_file_key_for_receiver(
    file_key: bytes,
    receiver_public_key_b64: str,
    file_id: int,
    sender_id: int,
    receiver_id: int
) -> tuple:
    """
    Phase 7 Key Wrapping Algorithm:
    1. Generate sender ephemeral P-256 key pair.
    2. Derive ECDH shared secret using sender ephemeral private key + receiver public key.
    3. HKDF-SHA256 derivation -> 32-byte key-wrapping key (info = b"secure-file-sharing-phase7-key-wrap").
    4. AES-256-GCM encrypt existing AES file key using derived 32-byte key, fresh nonce, and canonical AAD.
    5. Sender ephemeral private key is discarded.
    Returns tuple: (sender_ephemeral_public_key_b64, encrypted_aes_key_b64, key_wrap_nonce_b64)
    """
    if len(file_key) != 32:
        raise CryptographyError("File AES key must be 32 bytes.")

    receiver_public_key = deserialize_ecc_public_key(receiver_public_key_b64)

    # 1. Ephemeral key pair
    ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public_key = ephemeral_private_key.public_key()
    sender_ephemeral_public_key_b64 = serialize_ecc_public_key(ephemeral_public_key)

    # 2. ECDH
    ecdh_shared_secret = ephemeral_private_key.exchange(ec.ECDH(), receiver_public_key)

    # 3. HKDF-SHA256
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"secure-file-sharing-phase7-key-wrap"
    )
    wrapping_key = hkdf.derive(ecdh_shared_secret)

    # 4. AES-256-GCM Key Wrapping with Canonical AAD
    nonce = generate_nonce()
    aad = build_phase7_aad(file_id, sender_id, receiver_id)

    aesgcm = AESGCM(wrapping_key)
    encrypted_key_bytes = aesgcm.encrypt(nonce, file_key, aad)

    encrypted_aes_key_b64 = base64.b64encode(encrypted_key_bytes).decode('utf-8')
    key_wrap_nonce_b64 = base64.b64encode(nonce).decode('utf-8')

    return sender_ephemeral_public_key_b64, encrypted_aes_key_b64, key_wrap_nonce_b64


def unwrap_file_key_for_receiver(
    encrypted_aes_key_b64: str,
    key_wrap_nonce_b64: str,
    sender_ephemeral_public_key_b64: str,
    receiver_private_key_encrypted_b64: str,
    master_key: bytes,
    file_id: int,
    sender_id: int,
    receiver_id: int
) -> bytes:
    """
    Phase 7 Key Unwrapping Algorithm:
    1. Decrypt receiver's master-key-encrypted ECC private key.
    2. Deserialize sender's ephemeral P-256 public key.
    3. Derive identical ECDH shared secret using receiver private key + sender ephemeral public key.
    4. HKDF-SHA256 derivation -> identical 32-byte key-wrapping key.
    5. AES-256-GCM decrypt encrypted_aes_key using canonical AAD.
    Returns original 32-byte Phase 2 AES file key.
    """
    try:
        receiver_private_key = decrypt_user_ecc_private_key(receiver_private_key_encrypted_b64, master_key)
        sender_ephemeral_public_key = deserialize_ecc_public_key(sender_ephemeral_public_key_b64)

        # 1. ECDH
        ecdh_shared_secret = receiver_private_key.exchange(ec.ECDH(), sender_ephemeral_public_key)

        # 2. HKDF-SHA256
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"secure-file-sharing-phase7-key-wrap"
        )
        wrapping_key = hkdf.derive(ecdh_shared_secret)

        # 3. AES-256-GCM Unwrap
        nonce = base64.b64decode(key_wrap_nonce_b64)
        encrypted_key_bytes = base64.b64decode(encrypted_aes_key_b64)
        aad = build_phase7_aad(file_id, sender_id, receiver_id)

        aesgcm = AESGCM(wrapping_key)
        return aesgcm.decrypt(nonce, encrypted_key_bytes, aad)
    except InvalidTag:
        raise AuthenticationTagMismatchError("Phase 7 key unwrapping failed: authentication tag or canonical AAD mismatch.")
    except Exception as e:
        raise CryptographyError(f"Failed to unwrap file key: {str(e)}")
