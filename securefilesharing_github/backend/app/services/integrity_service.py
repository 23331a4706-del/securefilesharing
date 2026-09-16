import os
import hashlib
import hmac
import re

class FileIntegrityError(Exception):
    """Raised when SHA-256 file integrity verification fails."""
    pass

HEX_64_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")

def calculate_file_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """
    Calculates the SHA-256 checksum over the stored binary file on disk.
    Uses chunked reading (64KB chunks) for memory efficiency.
    Returns 64-character lowercase hexadecimal digest.
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target file for SHA-256 hashing not found: {file_path}")

    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(chunk_size):
            sha256_hash.update(chunk)
            
    return sha256_hash.hexdigest().lower()


def calculate_bytes_sha256(bytes_data: bytes) -> str:
    """Calculates SHA-256 hex digest for byte arrays in memory."""
    if not isinstance(bytes_data, (bytes, bytearray)):
        raise TypeError("Input data must be bytes or bytearray.")
    return hashlib.sha256(bytes_data).hexdigest().lower()


def verify_file_integrity(file_path: str, expected_hash: str) -> bool:
    """
    Verifies disk file integrity against expected SHA-256 hash using constant-time comparison.
    Raises FileIntegrityError if hash is missing, malformed, or mismatched.
    """
    if not expected_hash:
        raise FileIntegrityError("File integrity information is unavailable (SHA-256 hash missing from database).")

    cleaned_expected = str(expected_hash).strip().lower()
    if not HEX_64_PATTERN.match(cleaned_expected):
        raise FileIntegrityError("Invalid SHA-256 format stored in database.")

    actual_hash = calculate_file_sha256(file_path)

    if not hmac.compare_digest(actual_hash, cleaned_expected):
        raise FileIntegrityError("File integrity verification failed. Encrypted storage file has been modified or corrupted.")

    return True
