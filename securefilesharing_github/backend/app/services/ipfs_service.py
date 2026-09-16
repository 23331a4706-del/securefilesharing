import os
import json
import hashlib
import requests
import logging
from app.config import Config

logger = logging.getLogger(__name__)

class IPFSException(Exception):
    """Base exception class for IPFS operations."""
    pass

class IPFSUnavailableError(IPFSException):
    """Raised when the local IPFS Kubo daemon is unreachable or offline."""
    pass

class IPFSNotFoundError(IPFSException):
    """Raised when a requested CID is missing, invalid, or unavailable on IPFS."""
    pass


def get_ipfs_url(api_url: str = None) -> str:
    """Returns configured IPFS API base URL, stripping trailing slashes."""
    url = api_url or getattr(Config, "IPFS_API_URL", "http://127.0.0.1:5001")
    return url.rstrip("/")


def verify_ipfs_connection(api_url: str = None) -> bool:
    """
    Verifies whether the local IPFS Kubo node API is reachable and responding.
    Returns True if reachable, False otherwise.
    """
    base_url = get_ipfs_url(api_url)
    try:
        res = requests.post(f"{base_url}/api/v0/version", timeout=2.0)
        return res.status_code == 200
    except Exception:
        return False


def _ensure_local_ipfs_storage_dir() -> str:
    """Ensures local fallback storage directory exists."""
    storage_dir = getattr(Config, "ENCRYPTED_STORAGE_DIR", None)
    if not storage_dir:
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        storage_dir = os.path.join(base_dir, "storage", "encrypted")
    os.makedirs(storage_dir, exist_ok=True)
    return storage_dir


def add_bytes_to_ipfs(encrypted_bytes: bytes, api_url: str = None) -> str:
    """
    Uploads encrypted binary data to local IPFS Kubo node using /api/v0/add.
    If IPFS Kubo daemon is offline, falls back to local IPFS storage vault.
    Returns the real or simulated Content Identifier (CID).
    """
    if not isinstance(encrypted_bytes, bytes) or len(encrypted_bytes) == 0:
        raise ValueError("Cannot upload empty or non-bytes data to IPFS.")

    base_url = get_ipfs_url(api_url)
    files = {
        'file': ('encrypted.enc', encrypted_bytes, 'application/octet-stream')
    }

    # 1. Attempt connection to real IPFS Kubo node
    try:
        res = requests.post(f"{base_url}/api/v0/add?pin=true", files=files, timeout=5.0)
        if res.status_code == 200:
            lines = [line.strip() for line in res.text.strip().split('\n') if line.strip()]
            last_json = json.loads(lines[-1])
            cid = last_json.get("Hash")
            if cid:
                logger.info(f"Successfully pinned file to IPFS node (CID: {cid})")
                return cid
    except Exception as e:
        logger.warning(f"Real IPFS node unavailable on {base_url}. Using local IPFS vault fallback: {e}")

    # 2. Fallback to Local IPFS Vault Storage
    sha256_hex = hashlib.sha256(encrypted_bytes).hexdigest()
    cid = f"QmSimulatedIPFS{sha256_hex[:32]}"
    
    storage_dir = _ensure_local_ipfs_storage_dir()
    file_path = os.path.join(storage_dir, f"{cid}.enc")
    
    with open(file_path, "wb") as f:
        f.write(encrypted_bytes)
        
    logger.info(f"Persisted encrypted bytes to local IPFS storage vault (CID: {cid})")
    return cid


def get_bytes_from_ipfs(cid: str, api_url: str = None) -> bytes:
    """
    Retrieves encrypted binary data from IPFS using /api/v0/cat?arg=<cid>.
    If real IPFS daemon is offline or CID is local, reads from local IPFS vault.
    """
    if not cid or not isinstance(cid, str) or cid.strip() == "":
        raise IPFSNotFoundError("Encrypted file is unavailable from decentralized storage")

    cid = cid.strip()

    # 1. Check local IPFS vault first
    storage_dir = _ensure_local_ipfs_storage_dir()
    local_file_path = os.path.join(storage_dir, f"{cid}.enc")
    if os.path.exists(local_file_path):
        with open(local_file_path, "rb") as f:
            return f.read()

    # 2. Try fetching from real IPFS Kubo daemon
    base_url = get_ipfs_url(api_url)
    try:
        res = requests.post(f"{base_url}/api/v0/cat", params={'arg': cid}, timeout=5.0)
        if res.status_code == 200:
            return res.content
        if res.status_code in (404, 400):
            raise IPFSNotFoundError("Encrypted file is unavailable from decentralized storage")
    except IPFSNotFoundError:
        raise
    except Exception as e:
        logger.warning(f"Failed to fetch CID {cid} from IPFS daemon: {e}")

    raise IPFSNotFoundError(f"Encrypted file for CID '{cid}' is unavailable")


def unpin_from_ipfs(cid: str, api_url: str = None) -> bool:
    """
    Unpins CID from IPFS Kubo node or removes from local IPFS vault.
    """
    if not cid or not isinstance(cid, str) or cid.strip() == "":
        return False

    cid = cid.strip()
    storage_dir = _ensure_local_ipfs_storage_dir()
    local_file_path = os.path.join(storage_dir, f"{cid}.enc")
    if os.path.exists(local_file_path):
        try:
            os.remove(local_file_path)
        except OSError:
            pass

    base_url = get_ipfs_url(api_url)
    try:
        res = requests.post(f"{base_url}/api/v0/pin/rm", params={'arg': cid}, timeout=5.0)
        return res.status_code == 200
    except Exception:
        return True
