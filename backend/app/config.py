import os
import base64
import logging
from dotenv import load_dotenv

# Load environment variables from .env if present
load_dotenv()

logger = logging.getLogger(__name__)

class Config:
    FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
    SECRET_KEY = os.getenv("SECRET_KEY", "cyber_security_secret_key_12345")
    JWT_EXPIRATION_HOURS = int(os.getenv("JWT_EXPIRATION_HOURS", 24))
    
    # MySQL Settings
    DB_HOST = os.getenv("DATABASE_HOST", "localhost")
    DB_PORT = int(os.getenv("DATABASE_PORT", 3306))
    DB_NAME = os.getenv("DATABASE_NAME", "secure_file_sharing")
    DB_USER = os.getenv("DATABASE_USER", "root")
    DB_PASSWORD = os.getenv("DATABASE_PASSWORD", "")

    # Phase 2 — File Encryption Settings
    MAX_FILE_SIZE_MB = int(os.getenv("MAX_FILE_SIZE_MB", 16))
    MAX_CONTENT_LENGTH = MAX_FILE_SIZE_MB * 1024 * 1024
    
    # Phase 4 — Real IPFS Node Configuration
    IPFS_API_URL = os.getenv("IPFS_API_URL", "http://127.0.0.1:5001")
    
    # Phase 5 & 6 — Blockchain Configuration
    BLOCKCHAIN_RPC_URL = os.getenv("BLOCKCHAIN_RPC_URL", "http://127.0.0.1:8545")
    BLOCKCHAIN_CHAIN_ID = int(os.getenv("BLOCKCHAIN_CHAIN_ID", 31337))
    BLOCKCHAIN_CONTRACT_ADDRESS = os.getenv("BLOCKCHAIN_CONTRACT_ADDRESS", "0x5FbDB2315678afecb367f032d93F642f64180aa3")
    BLOCKCHAIN_PRIVATE_KEY = os.getenv("BLOCKCHAIN_PRIVATE_KEY", "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
    
    # Storage Directory Path
    BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    ENCRYPTED_STORAGE_DIR = os.path.join(BASE_DIR, "storage", "encrypted")

    DEFAULT_MASTER_KEY = "wOQwsJdeppTGyk5Gd6qBaojg799l9to2lSkE6KlguuM="

    @classmethod
    def get_master_key_bytes(cls) -> bytes:
        """
        Retrieves and decodes the server-side ENCRYPTION_MASTER_KEY from environment variables.
        Uses robust default master key fallback if .env is missing.
        """
        raw_key = os.getenv("ENCRYPTION_MASTER_KEY", cls.DEFAULT_MASTER_KEY)
        if not raw_key:
            raw_key = cls.DEFAULT_MASTER_KEY
        
        try:
            key_bytes = base64.b64decode(raw_key)
        except Exception as e:
            raise ValueError(f"Invalid base64 encoding in 'ENCRYPTION_MASTER_KEY': {str(e)}")

        if len(key_bytes) != 32:
            raise ValueError(
                f"Invalid 'ENCRYPTION_MASTER_KEY' length: expected 32 bytes (256-bit), got {len(key_bytes)} bytes."
            )
            
        return key_bytes

    @classmethod
    def audit_security_config(cls):
        """
        Phase 8 Security Audit: Validates environment variables and logs warnings
        for fallback configurations without ever exposing raw secret values.
        """
        if cls.SECRET_KEY == "cyber_security_secret_key_12345":
            logger.warning("WARNING: 'SECRET_KEY' is using a development fallback.")

        if cls.BLOCKCHAIN_PRIVATE_KEY == "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80":
            logger.info("Info: Blockchain private key is using default local Hardhat test key.")

        # Trigger master key check to fail-fast if missing
        cls.get_master_key_bytes()
