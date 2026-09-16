import os
import json
import logging
from typing import Dict, Any, Tuple
from web3 import Web3
from web3.exceptions import Web3Exception, ContractLogicError
from app.config import Config

logger = logging.getLogger(__name__)

# -----------------------------------------------------------------------------
# Custom Exceptions for Blockchain Operations
# -----------------------------------------------------------------------------
class BlockchainException(Exception):
    """Base exception for all blockchain-related errors."""
    pass

class BlockchainUnavailableError(BlockchainException):
    """Raised when the Web3 RPC node is unreachable or offline."""
    pass

class BlockchainConfigurationError(BlockchainException):
    """Raised when contract address, ABI, or signer key is misconfigured."""
    pass

class BlockchainRegistrationError(BlockchainException):
    """Raised when a blockchain registration transaction fails or reverts."""
    pass

class BlockchainMetadataMismatchError(BlockchainException):
    """Raised when requested file metadata conflicts with existing immutable on-chain record."""
    pass

# -----------------------------------------------------------------------------
# Helper: ABI Loader
# -----------------------------------------------------------------------------
def _load_contract_abi() -> list:
    """
    Loads contract ABI from Hardhat build artifact JSON.
    Searches multiple potential relative directory paths.
    """
    possible_paths = [
        os.path.join(Config.BASE_DIR, "..", "blockchain", "artifacts", "contracts", "FileMetadataRegistry.sol", "FileMetadataRegistry.json"),
        os.path.join(Config.BASE_DIR, "blockchain", "artifacts", "contracts", "FileMetadataRegistry.sol", "FileMetadataRegistry.json"),
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "blockchain", "artifacts", "contracts", "FileMetadataRegistry.sol", "FileMetadataRegistry.json"))
    ]

    for artifact_path in possible_paths:
        if os.path.exists(artifact_path):
            try:
                with open(artifact_path, "r", encoding="utf-8") as f:
                    artifact_json = json.load(f)
                    return artifact_json.get("abi", [])
            except Exception as e:
                logger.error(f"Failed to parse ABI from {artifact_path}: {e}")

    raise BlockchainConfigurationError(
        "Smart contract ABI artifact 'FileMetadataRegistry.json' not found. "
        "Run 'npx hardhat compile' inside the blockchain directory."
    )

# -----------------------------------------------------------------------------
# Core Web3 & Contract Accessors
# -----------------------------------------------------------------------------
def _get_web3() -> Web3:
    """Initializes and returns Web3 instance connected to Hardhat RPC."""
    try:
        w3 = Web3(Web3.HTTPProvider(Config.BLOCKCHAIN_RPC_URL, request_kwargs={"timeout": 5}))
        if not w3.is_connected():
            raise BlockchainUnavailableError(
                f"Cannot connect to Hardhat node at '{Config.BLOCKCHAIN_RPC_URL}'."
            )
        return w3
    except Exception as e:
        if isinstance(e, BlockchainUnavailableError):
            raise
        raise BlockchainUnavailableError(f"Web3 connection error: {str(e)}")

def get_contract() -> Tuple[Web3, Any, str]:
    """
    Returns (w3, contract_instance, checksummed_contract_address).
    Validates contract configuration and bytecode deployment.
    """
    w3 = _get_web3()
    contract_addr = Config.BLOCKCHAIN_CONTRACT_ADDRESS
    if not contract_addr or not Web3.is_address(contract_addr):
        raise BlockchainConfigurationError(
            f"Invalid or missing BLOCKCHAIN_CONTRACT_ADDRESS: '{contract_addr}'"
        )

    checksum_addr = w3.to_checksum_address(contract_addr)
    bytecode = w3.eth.get_code(checksum_addr)
    if not bytecode or bytecode == b"" or bytecode == b"0x":
        raise BlockchainConfigurationError(
            f"No smart contract code found at address '{checksum_addr}'. "
            "Ensure the contract is deployed using 'npx hardhat run scripts/deploy.js --network localhost'."
        )

    abi = _load_contract_abi()
    contract = w3.eth.contract(address=checksum_addr, abi=abi)
    return w3, contract, checksum_addr

# -----------------------------------------------------------------------------
# Blockchain Connection Verification & Security Check
# -----------------------------------------------------------------------------
def verify_blockchain_connection() -> Dict[str, Any]:
    """
    Validates Web3 RPC connectivity, chain ID 31337, deployed contract code,
    and confirms that the configured signing account is the contract owner.
    """
    w3, contract, checksum_addr = get_contract()

    # Verify Chain ID
    actual_chain_id = w3.eth.chain_id
    if actual_chain_id != Config.BLOCKCHAIN_CHAIN_ID:
        raise BlockchainConfigurationError(
            f"Chain ID mismatch: expected {Config.BLOCKCHAIN_CHAIN_ID}, got {actual_chain_id}"
        )

    # Verify Private Key & Account
    private_key = Config.BLOCKCHAIN_PRIVATE_KEY
    if not private_key:
        raise BlockchainConfigurationError("BLOCKCHAIN_PRIVATE_KEY is missing from environment variables.")

    try:
        signer_account = w3.eth.account.from_key(private_key)
    except Exception as e:
        raise BlockchainConfigurationError(f"Invalid BLOCKCHAIN_PRIVATE_KEY: {str(e)}")

    # Verify Owner Status
    try:
        contract_owner = contract.functions.owner().call()
    except Exception as e:
        raise BlockchainConfigurationError(f"Failed to query contract owner: {str(e)}")

    if signer_account.address.lower() != contract_owner.lower():
        raise BlockchainConfigurationError(
            f"Security Configuration Error: Signer account '{signer_account.address}' "
            f"is NOT the contract owner '{contract_owner}'."
        )

    return {
        "connected": True,
        "chain_id": actual_chain_id,
        "contract_address": checksum_addr,
        "contract_owner": contract_owner,
        "signer_address": signer_account.address
    }

# -----------------------------------------------------------------------------
# Smart Contract Operations
# -----------------------------------------------------------------------------
def is_file_registered(file_id: int) -> bool:
    """Checks if a file ID is registered on the blockchain."""
    w3, contract, _ = get_contract()
    try:
        return contract.functions.isFileRegistered(int(file_id)).call()
    except Exception as e:
        raise BlockchainException(f"Failed to query isFileRegistered({file_id}): {str(e)}")

def get_file_metadata(file_id: int) -> Dict[str, Any]:
    """
    Retrieves the immutable metadata record from the smart contract for a given file ID.
    Returns: file_id, owner_id, ipfs_cid, sha256_hash, timestamp, active.
    """
    w3, contract, _ = get_contract()
    try:
        record = contract.functions.getFile(int(file_id)).call()
        return {
            "file_id": record[0],
            "owner_id": str(record[1]),
            "ipfs_cid": record[2],
            "sha256_hash": record[3],
            "timestamp": record[4],
            "active": record[5]
        }
    except ContractLogicError as cle:
        raise BlockchainException(f"Smart contract revert: {str(cle)}")
    except Exception as e:
        raise BlockchainException(f"Failed to retrieve file metadata for ID {file_id}: {str(e)}")

def register_file_metadata(
    file_id: int,
    owner_id: Any,
    ipfs_cid: str,
    sha256_hash: str
) -> Dict[str, Any]:
    """
    Registers file metadata on the Solidity smart contract via a real signed transaction.
    
    Validation & Idempotency Rules:
    1. Validates non-zero file_id, non-empty owner_id and ipfs_cid, 64-char hex sha256_hash.
    2. If file_id is already registered on-chain:
       - If metadata matches requested values: returns existing record status without re-transacting.
       - If metadata differs: raises BlockchainMetadataMismatchError.
    3. Builds, signs using BLOCKCHAIN_PRIVATE_KEY, sends raw transaction, and waits for confirmation.
    4. Returns real transaction hash hex string (0x...).
    """
    file_id = int(file_id)
    owner_id = str(owner_id).strip()
    ipfs_cid = str(ipfs_cid).strip()
    sha256_hash = str(sha256_hash).strip().lower()

    if file_id <= 0:
        raise ValueError("Invalid file ID: must be greater than zero.")
    if not owner_id:
        raise ValueError("Invalid owner ID: cannot be empty.")
    if not ipfs_cid:
        raise ValueError("Invalid IPFS CID: cannot be empty.")
    if len(sha256_hash) != 64:
        raise ValueError("Invalid SHA-256 hash: must be exactly 64 hexadecimal characters.")

    w3, contract, _ = get_contract()

    # Idempotency Check
    if contract.functions.isFileRegistered(file_id).call():
        existing = get_file_metadata(file_id)
        if (existing["ipfs_cid"] == ipfs_cid and
            existing["sha256_hash"].lower() == sha256_hash and
            str(existing["owner_id"]) == owner_id):
            logger.info(f"File ID {file_id} is already registered on-chain with matching metadata.")
            return {
                "success": True,
                "already_registered": True,
                "file_id": file_id,
                "transaction_hash": None,
                "metadata": existing
            }
        else:
            raise BlockchainMetadataMismatchError(
                f"File ID {file_id} is already registered on-chain with conflicting metadata."
            )

    # Build Transaction
    private_key = Config.BLOCKCHAIN_PRIVATE_KEY
    if not private_key:
        raise BlockchainConfigurationError("BLOCKCHAIN_PRIVATE_KEY is missing.")

    signer_account = w3.eth.account.from_key(private_key)
    nonce = w3.eth.get_transaction_count(signer_account.address, "pending")

    tx_func = contract.functions.registerFile(file_id, owner_id, ipfs_cid, sha256_hash)

    try:
        gas_estimate = tx_func.estimate_gas({"from": signer_account.address})
        gas_limit = int(gas_estimate * 1.2)
    except Exception as e:
        logger.warning(f"Gas estimation failed, using fallback 300000: {e}")
        gas_limit = 300000

    tx_dict = tx_func.build_transaction({
        "from": signer_account.address,
        "nonce": nonce,
        "chainId": Config.BLOCKCHAIN_CHAIN_ID,
        "gas": gas_limit,
        "gasPrice": w3.eth.gas_price
    })

    # Sign & Broadcast Transaction
    signed_tx = w3.eth.account.sign_transaction(tx_dict, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_hash_hex = w3.to_hex(tx_hash)

    logger.info(f"Broadcasted transaction for file_id {file_id}. Tx Hash: {tx_hash_hex}")

    # Wait for Confirmation
    try:
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=15)
    except Exception as e:
        raise BlockchainRegistrationError(f"Transaction confirmation timed out or failed: {str(e)}")

    if receipt.get("status") != 1:
        raise BlockchainRegistrationError(f"Blockchain transaction reverted (status 0). Tx Hash: {tx_hash_hex}")

    logger.info(f"Successfully recorded file_id {file_id} on blockchain. Tx Hash: {tx_hash_hex}")

    return {
        "success": True,
        "already_registered": False,
        "file_id": file_id,
        "transaction_hash": tx_hash_hex,
        "block_number": receipt.get("blockNumber")
    }

def deactivate_file(file_id: int) -> str:
    """Deactivates a file record on-chain. Restricted to contract owner."""
    file_id = int(file_id)
    w3, contract, _ = get_contract()

    private_key = Config.BLOCKCHAIN_PRIVATE_KEY
    if not private_key:
        raise BlockchainConfigurationError("BLOCKCHAIN_PRIVATE_KEY is missing.")

    signer_account = w3.eth.account.from_key(private_key)
    nonce = w3.eth.get_transaction_count(signer_account.address, "pending")

    tx_func = contract.functions.deactivateFile(file_id)
    tx_dict = tx_func.build_transaction({
        "from": signer_account.address,
        "nonce": nonce,
        "chainId": Config.BLOCKCHAIN_CHAIN_ID,
        "gas": 200000,
        "gasPrice": w3.eth.gas_price
    })

    signed_tx = w3.eth.account.sign_transaction(tx_dict, private_key=private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    tx_hash_hex = w3.to_hex(tx_hash)

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=15)
    if receipt.get("status") != 1:
        raise BlockchainRegistrationError(f"Deactivation transaction reverted. Tx Hash: {tx_hash_hex}")

    return tx_hash_hex
