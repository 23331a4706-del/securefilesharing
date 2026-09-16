import io
from flask import Blueprint, request, jsonify, send_file
from app.routes.auth import decode_jwt_token
from app.services.file_service import (
    process_file_upload,
    get_user_files,
    decrypt_and_read_file,
    delete_user_file,
    get_file_blockchain_record,
    verify_file_full_integrity,
    retry_blockchain_registration
)
from app.services.encryption_service import CryptographyError, AuthenticationTagMismatchError
from app.services.integrity_service import FileIntegrityError
from app.services.ipfs_service import IPFSUnavailableError, IPFSNotFoundError
from app.services.blockchain_service import (
    BlockchainUnavailableError,
    BlockchainMetadataMismatchError,
    BlockchainRegistrationError,
    BlockchainException
)

file_bp = Blueprint('file', __name__)

def authenticate_request():
    """Extracts and verifies JWT token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    return decode_jwt_token(token)


@file_bp.route('/api/files/upload', methods=['POST'])
def upload_file():
    """
    POST /api/files/upload
    Receives file upload, encrypts content with AES-256-GCM, uploads encrypted payload to IPFS,
    calculates SHA-256 integrity hash, saves metadata in MySQL, and registers on blockchain.
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file part in request."}), 400

    uploaded_file = request.files['file']
    
    try:
        file_info = process_file_upload(uploaded_file, user_id)
        return jsonify({
            "success": True,
            "message": "File encrypted, stored on IPFS, and registered on blockchain successfully",
            "file": file_info
        }), 201
    except ValueError as ve:
        return jsonify({"success": False, "message": str(ve)}), 400
    except IPFSUnavailableError:
        return jsonify({"success": False, "message": "Secure decentralized storage is currently unavailable"}), 503
    except CryptographyError as ce:
        return jsonify({"success": False, "message": f"Encryption failed: {str(ce)}"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Upload failed: {str(e)}"}), 500


@file_bp.route('/api/files', methods=['GET'])
def list_files():
    """
    GET /api/files
    Returns metadata list of files belonging strictly to the authenticated user.
    Includes blockchain_recorded and blockchain_tx_hash status.
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        raw_files = get_user_files(user_id)
        files = []
        for f in raw_files:
            files.append({
                "id": f["id"],
                "original_filename": f["original_filename"],
                "file_size": f["file_size"],
                "mime_type": f["mime_type"],
                "encryption_algorithm": f["encryption_algorithm"],
                "integrity_status": "Verified" if f.get("sha256_hash") else "Pending",
                "sha256_hash": f.get("sha256_hash"),
                "ipfs_cid": f.get("ipfs_cid"),
                "storage_type": "IPFS" if f.get("ipfs_cid") else "Local",
                "blockchain_recorded": bool(f.get("blockchain_recorded")),
                "blockchain_tx_hash": f.get("blockchain_tx_hash"),
                "status": f.get("status", "encrypted"),
                "created_at": str(f["created_at"]) if f.get("created_at") else None
            })

        return jsonify({
            "success": True,
            "files": files
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve files: {str(e)}"}), 500


@file_bp.route('/api/files/<int:file_id>/blockchain', methods=['GET'])
def get_blockchain_record(file_id: int):
    """
    GET /api/files/<file_id>/blockchain
    Retrieves the on-chain immutable metadata record from the smart contract.
    Enforces JWT authentication and owner authorization.
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        result = get_file_blockchain_record(file_id, user_id)
        return jsonify(result), 200
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except BlockchainUnavailableError:
        return jsonify({"success": False, "message": "Blockchain service is currently unavailable"}), 503
    except Exception as e:
        return jsonify({"success": False, "message": f"Blockchain query failed: {str(e)}"}), 500


@file_bp.route('/api/files/<int:file_id>/verify', methods=['GET'])
def verify_file_integrity(file_id: int):
    """
    GET /api/files/<file_id>/verify
    Performs non-decrypting 4-way cross-system verification:
    MySQL Record ↔ Blockchain Record ↔ IPFS Encrypted Bytes SHA-256 Digest.
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        result = verify_file_full_integrity(file_id, user_id)
        return jsonify(result), 200
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except (FileIntegrityError, BlockchainMetadataMismatchError):
        return jsonify({
            "success": False,
            "verified": False,
            "message": "File integrity or blockchain metadata verification failed"
        }), 409
    except (IPFSUnavailableError, BlockchainUnavailableError):
        return jsonify({"success": False, "message": "Verification failed: IPFS or Blockchain service is currently unavailable"}), 503
    except Exception as e:
        return jsonify({"success": False, "message": f"Verification error: {str(e)}"}), 500


@file_bp.route('/api/files/<int:file_id>/blockchain/register', methods=['POST'])
def retry_blockchain_record(file_id: int):
    """
    POST /api/files/<file_id>/blockchain/register
    Manually retries blockchain registration for a pending file record.
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        result = retry_blockchain_registration(file_id, user_id)
        return jsonify(result), 200
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except FileIntegrityError:
        return jsonify({"success": False, "message": "Cannot register file: IPFS integrity verification failed"}), 409
    except BlockchainUnavailableError:
        return jsonify({"success": False, "message": "Blockchain service is currently unavailable"}), 503
    except BlockchainRegistrationError as bre:
        return jsonify({"success": False, "message": f"Blockchain registration failed: {str(bre)}"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Registration failed: {str(e)}"}), 500


@file_bp.route('/api/files/<int:file_id>/download', methods=['GET'])
def download_file(file_id: int):
    """
    GET /api/files/<file_id>/download
    Enforces Security Order:
    1. JWT authentication
    2. Ownership authorization (403 if non-owner)
    3. Retrieve encrypted .enc bytes from IPFS using CID (Zero local fallback)
       - 503 Service Unavailable if IPFS daemon is offline
       - 404 Not Found if CID is missing/invalid
    4. SHA-256 File Integrity Verification (409 if mismatch)
    5. AES-256-GCM Decryption (only after integrity pass)
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        plaintext_bytes, filename, mime_type = decrypt_and_read_file(file_id, user_id)
        
        return send_file(
            io.BytesIO(plaintext_bytes),
            mimetype=mime_type,
            as_attachment=True,
            download_name=filename
        )
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except IPFSUnavailableError:
        return jsonify({"success": False, "message": "IPFS storage is currently unavailable"}), 503
    except IPFSNotFoundError as infe:
        return jsonify({"success": False, "message": str(infe)}), 404
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except FileIntegrityError:
        return jsonify({"success": False, "message": "File integrity verification failed"}), 409
    except AuthenticationTagMismatchError:
        return jsonify({"success": False, "message": "File integrity verification failed"}), 409
    except CryptographyError as ce:
        return jsonify({"success": False, "message": f"Decryption failure: {str(ce)}"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Download error: {str(e)}"}), 500


@file_bp.route('/api/files/<int:file_id>', methods=['DELETE'])
def delete_file(file_id: int):
    """
    DELETE /api/files/<file_id>
    Verifies ownership, unpins CID from local IPFS node, removes disk file if present,
    and deletes database record. (Preserves immutable historical record on-chain).
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        delete_user_file(file_id, user_id)
        return jsonify({
            "success": True,
            "message": "File deleted successfully"
        }), 200
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except Exception as e:
        return jsonify({"success": False, "message": f"Delete failed: {str(e)}"}), 500
