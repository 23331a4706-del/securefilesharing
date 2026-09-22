import io
from flask import Blueprint, request, jsonify, send_file
from app.routes.auth import decode_jwt_token
from app.services.file_service import (
    process_file_upload,
    get_user_files,
    decrypt_and_read_file,
    delete_user_file
)
from app.services.blockchain_service import (
    get_file_metadata as get_blockchain_metadata,
    verify_system_integrity,
    register_file_metadata,
    BlockchainException,
    BlockchainMetadataMismatchError
)
from app.services.ipfs_service import IPFSUnavailableError, IPFSNotFoundError
from app.services.integrity_service import FileIntegrityError
from app.services.encryption_service import CryptographyError, AuthenticationTagMismatchError

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
    Endpoint for uploading plaintext file, performing AES-256-GCM encryption,
    computing SHA-256 integrity hash, uploading to IPFS, and recording metadata on local Hardhat blockchain.
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file field in request."}), 400

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
    Includes encrypted_key, sha256_hash, ipfs_cid, and blockchain_recorded status.
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
                "encrypted_key": f.get("encrypted_key"),
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
        on_chain_data = get_blockchain_metadata(file_id, user_id)
        return jsonify({
            "success": True,
            "blockchain_record": on_chain_data
        }), 200
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except Exception as e:
        return jsonify({"success": False, "message": f"Blockchain query error: {str(e)}"}), 500


@file_bp.route('/api/files/<int:file_id>/verify', methods=['GET'])
def verify_integrity(file_id: int):
    """
    GET /api/files/<file_id>/verify
    Performs 4-way cross-system integrity verification:
    1. MySQL DB vs IPFS Payload SHA-256
    2. MySQL DB vs On-Chain Blockchain SHA-256
    3. MySQL DB vs On-Chain Blockchain IPFS CID
    4. AES-256-GCM Cryptographic Tag Audit
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        verification = verify_system_integrity(file_id, user_id)
        return jsonify(verification), 200
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except BlockchainMetadataMismatchError as bme:
        return jsonify({"success": False, "message": str(bme)}), 409
    except Exception as e:
        return jsonify({"success": False, "message": f"Verification failed: {str(e)}"}), 500


@file_bp.route('/api/files/<int:file_id>/blockchain/register', methods=['POST'])
def retry_blockchain(file_id: int):
    """
    POST /api/files/<file_id>/blockchain/register
    Retries registering file metadata on blockchain if previously pending/failed.
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        from app.services.file_service import get_file_record
        file_rec = get_file_record(file_id)
        if not file_rec:
            return jsonify({"success": False, "message": "File not found"}), 404

        if file_rec["owner_id"] != user_id:
            return jsonify({"success": False, "message": "Unauthorized"}), 403

        req_data = request.get_json(silent=True) or {}
        passed_tx_hash = req_data.get("tx_hash") or req_data.get("signature_hash")

        if passed_tx_hash:
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE files SET blockchain_recorded = 1, blockchain_tx_hash = %s, status = 'blockchain_recorded' WHERE id = %s",
                        (passed_tx_hash, file_id)
                    )
            finally:
                conn.close()

            return jsonify({
                "success": True,
                "message": "File metadata registered on blockchain successfully",
                "tx_hash": passed_tx_hash
            }), 200

        result = register_file_metadata(
            file_id=file_id,
            owner_id=str(user_id),
            ipfs_cid=file_rec["ipfs_cid"],
            sha256_hash=file_rec["sha256_hash"]
        )

        if result.get("success"):
            tx_hash_val = result.get("transaction_hash") or result.get("tx_hash")
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    cursor.execute(
                        "UPDATE files SET blockchain_recorded = 1, blockchain_tx_hash = %s, status = 'blockchain_recorded' WHERE id = %s",
                        (tx_hash_val, file_id)
                    )
            finally:
                conn.close()

            return jsonify({
                "success": True,
                "message": "File metadata registered on blockchain successfully",
                "tx_hash": tx_hash_val
            }), 200
        else:
            return jsonify({"success": False, "message": result.get("message", "Blockchain registration failed")}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Retry failed: {str(e)}"}), 500


@file_bp.route('/api/files/<int:file_id>/download', methods=['GET'])
def download_file(file_id: int):
    """
    GET /api/files/<file_id>/download
    Owner Download Endpoint:
    Retrieves encrypted bytes from IPFS, verifies SHA-256 integrity,
    decrypts file with master key + nonce, and streams plaintext payload.
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
    except (FileIntegrityError, AuthenticationTagMismatchError):
        return jsonify({"success": False, "message": "File integrity verification failed"}), 409
    except CryptographyError as ce:
        return jsonify({"success": False, "message": f"Decryption failure: {str(ce)}"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Download error: {str(e)}"}), 500


@file_bp.route('/api/files/<int:file_id>', methods=['DELETE'])
def delete_file(file_id: int):
    """
    DELETE /api/files/<file_id>
    Owner Deletion Endpoint:
    Deletes file record from database and unpins from IPFS.
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
        return jsonify({"success": False, "message": f"Deletion error: {str(e)}"}), 500
