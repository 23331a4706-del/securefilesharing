import io
from flask import Blueprint, request, jsonify, send_file
from app.routes.auth import decode_jwt_token
from app.services.share_service import (
    create_or_update_file_share,
    revoke_file_share,
    get_file_shares_for_owner,
    get_shared_files_for_receiver,
    get_all_shares_by_sender,
    get_shareable_users,
    decrypt_and_read_shared_file,
    inspect_file_payload
)
from app.services.encryption_service import CryptographyError, AuthenticationTagMismatchError
from app.services.integrity_service import FileIntegrityError
from app.services.ipfs_service import IPFSUnavailableError, IPFSNotFoundError

share_bp = Blueprint('share', __name__)

def authenticate_request():
    """Extracts and verifies JWT token from Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    return decode_jwt_token(token)


@share_bp.route('/api/files/<int:file_id>/share', methods=['POST'])
def share_file(file_id: int):
    """
    POST /api/files/<file_id>/share
    Shares a file owned by the authenticated user with a designated receiver user.
    Request JSON: {"receiver_id": 7}
    """
    sender_id = authenticate_request()
    if not sender_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    data = request.get_json() or {}
    receiver_id = data.get("receiver_id")

    if not receiver_id:
        return jsonify({"success": False, "message": "receiver_id is required."}), 400

    try:
        result = create_or_update_file_share(
            file_id=file_id,
            sender_id=sender_id,
            receiver_id=int(receiver_id)
        )
        return jsonify(result), 200
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except ValueError as ve:
        return jsonify({"success": False, "message": str(ve)}), 409
    except CryptographyError as ce:
        return jsonify({"success": False, "message": f"Cryptographic operation failed: {str(ce)}"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to share file: {str(e)}"}), 500


@share_bp.route('/api/files/<int:file_id>/shares', methods=['GET'])
def list_file_shares(file_id: int):
    """
    GET /api/files/<file_id>/shares
    Retrieves list of active and revoked share records for an owned file.
    Restricted to file owner.
    """
    owner_id = authenticate_request()
    if not owner_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        shares = get_file_shares_for_owner(file_id=file_id, owner_id=owner_id)
        return jsonify({
            "success": True,
            "shares": shares
        }), 200
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve shares: {str(e)}"}), 500


@share_bp.route('/api/files/<int:file_id>/shares/<int:receiver_id>', methods=['DELETE'])
def revoke_share(file_id: int, receiver_id: int):
    """
    DELETE /api/files/<file_id>/shares/<receiver_id>
    Revokes access for a receiver user (sets active = False).
    Restricted to file owner.
    """
    owner_id = authenticate_request()
    if not owner_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        result = revoke_file_share(file_id=file_id, owner_id=owner_id, receiver_id=receiver_id)
        return jsonify(result), 200
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to revoke share: {str(e)}"}), 500


@share_bp.route('/api/shared-files', methods=['GET'])
def list_shared_with_me():
    """
    GET /api/shared-files
    Retrieves metadata list of files actively shared with the current authenticated user.
    """
    receiver_id = authenticate_request()
    if not receiver_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        files = get_shared_files_for_receiver(receiver_id=receiver_id)
        return jsonify({
            "success": True,
            "files": files
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve shared files: {str(e)}"}), 500


@share_bp.route('/api/shared-by-me', methods=['GET'])
def list_shared_by_me():
    """
    GET /api/shared-by-me
    Retrieves metadata list of files shared by the current authenticated user to recipients.
    """
    sender_id = authenticate_request()
    if not sender_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        shares = get_all_shares_by_sender(sender_id=sender_id)
        return jsonify({
            "success": True,
            "shares": shares
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve shared-by-me records: {str(e)}"}), 500


@share_bp.route('/api/users/shareable', methods=['GET'])
def list_users_for_sharing():
    """
    GET /api/users/shareable
    Returns list of candidate users available for file sharing.
    Excludes sensitive secrets.
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        users = get_shareable_users(current_user_id=user_id)
        return jsonify({
            "success": True,
            "users": users
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to retrieve shareable users: {str(e)}"}), 500


@share_bp.route('/api/shared-files/<int:file_id>/download', methods=['GET'])
def download_shared_file(file_id: int):
    """
    GET /api/shared-files/<file_id>/download
    Receiver Download Endpoint:
    Enforces Security Order:
    1. JWT Authentication
    2. Active Share Authorization (403 if unshared or revoked)
    3. Retrieve encrypted binary bytes strictly from IPFS using CID (503 if IPFS offline)
    4. SHA-256 Integrity Verification over retrieved IPFS bytes (409 if hash mismatch)
       - STOPS IMMEDIATELY before ECC private key decryption
    5. Receiver ECC Private Key Decryption & P-256 ECDH + HKDF Key Unwrapping
    6. AES-256-GCM File Decryption using recovered Phase 2 AES file key
    """
    receiver_id = authenticate_request()
    if not receiver_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        plaintext_bytes, filename, mime_type = decrypt_and_read_shared_file(file_id, receiver_id)

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


@share_bp.route('/api/files/<int:file_id>/inspect', methods=['GET'])
def inspect_file(file_id: int):
    """
    GET /api/files/<file_id>/inspect
    Real-Time Manual Inspection & Hash Verification Endpoint.
    Retrieves IPFS payload, generates real-time SHA-256 hash, and compares with sender's hash.
    """
    user_id = authenticate_request()
    if not user_id:
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    try:
        data = inspect_file_payload(file_id, user_id)
        return jsonify(data), 200
    except PermissionError as pe:
        return jsonify({"success": False, "message": str(pe)}), 403
    except FileNotFoundError as fnf:
        return jsonify({"success": False, "message": str(fnf)}), 404
    except Exception as e:
        return jsonify({"success": False, "message": f"Inspection failed: {str(e)}"}), 500

