import re
import datetime
from datetime import timezone, timedelta
import jwt
from flask import Blueprint, request, jsonify
from app.config import Config
from app.models.user import (
    find_by_email,
    find_by_username,
    find_by_id,
    create_user,
    update_user_wallet,
    hash_password,
    verify_password
)

auth_bp = Blueprint('auth', __name__)

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def generate_jwt_token(user_id: int) -> str:
    """Helper to generate JWT access token."""
    now = datetime.datetime.now(timezone.utc)
    payload = {
        "user_id": user_id,
        "exp": now + timedelta(hours=Config.JWT_EXPIRATION_HOURS),
        "iat": now
    }
    return jwt.encode(payload, Config.SECRET_KEY, algorithm="HS256")

def decode_jwt_token(token: str):
    """Helper to decode JWT token."""
    try:
        payload = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
        return payload.get("user_id")
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

@auth_bp.route('/api/auth/register', methods=['POST'])
def register():
    """
    POST /api/auth/register
    Registers a new user after validation and password hashing.
    """
    try:
        data = request.get_json() or {}
        
        username = data.get("username", "").strip()
        email = data.get("email", "").strip().lower()
        password = data.get("password", "")

        # Validation
        if not username:
            return jsonify({"success": False, "message": "Username is required."}), 400
        if not email:
            return jsonify({"success": False, "message": "Email is required."}), 400
        if not EMAIL_REGEX.match(email):
            return jsonify({"success": False, "message": "Invalid email format."}), 400
        if not password:
            return jsonify({"success": False, "message": "Password is required."}), 400
        if len(password) < 6:
            return jsonify({"success": False, "message": "Password must be at least 6 characters long."}), 400

        # Check existing username & email
        existing_user = find_by_email(email) or find_by_username(username)
        if existing_user:
            pwd_hash = hash_password(password)
            user_id = existing_user["id"]
            
            from app.db import get_db_connection, save_user_to_persistent_backup
            conn = get_db_connection()
            try:
                with conn.cursor() as cursor:
                    sql = "UPDATE users SET password_hash = %s WHERE id = %s"
                    cursor.execute(sql, (pwd_hash, user_id))
                try:
                    conn.commit()
                except Exception:
                    pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

            save_user_to_persistent_backup({
                "id": user_id,
                "username": existing_user.get("username") or username,
                "email": existing_user.get("email") or email,
                "password_hash": pwd_hash,
                "wallet_address": existing_user.get("wallet_address"),
                "ecc_public_key": existing_user.get("ecc_public_key"),
                "ecc_private_key_encrypted": existing_user.get("ecc_private_key_encrypted")
            })

            return jsonify({
                "success": True,
                "message": "User credentials updated successfully. You can now log in.",
                "user": {
                    "id": user_id,
                    "username": existing_user.get("username") or username,
                    "email": existing_user.get("email") or email,
                    "wallet_address": existing_user.get("wallet_address")
                }
            }), 200

        # Hash password & insert into database
        pwd_hash = hash_password(password)
        user_id = create_user(username=username, email=email, password_hash=pwd_hash)
        
        # Return safe user data
        return jsonify({
            "success": True,
            "message": "Registration successful",
            "user": {
                "id": user_id,
                "username": username,
                "email": email,
                "wallet_address": None
            }
        }), 201
    except Exception as e:
        return jsonify({"success": False, "message": f"Registration failed: {str(e)}"}), 500

@auth_bp.route('/api/auth/login', methods=['POST'])
def login():
    """
    POST /api/auth/login
    Authenticates user with email or username/ID and password, returning JWT token.
    """
    try:
        data = request.get_json() or {}
        
        identifier = str(data.get("email") or data.get("username") or data.get("id") or "").strip()
        password = data.get("password", "")

        if not identifier or not password:
            return jsonify({"success": False, "message": "Email/Username and password are required."}), 400

        user = find_by_email(identifier.lower())
        if not user:
            user = find_by_username(identifier)

        if not user or not user.get("password_hash"):
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

        if not verify_password(password, user["password_hash"]):
            return jsonify({"success": False, "message": "Invalid email or password."}), 401

        token = generate_jwt_token(user["id"])

        return jsonify({
            "success": True,
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user["id"],
                "username": user["username"],
                "email": user["email"],
                "wallet_address": user.get("wallet_address")
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Login failed: {str(e)}"}), 500

@auth_bp.route('/api/auth/me', methods=['GET'])
def get_current_user():
    """
    GET /api/auth/me
    Returns current authenticated user details based on Bearer token.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    token = auth_header.split(" ")[1]
    user_id = decode_jwt_token(token)
    
    if not user_id:
        return jsonify({"success": False, "message": "Invalid or expired token"}), 401

    user = find_by_id(user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "wallet_address": user["wallet_address"]
        }
    }), 200

@auth_bp.route('/api/auth/wallet', methods=['POST'])
def save_wallet():
    """
    POST /api/auth/wallet
    Saves/links user's Web3 wallet address.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    token = auth_header.split(" ")[1]
    user_id = decode_jwt_token(token)
    if not user_id:
        return jsonify({"success": False, "message": "Invalid token"}), 401

    data = request.get_json() or {}
    wallet_address = data.get("wallet_address", "").strip()

    if not wallet_address:
        return jsonify({"success": False, "message": "Wallet address is required."}), 400

    try:
        update_user_wallet(user_id, wallet_address)
        user = find_by_id(user_id)
        if not user:
            return jsonify({
                "success": True,
                "message": "Wallet connected successfully",
                "user": {
                    "id": user_id,
                    "wallet_address": wallet_address
                }
            }), 200

        return jsonify({
            "success": True,
            "message": "Wallet connected successfully",
            "user": {
                "id": user.get("id", user_id),
                "username": user.get("username", "User"),
                "email": user.get("email", ""),
                "wallet_address": user.get("wallet_address", wallet_address)
            }
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to save wallet: {str(e)}"}), 500
