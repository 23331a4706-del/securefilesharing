from flask import Blueprint, jsonify

health_bp = Blueprint('health', __name__)

@health_bp.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint confirming API availability."""
    return jsonify({
        "status": "success",
        "message": "Secure File Sharing API is running"
    }), 200
