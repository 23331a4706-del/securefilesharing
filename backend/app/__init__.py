import logging
from flask import Flask, jsonify, request
from flask_cors import CORS
from app.config import Config
from app.routes.health import health_bp
from app.routes.auth import auth_bp
from app.routes.file import file_bp
from app.routes.share import share_bp

logger = logging.getLogger(__name__)

def create_app():
    """Application factory for Flask backend with Phase 8 Security Hardening."""
    app = Flask(__name__)
    app.config.from_object(Config)

    # Phase 8: Audit security environment variables
    try:
        Config.audit_security_config()
    except Exception as e:
        logger.warning(f"Security config audit notice: {e}")

    # Strict CORS configuration matching local and network origins
    allowed_origins = [
        Config.FRONTEND_ORIGIN,
        "http://127.0.0.1:5173",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://localhost:3000"
    ]
    CORS(app, resources={r"/api/*": {
        "origins": allowed_origins,
        "methods": ["GET", "POST", "DELETE", "OPTIONS"],
        "allow_headers": ["Authorization", "Content-Type"]
    }})

    # Register blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(file_bp)
    app.register_blueprint(share_bp)

    # Modern HTTP Security Headers Middleware
    @app.after_request
    def set_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self' http://localhost:* http://127.0.0.1:*"
        response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
        
        if request.path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store, max-age=0'
            
        return response

    # Global Error Handlers with Sanitized Responses
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({"success": False, "message": "Bad Request"}), 400

    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({"success": False, "message": "Unauthorized"}), 401

    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({"success": False, "message": "Forbidden"}), 403

    @app.errorhandler(404)
    def not_found(error):
        return jsonify({"success": False, "message": "Resource not found"}), 404

    @app.errorhandler(409)
    def conflict(error):
        return jsonify({"success": False, "message": "Resource conflict"}), 409

    @app.errorhandler(413)
    def request_entity_too_large(error):
        return jsonify({
            "success": False,
            "message": f"File size exceeds maximum upload limit of {Config.MAX_FILE_SIZE_MB} MB."
        }), 413

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Internal server error: {error}", exc_info=True)
        return jsonify({"success": False, "message": "Internal server error"}), 500

    return app
