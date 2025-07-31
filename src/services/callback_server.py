"""
Sicherer Spotify OAuth Callback Server
CWE-352: CSRF Prevention, CWE-319: Secure Communications, CWE-20: Input Validation
Security: Follows OpenSSF Secure Coding Guidelines
"""

import logging
import secrets
import threading
import time
import urllib.parse
from typing import Dict, Optional

import requests
from flask import Flask, jsonify, request

from ..auth.token_storage import SecureTokenStorage
from ..core.config import ConfigManager

logger = logging.getLogger(__name__)


class SpotifyCallbackServer:
    """
    Sicherer OAuth Callback Server für Spotify

    Security Features:
    - CWE-352: CSRF Prevention durch State Parameter
    - CWE-20: Input Validation für alle Parameters
    - CWE-319: Sichere Token-Übertragung
    - CWE-79: XSS Prevention
    - CWE-400: DoS Prevention durch Timeouts
    """

    def __init__(self):
        self.config = ConfigManager()
        self.app = Flask(__name__)
        self.app.secret_key = secrets.token_hex(32)  # CWE-320: Secure Key

        # Server Configuration
        callback_config = self.config.get_callback_server_config()
        self.host = callback_config.get("host", "127.0.0.1")
        self.port = callback_config.get("port", 4444)
        self.timeout = callback_config.get("timeout_seconds", 300)
        self.debug = callback_config.get("debug", False)

        # OAuth Configuration
        oauth_config = self.config.get_oauth_config()
        self.scope = oauth_config.get("scope", "user-read-currently-playing")
        self.state_length = oauth_config.get("state_length", 16)

        # State Management - CWE-352: CSRF Prevention
        self.pending_states: Dict[str, float] = {}  # state -> timestamp
        self.received_token: Optional[Dict] = None
        self.auth_complete = False

        # Token Storage
        self.token_storage = SecureTokenStorage()

        self._setup_routes()

    def _setup_routes(self):
        """Setup Flask routes with security measures"""

        @self.app.route("/health", methods=["GET"])
        def health_check():
            """Health check endpoint"""
            try:
                return (
                    jsonify(
                        {
                            "status": "healthy",
                            "service": "spotify-callback-server",
                            "timestamp": time.time(),
                            "uptime": time.time()
                            - getattr(self, "_start_time", time.time()),
                        }
                    ),
                    200,
                )
            except Exception as e:
                logger.error(f"Health check failed: {e}")
                return jsonify({"status": "unhealthy", "error": str(e)}), 500

        @self.app.route("/callback", methods=["GET"])
        def spotify_callback():
            """Spotify OAuth callback endpoint"""
            try:
                # Input Validation - CWE-20
                code = request.args.get("code")
                state = request.args.get("state")
                error = request.args.get("error")

                # Error handling
                if error:
                    error_msg = f"OAuth error: {error}"
                    logger.error(error_msg)
                    return self._render_error_page(error_msg), 400

                # Validate required parameters
                if not code or not isinstance(code, str):
                    logger.error("Missing or invalid authorization code")
                    return self._render_error_page("Invalid authorization code"), 400

                if not state or not isinstance(state, str):
                    logger.error("Missing or invalid state parameter")
                    return self._render_error_page("Invalid state parameter"), 400

                # CSRF Protection - CWE-352
                if not self._validate_state(state):
                    logger.error("Invalid state parameter - possible CSRF attack")
                    return self._render_error_page("Security validation failed"), 403

                # Exchange code for token
                token_info = self._exchange_code_for_token(code)
                if not token_info:
                    return self._render_error_page("Failed to obtain access token"), 500

                # Save token securely
                self.token_storage.save_token(token_info)
                self.received_token = token_info
                self.auth_complete = True

                logger.info("OAuth authentication successful")
                return self._render_success_page(), 200

            except Exception as e:
                logger.error(f"Callback processing failed: {e}")
                return self._render_error_page("Internal server error"), 500

        @self.app.route("/status", methods=["GET"])
        def auth_status():
            """Get authentication status"""
            try:
                return (
                    jsonify(
                        {"has_token": self.auth_complete, "timestamp": time.time()}
                    ),
                    200,
                )
            except Exception as e:
                logger.error(f"Status check failed: {e}")
                return jsonify({"error": str(e)}), 500

        @self.app.route("/get_token", methods=["GET"])
        def get_token():
            """Get received token (one-time use)"""
            try:
                if not self.auth_complete or not self.received_token:
                    return jsonify({"error": "No token available"}), 404

                # Return token and clear it (one-time use)
                token = self.received_token
                self.received_token = None

                return jsonify(token), 200

            except Exception as e:
                logger.error(f"Token retrieval failed: {e}")
                return jsonify({"error": str(e)}), 500

    def _validate_state(self, state: str) -> bool:
        """Validate CSRF state parameter"""
        try:
            current_time = time.time()

            # Check if state exists and is not expired
            if state in self.pending_states:
                state_time = self.pending_states[state]
                if current_time - state_time < self.timeout:
                    # Remove used state
                    del self.pending_states[state]
                    return True
                else:
                    # Expired state
                    del self.pending_states[state]

            # Clean up expired states
            self._cleanup_expired_states()
            return False

        except Exception as e:
            logger.error(f"State validation failed: {e}")
            return False

    def _cleanup_expired_states(self):
        """Clean up expired state tokens"""
        try:
            current_time = time.time()
            expired_states = [
                state
                for state, timestamp in self.pending_states.items()
                if current_time - timestamp > self.timeout
            ]

            for state in expired_states:
                del self.pending_states[state]

        except Exception as e:
            logger.error(f"State cleanup failed: {e}")

    def _exchange_code_for_token(self, code: str) -> Optional[Dict]:
        """Exchange authorization code for access token"""
        try:
            spotify_config = self.config.spotify

            # Validate inputs - CWE-20
            if not code or len(code) < 10:
                logger.error("Invalid authorization code")
                return None

            # Token exchange request
            token_data = {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": spotify_config.redirect_uri,
                "client_id": spotify_config.client_id,
                "client_secret": spotify_config.client_secret,
            }

            # Send request - CWE-319: Secure HTTPS communication
            response = requests.post(
                "https://accounts.spotify.com/api/token",
                data=token_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,  # CWE-400: DoS Prevention
            )

            if response.status_code == 200:
                token_info = response.json()

                # Validate token response - CWE-20
                required_fields = ["access_token", "token_type", "expires_in"]
                if not all(field in token_info for field in required_fields):
                    logger.error("Invalid token response from Spotify")
                    return None

                # Add expires_at timestamp
                token_info["expires_at"] = time.time() + token_info["expires_in"]

                logger.info("Token exchange successful")
                return token_info
            else:
                logger.error(
                    f"Token exchange failed: {response.status_code} - {response.text}"
                )
                return None

        except Exception as e:
            logger.error(f"Token exchange error: {e}")
            return None

    def _render_success_page(self) -> str:
        """Render success page - CWE-79: XSS Prevention"""
        return """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Spotify Authorization Successful</title>
            <meta charset="utf-8">
            <style>
                body { font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }
                .success { color: #28a745; }
                .container { max-width: 500px; margin: 0 auto; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="success">✓ Authorization Successful</h1>
                <p>You have successfully authorized the Spotify application.</p>
                <p>You can now close this window and return to the application.</p>
            </div>
        </body>
        </html>
        """

    def _render_error_page(self, error_message: str) -> str:
        """Render error page - CWE-79: XSS Prevention"""
        # Sanitize error message to prevent XSS
        safe_error = str(error_message).replace("<", "&lt;").replace(">", "&gt;")[:200]

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Spotify Authorization Error</title>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; text-align: center; margin-top: 50px; }}
                .error {{ color: #dc3545; }}
                .container {{ max-width: 500px; margin: 0 auto; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1 class="error">✗ Authorization Failed</h1>
                <p>Error: {safe_error}</p>
                <p>Please try again or contact support if the problem persists.</p>
            </div>
        </body>
        </html>
        """

    def generate_auth_url(self) -> str:
        """Generate secure authorization URL"""
        try:
            spotify_config = self.config.spotify

            # Generate secure state parameter - CWE-352
            state = secrets.token_urlsafe(self.state_length)
            self.pending_states[state] = time.time()

            # Clean up old states
            self._cleanup_expired_states()

            # Build authorization URL
            auth_params = {
                "client_id": spotify_config.client_id,
                "response_type": "code",
                "redirect_uri": spotify_config.redirect_uri,
                "scope": self.scope,
                "state": state,
                "show_dialog": "true",
            }

            auth_url = (
                "https://accounts.spotify.com/authorize?"
                + urllib.parse.urlencode(auth_params)
            )
            logger.info(f"Generated authorization URL with state: {state[:8]}...")

            return auth_url

        except Exception as e:
            logger.error(f"Failed to generate auth URL: {e}")
            raise

    def start_background(self):
        """Start server in background thread"""
        try:
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()

            # Wait for server to start
            time.sleep(2)

            # Test if server is running
            try:
                response = requests.get(
                    f"http://{self.host}:{self.port}/health", timeout=5
                )
                if response.status_code == 200:
                    logger.info("Callback server started successfully in background")
                    return True
                else:
                    logger.error("Callback server health check failed")
                    return False
            except requests.exceptions.RequestException as e:
                logger.error(f"Callback server not responding: {e}")
                return False

        except Exception as e:
            logger.error(f"Failed to start callback server in background: {e}")
            return False

    def _run_server(self):
        """Run Flask server"""
        try:
            self._start_time = time.time()
            logger.info(f"Starting callback server on {self.host}:{self.port}")

            # Run Flask app - CWE-319: Local binding only for security
            self.app.run(
                host=self.host,
                port=self.port,
                debug=self.debug,
                threaded=True,
                use_reloader=False,  # Prevent double startup
            )

        except Exception as e:
            logger.error(f"Callback server failed: {e}")
            raise
