"""
Sicherer Spotify OAuth Manager
Automatische Token-Prüfung und sichere Autorisierung
CWE-287: Proper Authentication, CWE-319: Secure Communication
"""

import logging
import time
import webbrowser
from typing import Optional

import requests

from ..core.config import ConfigManager
from .token_storage import SecureTokenStorage

from ..utils.logging_setup import LoggingSetup

logger = LoggingSetup.get_logger(__name__)


class SpotifyOAuthManager:
    """
    Sicherer OAuth Manager für automatische Spotify-Authentifizierung

    Features:
    - Automatische Token-Validierung beim Start
    - Sichere Callback-Server Integration
    - CSRF-Protection durch State-Parameter
    - Benutzerfreundliche Browser-Integration
    """

    def __init__(self):
        self.config = ConfigManager()
        self.token_storage = SecureTokenStorage()

    def ensure_valid_token(self) -> bool:
        """
        Stellt sicher, dass ein gültiges Token verfügbar ist
        Führt bei Bedarf automatisch neue Autorisierung durch
        """
        try:
            logger.info("Checking for valid Spotify token...")

            # 1. Prüfe ob bereits ein gültiges Token existiert
            if self._has_valid_token():
                logger.info("[OK] Valid token found, no authorization needed")
                return True

            logger.info("No valid token found, starting authorization process...")

            # 2. Starte Callback-Server
            from ..services.callback_server import SpotifyCallbackServer

            callback_server = SpotifyCallbackServer()
            if not callback_server.start_background():
                logger.error("Failed to start callback server")
                return False

            # 3. Führe OAuth-Flow durch
            if not self._perform_oauth_flow(callback_server):
                logger.error("OAuth flow failed")
                return False

            # 4. Warte auf Token
            if not self._wait_for_token(callback_server):
                logger.error("Failed to receive token")
                return False

            logger.info("[OK] Authorization completed successfully")
            return True

        except Exception as e:
            logger.error(f"Token validation failed: {e}")
            return False

    def _has_valid_token(self) -> bool:
        """
        Prüft ob ein gültiges Token bereits vorhanden ist
        CWE-287: Proper Authentication Validation
        """
        try:
            # Lade gespeichertes Token
            token_info = self.token_storage.load_token()
            if not token_info:
                logger.info("No stored token found")
                return False

            # Prüfe Token-Gültigkeit
            if not self.token_storage.is_token_valid(token_info):
                logger.info("Stored token is expired or invalid")

                # Versuche Token zu refreshen
                if "refresh_token" in token_info:
                    logger.info("Attempting to refresh expired token...")
                    refreshed_token = self._refresh_token(token_info["refresh_token"])
                    if refreshed_token:
                        self.token_storage.save_token(refreshed_token)
                        logger.info("Token refreshed successfully")
                        return True
                    else:
                        logger.warning("Token refresh failed")

                return False

            # Token ist gültig, teste Spotify-Verbindung
            if self._test_spotify_connection(token_info["access_token"]):
                logger.info("Token validation successful")
                return True
            else:
                logger.warning(
                    "Token validation failed - Spotify connection test failed"
                )
                return False

        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False

    def _refresh_token(self, refresh_token: str) -> Optional[dict]:
        """Refresht abgelaufenes Token"""
        try:
            spotify_config = self.config.spotify

            token_params = {
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": spotify_config.client_id,
                "client_secret": spotify_config.client_secret,
            }

            response = requests.post(
                "https://accounts.spotify.com/api/token",
                data=token_params,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                timeout=10,
            )

            if response.status_code == 200:
                token_info = response.json()

                # Add expires_at timestamp
                if "expires_in" in token_info:
                    token_info["expires_at"] = time.time() + token_info["expires_in"]

                # Keep original refresh token if not provided
                if "refresh_token" not in token_info:
                    token_info["refresh_token"] = refresh_token

                logger.info("Token refresh successful")
                return token_info
            else:
                logger.error(f"Token refresh failed: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            return None

    def _test_spotify_connection(self, access_token: str) -> bool:
        """Testet Spotify-Verbindung mit Token"""
        try:
            headers = {"Authorization": f"Bearer {access_token}"}
            response = requests.get(
                "https://api.spotify.com/v1/me", headers=headers, timeout=10
            )

            if response.status_code == 200:
                user_info = response.json()
                logger.info(
                    f"Connected to Spotify as: {user_info.get('display_name', 'Unknown')}"
                )
                return True
            else:
                logger.error(f"Spotify connection test failed: {response.status_code}")
                return False

        except Exception as e:
            logger.error(f"Spotify connection test error: {e}")
            return False

    def _perform_oauth_flow(self, callback_server) -> bool:
        """Führt OAuth-Flow mit Browser durch"""
        try:
            # Generiere sichere Authorization URL
            auth_url = callback_server.generate_auth_url()

            logger.info("Opening browser for Spotify authorization...")
            print("\n" + "=" * 60)
            print("SPOTIFY AUTHORIZATION REQUIRED")
            print("=" * 60)
            print("Opening your web browser for Spotify authorization...")
            print("Please complete the authorization in your browser.")
            print("The application will automatically continue once you authorize.")
            print("\nIf the browser doesn't open automatically, please visit:")
            print(auth_url)
            print("=" * 60 + "\n")

            # Öffne Browser automatisch
            try:
                webbrowser.open(auth_url)
                logger.info("Browser opened successfully")
            except Exception as e:
                logger.warning(f"Failed to open browser automatically: {e}")
                print(f"Please manually open: {auth_url}")

            return True

        except Exception as e:
            logger.error(f"OAuth flow failed: {e}")
            return False

    def _wait_for_token(self, callback_server, timeout: int = 300) -> bool:
        """Wartet auf Token vom Callback-Server"""
        try:
            logger.info(f"Waiting for authorization (timeout: {timeout}s)...")

            start_time = time.time()
            check_interval = 2

            while time.time() - start_time < timeout:
                try:
                    # Prüfe Server-Status
                    callback_config = self.config.get_callback_server_config()
                    server_url = (
                        f"http://{callback_config['host']}:{callback_config['port']}"
                    )

                    response = requests.get(f"{server_url}/status", timeout=2)

                    if response.status_code == 200:
                        status_data = response.json()

                        if status_data.get("has_token"):
                            logger.info("Authorization completed, retrieving token...")

                            # Token abrufen
                            token_response = requests.get(
                                f"{server_url}/get_token", timeout=5
                            )

                            if token_response.status_code == 200:
                                token_info = token_response.json()

                                # Token validieren und speichern
                                if self._validate_received_token(token_info):
                                    self.token_storage.save_token(token_info)
                                    logger.info("Token received and saved successfully")
                                    return True
                                else:
                                    logger.error("Received invalid token")
                                    return False
                            else:
                                logger.error(
                                    "Failed to retrieve token from callback server"
                                )
                                return False

                except requests.exceptions.RequestException:
                    # Server noch nicht bereit oder Fehler - weiterwarten
                    pass

                # Progress indicator
                elapsed = int(time.time() - start_time)
                if elapsed % 30 == 0 and elapsed > 0:
                    print(f"Still waiting for authorization... ({elapsed}s/{timeout}s)")

                time.sleep(check_interval)

            logger.error("Timeout waiting for authorization")
            print("\nAuthorization timed out. Please try again.")
            return False

        except Exception as e:
            logger.error(f"Token waiting failed: {e}")
            return False

    def _validate_received_token(self, token_info: dict) -> bool:
        """Validiert empfangenes Token"""
        try:
            # Prüfe erforderliche Felder
            required_fields = ["access_token", "token_type", "expires_at"]
            if not all(field in token_info for field in required_fields):
                logger.error("Token missing required fields")
                return False

            # Prüfe Token-Format
            access_token = token_info["access_token"]
            if not isinstance(access_token, str) or len(access_token) < 50:
                logger.error("Invalid access token format")
                return False

            # Teste Token mit Spotify API
            if not self._test_spotify_connection(access_token):
                logger.error("Token validation failed - Spotify connection test failed")
                return False

            return True

        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return False

    def get_valid_token(self) -> Optional[dict]:
        """Gibt gültiges Token zurück oder None"""
        if self.ensure_valid_token():
            return self.token_storage.load_token()
        return None
