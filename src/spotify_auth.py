"""
Sichere Spotify API Authentifizierung
CWE-287: Improper Authentication, CWE-319: Cleartext Transmission Prevention
Bandit: B108, B113, B322
"""

import json
import logging
import os
from pathlib import Path
from typing import Optional

import spotipy
from cryptography.fernet import Fernet
from spotipy.oauth2 import SpotifyOAuth

from config import ConfigManager

logger = logging.getLogger(__name__)


class SecureTokenStorage:
    """
    Sichere Token-Speicherung mit Verschlüsselung
    CWE-312: Cleartext Storage of Sensitive Information Prevention
    CWE-320: Key Management Errors Prevention
    """

    def __init__(self, token_file: str = "data/.spotify_token"):
        self.token_file = Path(token_file)
        self.token_file.parent.mkdir(parents=True, exist_ok=True)
        self._key = self._get_or_create_key()
        self._cipher = Fernet(self._key)

    def _get_or_create_key(self) -> bytes:
        """
        Erstellt oder lädt Verschlüsselungsschlüssel
        CWE-320: Key Management - Sicherer Schlüssel
        """
        key_file = self.token_file.parent / ".key"

        if key_file.exists():
            with open(key_file, "rb") as f:
                return f.read()
        else:
            # Generiere sicheren Schlüssel
            key = Fernet.generate_key()
            # Sichere Dateiberechtigung - nur Owner kann lesen
            with open(key_file, "wb") as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Bandit B103: set_bad_file_permissions
            return key

    def save_token(self, token_info: dict) -> None:
        """
        Speichert Token verschlüsselt
        CWE-312: Cleartext Storage Prevention
        """
        try:
            token_json = json.dumps(token_info)
            encrypted_token = self._cipher.encrypt(token_json.encode())

            with open(self.token_file, "wb") as f:
                f.write(encrypted_token)

            # Sichere Dateiberechtigung
            os.chmod(self.token_file, 0o600)
            logger.info("Token securely stored")

        except Exception as e:
            logger.error(f"Failed to store token: {e}")
            raise

    def load_token(self) -> Optional[dict]:
        """
        Lädt verschlüsselten Token
        CWE-312: Cleartext Storage Prevention
        """
        try:
            if not self.token_file.exists():
                return None

            with open(self.token_file, "rb") as f:
                encrypted_token = f.read()

            decrypted_token = self._cipher.decrypt(encrypted_token)
            token_info = json.loads(decrypted_token.decode())

            logger.info("Token loaded successfully")
            return token_info

        except Exception as e:
            logger.warning(f"Failed to load token: {e}")
            return None


class SpotifyAuthenticator:
    """
    Sichere Spotify-Authentifizierung mit OAuth2
    CWE-287: Improper Authentication Prevention
    CWE-319: Cleartext Transmission Prevention durch HTTPS
    """

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.token_storage = SecureTokenStorage()
        self._spotify_client: Optional[spotipy.Spotify] = None

        # Scope für benötigte Berechtigungen - erweitert für vollständigen Zugriff
        self.scope = "user-read-currently-playing user-read-playback-state playlist-modify-public playlist-modify-private playlist-read-private user-library-read"

        self._setup_oauth()

    def _setup_oauth(self) -> None:
        """
        Konfiguriert OAuth2 sicher
        CWE-287: Proper Authentication Setup
        """
        try:
            spotify_config = self.config.spotify

            # SpotifyOAuth mit sicheren Einstellungen
            self.oauth = SpotifyOAuth(
                client_id=spotify_config.client_id,
                client_secret=spotify_config.client_secret,
                redirect_uri=spotify_config.redirect_uri,
                scope=self.scope,
                cache_handler=None,  # Verwende eigene sichere Token-Speicherung
                show_dialog=True,  # Zeige immer Autorisierungsdialog
                requests_timeout=30,  # CWE-400: Timeout für DoS-Prevention
                open_browser=True,
            )

            logger.info("OAuth2 setup completed")

        except Exception as e:
            logger.error(f"OAuth setup failed: {e}")
            raise

    def authenticate(self) -> spotipy.Spotify:
        """
        Führt sichere Authentifizierung durch
        CWE-287: Improper Authentication Prevention
        """
        try:
            # Versuche gespeicherten Token zu laden
            token_info = self.token_storage.load_token()

            if token_info:
                # Prüfe Token-Gültigkeit
                if self.oauth.is_token_expired(token_info):
                    logger.info("Token expired, refreshing...")
                    token_info = self.oauth.refresh_access_token(
                        token_info["refresh_token"]
                    )
                    self.token_storage.save_token(token_info)
            else:
                # Neue Authentifizierung erforderlich
                logger.info("No valid token found, starting authentication flow...")
                auth_url = self.oauth.get_authorize_url()
                print(f"Please visit this URL to authorize the application: {auth_url}")

                # Warte auf Callback
                code = self.oauth.parse_response_code(
                    input("Enter the URL you were redirected to: ")
                )
                token_info = self.oauth.get_access_token(code)
                self.token_storage.save_token(token_info)

            # Erstelle Spotify Client
            self._spotify_client = spotipy.Spotify(
                auth=token_info["access_token"],
                requests_timeout=30,  # CWE-400: DoS Prevention
                retries=3,  # Retry-Mechanismus
            )

            # Teste Verbindung
            user_info = self._spotify_client.current_user()
            logger.info(f"Successfully authenticated as: {user_info['display_name']}")

            return self._spotify_client

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            raise

    @property
    def spotify(self) -> spotipy.Spotify:
        """Gibt authentifizierten Spotify Client zurück"""
        if self._spotify_client is None:
            raise RuntimeError("Not authenticated. Call authenticate() first.")
        return self._spotify_client

    def is_authenticated(self) -> bool:
        """Prüft ob Client authentifiziert ist"""
        return self._spotify_client is not None

    def authenticate_with_code(self, authorization_code: str) -> bool:
        """
        Authentifiziert mit einem Authorization Code vom Callback
        Für den separaten Callback-Server
        """
        try:
            logger.info("Exchanging authorization code for tokens...")

            # Tausche Code gegen Token
            token_info = self.oauth.get_access_token(authorization_code)

            if not token_info:
                logger.error("Failed to get token from authorization code")
                return False

            # Speichere Token sicher
            self.token_storage.save_token(token_info)

            # Erstelle Spotify Client
            self._spotify_client = spotipy.Spotify(
                auth=token_info["access_token"], requests_timeout=30, retries=3
            )

            # Teste Verbindung
            user_info = self._spotify_client.current_user()
            logger.info(f"Successfully authenticated as: {user_info['display_name']}")

            return True

        except Exception as e:
            logger.error(f"Code authentication failed: {e}")
            return False

    def get_auth_url(self) -> str:
        """Gibt die Authorization URL für die Authentifizierung zurück"""
        return self.oauth.get_authorize_url()

    def authenticate_from_stored_token(self) -> bool:
        """
        Versucht Authentifizierung mit gespeicherten Token
        Für automatischen Service-Start ohne Interaktion
        """
        try:
            # Versuche gespeicherten Token zu laden
            token_info = self.token_storage.load_token()

            if not token_info:
                logger.info("No stored token found")
                return False

            # Prüfe Token-Gültigkeit
            if self.oauth.is_token_expired(token_info):
                logger.info("Token expired, trying to refresh...")
                try:
                    token_info = self.oauth.refresh_access_token(
                        token_info["refresh_token"]
                    )
                    self.token_storage.save_token(token_info)
                    logger.info("Token refreshed successfully")
                except Exception as e:
                    logger.error(f"Token refresh failed: {e}")
                    return False

            # Erstelle Spotify Client
            self._spotify_client = spotipy.Spotify(
                auth=token_info["access_token"], requests_timeout=30, retries=3
            )

            # Teste Verbindung
            user_info = self._spotify_client.current_user()
            logger.info(
                f"Successfully authenticated from stored token as: {user_info['display_name']}"
            )

            return True

        except Exception as e:
            logger.error(f"Stored token authentication failed: {e}")
            return False
