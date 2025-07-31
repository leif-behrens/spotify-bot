"""
Sichere Token-Speicherung mit Verschlüsselung
CWE-312: Cleartext Storage of Sensitive Information Prevention
CWE-320: Key Management Errors Prevention
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

from cryptography.fernet import Fernet

from ..utils.logging_setup import LoggingSetup

logger = LoggingSetup.get_logger(__name__)


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
            os.chmod(key_file, 0o600)
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

    def is_token_valid(self, token_info: dict) -> bool:
        """Prüft ob Token noch gültig ist"""
        try:
            if not token_info or "expires_at" not in token_info:
                return False

            # Token ist gültig wenn expires_at in der Zukunft liegt (mit 60s Puffer)
            return time.time() < (token_info["expires_at"] - 60)

        except Exception as e:
            logger.error(f"Token validity check failed: {e}")
            return False

    def clear_token(self) -> None:
        """Löscht gespeicherten Token"""
        try:
            if self.token_file.exists():
                self.token_file.unlink()
                logger.info("Token cleared")
        except Exception as e:
            logger.error(f"Failed to clear token: {e}")
