"""
Sichere Konfigurationsverwaltung für Spotify Bot
CWE-20: Input Validation, CWE-798: Hard-coded Credentials Prevention
Bandit: B105, B106, B107, B108
"""

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from dotenv import load_dotenv
from jsonschema import ValidationError, validate

logger = logging.getLogger(__name__)

CONFIG_SCHEMA = {
    "type": "object",
    "properties": {
        "monitoring": {
            "type": "object",
            "properties": {
                "check_interval_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 300,
                },
                "minimum_play_duration_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 3600,
                },
            },
            "required": ["check_interval_seconds", "minimum_play_duration_seconds"],
        },
        "playlist": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 100},
                "description": {"type": "string", "maxLength": 300},
            },
            "required": ["name"],
        },
        "service": {
            "type": "object",
            "properties": {
                "max_retries": {"type": "integer", "minimum": 0, "maximum": 10},
                "retry_delay_seconds": {"type": "integer", "minimum": 1, "maximum": 60},
            },
            "required": ["max_retries", "retry_delay_seconds"],
        },
    },
    "required": ["monitoring", "playlist", "service"],
}


@dataclass
class SpotifyConfig:
    """Spotify API Konfiguration - Sicher aus Environment Variables geladen"""

    client_id: str
    client_secret: str
    redirect_uri: str

    def __post_init__(self):
        # CWE-20: Input Validation für Spotify Credentials
        if not self.client_id or len(self.client_id) < 10:
            raise ValueError("Invalid Spotify Client ID")
        if not self.client_secret or len(self.client_secret) < 10:
            raise ValueError("Invalid Spotify Client Secret")
        if not self.redirect_uri.startswith(("http://", "https://")):
            raise ValueError("Invalid redirect URI format")


class ConfigManager:
    """
    Sichere Konfigurationsverwaltung
    - CWE-798: Verhindert hard-coded credentials
    - CWE-20: Validiert alle Eingaben
    - Bandit B105-B108: Sichere Dateipfade und JSON-Handling
    """

    def __init__(self, config_path: str = "config.json"):
        self.config_path = Path(config_path)
        self._config: Optional[Dict[str, Any]] = None
        self._spotify_config: Optional[SpotifyConfig] = None

        # Lade Environment Variables sicher
        load_dotenv()
        self._load_config()
        self._load_spotify_config()

    def _load_config(self) -> None:
        """
        Lädt und validiert JSON-Konfiguration
        CWE-20: Input Validation, Bandit B101: assert_used
        """
        try:
            if not self.config_path.exists():
                raise FileNotFoundError(f"Config file not found: {self.config_path}")

            # Sichere Dateipfad-Validierung - CWE-22: Path Traversal Prevention
            if not str(self.config_path.resolve()).startswith(str(Path.cwd())):
                raise ValueError("Config file outside allowed directory")

            with open(self.config_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)

            # JSON Schema Validation - CWE-20: Input Validation
            validate(instance=config_data, schema=CONFIG_SCHEMA)
            self._config = config_data

            logger.info("Configuration loaded and validated successfully")

        except ValidationError as e:
            logger.error(f"Configuration validation failed: {e.message}")
            raise ValueError(f"Invalid configuration: {e.message}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            raise ValueError(f"Invalid JSON format: {e}")
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise

    def _load_spotify_config(self) -> None:
        """
        Lädt Spotify-Credentials aus Environment Variables
        CWE-798: Use of Hard-coded Credentials Prevention
        """
        try:
            client_id = os.environ.get("SPOTIFY_CLIENT_ID")
            client_secret = os.environ.get("SPOTIFY_CLIENT_SECRET")
            redirect_uri = os.environ.get("SPOTIFY_REDIRECT_URI")

            if not all([client_id, client_secret, redirect_uri]):
                raise ValueError("Missing Spotify credentials in environment variables")

            self._spotify_config = SpotifyConfig(
                client_id=client_id,
                client_secret=client_secret,
                redirect_uri=redirect_uri,
            )

            logger.info("Spotify configuration loaded from environment")

        except Exception as e:
            logger.error(f"Failed to load Spotify configuration: {e}")
            raise

    @property
    def config(self) -> Dict[str, Any]:
        """Gibt validierte Konfiguration zurück"""
        if self._config is None:
            raise RuntimeError("Configuration not loaded")
        return self._config

    @property
    def spotify(self) -> SpotifyConfig:
        """Gibt Spotify-Konfiguration zurück"""
        if self._spotify_config is None:
            raise RuntimeError("Spotify configuration not loaded")
        return self._spotify_config

    def get_monitoring_config(self) -> Dict[str, int]:
        """Gibt Monitoring-Konfiguration zurück"""
        return self.config["monitoring"]

    def get_playlist_config(self) -> Dict[str, str]:
        """Gibt Playlist-Konfiguration zurück"""
        return self.config["playlist"]

    def get_service_config(self) -> Dict[str, int]:
        """Gibt Service-Konfiguration zurück"""
        return self.config["service"]
