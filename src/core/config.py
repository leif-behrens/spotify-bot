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
        "callback_server": {
            "type": "object",
            "properties": {
                "host": {"type": "string", "pattern": "^127\\.0\\.0\\.1$|^localhost$"},
                "port": {"type": "integer", "minimum": 1024, "maximum": 65535},
                "timeout_seconds": {"type": "integer", "minimum": 60, "maximum": 600},
                "debug": {"type": "boolean"},
            },
            "required": ["host", "port", "timeout_seconds", "debug"],
        },
        "oauth": {
            "type": "object",
            "properties": {
                "scope": {"type": "string", "minLength": 10},
                "state_length": {"type": "integer", "minimum": 8, "maximum": 32},
            },
            "required": ["scope", "state_length"],
        },
        "logging": {
            "type": "object",
            "properties": {
                "level": {
                    "type": "string",
                    "enum": ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                },
                "format": {"type": "string", "minLength": 10},
                "file_enabled": {"type": "boolean"},
                "file_path": {"type": "string"},
                "console_enabled": {"type": "boolean"},
            },
            "required": ["level", "format", "file_enabled", "console_enabled"],
        },
        "watchdog": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "check_interval_seconds": {
                    "type": "integer",
                    "minimum": 10,
                    "maximum": 300,
                },
                "max_restart_attempts": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10,
                },
                "restart_cooldown_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": 600,
                },
                "failure_notification_enabled": {"type": "boolean"},
                "services_to_monitor": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["discovery", "callback"]},
                    "uniqueItems": True,
                },
            },
            "required": [
                "enabled",
                "check_interval_seconds",
                "max_restart_attempts",
                "restart_cooldown_seconds",
                "failure_notification_enabled",
                "services_to_monitor",
            ],
        },
        "email_notifications": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "smtp_server": {"type": "string"},
                "smtp_port": {"type": "integer", "minimum": 1, "maximum": 65535},
                "use_tls": {"type": "boolean"},
                "sender_email": {"type": "string"},
                "sender_password": {"type": "string"},
                "recipient_email": {"type": "string"},
                "subject_prefix": {"type": "string", "maxLength": 50},
            },
            "required": [
                "enabled",
                "smtp_server",
                "smtp_port",
                "use_tls",
                "sender_email",
                "sender_password",
                "recipient_email",
                "subject_prefix",
            ],
        },
        "telegram_notifications": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean"},
                "timeout_seconds": {"type": "integer", "minimum": 5, "maximum": 120},
                "retry_attempts": {"type": "integer", "minimum": 1, "maximum": 5},
                "retry_delay_seconds": {"type": "integer", "minimum": 1, "maximum": 30},
                "rate_limit_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": 300,
                },
                "message_max_length": {
                    "type": "integer",
                    "minimum": 100,
                    "maximum": 4096,
                },
            },
            "required": [
                "enabled",
                "timeout_seconds",
                "retry_attempts",
                "retry_delay_seconds",
                "rate_limit_seconds",
                "message_max_length",
            ],
        },
    },
    "required": [
        "monitoring",
        "playlist",
        "service",
        "callback_server",
        "oauth",
        "logging",
        "watchdog",
        "email_notifications",
        "telegram_notifications",
    ],
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

    def __init__(self, config_path: str = "config/config.json"):
        self.config_path = Path(config_path)
        self._config: Optional[Dict[str, Any]] = None
        self._spotify_config: Optional[SpotifyConfig] = None

        # Lade Environment Variables sicher mit Override
        # Bestimme .env Pfad relativ zum Projekt-Root
        project_root = Path(__file__).parent.parent.parent
        env_file = project_root / ".env"
        load_dotenv(env_file, override=True)
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

    def get_callback_server_config(self) -> Dict[str, Any]:
        """Gibt Callback-Server-Konfiguration zurück"""
        return self.config["callback_server"]

    def get_oauth_config(self) -> Dict[str, Any]:
        """Gibt OAuth-Konfiguration zurück"""
        return self.config["oauth"]

    def get_logging_config(self) -> Dict[str, Any]:
        """Gibt Logging-Konfiguration zurück"""
        return self.config["logging"]

    def get_watchdog_config(self) -> Dict[str, Any]:
        """Gibt Watchdog-Konfiguration zurück"""
        return self.config["watchdog"]

    def get_email_notifications_config(self) -> Dict[str, Any]:
        """Gibt E-Mail-Benachrichtigungs-Konfiguration zurück"""
        email_config = self.config["email_notifications"]

        # Validierung: Wenn E-Mail aktiviert ist, müssen Credentials vorhanden sein
        if email_config.get("enabled", False):
            required_fields = [
                "smtp_server",
                "sender_email",
                "sender_password",
                "recipient_email",
            ]
            missing_fields = [
                field
                for field in required_fields
                if not email_config.get(field, "").strip()
            ]

            if missing_fields:
                logger.warning(
                    f"Email notifications enabled but missing: {', '.join(missing_fields)}"
                )
                logger.warning(
                    "Email notifications will be disabled until credentials are provided"
                )
                # Erstelle eine Kopie der Konfiguration mit disabled status
                email_config = email_config.copy()
                email_config["enabled"] = False

        return email_config

    def get_telegram_notifications_config(self) -> Dict[str, Any]:
        """Gibt Telegram-Benachrichtigungs-Konfiguration zurück"""
        telegram_config = self.config["telegram_notifications"]

        # Validierung: Wenn Telegram aktiviert ist, müssen Credentials vorhanden sein
        if telegram_config.get("enabled", False):
            bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
            chat_id = os.environ.get("TELEGRAM_CHAT_ID")

            if not bot_token or not chat_id:
                logger.warning(
                    "Telegram notifications enabled but missing TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID"
                )
                logger.warning(
                    "Telegram notifications will be disabled until credentials are provided"
                )
                # Erstelle eine Kopie der Konfiguration mit disabled status
                telegram_config = telegram_config.copy()
                telegram_config["enabled"] = False

        return telegram_config
