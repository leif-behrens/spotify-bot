"""
Zentrales Logging-Setup für Spotify Bot
CWE-532: Information Exposure Prevention, sichere Konfigurierbarkeit
"""

import logging
import logging.handlers
import os
from pathlib import Path
from typing import Optional

# Import wird später gemacht, um zirkuläre Imports zu vermeiden


class LoggingSetup:
    """
    Zentrales Logging-Setup mit konfigurierbaren Optionen
    
    Features:
    - Konfigurierbare Log-Level über config.json
    - Optional File-Logging mit Rotation
    - Sichere Log-Formate ohne sensitive Daten
    - CWE-532: Information Exposure Prevention
    """
    
    _initialized = False
    
    @classmethod
    def setup_logging(cls, config_manager = None) -> None:
        """
        Initialisiert das Logging-System basierend auf Konfiguration
        Wird nur einmal ausgeführt (Singleton-Pattern)
        """
        if cls._initialized:
            return
            
        try:
            if config_manager is None:
                # Late import um zirkuläre Imports zu vermeiden
                from ..core.config import ConfigManager
                config_manager = ConfigManager()
                
            logging_config = config_manager.get_logging_config()
            
            # Root Logger konfigurieren
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.DEBUG)  # Alle Messages zulassen
            
            # Entferne alle existierenden Handler
            for handler in root_logger.handlers[:]:
                root_logger.removeHandler(handler)
            
            # Log-Level aus Config
            log_level = getattr(logging, logging_config.get("level", "INFO").upper())
            log_format = logging_config.get(
                "format", 
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            
            formatter = logging.Formatter(log_format)
            
            # Console Handler (falls aktiviert)
            if logging_config.get("console_enabled", True):
                console_handler = logging.StreamHandler()
                console_handler.setLevel(log_level)
                console_handler.setFormatter(formatter)
                root_logger.addHandler(console_handler)
            
            # File Handler (falls aktiviert)
            if logging_config.get("file_enabled", False):
                log_file_path = logging_config.get("file_path", "data/spotify-bot.log")
                log_file = Path(log_file_path)
                
                # Stelle sicher, dass das Verzeichnis existiert
                log_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Rotating File Handler mit sicheren Dateiberechtigungen
                file_handler = logging.handlers.RotatingFileHandler(
                    log_file,
                    maxBytes=10*1024*1024,  # 10MB
                    backupCount=5,
                    encoding='utf-8'
                )
                file_handler.setLevel(log_level)
                file_handler.setFormatter(formatter)
                root_logger.addHandler(file_handler)
                
                # Sichere Dateiberechtigungen - CWE-532
                try:
                    os.chmod(log_file, 0o600)  # Nur Owner kann lesen/schreiben
                except (OSError, AttributeError):
                    # Windows oder andere Systeme ohne chmod
                    pass
            
            # Logging für externe Libraries reduzieren
            logging.getLogger("urllib3").setLevel(logging.WARNING)
            logging.getLogger("requests").setLevel(logging.WARNING)
            logging.getLogger("werkzeug").setLevel(logging.WARNING)
            
            cls._initialized = True
            
            # Bestätigungsnachricht
            logger = logging.getLogger(__name__)
            logger.info(f"Logging initialized - Level: {logging_config.get('level', 'INFO')}")
            
            if logging_config.get("file_enabled", False):
                logger.info(f"File logging enabled: {logging_config.get('file_path')}")
                
        except Exception as e:
            # Fallback auf Standard-Logging
            logging.basicConfig(
                level=logging.INFO,
                format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to setup logging from config, using defaults: {e}")
            cls._initialized = True

    @classmethod 
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Gibt einen Logger zurück und stellt sicher, dass Logging initialisiert ist
        """
        if not cls._initialized:
            cls.setup_logging()
        return logging.getLogger(name)