"""
Hauptanwendung für Spotify Mikroservice-Architektur
Sicherer Entry Point für Service-Management Dashboard

CWE-754: Error Handling - Comprehensive exception handling
CWE-400: Resource Management - Proper resource cleanup
CWE-20: Input Validation - Environment variable validation
CWE-532: Information Exposure Prevention - Secure logging
Bandit: B101, B104
"""

import logging
import os
import signal
import sys
from pathlib import Path
from typing import Optional

# Füge Projektverzeichnisse zum Python-Pfad hinzu
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))  # Hauptverzeichnis zuerst
sys.path.insert(1, str(project_root / "src"))  # src als zweites

# Imports mit try/except für bessere Fehlerbehandlung
try:
    from dashboard.service_control import ServiceControlDashboard
    from src.config import ConfigManager
except ImportError as e:
    print(f"Import Error: {e}")
    print("Current working directory:", os.getcwd())
    print("Python path:", sys.path[:3])
    sys.exit(1)


def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Konfiguriert sicheres Logging für die Anwendung
    CWE-532: Information Exposure Through Log Files Prevention
    """
    # Log-Level validieren - CWE-20: Input Validation
    valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    if log_level.upper() not in valid_levels:
        log_level = "INFO"

    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    handlers = [logging.StreamHandler(sys.stdout)]

    # Log-Datei Handler hinzufügen falls angegeben
    if log_file:
        try:
            # Sicherer Pfad-Handling
            log_path = Path(log_file).resolve()
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            handlers.append(file_handler)
        except Exception as e:
            print(f"Warning: Could not setup log file {log_file}: {e}")

    # Logging konfigurieren
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        handlers=handlers,
        force=True,  # Überschreibt bestehende Konfiguration
    )

    # Externe Library-Logs reduzieren für bessere Sicherheit
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("spotipy").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


class SpotifyMicroserviceApp:
    """
    Hauptanwendung für Spotify Mikroservice-Architektur

    Sicherheitsfeatures:
    - CWE-754: Comprehensive Error Handling
    - CWE-400: Resource Management mit graceful shutdown
    - CWE-20: Input Validation für alle Konfigurationsparameter
    - CWE-532: Sichere Logging-Praktiken
    """

    def __init__(self, config_path: str = "config.json"):
        """
        Initialisiert Hauptanwendung sicher
        CWE-20: Input Validation
        """
        self.logger = logging.getLogger(__name__)
        self.config_manager: Optional[ConfigManager] = None
        self.dashboard: Optional[ServiceControlDashboard] = None
        self.is_running = False

        # Input Validation für config_path
        if not isinstance(config_path, str) or len(config_path.strip()) == 0:
            raise ValueError("Config path must be non-empty string")

        self.config_path = config_path.strip()

        # Signal Handler für graceful shutdown registrieren
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.logger.info("Spotify Microservice App initialized")

    def _signal_handler(self, signum, frame):
        """
        Signal Handler für graceful shutdown
        CWE-754: Proper Resource Cleanup
        """
        self.logger.info(f"Signal {signum} received, shutting down gracefully...")
        self.stop()
        sys.exit(0)

    def initialize(self) -> bool:
        """
        Initialisiert alle Anwendungskomponenten
        CWE-754: Proper Initialization with Error Handling
        """
        try:
            self.logger.info("Initializing Spotify Microservice Application...")

            # Konfiguration laden
            self.config_manager = ConfigManager(self.config_path)
            self.logger.info("Configuration loaded successfully")

            # Service Control Dashboard erstellen
            self.dashboard = ServiceControlDashboard(self.config_manager)
            self.logger.info("Service Control Dashboard created")

            self.logger.info("Application initialization completed successfully")
            return True

        except Exception as e:
            self.logger.error(f"Application initialization failed: {e}")
            return False

    def run(
        self, host: str = "127.0.0.1", port: int = 5000, debug: bool = False
    ) -> None:
        """
        Startet die Hauptanwendung
        CWE-754: Comprehensive Error Handling
        CWE-20: Input Validation für Parameter
        """
        try:
            # Input Validation
            if not isinstance(host, str) or len(host.strip()) == 0:
                raise ValueError("Host must be non-empty string")

            if not isinstance(port, int) or port < 1 or port > 65535:
                raise ValueError("Port must be valid integer between 1-65535")

            if not isinstance(debug, bool):
                debug = False

            host = host.strip()

            # Initialisierung
            if not self.initialize():
                raise RuntimeError("Application initialization failed")

            if not self.dashboard:
                raise RuntimeError("Dashboard not initialized")

            self.is_running = True
            self.logger.info(f"Starting Spotify Microservice App on {host}:{port}")

            # Sicherheitswarnung für Production
            if not debug and host != "127.0.0.1":
                self.logger.warning(
                    "Running on non-localhost in production mode - "
                    "ensure proper security measures are in place"
                )

            # Dashboard starten (blockierend)
            self.dashboard.run(host=host, port=port, debug=debug)

        except KeyboardInterrupt:
            self.logger.info("Shutdown requested by user")
        except Exception as e:
            self.logger.error(f"Application execution failed: {e}")
            raise
        finally:
            self.stop()

    def stop(self) -> None:
        """
        Stoppt die Anwendung sicher
        CWE-754: Graceful Shutdown
        CWE-400: Resource Management
        """
        try:
            if not self.is_running:
                return

            self.logger.info("Stopping Spotify Microservice Application...")
            self.is_running = False

            # Dashboard cleanup
            if self.dashboard:
                try:
                    service_manager = self.dashboard.get_service_manager()
                    service_manager.shutdown_all()
                    self.logger.info("All services shut down")
                except Exception as e:
                    self.logger.error(f"Error shutting down services: {e}")

            self.logger.info("Application stopped successfully")

        except Exception as e:
            self.logger.error(f"Error during application shutdown: {e}")


def validate_environment() -> dict:
    """
    Validiert und sammelt Umgebungsvariablen
    CWE-20: Input Validation
    CWE-798: Secure Configuration Management
    """
    env_config = {}

    # Flask-Konfiguration
    env_config["host"] = os.environ.get("FLASK_HOST", "127.0.0.1")

    # Port validieren
    try:
        port = int(os.environ.get("FLASK_PORT", "5000"))
        if 1 <= port <= 65535:
            env_config["port"] = port
        else:
            raise ValueError("Port out of range")
    except (ValueError, TypeError):
        env_config["port"] = 5000

    # Debug-Modus
    debug_str = os.environ.get("FLASK_DEBUG", "False").lower()
    env_config["debug"] = debug_str in ("true", "1", "yes", "on")

    # Logging-Konfiguration
    env_config["log_level"] = os.environ.get("LOG_LEVEL", "INFO").upper()
    env_config["log_file"] = os.environ.get("LOG_FILE", "logs/microservices.log")

    return env_config


def main():
    """
    Hauptfunktion - Entry Point der Anwendung
    CWE-754: Top-level Error Handling
    """
    try:
        # Umgebungsvariablen validieren
        env_config = validate_environment()

        # Logging konfigurieren
        setup_logging(
            log_level=env_config["log_level"], log_file=env_config["log_file"]
        )

        logger = logging.getLogger(__name__)
        logger.info("Starting Spotify Microservice Application")
        logger.info(f"Python version: {sys.version}")
        logger.info(f"Working directory: {os.getcwd()}")

        # Anwendung erstellen und starten
        app = SpotifyMicroserviceApp()
        app.run(
            host=env_config["host"], port=env_config["port"], debug=env_config["debug"]
        )

    except KeyboardInterrupt:
        print("\nShutdown requested by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
