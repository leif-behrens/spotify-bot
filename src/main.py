"""
Hauptanwendung für Spotify Auto-Discovery Bot
CWE-754: Error Handling, CWE-400: Resource Management
Bandit: B101, B104
"""

import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Optional

# Füge src-Verzeichnis zum Python-Pfad hinzu
sys.path.insert(0, str(Path(__file__).parent))

from config import ConfigManager  # noqa: E402
from dashboard import SecureDashboard  # noqa: E402
from monitoring_service import SpotifyMonitoringService  # noqa: E402


# Logging konfigurieren
def setup_logging(log_level: str = "INFO", log_file: Optional[str] = None) -> None:
    """
    Konfiguriert sicheres Logging
    CWE-532: Information Exposure Through Log Files Prevention
    """
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

    # Log-Level validieren
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    # Logging konfigurieren
    logging.basicConfig(
        level=numeric_level,
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler(log_file, encoding="utf-8")
            if log_file
            else logging.NullHandler(),
        ],
    )

    # Externe Library-Logs reduzieren
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("spotipy").setLevel(logging.WARNING)


class SpotifyBot:
    """
    Hauptanwendung für Spotify Auto-Discovery Bot
    CWE-754: Comprehensive Error Handling
    CWE-400: Resource Management
    """

    def __init__(self, config_path: str = "config.json"):
        self.logger = logging.getLogger(__name__)
        self.config_manager: Optional[ConfigManager] = None
        self.monitoring_service: Optional[SpotifyMonitoringService] = None
        self.dashboard: Optional[SecureDashboard] = None
        self.dashboard_thread: Optional[threading.Thread] = None
        self.is_running = False
        self.config_path = config_path

        # Signal Handler für graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """
        Signal Handler für graceful shutdown
        CWE-754: Proper Resource Cleanup
        """
        self.logger.info(f"Signal {signum} received, shutting down gracefully...")
        self.stop()
        sys.exit(0)

    def initialize(self) -> None:
        """
        Initialisiert alle Bot-Komponenten
        CWE-754: Proper Initialization with Error Handling
        """
        try:
            self.logger.info("Initializing Spotify Auto-Discovery Bot...")

            # Konfiguration laden
            self.config_manager = ConfigManager(self.config_path)
            self.logger.info("Configuration loaded successfully")

            # Monitoring Service erstellen
            self.monitoring_service = SpotifyMonitoringService(self.config_manager)
            self.logger.info("Monitoring service created")

            # Dashboard erstellen
            self.dashboard = SecureDashboard(
                self.config_manager, self.monitoring_service
            )
            self.logger.info("Dashboard created")

            # Event Callbacks registrieren
            self.monitoring_service.set_track_added_callback(self._on_track_added)

            self.logger.info("Bot initialization completed successfully")

        except Exception as e:
            self.logger.error(f"Bot initialization failed: {e}")
            raise

    def _on_track_added(self, track_data: dict) -> None:
        """
        Callback für hinzugefügte Tracks
        CWE-532: Prevent Sensitive Information Logging
        """
        try:
            track_name = track_data.get("track_name", "Unknown")
            artist_name = track_data.get("artist_name", "Unknown")

            # Log ohne sensible Daten
            self.logger.info(
                f"Track added to playlist: {track_name[:50]} by {artist_name[:50]}"
            )

        except Exception as e:
            self.logger.error(f"Error in track added callback: {e}")

    def start_monitoring(self) -> None:
        """
        Startet den Monitoring-Service
        CWE-754: Error Handling
        """
        try:
            if not self.monitoring_service:
                raise RuntimeError("Monitoring service not initialized")

            self.logger.info("Starting monitoring service...")
            self.monitoring_service.start()
            self.logger.info("Monitoring service started successfully")

        except Exception as e:
            self.logger.error(f"Failed to start monitoring service: {e}")
            raise

    def start_dashboard(
        self, host: str = "127.0.0.1", port: int = 5000, debug: bool = False
    ) -> None:
        """
        Startet das Dashboard in einem separaten Thread
        CWE-400: Controlled Threading
        """
        try:
            if not self.dashboard:
                raise RuntimeError("Dashboard not initialized")

            # Dashboard in separatem Thread starten
            def run_dashboard():
                try:
                    self.dashboard.run(host=host, port=port, debug=debug)
                except Exception as e:
                    self.logger.error(f"Dashboard error: {e}")

            self.dashboard_thread = threading.Thread(
                target=run_dashboard,
                name="DashboardThread",
                daemon=True,  # Daemon Thread für automatisches cleanup
            )

            self.dashboard_thread.start()
            self.logger.info(f"Dashboard started on http://{host}:{port}")

        except Exception as e:
            self.logger.error(f"Failed to start dashboard: {e}")
            raise

    def run(
        self,
        start_monitoring: bool = True,
        start_dashboard: bool = True,
        dashboard_host: str = "127.0.0.1",
        dashboard_port: int = 5000,
        dashboard_debug: bool = False,
    ) -> None:
        """
        Hauptlaufmethode
        CWE-754: Comprehensive Error Handling
        """
        try:
            self.initialize()

            if start_dashboard:
                self.start_dashboard(dashboard_host, dashboard_port, dashboard_debug)
                time.sleep(2)  # Warte bis Dashboard gestartet ist

            if start_monitoring:
                self.start_monitoring()

            self.is_running = True
            self.logger.info("Spotify Bot is running. Press Ctrl+C to stop.")

            # Hauptschleife - warte auf Shutdown
            try:
                while self.is_running:
                    time.sleep(1)

                    # Prüfe Service-Gesundheit
                    if (
                        self.monitoring_service
                        and start_monitoring
                        and not self.monitoring_service.is_running
                    ):
                        self.logger.warning("Monitoring service stopped unexpectedly")

                        # Automatischer Neustart nach Fehlern
                        try:
                            self.logger.info(
                                "Attempting to restart monitoring service..."
                            )
                            self.monitoring_service.start()
                            self.logger.info(
                                "Monitoring service restarted successfully"
                            )
                        except Exception as e:
                            self.logger.error(
                                f"Failed to restart monitoring service: {e}"
                            )
                            break

            except KeyboardInterrupt:
                self.logger.info("Shutdown requested by user")

        except Exception as e:
            self.logger.error(f"Bot execution failed: {e}")
            raise
        finally:
            self.stop()

    def stop(self) -> None:
        """
        Stoppt den Bot sicher
        CWE-754: Graceful Shutdown
        """
        try:
            self.logger.info("Stopping Spotify Bot...")
            self.is_running = False

            # Monitoring Service stoppen
            if self.monitoring_service:
                try:
                    self.monitoring_service.stop()
                    self.logger.info("Monitoring service stopped")
                except Exception as e:
                    self.logger.error(f"Error stopping monitoring service: {e}")

            # Dashboard-Thread beenden (läuft als Daemon)
            if self.dashboard_thread and self.dashboard_thread.is_alive():
                self.logger.info("Dashboard thread will be cleaned up automatically")

            self.logger.info("Bot stopped successfully")

        except Exception as e:
            self.logger.error(f"Error during bot shutdown: {e}")


def main():
    """
    Hauptfunktion
    CWE-754: Top-level Error Handling
    """
    try:
        # Logging konfigurieren
        log_level = os.environ.get("LOG_LEVEL", "INFO")
        log_file = os.environ.get("LOG_FILE", "logs/spotify_bot.log")

        # Log-Verzeichnis erstellen
        if log_file:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        setup_logging(log_level, log_file)

        logger = logging.getLogger(__name__)
        logger.info("Starting Spotify Auto-Discovery Bot")

        # Bot erstellen und starten
        bot = SpotifyBot()

        # Konfiguration aus Environment Variables
        dashboard_host = os.environ.get("FLASK_HOST", "127.0.0.1")
        dashboard_port = int(os.environ.get("FLASK_PORT", "5000"))
        dashboard_debug = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

        # Bot ausführen
        bot.run(
            start_monitoring=True,
            start_dashboard=True,
            dashboard_host=dashboard_host,
            dashboard_port=dashboard_port,
            dashboard_debug=dashboard_debug,
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
