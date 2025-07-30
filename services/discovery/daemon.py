"""
Discovery Service Daemon - Standalone Process
Läuft unabhängig vom Dashboard als eigener Prozess

CWE-754: Error Handling - Comprehensive exception handling
CWE-400: Resource Management - Process lifecycle management
CWE-20: Input Validation - Command validation
CWE-532: Information Exposure Prevention - Secure logging
Bandit: B101, B104
"""

import logging
import os
import signal
import sys
import time
from pathlib import Path
from typing import Dict, Optional

# Füge Projektverzeichnis zum Pfad hinzu
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))
sys.path.insert(1, str(project_root / "src"))

from config import ConfigManager
from ipc.communication import IPCServer, ServiceMessage, ServiceRegistry
from services.discovery.service import SpotifyDiscoveryService


class DiscoveryServiceDaemon:
    """
    Standalone Discovery Service Daemon

    Sicherheitsfeatures:
    - CWE-754: Comprehensive Error Handling
    - CWE-400: Resource Management mit graceful shutdown
    - CWE-20: Input Validation für alle Commands
    - CWE-532: Sichere Logging-Praktiken
    """

    def __init__(self, port: int = 9001):
        """
        Initialisiert Service-Daemon
        CWE-20: Input Validation
        """
        self.service_name = "discovery"
        self.port = max(1024, min(port, 65535))  # Port-Validierung

        # Logging setup
        self.logger = self._setup_logging()

        # Komponenten
        self.config: Optional[ConfigManager] = None
        self.discovery_service: Optional[SpotifyDiscoveryService] = None
        self.ipc_server: Optional[IPCServer] = None
        self.registry = ServiceRegistry()

        # Daemon State
        self.is_running = False
        self.pid = os.getpid()

        # Signal Handler für graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        self.logger.info(f"Discovery Service Daemon initialized (PID: {self.pid})")

    def _setup_logging(self) -> logging.Logger:
        """
        Konfiguriert sicheres Logging für Daemon
        CWE-532: Information Exposure Through Log Files Prevention
        """
        logger = logging.getLogger(f"daemon.{self.service_name}")

        # Log-Verzeichnis erstellen
        log_dir = project_root / "logs"
        log_dir.mkdir(exist_ok=True)

        # File Handler für Service-spezifische Logs
        log_file = log_dir / f"{self.service_name}_daemon.log"
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.INFO)

        # Console Handler für Debugging
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)

        # Logger konfigurieren
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        logger.setLevel(logging.INFO)

        return logger

    def _signal_handler(self, signum, frame):
        """
        Signal Handler für graceful shutdown
        CWE-754: Proper Resource Cleanup
        """
        self.logger.info(f"Signal {signum} received, shutting down daemon...")
        self.stop()
        sys.exit(0)

    def initialize(self) -> bool:
        """
        Initialisiert Daemon-Komponenten
        CWE-754: Proper Initialization with Error Handling
        """
        try:
            self.logger.info("Initializing Discovery Service Daemon...")

            # Konfiguration laden
            config_path = project_root / "config.json"
            self.config = ConfigManager(str(config_path))
            self.logger.info("Configuration loaded")

            # Discovery Service erstellen
            self.discovery_service = SpotifyDiscoveryService(
                service_name=self.service_name, config=self.config
            )
            self.logger.info("Discovery service created")

            # IPC Server einrichten
            self.ipc_server = IPCServer(self.service_name, self.port)
            self._register_command_handlers()
            self.logger.info(f"IPC server configured on port {self.port}")

            # Check if we can auto-start the discovery service
            self.logger.info("Checking if discovery service can auto-start...")

            # Check if authenticated
            if self.discovery_service.authenticator.is_authenticated():
                self.logger.info(
                    "Spotify authentication found, auto-starting discovery service..."
                )
                if self.discovery_service.start():
                    self.logger.info("Discovery service auto-started successfully")
                else:
                    self.logger.warning("Failed to auto-start discovery service")
            else:
                self.logger.info(
                    "Spotify authentication required - service will start after authentication"
                )
                self.logger.info("Use the dashboard or CLI to trigger authentication")

            self.logger.info("Daemon initialization completed")
            return True

        except Exception as e:
            self.logger.error(f"Daemon initialization failed: {e}")
            return False

    def _register_command_handlers(self) -> None:
        """
        Registriert IPC Command Handler
        CWE-754: Exception Handling
        """
        if not self.ipc_server:
            return

        self.ipc_server.register_handler("status", self._handle_status)
        self.ipc_server.register_handler("start", self._handle_start)
        self.ipc_server.register_handler("stop", self._handle_stop)
        self.ipc_server.register_handler("restart", self._handle_restart)
        self.ipc_server.register_handler("health", self._handle_health)

        self.logger.info("IPC command handlers registered")

    def _handle_status(self, message: ServiceMessage) -> Dict:
        """
        Status Command Handler
        CWE-200: Information Exposure Prevention
        """
        try:
            if not self.discovery_service:
                return {
                    "success": True,
                    "status": "not_initialized",
                    "is_healthy": False,
                    "daemon_pid": self.pid,
                }

            # Service Status vom Discovery Service holen
            service_status = self.discovery_service.get_status()

            # Daemon-spezifische Informationen hinzufügen
            status = {
                "success": True,
                "daemon_pid": self.pid,
                "daemon_port": self.port,
                "daemon_running": self.is_running,
                **service_status,  # Service-spezifischer Status
            }

            return status

        except Exception as e:
            self.logger.error(f"Error getting status: {e}")
            return {"success": False, "error": str(e), "daemon_pid": self.pid}

    def _handle_start(self, message: ServiceMessage) -> Dict:
        """Start Command Handler - Auto-starts the discovery service"""
        try:
            if not self.discovery_service:
                return {"success": False, "error": "Service not initialized"}

            if self.discovery_service.is_running():
                return {"success": True, "message": "Service already running"}

            # Auto-start the discovery service when daemon starts
            success = self.discovery_service.start()
            if success:
                self.logger.info("Discovery service started via IPC command")
                return {"success": True, "message": "Service started successfully"}
            else:
                return {"success": False, "error": "Failed to start service"}

        except Exception as e:
            self.logger.error(f"Error starting service: {e}")
            return {"success": False, "error": str(e)}

    def _handle_stop(self, message: ServiceMessage) -> Dict:
        """Stop Command Handler"""
        try:
            if not self.discovery_service:
                return {"success": True, "message": "Service not running"}

            if not self.discovery_service.is_running():
                return {"success": True, "message": "Service already stopped"}

            success = self.discovery_service.stop()
            if success:
                self.logger.info("Discovery service stopped via IPC command")
                return {"success": True, "message": "Service stopped successfully"}
            else:
                return {"success": False, "error": "Failed to stop service"}

        except Exception as e:
            self.logger.error(f"Error stopping service: {e}")
            return {"success": False, "error": str(e)}

    def _handle_restart(self, message: ServiceMessage) -> Dict:
        """Restart Command Handler"""
        try:
            # Service stoppen
            stop_result = self._handle_stop(message)
            if not stop_result.get("success", False):
                return stop_result

            # Kurz warten
            time.sleep(2)

            # Service starten
            start_result = self._handle_start(message)
            if start_result.get("success", False):
                self.logger.info("Discovery service restarted via IPC command")
                return {"success": True, "message": "Service restarted successfully"}
            else:
                return start_result

        except Exception as e:
            self.logger.error(f"Error restarting service: {e}")
            return {"success": False, "error": str(e)}

    def _handle_health(self, message: ServiceMessage) -> Dict:
        """Health Check Command Handler"""
        try:
            if not self.discovery_service:
                return {
                    "success": True,
                    "is_healthy": False,
                    "health_status": "service_not_initialized",
                }

            is_healthy = self.discovery_service.is_healthy()
            status = self.discovery_service.get_status()

            return {
                "success": True,
                "is_healthy": is_healthy,
                "health_status": "healthy" if is_healthy else "unhealthy",
                "error_count": status.get("error_count", 0),
                "last_error": status.get("last_error"),
            }

        except Exception as e:
            self.logger.error(f"Error checking health: {e}")
            return {"success": False, "is_healthy": False, "error": str(e)}

    def start(self) -> bool:
        """
        Startet den Service-Daemon
        CWE-754: Comprehensive Error Handling
        """
        try:
            if not self.initialize():
                return False

            # IPC Server starten
            if not self.ipc_server or not self.ipc_server.start():
                self.logger.error("Failed to start IPC server")
                return False

            # Service in Registry registrieren
            if not self.registry.register_service(
                self.service_name, self.pid, self.port, "running"
            ):
                self.logger.warning("Failed to register service in registry")

            self.is_running = True
            self.logger.info(f"Discovery Service Daemon started successfully")
            self.logger.info(f"IPC Server listening on port {self.port}")

            # Hauptschleife
            self._run_daemon_loop()

            return True

        except Exception as e:
            self.logger.error(f"Failed to start daemon: {e}")
            return False
        finally:
            self.stop()

    def _run_daemon_loop(self) -> None:
        """
        Hauptschleife des Daemons
        CWE-754: Exception Handling in Main Loop
        """
        self.logger.info("Starting daemon main loop")

        heartbeat_interval = 30  # Sekunden
        last_heartbeat = 0

        try:
            while self.is_running:
                current_time = time.time()

                # Heartbeat senden
                if current_time - last_heartbeat >= heartbeat_interval:
                    self.registry.update_heartbeat(self.service_name)
                    last_heartbeat = current_time

                # Kurz schlafen
                time.sleep(1)

        except KeyboardInterrupt:
            self.logger.info("Daemon interrupted by user")
        except Exception as e:
            self.logger.error(f"Error in daemon main loop: {e}")

        self.logger.info("Daemon main loop ended")

    def stop(self) -> None:
        """
        Stoppt den Service-Daemon sicher
        CWE-754: Graceful Shutdown
        CWE-400: Resource Management
        """
        try:
            self.logger.info("Stopping Discovery Service Daemon...")
            self.is_running = False

            # Discovery Service stoppen
            if self.discovery_service:
                try:
                    self.discovery_service.stop()
                    self.logger.info("Discovery service stopped")
                except Exception as e:
                    self.logger.error(f"Error stopping discovery service: {e}")

            # IPC Server stoppen
            if self.ipc_server:
                try:
                    self.ipc_server.stop()
                    self.logger.info("IPC server stopped")
                except Exception as e:
                    self.logger.error(f"Error stopping IPC server: {e}")

            # Service aus Registry entfernen
            try:
                self.registry.unregister_service(self.service_name)
                self.logger.info("Service unregistered from registry")
            except Exception as e:
                self.logger.error(f"Error unregistering service: {e}")

            self.logger.info("Discovery Service Daemon stopped successfully")

        except Exception as e:
            self.logger.error(f"Error during daemon shutdown: {e}")


def main():
    """
    Hauptfunktion für Daemon
    CWE-754: Top-level Error Handling
    """
    try:
        # Port aus Umgebungsvariablen oder Argument
        port = int(os.environ.get("DISCOVERY_SERVICE_PORT", "9001"))

        # Daemon erstellen und starten
        daemon = DiscoveryServiceDaemon(port=port)
        daemon.start()

    except KeyboardInterrupt:
        print("\nDaemon interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal daemon error: {e}")
        logging.error(f"Fatal daemon error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
