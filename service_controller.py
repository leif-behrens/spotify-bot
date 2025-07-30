"""
Service Controller CLI für Spotify Mikroservices
Command-Line Interface für Service-Management unabhängig vom Dashboard

CWE-754: Error Handling - Comprehensive exception handling
CWE-20: Input Validation - CLI argument validation
CWE-400: Resource Management - Process management
CWE-532: Information Exposure Prevention - Secure logging
Bandit: B101, B104, B602
"""

import argparse
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

# Füge Projektverzeichnis zum Pfad hinzu
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from ipc.communication import IPCClient, ServiceRegistry


class ServiceController:
    """
    CLI Controller für Service-Management

    Sicherheitsfeatures:
    - CWE-754: Comprehensive Error Handling
    - CWE-20: Input Validation für alle CLI-Parameter
    - CWE-400: Resource Management für Prozesse
    - CWE-532: Sichere Logging-Praktiken
    """

    def __init__(self):
        self.project_root = project_root
        self.registry = ServiceRegistry()
        self.ipc_client = IPCClient(timeout=15)

        # Service-Definitionen
        self.services = {
            "discovery": {
                "name": "discovery",
                "display_name": "Auto Discovery Service",
                "daemon_script": "services/discovery/daemon.py",
                "default_port": 9001,
                "description": "Automatic music discovery based on listening behavior",
            }
            # Weitere Services können hier hinzugefügt werden
        }

        # Logging setup
        self.logger = self._setup_logging()

    def _setup_logging(self) -> logging.Logger:
        """
        Konfiguriert Logging für Controller
        CWE-532: Information Exposure Prevention
        """
        logger = logging.getLogger("service_controller")

        # Console Handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter("%(levelname)s: %(message)s")
        console_handler.setFormatter(formatter)

        logger.addHandler(console_handler)
        logger.setLevel(logging.INFO)

        return logger

    def list_services(self) -> None:
        """
        Listet alle verfügbaren Services
        CWE-200: Information Exposure Prevention
        """
        print("Available Spotify Services:")
        print("-" * 50)

        # Registry-Status laden
        registry_services = self.registry.list_services()

        for service_name, service_info in self.services.items():
            # Status aus Registry
            registry_info = registry_services.get(service_name, {})

            status = "[STOPPED]"
            pid_info = ""

            if registry_info:
                if self._is_process_running(registry_info.get("pid")):
                    status = "[RUNNING]"
                    pid_info = f" (PID: {registry_info.get('pid')}, Port: {registry_info.get('port')})"
                else:
                    status = "[ZOMBIE] (Process no longer exists)"
                    # Cleanup zombie entry
                    self.registry.unregister_service(service_name)

            print(f"* {service_info['display_name']}")
            print(f"   Name: {service_name}")
            print(f"   Status: {status}{pid_info}")
            print(f"   Description: {service_info['description']}")
            print()

    def _is_process_running(self, pid: Optional[int]) -> bool:
        """
        Prüft ob Prozess läuft
        CWE-754: Exception Handling
        """
        if not pid:
            return False

        try:
            if os.name == "nt":  # Windows
                try:
                    import psutil

                    return psutil.pid_exists(pid)
                except ImportError:
                    # Fallback für Windows ohne psutil
                    try:
                        result = subprocess.run(
                            ["tasklist", "/FI", f"PID eq {pid}"],
                            capture_output=True,
                            text=True,
                        )
                        return str(pid) in result.stdout
                    except:
                        return False
            else:  # Unix/Linux
                os.kill(pid, 0)
                return True
        except (OSError, ImportError):
            return False

    def start_service(self, service_name: str) -> bool:
        """
        Startet Service
        CWE-754: Exception Handling
        CWE-400: Resource Management
        """
        # Input Validation - CWE-20
        if service_name not in self.services:
            self.logger.error(f"Unknown service: {service_name}")
            self.logger.info(f"Available services: {list(self.services.keys())}")
            return False

        service_info = self.services[service_name]

        try:
            # Prüfe ob Service bereits läuft
            registry_info = self.registry.get_service_info(service_name)
            if registry_info and self._is_process_running(registry_info.get("pid")):
                self.logger.info(
                    f"Service '{service_name}' läuft bereits (PID: {registry_info.get('pid')})"
                )
                return True

            # Cleanup alte Registry-Einträge
            if registry_info:
                self.registry.unregister_service(service_name)

            # Daemon-Script Pfad
            daemon_script = self.project_root / service_info["daemon_script"]
            if not daemon_script.exists():
                self.logger.error(f"Daemon script not found: {daemon_script}")
                return False

            # Python-Prozess starten
            self.logger.info(f"Starting {service_info['display_name']}...")

            # Umgebungsvariablen setzen
            env = os.environ.copy()
            env[f"{service_name.upper()}_SERVICE_PORT"] = str(
                service_info["default_port"]
            )

            # Subprocess starten (detached, kein neues Fenster)
            if os.name == "nt":  # Windows
                # Windows: Versteckter Prozess ohne neues Fenster
                process = subprocess.Popen(
                    [sys.executable, str(daemon_script)],
                    cwd=str(self.project_root),
                    env=env,
                    creationflags=subprocess.CREATE_NO_WINDOW
                    | subprocess.DETACHED_PROCESS,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                )
            else:  # Unix/Linux
                # Unix: Nohup für Background-Prozess
                process = subprocess.Popen(
                    [sys.executable, str(daemon_script)],
                    cwd=str(self.project_root),
                    env=env,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )

            # Kurz warten damit Service starten kann
            time.sleep(3)

            # Debug: Prüfen ob Prozess existiert
            self.logger.info(f"Checking if process {process.pid} is running...")

            # Prüfen ob Prozess läuft
            if self._is_process_running(process.pid):
                self.logger.info(
                    f"Service '{service_name}' erfolgreich gestartet (PID: {process.pid})"
                )

                # Warten bis Service in Registry registriert ist
                max_wait = 10
                for i in range(max_wait):
                    registry_info = self.registry.get_service_info(service_name)
                    if registry_info:
                        self.logger.info(
                            f"   IPC Server läuft auf Port {registry_info.get('port')}"
                        )
                        return True
                    time.sleep(1)
                    self.logger.info(
                        f"   Waiting for IPC registration... ({i+1}/{max_wait})"
                    )

                self.logger.warning(
                    "Service gestartet, aber IPC-Registrierung nicht bestätigt"
                )
                return True
            else:
                self.logger.error(
                    f"Service '{service_name}' process (PID: {process.pid}) ist nicht mehr da"
                )

                # Debug: Versuche direkt zu starten um Fehler zu sehen
                self.logger.info("Trying to start daemon directly for debugging...")
                try:
                    debug_process = subprocess.run(
                        [sys.executable, str(daemon_script)],
                        cwd=str(self.project_root),
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.logger.error(f"Daemon stdout: {debug_process.stdout}")
                    self.logger.error(f"Daemon stderr: {debug_process.stderr}")
                    self.logger.error(f"Daemon exit code: {debug_process.returncode}")
                except subprocess.TimeoutExpired:
                    self.logger.info(
                        "Debug daemon run timed out (normal for background service)"
                    )
                except Exception as e:
                    self.logger.error(f"Debug daemon run failed: {e}")

                return False

        except Exception as e:
            self.logger.error(f"Error starting service {service_name}: {e}")
            return False

    def stop_service(self, service_name: str) -> bool:
        """
        Stoppt Service
        CWE-754: Exception Handling
        """
        # Input Validation
        if service_name not in self.services:
            self.logger.error(f"Unknown service: {service_name}")
            return False

        try:
            # Erst via IPC versuchen (graceful shutdown)
            self.logger.info(
                f"Stopping {self.services[service_name]['display_name']}..."
            )

            response = self.ipc_client.stop_service(service_name)
            if response:
                self.logger.info(f"Service '{service_name}' erfolgreich gestoppt")
                return True

            # Falls IPC nicht funktioniert, Prozess direkt beenden
            registry_info = self.registry.get_service_info(service_name)
            if registry_info:
                pid = registry_info.get("pid")
                if pid and self._is_process_running(pid):
                    self.logger.info(
                        f"IPC failed, terminating process {pid} directly..."
                    )

                    try:
                        if os.name == "nt":  # Windows
                            subprocess.run(
                                ["taskkill", "/F", "/PID", str(pid)],
                                check=True,
                                capture_output=True,
                            )
                        else:  # Unix/Linux
                            os.kill(pid, 15)  # SIGTERM
                            time.sleep(2)
                            if self._is_process_running(pid):
                                os.kill(pid, 9)  # SIGKILL

                        self.logger.info(f"Service '{service_name}' prozess beendet")

                        # Registry cleanup
                        self.registry.unregister_service(service_name)
                        return True

                    except Exception as e:
                        self.logger.error(f"Failed to kill process {pid}: {e}")

            self.logger.warning(f"Service '{service_name}' war nicht am Laufen")
            return True

        except Exception as e:
            self.logger.error(f"Error stopping service {service_name}: {e}")
            return False

    def restart_service(self, service_name: str) -> bool:
        """Startet Service neu"""
        self.logger.info(
            f"Restarting {self.services.get(service_name, {}).get('display_name', service_name)}..."
        )

        # Service stoppen
        if not self.stop_service(service_name):
            return False

        # Kurz warten
        time.sleep(2)

        # Service starten
        return self.start_service(service_name)

    def status_service(self, service_name: str) -> None:
        """
        Zeigt detaillierten Service-Status
        CWE-200: Information Exposure Prevention
        """
        if service_name not in self.services:
            self.logger.error(f"Unknown service: {service_name}")
            return

        service_info = self.services[service_name]
        print(f"Status: {service_info['display_name']}")
        print("-" * 50)

        # Registry-Informationen
        registry_info = self.registry.get_service_info(service_name)
        if not registry_info:
            print("[STOPPED] Service is not registered")
            return

        pid = registry_info.get("pid")
        port = registry_info.get("port")

        # Process Status
        if not self._is_process_running(pid):
            print(f"[ERROR] Service process (PID: {pid}) is no longer running")
            print("   Cleaning up registry...")
            self.registry.unregister_service(service_name)
            return

        print(f"[RUNNING] Process is running (PID: {pid})")
        print(f"IPC Port: {port}")
        print(f"Registered: {registry_info.get('registered_at', 'Unknown')}")
        print(f"Last Heartbeat: {registry_info.get('last_heartbeat', 'Unknown')}")

        # Service-specific status via IPC
        print("\nService Details:")
        try:
            status = self.ipc_client.get_service_status(service_name)
            if status:
                print(f"   Status: {status.get('status', 'unknown')}")
                print(f"   Healthy: {'OK' if status.get('is_healthy') else 'ERROR'}")
                print(f"   Uptime: {status.get('uptime_seconds', 0)} seconds")
                print(f"   Error Count: {status.get('error_count', 0)}")

                if status.get("last_error"):
                    print(f"   Last Error: {status.get('last_error')[:100]}")
            else:
                print("   [WARNING] Service does not respond to status request")
        except Exception as e:
            print(f"   [ERROR] Error getting status: {e}")

    def stop_all(self) -> None:
        """Stoppt alle Services"""
        print("Stopping all services...")

        registry_services = self.registry.list_services()
        for service_name in registry_services:
            if service_name in self.services:
                self.stop_service(service_name)

    def status_all(self) -> None:
        """Shows status of all services"""
        print("Status of all Services:")
        print("=" * 60)

        for service_name in self.services:
            self.status_service(service_name)
            print()

    def authenticate_service(self, service_name: str) -> bool:
        """
        Triggers interactive authentication for a service
        """
        if service_name not in self.services:
            self.logger.error(f"Unknown service: {service_name}")
            return False

        try:
            self.logger.info(f"Starting interactive authentication for {service_name}")

            # Import authentication directly
            import sys
            from pathlib import Path

            project_root = Path(__file__).parent
            sys.path.insert(0, str(project_root / "src"))

            from config import ConfigManager
            from spotify_auth import SpotifyAuthenticator

            # Create authenticator
            config = ConfigManager()
            authenticator = SpotifyAuthenticator(config)

            self.logger.info("Opening browser for Spotify authentication...")
            self.logger.info("Please complete the authentication in your browser")

            # Trigger interactive authentication
            if authenticator.authenticate_interactive():
                self.logger.info("✅ Authentication successful!")
                self.logger.info("You can now start the discovery service")
                return True
            else:
                self.logger.error("❌ Authentication failed")
                return False

        except Exception as e:
            self.logger.error(f"Error during authentication: {e}")
            return False


def main():
    """
    Hauptfunktion für CLI
    CWE-754: Top-level Error Handling
    CWE-20: Input Validation für CLI Args
    """
    try:
        # Argument Parser
        parser = argparse.ArgumentParser(
            description="Spotify Mikroservice Controller",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s list                    # List all services
  %(prog)s start discovery         # Start Discovery service
  %(prog)s stop discovery          # Stop Discovery service
  %(prog)s restart discovery       # Restart Discovery service
  %(prog)s status discovery        # Discovery service Status
  %(prog)s status                  # Status of all services
  %(prog)s auth discovery          # Authenticate Discovery service
  %(prog)s stop-all               # Stop all services
            """,
        )

        parser.add_argument(
            "command",
            choices=["list", "start", "stop", "restart", "status", "stop-all", "auth"],
            help="Command to execute",
        )

        parser.add_argument(
            "service", nargs="?", help="Service-Name (für start/stop/restart/status)"
        )

        args = parser.parse_args()

        # Controller erstellen
        controller = ServiceController()

        # Commands ausführen
        if args.command == "list":
            controller.list_services()

        elif args.command == "start":
            if not args.service:
                parser.error("Service-Name erforderlich für 'start'")
            controller.start_service(args.service)

        elif args.command == "stop":
            if not args.service:
                parser.error("Service-Name erforderlich für 'stop'")
            controller.stop_service(args.service)

        elif args.command == "restart":
            if not args.service:
                parser.error("Service-Name erforderlich für 'restart'")
            controller.restart_service(args.service)

        elif args.command == "status":
            if args.service:
                controller.status_service(args.service)
            else:
                controller.status_all()

        elif args.command == "stop-all":
            controller.stop_all()

        elif args.command == "auth":
            if not args.service:
                parser.error("Service name required for 'auth'")
            controller.authenticate_service(args.service)

    except KeyboardInterrupt:
        print("\nOperation interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
