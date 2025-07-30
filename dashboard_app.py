"""
Dashboard-Only Application für Spotify Mikroservices
Nur UI/Dashboard - Services laufen als separate Prozesse

CWE-754: Error Handling - Comprehensive exception handling
CWE-400: Resource Management - Clean dashboard lifecycle
CWE-20: Input Validation - Parameter validation
CWE-200: Information Exposure Prevention - Sanitized outputs
Bandit: B201, B104, B105
"""

import json
import logging
import os
import secrets
import sys
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template, request, session

# Füge Projektverzeichnis zum Pfad hinzu
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))
sys.path.insert(1, str(project_root / "src"))

from ipc.communication import IPCClient, ServiceRegistry


class MicroserviceDashboard:
    """
    Reines Dashboard für Mikroservice-Management

    Sicherheitsfeatures:
    - CWE-79: XSS Prevention durch Template Escaping
    - CWE-352: CSRF Prevention durch sichere Sessions
    - CWE-200: Information Exposure Prevention
    - CWE-20: Input Validation für alle Parameter
    """

    def __init__(self):
        # IPC Components
        self.registry = ServiceRegistry()
        self.ipc_client = IPCClient(timeout=10)

        # Service-Definitionen (gleich wie im Controller)
        self.services = {
            "discovery": {
                "name": "discovery",
                "display_name": "Auto Discovery",
                "description": "Automatische Musik-Entdeckung",
                "daemon_script": "services/discovery/daemon.py",
                "default_port": 9001,
            }
            # Weitere Services hier hinzufügen
        }

        # Flask App erstellen
        self.app = Flask(
            __name__,
            template_folder="dashboard/templates",
            static_folder="dashboard/static",
        )

        # Logging
        self.logger = logging.getLogger(__name__)

        # Flask konfigurieren
        self._configure_flask()
        self._add_template_filters()
        self._register_routes()

        self.logger.info("Microservice Dashboard initialized")

    def _configure_flask(self) -> None:
        """
        Konfiguriert Flask sicher
        CWE-798: Secure Configuration
        CWE-352: CSRF Prevention
        """
        # Secret Key für Session-Sicherheit
        secret_key = os.environ.get("FLASK_SECRET_KEY")
        if not secret_key:
            secret_key = secrets.token_hex(32)
            self.logger.warning(
                "Using generated secret key - set FLASK_SECRET_KEY for production"
            )

        self.app.config.update(
            {
                "SECRET_KEY": secret_key,
                "SESSION_COOKIE_SECURE": False,  # Für Development
                "SESSION_COOKIE_HTTPONLY": True,  # CWE-79: XSS Prevention
                "SESSION_COOKIE_SAMESITE": "Lax",  # CSRF Protection
                "PERMANENT_SESSION_LIFETIME": timedelta(hours=12),
                "JSON_SORT_KEYS": False,
                "JSONIFY_PRETTYPRINT_REGULAR": False,
            }
        )

        # Security Headers
        @self.app.after_request
        def add_security_headers(response):
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["X-Frame-Options"] = "DENY"
            response.headers["X-XSS-Protection"] = "1; mode=block"
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'"
            )
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

            # No-cache für dynamische Inhalte
            if request.endpoint in ["dashboard", "api_services_status"]:
                response.headers[
                    "Cache-Control"
                ] = "no-cache, no-store, must-revalidate"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"

            return response

    def _add_template_filters(self) -> None:
        """
        Fügt custom Jinja2 Filter hinzu
        CWE-79: XSS Prevention
        """

        @self.app.template_filter("tojsonfilter")
        def to_json_filter(obj):
            try:
                json_str = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
                # HTML-safe Escaping
                json_str = json_str.replace("<", "\\u003c")
                json_str = json_str.replace(">", "\\u003e")
                json_str = json_str.replace("&", "\\u0026")
                json_str = json_str.replace("'", "\\u0027")
                return json_str
            except (TypeError, ValueError):
                return "{}"

    def _sanitize_input(self, value: str, max_length: int = 50) -> str:
        """
        Sanitisiert User-Eingaben
        CWE-20: Input Validation
        CWE-79: XSS Prevention
        """
        if not isinstance(value, str):
            return ""

        sanitized = str(value)[:max_length]
        dangerous_chars = ["<", ">", '"', "'", "&", "\n", "\r", "\t", ";", "|"]
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")

        return sanitized.strip()

    def _require_valid_session(self, f):
        """Session-Validierung Decorator"""

        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "initialized" not in session:
                session["initialized"] = True
                session.permanent = True
            return f(*args, **kwargs)

        return decorated_function

    def _is_process_running(self, pid: Optional[int]) -> bool:
        """Prüft ob Prozess läuft (simplified version)"""
        if not pid:
            return False
        try:
            if os.name == "nt":  # Windows
                import psutil

                return psutil.pid_exists(pid)
            else:
                os.kill(pid, 0)
                return True
        except (OSError, ImportError):
            return False

    def _register_routes(self) -> None:
        """Registriert Flask-Routes"""

        @self.app.route("/")
        @self._require_valid_session
        def dashboard():
            """Haupt-Dashboard"""
            try:
                # Service-Status von Registry + IPC holen
                services_status = self._get_all_services_status()

                # Verfügbare Services aus Service-Definition
                available_services = []
                for service_name, service_info in self.services.items():
                    available_services.append(
                        {
                            "name": service_name,
                            "display_name": service_info["display_name"],
                            "description": service_info["description"],
                        }
                    )

                return render_template(
                    "service_dashboard.html",
                    services_status=services_status,
                    available_services=available_services,
                    current_time=datetime.now(),
                )

            except Exception as e:
                self.logger.error(f"Dashboard error: {e}")
                return (
                    render_template(
                        "error.html",
                        error_message="Dashboard konnte nicht geladen werden",
                    ),
                    500,
                )

        @self.app.route("/api/services/status")
        @self._require_valid_session
        def api_services_status():
            """API Endpoint für Service-Status"""
            try:
                services_status = self._get_all_services_status()

                # Sanitisiere Output
                sanitized_status = {}
                for service_name, status in services_status.items():
                    sanitized_status[service_name] = {
                        "service_name": self._sanitize_input(
                            status.get("service_name", "")
                        ),
                        "status": self._sanitize_input(status.get("status", "unknown")),
                        "is_healthy": bool(status.get("is_healthy", False)),
                        "uptime_seconds": max(0, int(status.get("uptime_seconds", 0))),
                        "error_count": min(int(status.get("error_count", 0)), 999),
                        "consecutive_failures": min(
                            int(status.get("consecutive_failures", 0)), 99
                        ),
                        "last_error": (
                            self._sanitize_input(status.get("last_error", ""), 100)
                            if status.get("last_error")
                            else None
                        ),
                        "daemon_pid": status.get("daemon_pid"),
                        "daemon_port": status.get("daemon_port"),
                    }

                return jsonify(sanitized_status)

            except Exception as e:
                self.logger.error(f"API services status error: {e}")
                return jsonify({"error": "Status nicht verfügbar"}), 500

        @self.app.route("/api/service/<service_name>/start", methods=["POST"])
        @self._require_valid_session
        def api_start_service(service_name: str):
            """Startet Service über IPC"""
            try:
                service_name = self._sanitize_input(service_name, 30)
                if not service_name or service_name not in self.services:
                    return (
                        jsonify({"success": False, "message": "Invalid service name"}),
                        400,
                    )

                # Erst prüfen ob Service bereits läuft
                registry_info = self.registry.get_service_info(service_name)
                if registry_info and self._is_process_running(registry_info.get("pid")):
                    # Service läuft bereits, versuche via IPC zu starten
                    response = self.ipc_client.start_service(service_name)
                    if response:
                        return jsonify(
                            {
                                "success": True,
                                "message": f"Service {service_name} gestartet",
                            }
                        )

                # Service läuft nicht - muss extern gestartet werden
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": f"Service {service_name} muss zuerst als Daemon gestartet werden",
                            "hint": f"Verwende: python service_controller.py start {service_name}",
                        }
                    ),
                    400,
                )

            except Exception as e:
                self.logger.error(f"Error starting service {service_name}: {e}")
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Fehler beim Starten des Services",
                        }
                    ),
                    500,
                )

        @self.app.route("/api/service/<service_name>/stop", methods=["POST"])
        @self._require_valid_session
        def api_stop_service(service_name: str):
            """Stoppt Service über IPC"""
            try:
                service_name = self._sanitize_input(service_name, 30)
                if not service_name or service_name not in self.services:
                    return (
                        jsonify({"success": False, "message": "Invalid service name"}),
                        400,
                    )

                success = self.ipc_client.stop_service(service_name)

                if success:
                    self.logger.info(f"Service {service_name} stopped via dashboard")
                    return jsonify(
                        {"success": True, "message": f"Service {service_name} gestoppt"}
                    )
                else:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "message": f"Service {service_name} antwortet nicht oder ist bereits gestoppt",
                            }
                        ),
                        500,
                    )

            except Exception as e:
                self.logger.error(f"Error stopping service {service_name}: {e}")
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Fehler beim Stoppen des Services",
                        }
                    ),
                    500,
                )

        @self.app.route("/api/service/<service_name>/restart", methods=["POST"])
        @self._require_valid_session
        def api_restart_service(service_name: str):
            """Startet Service über IPC neu"""
            try:
                service_name = self._sanitize_input(service_name, 30)
                if not service_name or service_name not in self.services:
                    return (
                        jsonify({"success": False, "message": "Invalid service name"}),
                        400,
                    )

                success = self.ipc_client.restart_service(service_name)

                if success:
                    self.logger.info(f"Service {service_name} restarted via dashboard")
                    return jsonify(
                        {
                            "success": True,
                            "message": f"Service {service_name} neu gestartet",
                        }
                    )
                else:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "message": f"Service {service_name} konnte nicht neu gestartet werden",
                            }
                        ),
                        500,
                    )

            except Exception as e:
                self.logger.error(f"Error restarting service {service_name}: {e}")
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Fehler beim Neustart des Services",
                        }
                    ),
                    500,
                )

        @self.app.errorhandler(404)
        def not_found(error):
            return (
                render_template("error.html", error_message="Seite nicht gefunden"),
                404,
            )

        @self.app.errorhandler(500)
        def internal_error(error):
            self.logger.error(f"Internal server error: {error}")
            return (
                render_template("error.html", error_message="Interner Serverfehler"),
                500,
            )

    def _get_all_services_status(self) -> Dict[str, Dict]:
        """
        Sammelt Service-Status aus Registry + IPC
        CWE-200: Information Exposure Prevention
        """
        services_status = {}

        # Registry-Services durchgehen
        registry_services = self.registry.list_services()

        for service_name in self.services:
            registry_info = registry_services.get(service_name)

            if not registry_info:
                # Service nicht registriert = gestoppt
                services_status[service_name] = {
                    "service_name": service_name,
                    "status": "stopped",
                    "is_healthy": False,
                    "uptime_seconds": 0,
                    "error_count": 0,
                    "consecutive_failures": 0,
                    "last_error": None,
                }
                continue

            pid = registry_info.get("pid")
            port = registry_info.get("port")

            # Prüfe ob Prozess noch läuft
            if not self._is_process_running(pid):
                # Zombie-Eintrag cleanup
                self.registry.unregister_service(service_name)
                services_status[service_name] = {
                    "service_name": service_name,
                    "status": "stopped",
                    "is_healthy": False,
                    "uptime_seconds": 0,
                    "error_count": 0,
                    "consecutive_failures": 0,
                    "last_error": "Process not running",
                }
                continue

            # Service läuft - hole Status via IPC
            try:
                ipc_status = self.ipc_client.get_service_status(service_name)
                if ipc_status:
                    services_status[service_name] = {
                        **ipc_status,
                        "daemon_pid": pid,
                        "daemon_port": port,
                    }
                else:
                    # IPC antwortet nicht
                    services_status[service_name] = {
                        "service_name": service_name,
                        "status": "error",
                        "is_healthy": False,
                        "uptime_seconds": 0,
                        "error_count": 1,
                        "consecutive_failures": 1,
                        "last_error": "IPC communication failed",
                        "daemon_pid": pid,
                        "daemon_port": port,
                    }
            except Exception as e:
                self.logger.error(f"Error getting status for {service_name}: {e}")
                services_status[service_name] = {
                    "service_name": service_name,
                    "status": "error",
                    "is_healthy": False,
                    "uptime_seconds": 0,
                    "error_count": 1,
                    "consecutive_failures": 1,
                    "last_error": str(e)[:100],
                    "daemon_pid": pid,
                    "daemon_port": port,
                }

        return services_status

    def run(
        self, host: str = "127.0.0.1", port: int = 5000, debug: bool = False
    ) -> None:
        """
        Startet Dashboard-App
        CWE-489: Debug Information Exposure Prevention
        """
        try:
            self.logger.info(f"Starting Microservice Dashboard on {host}:{port}")

            if not debug and host != "127.0.0.1":
                self.logger.warning("Running on non-localhost in production mode")

            self.app.run(
                host=host, port=port, debug=debug, threaded=True, use_reloader=False
            )

        except Exception as e:
            self.logger.error(f"Failed to start dashboard: {e}")
            raise


def setup_logging(log_level: str = "INFO") -> None:
    """Logging setup"""
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # Externe Library-Logs reduzieren
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def main():
    """Hauptfunktion für Dashboard-App"""
    try:
        # Logging konfigurieren
        log_level = os.environ.get("LOG_LEVEL", "INFO")
        setup_logging(log_level)

        logger = logging.getLogger(__name__)
        logger.info("Starting Spotify Microservice Dashboard")

        # Dashboard erstellen und starten
        dashboard = MicroserviceDashboard()

        # Konfiguration aus Environment
        host = os.environ.get("FLASK_HOST", "127.0.0.1")
        port = int(os.environ.get("FLASK_PORT", "5000"))
        debug = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

        dashboard.run(host=host, port=port, debug=debug)

    except KeyboardInterrupt:
        print("\nDashboard interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Fatal error: {e}")
        logging.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
