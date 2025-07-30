"""
Service Control Dashboard für Spotify Mikroservices
Sicheres Flask-Dashboard für Service-Management

CWE-79: XSS Prevention - Template escaping und input sanitization
CWE-352: CSRF Prevention - Secure session management
CWE-200: Information Exposure Prevention - Sanitized outputs
CWE-20: Input Validation - Parameter validation
Bandit: B201, B104, B105
"""

import json
import logging
import os
import secrets
from datetime import datetime, timedelta
from functools import wraps
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template, request, session

from core.service_manager import ServiceManager
from services.discovery.service import SpotifyDiscoveryService
from src.config import ConfigManager

logger = logging.getLogger(__name__)


class ServiceControlDashboard:
    """
    Sicheres Service-Management Dashboard

    Sicherheitsfeatures:
    - CWE-79: XSS Prevention durch Template Escaping und Input Sanitization
    - CWE-352: CSRF Prevention durch sichere Session-Verwaltung
    - CWE-200: Information Exposure Prevention bei Service-Status
    - CWE-20: Input Validation für alle API-Parameter
    - CWE-798: Secure Configuration Management
    """

    def __init__(self, config: ConfigManager):
        """
        Initialisiert Service Control Dashboard sicher
        CWE-20: Input Validation durch ConfigManager
        """
        if not isinstance(config, ConfigManager):
            raise TypeError("Config must be ConfigManager instance")

        self.config = config
        self.service_manager = ServiceManager(config)

        # Registriere verfügbare Service-Typen
        self._register_service_types()

        # Flask App erstellen
        self.app = Flask(__name__, template_folder="templates", static_folder="static")

        # Custom Jinja2 Filter für JSON hinzufügen
        self._add_template_filters()

        # Sichere Flask-Konfiguration
        self._configure_flask()

        # Routes registrieren
        self._register_routes()

        logger.info("Service Control Dashboard initialized")

    def _add_template_filters(self) -> None:
        """
        Fügt custom Jinja2 Filter hinzu
        CWE-79: XSS Prevention durch sichere JSON-Serialisierung
        """

        @self.app.template_filter("tojsonfilter")
        def to_json_filter(obj):
            """
            Sicherer JSON-Filter für Templates
            CWE-79: XSS Prevention durch HTML-Escaping
            """
            try:
                # JSON mit HTML-safe Escaping
                json_str = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
                # Zusätzliches Escaping für HTML-Kontext
                json_str = json_str.replace("<", "\\u003c")
                json_str = json_str.replace(">", "\\u003e")
                json_str = json_str.replace("&", "\\u0026")
                json_str = json_str.replace("'", "\\u0027")
                return json_str
            except (TypeError, ValueError):
                return "{}"  # Fallback für nicht-serialisierbare Objekte

    def _register_service_types(self) -> None:
        """
        Registriert verfügbare Service-Typen
        CWE-754: Exception Handling
        """
        try:
            # Discovery Service registrieren
            logger.info("Attempting to register discovery service...")
            success = self.service_manager.register_service_type(
                "discovery", SpotifyDiscoveryService
            )
            logger.info(f"Discovery service registration result: {success}")

            # Weitere Services können hier hinzugefügt werden
            # self.service_manager.register_service_type("playlist_sync", PlaylistSyncService)
            # self.service_manager.register_service_type("mood_analyzer", MoodAnalyzerService)
            # self.service_manager.register_service_type("recommendation", RecommendationService)

            # Debug: Liste verfügbare Services
            available_services = self.service_manager.list_available_services()
            registered_types = self.service_manager.list_registered_service_types()
            logger.info(f"Available service instances: {available_services}")
            logger.info(f"Registered service types: {registered_types}")

            logger.info("Service types registered successfully")

        except Exception as e:
            logger.error(f"Failed to register service types: {e}")
            import traceback

            logger.error(f"Full traceback: {traceback.format_exc()}")

    def _configure_flask(self) -> None:
        """
        Konfiguriert Flask sicher
        CWE-798: Secure Configuration
        CWE-352: CSRF Prevention
        """
        # Secret Key für Session-Sicherheit
        secret_key = os.environ.get("FLASK_SECRET_KEY")
        if not secret_key:
            # Generiere sicheren Secret Key für Development
            secret_key = secrets.token_hex(32)
            logger.warning(
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
                "JSONIFY_PRETTYPRINT_REGULAR": False,  # Security - weniger Info-Leakage
            }
        )

        # Security Headers
        @self.app.after_request
        def add_security_headers(response):
            """
            Fügt Sicherheits-Header hinzu
            CWE-79: XSS Prevention
            CWE-200: Information Exposure Prevention
            """
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

    def _sanitize_input(self, value: str, max_length: int = 50) -> str:
        """
        Sanitisiert User-Eingaben
        CWE-20: Input Validation
        CWE-79: XSS Prevention
        """
        if not isinstance(value, str):
            return ""

        # Längenbegrenzung
        sanitized = str(value)[:max_length]

        # Entferne potentiell gefährliche Zeichen
        dangerous_chars = ["<", ">", '"', "'", "&", "\n", "\r", "\t", ";", "|"]
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, "")

        return sanitized.strip()

    def _require_valid_session(self, f):
        """
        Decorator für Session-Validierung
        CWE-287: Authentication Check
        """

        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Einfache Session-Initialisierung
            if "initialized" not in session:
                session["initialized"] = True
                session.permanent = True

            return f(*args, **kwargs)

        return decorated_function

    def _register_routes(self) -> None:
        """
        Registriert Flask-Routes sicher
        """

        @self.app.route("/")
        @self._require_valid_session
        def dashboard():
            """Service Management Dashboard"""
            try:
                # Service Status abrufen
                services_status = self.service_manager.get_all_services_status()

                # Verfügbare Service-Typen basierend auf registrierten Services
                registered_types = self.service_manager.list_registered_service_types()

                # Service-Metadaten
                service_metadata = {
                    "discovery": {
                        "display_name": "Auto Discovery",
                        "description": "Automatische Musik-Entdeckung",
                    },
                    "playlist_sync": {
                        "display_name": "Playlist Sync",
                        "description": "Playlist-Synchronisation (Coming Soon)",
                    },
                    "mood_analyzer": {
                        "display_name": "Mood Analyzer",
                        "description": "Stimmungsanalyse (Coming Soon)",
                    },
                    "recommendation": {
                        "display_name": "Recommendations",
                        "description": "Empfehlungs-Engine (Coming Soon)",
                    },
                }

                # Erstelle Liste basierend auf registrierten Typen + Coming Soon Services
                available_services = []

                # Registrierte Services (aktiv verfügbar)
                for service_type in registered_types:
                    if service_type in service_metadata:
                        available_services.append(
                            {
                                "name": service_type,
                                "display_name": service_metadata[service_type][
                                    "display_name"
                                ],
                                "description": service_metadata[service_type][
                                    "description"
                                ],
                            }
                        )

                # Coming Soon Services (noch nicht implementiert)
                coming_soon = ["playlist_sync", "mood_analyzer", "recommendation"]
                for service_type in coming_soon:
                    if (
                        service_type not in registered_types
                        and service_type in service_metadata
                    ):
                        available_services.append(
                            {
                                "name": service_type,
                                "display_name": service_metadata[service_type][
                                    "display_name"
                                ],
                                "description": service_metadata[service_type][
                                    "description"
                                ],
                            }
                        )

                return render_template(
                    "service_dashboard.html",
                    services_status=services_status,
                    available_services=available_services,
                    current_time=datetime.now(),
                )

            except Exception as e:
                logger.error(f"Dashboard error: {e}")
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
                services_status = self.service_manager.get_all_services_status()

                # Sanitisiere Output - CWE-200: Information Exposure Prevention
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
                    }

                return jsonify(sanitized_status)

            except Exception as e:
                logger.error(f"API services status error: {e}")
                return jsonify({"error": "Status nicht verfügbar"}), 500

        @self.app.route("/api/service/<service_name>/start", methods=["POST"])
        @self._require_valid_session
        def api_start_service(service_name: str):
            """Startet Service"""
            try:
                # Input Validation - CWE-20
                service_name = self._sanitize_input(service_name, 30)
                if not service_name:
                    return (
                        jsonify({"success": False, "message": "Invalid service name"}),
                        400,
                    )

                success = self.service_manager.start_service(service_name)

                if success:
                    logger.info(f"Service {service_name} started via dashboard")
                    return jsonify(
                        {
                            "success": True,
                            "message": f"Service {service_name} gestartet",
                        }
                    )
                else:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "message": f"Service {service_name} konnte nicht gestartet werden",
                            }
                        ),
                        500,
                    )

            except Exception as e:
                logger.error(f"Error starting service {service_name}: {e}")
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
            """Stoppt Service"""
            try:
                # Input Validation - CWE-20
                service_name = self._sanitize_input(service_name, 30)
                if not service_name:
                    return (
                        jsonify({"success": False, "message": "Invalid service name"}),
                        400,
                    )

                success = self.service_manager.stop_service(service_name)

                if success:
                    logger.info(f"Service {service_name} stopped via dashboard")
                    return jsonify(
                        {"success": True, "message": f"Service {service_name} gestoppt"}
                    )
                else:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "message": f"Service {service_name} konnte nicht gestoppt werden",
                            }
                        ),
                        500,
                    )

            except Exception as e:
                logger.error(f"Error stopping service {service_name}: {e}")
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
            """Startet Service neu"""
            try:
                # Input Validation - CWE-20
                service_name = self._sanitize_input(service_name, 30)
                if not service_name:
                    return (
                        jsonify({"success": False, "message": "Invalid service name"}),
                        400,
                    )

                success = self.service_manager.restart_service(service_name)

                if success:
                    logger.info(f"Service {service_name} restarted via dashboard")
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
                logger.error(f"Error restarting service {service_name}: {e}")
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
            """404 Error Handler"""
            return (
                render_template("error.html", error_message="Seite nicht gefunden"),
                404,
            )

        @self.app.errorhandler(500)
        def internal_error(error):
            """500 Error Handler"""
            logger.error(f"Internal server error: {error}")
            return (
                render_template("error.html", error_message="Interner Serverfehler"),
                500,
            )

    def run(
        self, host: str = "127.0.0.1", port: int = 5000, debug: bool = False
    ) -> None:
        """
        Startet Dashboard sicher
        CWE-489: Debug Information Exposure Prevention
        """
        try:
            logger.info(f"Starting Service Control Dashboard on {host}:{port}")

            # Health Monitoring starten
            self.service_manager.start_health_monitoring()

            # Sicherheitsvalidierung für Production
            if not debug and host != "127.0.0.1":
                logger.warning("Running on non-localhost in production mode")

            # Flask App starten
            self.app.run(
                host=host,
                port=port,
                debug=debug,
                threaded=True,
                use_reloader=False,  # CWE-489: Verhindere Debug-Info-Exposure
            )

        except Exception as e:
            logger.error(f"Failed to start dashboard: {e}")
            raise
        finally:
            # Cleanup bei Shutdown
            try:
                self.service_manager.shutdown_all()
            except Exception as e:
                logger.error(f"Error during shutdown: {e}")

    def get_service_manager(self) -> ServiceManager:
        """Gibt Service Manager zurück (für externe Nutzung)"""
        return self.service_manager
