"""
Service Registry und Manager für Spotify Mikroservices
Implementiert sichere Service-Verwaltung nach OpenSSF und OWASP Standards

CWE-754: Error Handling - Comprehensive exception handling
CWE-400: Resource Management - Service lifecycle management
CWE-20: Input Validation - Parameter validation
CWE-200: Information Exposure Prevention - Sanitized outputs
Bandit: B101, B104, B322
"""

import logging
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Type, Union

from core.service_base import BaseSpotifyService, ServiceStatus
from src.config import ConfigManager


class ServiceRegistry:
    """
    Sichere Service-Registry für Mikroservice-Architektur

    Sicherheitsfeatures:
    - CWE-754: Exception Handling für alle Registry-Operationen
    - CWE-400: Resource Management mit Cleanup
    - CWE-20: Input Validation für Service-Parameter
    - CWE-200: Information Exposure Prevention bei Status-Abfragen
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._services: Dict[str, BaseSpotifyService] = {}
        self._service_classes: Dict[str, Type[BaseSpotifyService]] = {}
        self._lock = threading.RLock()
        self.logger.info("Service Registry initialized")

    def register_service_class(
        self, service_name: str, service_class: Type[BaseSpotifyService]
    ) -> bool:
        """
        Registriert Service-Klasse sicher
        CWE-20: Input Validation
        """
        try:
            # Input Validation
            if not isinstance(service_name, str) or len(service_name.strip()) == 0:
                raise ValueError("Service name must be non-empty string")

            if not issubclass(service_class, BaseSpotifyService):
                raise TypeError("Service class must inherit from BaseSpotifyService")

            service_name = service_name.strip()[:50]  # Längen-Begrenzung

            with self._lock:
                if service_name in self._service_classes:
                    self.logger.warning(
                        f"Service class {service_name} already registered"
                    )
                    return False

                self._service_classes[service_name] = service_class
                self.logger.info(f"Registered service class: {service_name}")
                return True

        except Exception as e:
            self.logger.error(f"Failed to register service class {service_name}: {e}")
            return False

    def create_service(
        self, service_name: str, config: ConfigManager, **kwargs
    ) -> Optional[BaseSpotifyService]:
        """
        Erstellt Service-Instanz sicher
        CWE-754: Exception Handling
        CWE-400: Resource Management
        """
        try:
            # Input Validation - CWE-20
            if not isinstance(service_name, str) or len(service_name.strip()) == 0:
                raise ValueError("Service name must be non-empty string")

            if not isinstance(config, ConfigManager):
                raise TypeError("Config must be ConfigManager instance")

            service_name = service_name.strip()

            with self._lock:
                # Prüfe ob Service bereits existiert
                if service_name in self._services:
                    self.logger.warning(f"Service {service_name} already exists")
                    return self._services[service_name]

                # Prüfe ob Service-Klasse registriert ist
                if service_name not in self._service_classes:
                    self.logger.error(f"Service class {service_name} not registered")
                    return None

                # Erstelle Service-Instanz
                service_class = self._service_classes[service_name]
                service_instance = service_class(
                    service_name=service_name, config=config, **kwargs
                )

                self._services[service_name] = service_instance
                self.logger.info(f"Created service: {service_name}")
                return service_instance

        except Exception as e:
            self.logger.error(f"Failed to create service {service_name}: {e}")
            return None

    def get_service(self, service_name: str) -> Optional[BaseSpotifyService]:
        """
        Gibt Service-Instanz zurück
        CWE-20: Input Validation
        """
        if not isinstance(service_name, str) or len(service_name.strip()) == 0:
            return None

        with self._lock:
            return self._services.get(service_name.strip())

    def remove_service(self, service_name: str) -> bool:
        """
        Entfernt Service sicher mit Cleanup
        CWE-754: Exception Handling
        CWE-400: Resource Management
        """
        try:
            if not isinstance(service_name, str) or len(service_name.strip()) == 0:
                return False

            service_name = service_name.strip()

            with self._lock:
                if service_name not in self._services:
                    return False

                service = self._services[service_name]

                # Service stoppen falls läuft
                if service.is_running():
                    service.stop(timeout=10)

                # Aus Registry entfernen
                del self._services[service_name]
                self.logger.info(f"Removed service: {service_name}")
                return True

        except Exception as e:
            self.logger.error(f"Failed to remove service {service_name}: {e}")
            return False

    def list_services(self) -> List[str]:
        """
        Listet alle registrierten Services
        CWE-200: Information Exposure Prevention
        """
        with self._lock:
            return list(self._services.keys())

    def get_all_status(self) -> Dict[str, Dict]:
        """
        Gibt Status aller Services zurück
        CWE-200: Information Exposure Prevention
        """
        status_dict = {}

        with self._lock:
            for name, service in self._services.items():
                try:
                    status_dict[name] = service.get_status()
                except Exception as e:
                    self.logger.error(f"Failed to get status for {name}: {e}")
                    status_dict[name] = {
                        "service_name": name,
                        "status": "error",
                        "error": "Status unavailable",
                    }

        return status_dict


class ServiceManager:
    """
    Zentraler Service-Manager für Mikroservice-Orchestrierung

    Sicherheitsfeatures:
    - CWE-754: Comprehensive Error Handling
    - CWE-400: Resource Management mit automatischem Cleanup
    - CWE-20: Input Validation für alle Operationen
    - CWE-532: Sichere Logging-Praktiken
    """

    def __init__(self, config: ConfigManager):
        """
        Initialisiert Service-Manager sicher
        CWE-20: Input Validation
        """
        if not isinstance(config, ConfigManager):
            raise TypeError("Config must be ConfigManager instance")

        self.config = config
        self.registry = ServiceRegistry()
        self.logger = logging.getLogger(__name__)

        # Health Monitoring
        self._health_check_thread: Optional[threading.Thread] = None
        self._health_check_stop = threading.Event()
        self._health_check_interval = 30  # Sekunden

        self.logger.info("Service Manager initialized")

    def register_service_type(
        self, service_name: str, service_class: Type[BaseSpotifyService]
    ) -> bool:
        """
        Registriert neuen Service-Typ
        CWE-20: Input Validation Delegation
        """
        return self.registry.register_service_class(service_name, service_class)

    def start_service(self, service_name: str, **kwargs) -> bool:
        """
        Startet Service sicher
        CWE-754: Exception Handling
        """
        try:
            # Service-Instanz holen oder erstellen
            service = self.registry.get_service(service_name)
            if not service:
                service = self.registry.create_service(
                    service_name, self.config, **kwargs
                )

            if not service:
                self.logger.error(f"Could not create service: {service_name}")
                return False

            # Service starten
            success = service.start()
            if success:
                self.logger.info(f"Service {service_name} started successfully")
            else:
                self.logger.error(f"Failed to start service {service_name}")

            return success

        except Exception as e:
            self.logger.error(f"Error starting service {service_name}: {e}")
            return False

    def stop_service(self, service_name: str) -> bool:
        """
        Stoppt Service sicher
        CWE-754: Exception Handling
        """
        try:
            service = self.registry.get_service(service_name)
            if not service:
                self.logger.warning(f"Service {service_name} not found")
                return False

            success = service.stop()
            if success:
                self.logger.info(f"Service {service_name} stopped successfully")
            else:
                self.logger.error(f"Failed to stop service {service_name}")

            return success

        except Exception as e:
            self.logger.error(f"Error stopping service {service_name}: {e}")
            return False

    def restart_service(self, service_name: str) -> bool:
        """
        Startet Service neu
        CWE-754: Exception Handling
        """
        try:
            self.logger.info(f"Restarting service {service_name}")

            # Service stoppen
            if not self.stop_service(service_name):
                self.logger.error(f"Failed to stop service {service_name} for restart")
                return False

            # Kurz warten
            time.sleep(2)

            # Service starten
            if not self.start_service(service_name):
                self.logger.error(
                    f"Failed to start service {service_name} after restart"
                )
                return False

            self.logger.info(f"Service {service_name} restarted successfully")
            return True

        except Exception as e:
            self.logger.error(f"Error restarting service {service_name}: {e}")
            return False

    def get_service_status(self, service_name: str) -> Optional[Dict]:
        """
        Gibt Service-Status zurück
        CWE-20: Input Validation
        """
        service = self.registry.get_service(service_name)
        if not service:
            return None

        try:
            return service.get_status()
        except Exception as e:
            self.logger.error(f"Failed to get status for {service_name}: {e}")
            return None

    def get_all_services_status(self) -> Dict[str, Dict]:
        """
        Gibt Status aller Services zurück
        CWE-200: Information Exposure Prevention
        """
        return self.registry.get_all_status()

    def list_available_services(self) -> List[str]:
        """Listet verfügbare Service-Instanzen"""
        return self.registry.list_services()

    def list_registered_service_types(self) -> List[str]:
        """Listet registrierte Service-Typen"""
        with self.registry._lock:
            return list(self.registry._service_classes.keys())

    def start_health_monitoring(self) -> bool:
        """
        Startet Health-Monitoring Thread
        CWE-400: Resource Management
        """
        try:
            if self._health_check_thread and self._health_check_thread.is_alive():
                self.logger.warning("Health monitoring already running")
                return True

            self._health_check_stop.clear()
            self._health_check_thread = threading.Thread(
                target=self._health_monitor_loop,
                name="ServiceHealthMonitor",
                daemon=True,
            )
            self._health_check_thread.start()

            self.logger.info("Health monitoring started")
            return True

        except Exception as e:
            self.logger.error(f"Failed to start health monitoring: {e}")
            return False

    def stop_health_monitoring(self) -> bool:
        """
        Stoppt Health-Monitoring
        CWE-400: Resource Management
        """
        try:
            self._health_check_stop.set()

            if self._health_check_thread and self._health_check_thread.is_alive():
                self._health_check_thread.join(timeout=5)

            self.logger.info("Health monitoring stopped")
            return True

        except Exception as e:
            self.logger.error(f"Error stopping health monitoring: {e}")
            return False

    def _health_monitor_loop(self) -> None:
        """
        Health-Monitoring Loop
        CWE-754: Exception Handling in Threading
        """
        self.logger.info("Health monitoring loop started")

        while not self._health_check_stop.is_set():
            try:
                # Prüfe alle Services
                services_status = self.get_all_services_status()
                unhealthy_services = []

                for service_name, status in services_status.items():
                    if not status.get("is_healthy", True):
                        unhealthy_services.append(service_name)

                # Log unhealthy services
                if unhealthy_services:
                    self.logger.warning(
                        f"Unhealthy services detected: {unhealthy_services}"
                    )

                # Optional: Auto-restart bei kritischen Services
                # (Kann später konfigurierbar gemacht werden)

            except Exception as e:
                self.logger.error(f"Error in health monitoring: {e}")

            # Warte bis zum nächsten Check
            if self._health_check_stop.wait(self._health_check_interval):
                break

        self.logger.info("Health monitoring loop stopped")

    def shutdown_all(self) -> bool:
        """
        Stoppt alle Services sicher
        CWE-400: Resource Management
        CWE-754: Graceful Shutdown
        """
        try:
            self.logger.info("Shutting down all services")

            # Health Monitoring stoppen
            self.stop_health_monitoring()

            # Alle Services stoppen
            services = self.list_available_services()
            success = True

            for service_name in services:
                if not self.stop_service(service_name):
                    success = False

            # Registry cleanup
            for service_name in services:
                self.registry.remove_service(service_name)

            self.logger.info("All services shutdown completed")
            return success

        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")
            return False
