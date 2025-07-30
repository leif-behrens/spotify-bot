"""
Basis-Klasse für alle Spotify Mikroservices
Implementiert sichere Service-Architektur nach OpenSSF und OWASP Standards

CWE-754: Error Handling - Comprehensive exception handling
CWE-400: Resource Management - Proper lifecycle management
CWE-20: Input Validation - Strict parameter validation
Bandit: B101, B104, B322
"""

import logging
import threading
import time
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional, Union

from src.config import ConfigManager


class ServiceStatus(Enum):
    """
    Service-Statuswerte für sichere Zustandsverwaltung
    CWE-20: Input Validation durch Enum-Verwendung
    """

    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    ERROR = "error"
    UNKNOWN = "unknown"


class ServiceHealth:
    """
    Service-Gesundheitsstatus mit sicherer Datenkapselung
    CWE-200: Information Exposure Prevention
    """

    def __init__(self):
        self.is_healthy: bool = True
        self.last_health_check: datetime = datetime.now()
        self.consecutive_failures: int = 0
        self.last_error: Optional[str] = None
        self.error_count: int = 0

    def mark_healthy(self) -> None:
        """Markiert Service als gesund - CWE-754: State Management"""
        self.is_healthy = True
        self.consecutive_failures = 0
        self.last_health_check = datetime.now()

    def mark_unhealthy(self, error_message: str) -> None:
        """
        Markiert Service als ungesund mit sanitisierter Fehlermeldung
        CWE-532: Information Exposure Through Log Files Prevention
        """
        self.is_healthy = False
        self.consecutive_failures += 1
        self.error_count += 1
        self.last_health_check = datetime.now()

        # Sanitisiere Fehlermeldung für sicheres Logging
        self.last_error = str(error_message)[:200] if error_message else "Unknown error"


class BaseSpotifyService(ABC):
    """
    Sichere Basis-Klasse für alle Spotify Services

    Sicherheitsfeatures:
    - CWE-754: Comprehensive Error Handling in allen Methoden
    - CWE-400: Resource Management mit proper cleanup
    - CWE-20: Input Validation für alle Parameter
    - CWE-532: Sichere Logging-Praktiken ohne sensible Daten
    - Bandit B101: Keine hardcoded Passwörter/Secrets
    """

    def __init__(self, service_name: str, config, check_interval: int = 30):
        """
        Initialisiert Service mit sicherer Konfiguration
        CWE-20: Input Validation für alle Parameter
        """
        # Input Validation - CWE-20
        if not isinstance(service_name, str) or len(service_name.strip()) == 0:
            raise ValueError("Service name must be a non-empty string")

        # Flexiblere Config-Validierung
        if not hasattr(config, "get_monitoring_config"):
            raise TypeError("Config must have required methods")

        if not isinstance(check_interval, int) or check_interval < 1:
            raise ValueError("Check interval must be positive integer")

        self.service_name = service_name.strip()[:50]  # Längen-Begrenzung
        self.config = config
        self.check_interval = min(max(check_interval, 1), 3600)  # 1s-1h Begrenzung

        # Service State Management - CWE-754
        self.status = ServiceStatus.STOPPED
        self.health = ServiceHealth()
        self.start_time: Optional[datetime] = None
        self.stop_time: Optional[datetime] = None

        # Thread Management - CWE-400
        self._service_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._lock = threading.RLock()

        # Logging Setup - CWE-532: Sichere Logging-Konfiguration
        self.logger = logging.getLogger(f"service.{self.service_name}")
        self.logger.info(f"Service {self.service_name} initialized")

    @abstractmethod
    def _initialize_service(self) -> bool:
        """
        Service-spezifische Initialisierung
        Muss von Subklassen implementiert werden

        Returns:
            bool: True wenn erfolgreich, False bei Fehler
        """
        pass

    @abstractmethod
    def _run_service_loop(self) -> None:
        """
        Hauptservice-Loop
        Muss von Subklassen implementiert werden
        """
        pass

    @abstractmethod
    def _cleanup_service(self) -> None:
        """
        Service-spezifisches Cleanup
        Muss von Subklassen implementiert werden
        """
        pass

    def start(self) -> bool:
        """
        Startet Service sicher mit Error Handling
        CWE-754: Comprehensive Error Handling
        CWE-400: Resource Management
        """
        with self._lock:
            try:
                if self.status == ServiceStatus.RUNNING:
                    self.logger.warning(f"Service {self.service_name} already running")
                    return True

                if self.status == ServiceStatus.STARTING:
                    self.logger.warning(f"Service {self.service_name} already starting")
                    return False

                self.logger.info(f"Starting service {self.service_name}")
                self.status = ServiceStatus.STARTING
                self._stop_event.clear()

                # Service-spezifische Initialisierung
                if not self._initialize_service():
                    self.status = ServiceStatus.ERROR
                    self.health.mark_unhealthy("Service initialization failed")
                    return False

                # Service-Thread starten
                self._service_thread = threading.Thread(
                    target=self._safe_service_runner,
                    name=f"Service-{self.service_name}",
                    daemon=False,  # Explizit nicht daemon für proper cleanup
                )
                self._service_thread.start()

                self.start_time = datetime.now()
                self.status = ServiceStatus.RUNNING
                self.health.mark_healthy()

                self.logger.info(f"Service {self.service_name} started successfully")
                return True

            except Exception as e:
                self.logger.error(f"Failed to start service {self.service_name}: {e}")
                self.status = ServiceStatus.ERROR
                self.health.mark_unhealthy(str(e))
                return False

    def stop(self, timeout: int = 30) -> bool:
        """
        Stoppt Service sicher mit Timeout
        CWE-754: Graceful Shutdown
        CWE-400: Resource Management
        """
        with self._lock:
            try:
                if self.status == ServiceStatus.STOPPED:
                    self.logger.info(f"Service {self.service_name} already stopped")
                    return True

                self.logger.info(f"Stopping service {self.service_name}")
                self.status = ServiceStatus.STOPPING

                # Stop-Signal setzen
                self._stop_event.set()

                # Warte auf Thread-Beendigung mit Timeout
                if self._service_thread and self._service_thread.is_alive():
                    self._service_thread.join(timeout=max(1, min(timeout, 60)))

                    # Forceful cleanup wenn Thread nicht beendet
                    if self._service_thread.is_alive():
                        self.logger.warning(
                            f"Service {self.service_name} thread did not stop gracefully"
                        )

                # Service-spezifisches Cleanup
                self._cleanup_service()

                self.stop_time = datetime.now()
                self.status = ServiceStatus.STOPPED
                self.logger.info(f"Service {self.service_name} stopped successfully")
                return True

            except Exception as e:
                self.logger.error(f"Error stopping service {self.service_name}: {e}")
                self.status = ServiceStatus.ERROR
                self.health.mark_unhealthy(str(e))
                return False

    def _safe_service_runner(self) -> None:
        """
        Sicherer Service-Runner mit Exception Handling
        CWE-754: Exception Handling in Threading
        """
        try:
            self._run_service_loop()
        except Exception as e:
            self.logger.error(f"Service {self.service_name} crashed: {e}")
            self.status = ServiceStatus.ERROR
            self.health.mark_unhealthy(str(e))

    def get_status(self) -> Dict[str, Any]:
        """
        Gibt sicheren Service-Status zurück
        CWE-200: Information Exposure Prevention
        """
        with self._lock:
            uptime_seconds = 0
            if self.start_time and self.status == ServiceStatus.RUNNING:
                uptime_seconds = int((datetime.now() - self.start_time).total_seconds())

            # Sanitisierte Status-Informationen
            return {
                "service_name": self.service_name,
                "status": self.status.value,
                "is_healthy": self.health.is_healthy,
                "uptime_seconds": max(0, uptime_seconds),
                "error_count": min(self.health.error_count, 9999),  # Limit exposure
                "consecutive_failures": min(self.health.consecutive_failures, 99),
                "last_error": self.health.last_error[:100]
                if self.health.last_error
                else None,
                "last_health_check": self.health.last_health_check.isoformat(),
            }

    def is_running(self) -> bool:
        """Prüft ob Service läuft"""
        return self.status == ServiceStatus.RUNNING

    def is_healthy(self) -> bool:
        """Prüft Service-Gesundheit"""
        return self.health.is_healthy

    def should_stop(self) -> bool:
        """Prüft ob Service stoppen soll - für Service-Loops"""
        return self._stop_event.is_set()

    def wait_or_stop(self, seconds: Union[int, float]) -> bool:
        """
        Wartet oder bricht bei Stop-Signal ab
        CWE-400: Controlled Waiting

        Returns:
            bool: True wenn gewartet, False wenn Stop-Signal empfangen
        """
        if seconds <= 0:
            return not self.should_stop()

        # Begrenze Wartezeit für bessere Responsiveness
        wait_time = min(max(seconds, 0.1), 300)  # 0.1s - 5min
        return not self._stop_event.wait(timeout=wait_time)
