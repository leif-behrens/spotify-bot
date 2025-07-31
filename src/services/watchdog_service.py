"""
Watchdog Service für Spotify Bot - Automatisches Service Monitoring und Recovery
CWE-400: Resource Management, CWE-754: Comprehensive Error Handling
Security: Follows OpenSSF Secure Coding Guidelines
"""

import threading
import time
from datetime import datetime, timedelta
from typing import Dict, Optional, Set

from ..core.config import ConfigManager
from ..utils.email_notifier import EmailNotifier
from ..utils.logging_setup import LoggingSetup
from .service_manager import SpotifyServiceManager

logger = LoggingSetup.get_logger("watchdog")


class ServiceHealthInfo:
    """Tracking-Informationen für Service-Gesundheit"""

    def __init__(self, service_name: str):
        self.service_name = service_name
        self.restart_attempts = 0
        self.last_restart_time: Optional[datetime] = None
        self.last_failure_time: Optional[datetime] = None
        self.consecutive_failures = 0
        self.total_restarts = 0
        self.is_in_cooldown = False
        self.failure_notified = False

    def reset_failure_count(self):
        """Reset failure tracking nach erfolgreichem Neustart"""
        self.consecutive_failures = 0
        self.restart_attempts = 0
        self.failure_notified = False

    def increment_failure(self):
        """Registriert einen Service-Ausfall"""
        self.consecutive_failures += 1
        self.last_failure_time = datetime.now()

    def attempt_restart(self):
        """Registriert einen Neustart-Versuch"""
        self.restart_attempts += 1
        self.total_restarts += 1
        self.last_restart_time = datetime.now()

    def enter_cooldown(self):
        """Aktiviert Cooldown-Phase"""
        self.is_in_cooldown = True

    def is_cooldown_expired(self, cooldown_seconds: int) -> bool:
        """Prüft ob Cooldown-Phase abgelaufen ist"""
        if not self.is_in_cooldown or not self.last_restart_time:
            return True

        time_since_restart = (datetime.now() - self.last_restart_time).total_seconds()
        if time_since_restart >= cooldown_seconds:
            self.is_in_cooldown = False
            return True

        return False


class SpotifyWatchdogService:
    """
    Automatischer Service Watchdog für Spotify Bot

    Features:
    - Kontinuierliches Monitoring aller konfigurierten Services
    - Automatischer Neustart bei Service-Ausfällen
    - Konfigurierbare Retry-Limits mit Exponential Backoff
    - E-Mail-Benachrichtigungen bei kritischen Fehlern
    - Detailliertes Logging aller Monitoring-Aktivitäten
    - Rate-Limiting für Restart-Versuche
    """

    def __init__(self):
        self.config_manager = ConfigManager()
        self.watchdog_config = self.config_manager.get_watchdog_config()
        self.service_manager = SpotifyServiceManager()
        self.email_notifier = EmailNotifier()

        # Service Health Tracking
        self.service_health: Dict[str, ServiceHealthInfo] = {}
        self.monitored_services: Set[str] = set(
            self.watchdog_config.get("services_to_monitor", [])
        )

        # Initialisiere Health-Tracking für alle Services
        for service_name in self.monitored_services:
            self.service_health[service_name] = ServiceHealthInfo(service_name)

        # Control flags
        self.is_running = False
        self.monitor_thread: Optional[threading.Thread] = None

        # Konfiguration
        self.check_interval = self.watchdog_config.get("check_interval_seconds", 30)
        self.max_restart_attempts = self.watchdog_config.get("max_restart_attempts", 3)
        self.restart_cooldown = self.watchdog_config.get("restart_cooldown_seconds", 60)
        self.notification_enabled = self.watchdog_config.get(
            "failure_notification_enabled", True
        )

        logger.info(
            f"Watchdog initialized - monitoring services: {list(self.monitored_services)}"
        )
        logger.info(
            f"Check interval: {self.check_interval}s, Max restarts: {self.max_restart_attempts}"
        )

    def is_enabled(self) -> bool:
        """Prüft ob Watchdog aktiviert ist"""
        return self.watchdog_config.get("enabled", False)

    def start(self) -> bool:
        """Startet den Watchdog-Service"""
        try:
            if not self.is_enabled():
                logger.info("Watchdog is disabled in configuration")
                return False

            if self.is_running:
                logger.warning("Watchdog is already running")
                return True

            logger.info("Starting Spotify Watchdog Service...")

            self.is_running = True
            self.monitor_thread = threading.Thread(
                target=self._monitor_loop, daemon=True
            )
            self.monitor_thread.start()

            logger.info("Watchdog Service started successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to start Watchdog Service: {e}")
            self.is_running = False
            return False

    def stop(self) -> bool:
        """Stoppt den Watchdog-Service"""
        try:
            if not self.is_running:
                logger.info("Watchdog is not running")
                return True

            logger.info("Stopping Spotify Watchdog Service...")
            self.is_running = False

            # Warte auf Thread-Beendigung
            if self.monitor_thread and self.monitor_thread.is_alive():
                self.monitor_thread.join(timeout=5)

            logger.info("Watchdog Service stopped")
            return True

        except Exception as e:
            logger.error(f"Failed to stop Watchdog Service: {e}")
            return False

    def get_status(self) -> Dict:
        """Gibt detaillierten Watchdog-Status zurück"""
        return {
            "service": "watchdog",
            "status": "running" if self.is_running else "stopped",
            "enabled": self.is_enabled(),
            "monitored_services": list(self.monitored_services),
            "check_interval_seconds": self.check_interval,
            "max_restart_attempts": self.max_restart_attempts,
            "service_health": {
                name: {
                    "restart_attempts": health.restart_attempts,
                    "consecutive_failures": health.consecutive_failures,
                    "total_restarts": health.total_restarts,
                    "is_in_cooldown": health.is_in_cooldown,
                    "last_failure": health.last_failure_time.isoformat()
                    if health.last_failure_time
                    else None,
                    "last_restart": health.last_restart_time.isoformat()
                    if health.last_restart_time
                    else None,
                }
                for name, health in self.service_health.items()
            },
        }

    def _monitor_loop(self):
        """Haupt-Monitoring-Schleife"""
        logger.info("Watchdog monitoring started")

        while self.is_running:
            try:
                self._check_all_services()
                time.sleep(self.check_interval)

            except Exception as e:
                logger.error(f"Error in watchdog monitoring loop: {e}")
                time.sleep(self.check_interval)

        logger.info("Watchdog monitoring stopped")

    def _check_all_services(self):
        """Überprüft alle konfigurierten Services"""
        for service_name in self.monitored_services:
            try:
                self._check_service(service_name)
            except Exception as e:
                logger.error(f"Error checking service {service_name}: {e}")

    def _check_service(self, service_name: str):
        """Überprüft einen einzelnen Service"""
        health_info = self.service_health[service_name]

        # Service-Status prüfen
        is_running = self.service_manager.is_running(service_name)

        if is_running:
            # Service läuft - Reset failure count wenn vorher ausgefallen
            if health_info.consecutive_failures > 0:
                logger.info(
                    f"Service {service_name} recovered after {health_info.consecutive_failures} failures"
                )

                # Recovery-Benachrichtigung senden
                if health_info.failure_notified and self.notification_enabled:
                    self.email_notifier.send_service_recovery_notification(service_name)

                health_info.reset_failure_count()

        else:
            # Service ist ausgefallen
            health_info.increment_failure()
            logger.warning(
                f"Service {service_name} is not running (failure #{health_info.consecutive_failures})"
            )

            # Versuche Neustart wenn möglich
            self._attempt_service_restart(service_name, health_info)

    def _attempt_service_restart(
        self, service_name: str, health_info: ServiceHealthInfo
    ):
        """Versucht Service-Neustart mit Rate-Limiting"""

        # Prüfe Cooldown-Phase
        if not health_info.is_cooldown_expired(self.restart_cooldown):
            remaining_cooldown = self.restart_cooldown - int(
                (datetime.now() - health_info.last_restart_time).total_seconds()
            )
            logger.debug(
                f"Service {service_name} in cooldown, {remaining_cooldown}s remaining"
            )
            return

        # Prüfe Restart-Limit
        if health_info.restart_attempts >= self.max_restart_attempts:
            if not health_info.failure_notified:
                logger.critical(
                    f"Service {service_name} failed permanently after {self.max_restart_attempts} restart attempts"
                )

                # Benachrichtigung über permanenten Ausfall
                if self.notification_enabled:
                    self.email_notifier.send_service_failure_notification(
                        service_name=service_name,
                        failure_reason=f"Service not responding after {health_info.consecutive_failures} checks",
                        restart_attempts=health_info.restart_attempts,
                        max_attempts=self.max_restart_attempts,
                    )

                health_info.failure_notified = True
            return

        # Restart-Versuch
        logger.info(
            f"Attempting to restart service {service_name} (attempt {health_info.restart_attempts + 1}/{self.max_restart_attempts})"
        )

        health_info.attempt_restart()
        health_info.enter_cooldown()

        success = self.service_manager.start(service_name)

        if success:
            logger.info(f"Service {service_name} restarted successfully")

            # Warte kurz und prüfe ob Service wirklich läuft
            time.sleep(3)
            if self.service_manager.is_running(service_name):
                logger.info(f"Service {service_name} restart confirmed")
            else:
                logger.warning(
                    f"Service {service_name} restart failed - not running after restart"
                )
        else:
            logger.error(f"Failed to restart service {service_name}")

            # Bei wiederholten Fehlschlägen Benachrichtigung senden
            if (
                health_info.restart_attempts >= 2
                and not health_info.failure_notified
                and self.notification_enabled
            ):
                self.email_notifier.send_service_failure_notification(
                    service_name=service_name,
                    failure_reason=f"Multiple restart attempts failed ({health_info.restart_attempts} attempts)",
                    restart_attempts=health_info.restart_attempts,
                    max_attempts=self.max_restart_attempts,
                )

    def reset_service_health(self, service_name: str) -> bool:
        """Reset Health-Tracking für einen Service (für manuelle Intervention)"""
        if service_name not in self.service_health:
            logger.error(f"Unknown service: {service_name}")
            return False

        health_info = self.service_health[service_name]
        old_attempts = health_info.restart_attempts

        health_info.reset_failure_count()
        health_info.is_in_cooldown = False

        logger.info(
            f"Reset health tracking for service {service_name} (was {old_attempts} restart attempts)"
        )
        return True

    def get_service_health_summary(self) -> str:
        """Gibt eine lesbare Zusammenfassung der Service-Gesundheit zurück"""
        if not self.service_health:
            return "No services being monitored"

        summary_lines = ["Service Health Summary:"]

        for service_name, health in self.service_health.items():
            is_running = self.service_manager.is_running(service_name)
            status = "RUNNING" if is_running else "FAILED"

            line = f"  {service_name}: {status}"

            if health.restart_attempts > 0:
                line += f" (restarts: {health.restart_attempts}/{self.max_restart_attempts})"

            if health.is_in_cooldown:
                line += " [COOLDOWN]"

            summary_lines.append(line)

        return "\n".join(summary_lines)
