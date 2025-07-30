#!/usr/bin/env python3
"""
Service Watchdog für Spotify Monitoring Service
Überwacht Service-Health und startet automatisch neu bei Problemen

CWE-754: Proper Error Handling
CWE-400: Resource Management
CWE-772: Missing Release of Resource after Effective Lifetime
Bandit: B113 (subprocess usage), B324 (timing attack)
"""

import logging
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Callable, Optional

logger = logging.getLogger(__name__)


@dataclass
class HealthStatus:
    """
    Health Check Status Datenstruktur
    CWE-20: Input Validation durch Dataclass
    """

    is_healthy: bool
    last_check: datetime
    consecutive_failures: int
    last_error: Optional[str] = None
    uptime_seconds: int = 0


class ServiceWatchdog:
    """
    Robuster Service Watchdog für kontinuierliche Überwachung

    Security Features:
    - CWE-754: Comprehensive Error Handling
    - CWE-400: Resource Management mit Thread-Limits
    - CWE-772: Proper Resource Cleanup
    - CWE-326: Weak Encryption - Secure Configuration Storage
    """

    def __init__(
        self,
        service_instance,
        check_interval_seconds: int = 30,
        max_failures: int = 3,
        restart_delay_seconds: int = 60,
    ):
        """
        Initialisiert Service Watchdog

        Args:
            service_instance: SpotifyMonitoringService Instanz
            check_interval_seconds: Health Check Intervall (CWE-400: Rate Limiting)
            max_failures: Max consecutive failures vor Restart
            restart_delay_seconds: Wartezeit zwischen Restarts
        """
        self.service = service_instance
        self.check_interval = max(10, check_interval_seconds)  # Min 10s (CWE-400)
        self.max_failures = max(1, max_failures)
        self.restart_delay = max(30, restart_delay_seconds)  # Min 30s (CWE-400)

        # Health Status
        self.health_status = HealthStatus(
            is_healthy=True, last_check=datetime.now(), consecutive_failures=0
        )

        # Watchdog Control
        self.is_running = False
        self.watchdog_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._health_lock = threading.RLock()

        # Callbacks
        self.on_service_restart: Optional[Callable] = None
        self.on_health_change: Optional[Callable] = None

        # Statistics
        self.start_time = datetime.now()
        self.restart_count = 0
        self.total_downtime_seconds = 0

        logger.info(
            f"ServiceWatchdog initialized (check_interval={check_interval_seconds}s, max_failures={max_failures})"
        )

    def start(self) -> None:
        """
        Startet Watchdog-Thread
        CWE-366: Race Condition within a Thread
        """
        with self._health_lock:
            if self.is_running:
                logger.warning("Watchdog already running")
                return

            self.is_running = True
            self._stop_event.clear()

            # Daemon Thread für automatisches Cleanup
            self.watchdog_thread = threading.Thread(
                target=self._watchdog_loop, name="ServiceWatchdog", daemon=True
            )
            self.watchdog_thread.start()

            logger.info("Service Watchdog started")

    def stop(self) -> None:
        """
        Stoppt Watchdog gracefully
        CWE-772: Proper Resource Release
        """
        with self._health_lock:
            if not self.is_running:
                return

            logger.info("Stopping Service Watchdog...")

            self.is_running = False
            self._stop_event.set()

            # Warte auf Thread-Ende (max 10s)
            if self.watchdog_thread and self.watchdog_thread.is_alive():
                self.watchdog_thread.join(timeout=10)

            logger.info("Service Watchdog stopped")

    def _watchdog_loop(self) -> None:
        """
        Hauptschleife des Watchdog
        CWE-835: Loop with Unreachable Exit Condition Prevention
        """
        logger.info("Watchdog monitoring loop started")

        try:
            while self.is_running and not self._stop_event.is_set():
                try:
                    # Health Check ausführen
                    self._perform_health_check()

                    # Warte bis zum nächsten Check (interruptible)
                    if self._stop_event.wait(timeout=self.check_interval):
                        break  # Stop requested

                except Exception as e:
                    logger.error(f"Watchdog loop error: {e}")
                    # Kurze Pause bei Fehlern, dann weitermachen
                    time.sleep(5)

        except Exception as e:
            logger.critical(f"Watchdog loop crashed: {e}")
        finally:
            logger.info("Watchdog monitoring loop ended")

    def _perform_health_check(self) -> None:
        """
        Führt Health Check durch und startet Service bei Bedarf neu
        CWE-754: Proper Check for Unusual Conditions
        """
        try:
            with self._health_lock:
                current_time = datetime.now()

                # Prüfe Service-Health
                is_healthy = self._check_service_health()

                # Update Health Status
                was_healthy = self.health_status.is_healthy
                self.health_status.last_check = current_time
                self.health_status.uptime_seconds = int(
                    (current_time - self.start_time).total_seconds()
                )

                if is_healthy:
                    # Service ist gesund
                    if not was_healthy:
                        logger.info("Service health recovered")
                        if self.on_health_change:
                            self.on_health_change(True)

                    self.health_status.is_healthy = True
                    self.health_status.consecutive_failures = 0
                    self.health_status.last_error = None

                else:
                    # Service ist ungesund
                    self.health_status.is_healthy = False
                    self.health_status.consecutive_failures += 1

                    logger.warning(
                        f"Service health check failed (attempt {self.health_status.consecutive_failures}/{self.max_failures})"
                    )

                    # Callback bei Health-Änderung
                    if was_healthy and self.on_health_change:
                        self.on_health_change(False)

                    # Restart bei zu vielen Fehlern
                    if self.health_status.consecutive_failures >= self.max_failures:
                        self._attempt_service_restart()

        except Exception as e:
            logger.error(f"Health check failed: {e}")
            self.health_status.last_error = str(e)

    def _check_service_health(self) -> bool:
        """
        Prüft Service-Health anhand verschiedener Kriterien
        CWE-754: Comprehensive Health Validation
        """
        try:
            # 1. Prüfe ob Service läuft
            if not self.service.is_running:
                logger.debug("Health check failed: Service not running")
                return False

            # 2. Prüfe Error Count (Circuit Breaker)
            max_allowed_errors = self.service.service_config.get("max_retries", 10)
            if self.service.error_count > max_allowed_errors:
                logger.debug(
                    f"Health check failed: Too many errors ({self.service.error_count})"
                )
                return False

            # 3. Prüfe Scheduler Status
            if not self.service._scheduler_running or not self.service.scheduler:
                logger.debug("Health check failed: Scheduler not running")
                return False

            # 4. Prüfe Authentication Status
            if not self.service.authenticator or not self.service.spotify_client:
                logger.debug("Health check failed: Not authenticated")
                return False

            # 5. Test Spotify API Connectivity (lightweight)
            try:
                # Lightweight API call für Health Check
                user_info = self.service.spotify_client.current_user()
                if not user_info or not user_info.get("id"):
                    logger.debug("Health check failed: Invalid Spotify API response")
                    return False
            except Exception as e:
                logger.debug(f"Health check failed: Spotify API error: {e}")
                return False

            return True

        except Exception as e:
            logger.debug(f"Health check exception: {e}")
            return False

    def _attempt_service_restart(self) -> None:
        """
        Versucht Service-Restart mit exponential backoff
        CWE-400: DoS Prevention, CWE-754: Error Recovery
        """
        try:
            downtime_start = datetime.now()
            logger.warning(
                f"Attempting service restart (attempt #{self.restart_count + 1})"
            )

            # Stop Service sicher
            if self.service.is_running:
                self.service.stop()
                time.sleep(2)  # Kurze Pause für sauberen Stop

            # Warte mit exponential backoff
            backoff_delay = min(
                self.restart_delay * (2 ** min(self.restart_count, 5)), 300
            )  # Max 5min
            logger.info(f"Waiting {backoff_delay}s before restart...")

            if self._stop_event.wait(timeout=backoff_delay):
                return  # Stop requested during delay

            # Versuche Service-Restart mit gespeicherten Tokens
            if self.service.start_from_stored_token():
                downtime_end = datetime.now()
                downtime_duration = int((downtime_end - downtime_start).total_seconds())

                self.restart_count += 1
                self.total_downtime_seconds += downtime_duration

                logger.info(
                    f"Service successfully restarted (downtime: {downtime_duration}s)"
                )

                # Reset failure counter nach erfolgreichem Restart
                self.health_status.consecutive_failures = 0

                # Callback ausführen
                if self.on_service_restart:
                    self.on_service_restart(self.restart_count, downtime_duration)

            else:
                logger.error("Service restart failed - authentication required")
                self.health_status.last_error = (
                    "Restart failed: Authentication required"
                )

        except Exception as e:
            logger.error(f"Service restart attempt failed: {e}")
            self.health_status.last_error = f"Restart failed: {e}"

    def get_health_status(self) -> HealthStatus:
        """
        Gibt aktuellen Health Status zurück
        CWE-766: Critical Data Element without Synchronization
        """
        with self._health_lock:
            return HealthStatus(
                is_healthy=self.health_status.is_healthy,
                last_check=self.health_status.last_check,
                consecutive_failures=self.health_status.consecutive_failures,
                last_error=self.health_status.last_error,
                uptime_seconds=self.health_status.uptime_seconds,
            )

    def get_statistics(self) -> dict:
        """
        Gibt Watchdog-Statistiken zurück
        """
        with self._health_lock:
            uptime = datetime.now() - self.start_time
            uptime_seconds = int(uptime.total_seconds())

            return {
                "is_running": self.is_running,
                "uptime_seconds": uptime_seconds,
                "restart_count": self.restart_count,
                "total_downtime_seconds": self.total_downtime_seconds,
                "availability_percent": round(
                    (
                        (uptime_seconds - self.total_downtime_seconds)
                        / max(uptime_seconds, 1)
                    )
                    * 100,
                    2,
                ),
                "health_status": self.get_health_status(),
            }
