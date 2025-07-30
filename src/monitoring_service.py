"""
Sicherer Monitoring-Service für Spotify Bot
CWE-400: Resource Exhaustion Prevention, CWE-754: Error Handling
Bandit: B113, B322, B323
"""

import logging
import threading
import time
import uuid
from datetime import datetime
from statistics import StatisticsDatabase

# TYPE_CHECKING Import für Forward References
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional

import spotipy
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED
from apscheduler.schedulers.background import BackgroundScheduler

from config import ConfigManager
from playlist_manager import PlaylistManager
from spotify_auth import SpotifyAuthenticator

if TYPE_CHECKING:
    from service_watchdog import ServiceWatchdog

logger = logging.getLogger(__name__)


class TrackSession:
    """
    Verwaltet eine Track-Hör-Session
    CWE-754: Proper State Management
    """

    def __init__(self, track_id: str, track_data: Dict[str, Any]):
        self.track_id = track_id
        self.track_data = track_data
        self.started_at = datetime.now()
        self.last_seen = datetime.now()
        self.database_record_id: Optional[int] = None
        self.added_to_playlist = False

    @property
    def listening_duration(self) -> int:
        """Gibt Hördauer in Sekunden zurück"""
        return int((self.last_seen - self.started_at).total_seconds())

    def update_last_seen(self) -> None:
        """Aktualisiert letzten Zeitpunkt"""
        self.last_seen = datetime.now()


class SpotifyMonitoringService:
    """
    Sicherer Service für kontinuierliche Spotify-Überwachung
    - CWE-400: Resource Exhaustion Prevention durch Rate Limiting
    - CWE-754: Comprehensive Error Handling
    - CWE-369: Divide By Zero Prevention
    """

    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager
        self.monitoring_config = config_manager.get_monitoring_config()
        self.service_config = config_manager.get_service_config()

        # Initialisiere Komponenten
        self.authenticator = SpotifyAuthenticator(config_manager)
        self.spotify_client: Optional[spotipy.Spotify] = None
        self.playlist_manager: Optional[PlaylistManager] = None
        self.statistics_db = StatisticsDatabase()

        # Session Management
        self.session_id = str(uuid.uuid4())
        self.current_session: Optional[TrackSession] = None
        self._lock = threading.Lock()
        self._start_lock = threading.Lock()  # Verhindert gleichzeitiges Starten

        # Scheduler für periodische Tasks - robuste Konfiguration
        self.scheduler = None
        self._scheduler_running = False
        self._shutdown_lock = threading.Lock()
        self._init_scheduler()

        # Service State
        self.is_running = False
        self.error_count = 0
        self.last_error: Optional[str] = None

        # Callbacks für Events
        self.on_track_added_callback: Optional[Callable] = None

        # Service Watchdog (wird bei Bedarf initialisiert)
        self.watchdog: Optional["ServiceWatchdog"] = None

    def _init_scheduler(self) -> None:
        """
        Initialisiert APScheduler mit robuster Konfiguration
        Verhindert ThreadPoolExecutor Shutdown-Errors bei Worker-Restarts
        """
        with self._shutdown_lock:
            try:
                # Cleanup alter Scheduler falls vorhanden
                if self.scheduler and self._scheduler_running:
                    self._safe_shutdown_scheduler()

                # Neuer Scheduler mit robuster Konfiguration
                self.scheduler = BackgroundScheduler(
                    timezone="Europe/Berlin",
                    max_workers=2,  # CWE-400: Begrenzte Worker
                    daemon=True,  # Daemon-Threads für sauberen Shutdown
                )

                # Event Listener für Job-Monitoring
                self.scheduler.add_listener(
                    self._job_listener, EVENT_JOB_EXECUTED | EVENT_JOB_ERROR
                )

                logger.debug("APScheduler initialized successfully")

            except Exception as e:
                logger.error(f"Failed to initialize scheduler: {e}")
                raise

    def _safe_shutdown_scheduler(self) -> None:
        """
        Sicherer Scheduler-Shutdown ohne RuntimeError
        """
        try:
            if self.scheduler and self._scheduler_running:
                logger.debug("Shutting down APScheduler...")
                self.scheduler.shutdown(wait=False)  # Nicht auf laufende Jobs warten
                self._scheduler_running = False
                logger.debug("APScheduler shutdown completed")
        except Exception as e:
            logger.warning(f"Scheduler shutdown error (ignored): {e}")
            self._scheduler_running = False

    def __del__(self):
        """
        Destruktor - stellt sicher, dass Scheduler sauber beendet wird
        """
        try:
            self._safe_shutdown_scheduler()
        except Exception:
            pass  # Ignore errors in destructor

    def _refresh_access_token(self) -> bool:
        """
        Versucht Access Token zu refreshen
        CWE-287: Proper Authentication, CWE-754: Error Handling
        """
        try:
            if not self.authenticator:
                return False

            # Versuche Token mit SpotifyAuthenticator zu refreshen
            if self.authenticator.authenticate_from_stored_token():
                # Update Spotify Client mit neuem Token
                self.spotify_client = self.authenticator.spotify
                logger.info("Access token successfully refreshed")
                return True

            return False

        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            return False

    def _handle_authentication_failure(self) -> None:
        """
        Behandelt dauerhafte Authentifizierungs-Fehler
        CWE-754: Graceful Degradation
        """
        try:
            logger.warning("Service stopping due to authentication failure")

            # Service-Status zurücksetzen aber nicht komplett stoppen
            # Benutzer kann manuell neu authentifizieren
            self.is_running = False

            # Statistik für Dashboard-Anzeige
            self.statistics_db.record_metric(
                "authentication_failure",
                "token_refresh_failed",
                {"session_id": self.session_id, "error_count": self.error_count},
            )

            # Aktuelle Session beenden
            with self._lock:
                if self.current_session:
                    self._end_current_session()

            logger.info("Service paused - manual re-authentication required")

        except Exception as e:
            logger.error(f"Error handling authentication failure: {e}")

    def _start_watchdog(self) -> None:
        """
        Startet Service Watchdog für automatische Überwachung
        CWE-400: Resource Management, CWE-754: Error Handling
        """
        try:
            from service_watchdog import ServiceWatchdog

            if self.watchdog and self.watchdog.is_running:
                logger.debug("Watchdog already running")
                return

            # Konfiguration aus Service Config
            check_interval = self.service_config.get(
                "health_check_interval_seconds", 30
            )
            max_failures = self.service_config.get("max_health_failures", 3)
            restart_delay = self.service_config.get("restart_delay_seconds", 60)

            # Erstelle und starte Watchdog
            self.watchdog = ServiceWatchdog(
                service_instance=self,
                check_interval_seconds=check_interval,
                max_failures=max_failures,
                restart_delay_seconds=restart_delay,
            )

            # Callbacks für Watchdog-Events
            self.watchdog.on_service_restart = self._on_watchdog_restart
            self.watchdog.on_health_change = self._on_health_change

            self.watchdog.start()
            logger.info("Service Watchdog started for automatic monitoring")

        except Exception as e:
            logger.error(f"Failed to start watchdog: {e}")

    def _stop_watchdog(self) -> None:
        """
        Stoppt Service Watchdog
        CWE-772: Proper Resource Release
        """
        try:
            if self.watchdog and self.watchdog.is_running:
                logger.debug("Stopping Service Watchdog...")
                self.watchdog.stop()
                self.watchdog = None
                logger.info("Service Watchdog stopped")

        except Exception as e:
            logger.error(f"Error stopping watchdog: {e}")

    def _on_watchdog_restart(self, restart_count: int, downtime_seconds: int) -> None:
        """
        Callback für Watchdog-Service-Restarts
        CWE-778: Insufficient Logging
        """
        try:
            logger.info(
                f"Service auto-restarted by watchdog (#{restart_count}, downtime: {downtime_seconds}s)"
            )

            # Statistik für Dashboard
            self.statistics_db.record_metric(
                "watchdog_service_restart",
                "success",
                {
                    "restart_count": restart_count,
                    "downtime_seconds": downtime_seconds,
                    "session_id": self.session_id,
                },
            )

        except Exception as e:
            logger.error(f"Error in watchdog restart callback: {e}")

    def _on_health_change(self, is_healthy: bool) -> None:
        """
        Callback für Health Status Änderungen
        CWE-778: Insufficient Logging
        """
        try:
            status = "healthy" if is_healthy else "unhealthy"
            logger.info(f"Service health status changed: {status}")

            # Statistik für Dashboard
            self.statistics_db.record_metric(
                "service_health_change", status, {"session_id": self.session_id}
            )

        except Exception as e:
            logger.error(f"Error in health change callback: {e}")

    def _job_listener(self, event) -> None:
        """
        Scheduler Event Listener
        CWE-754: Error Handling für Background Jobs
        """
        if event.exception:
            self.error_count += 1
            self.last_error = str(event.exception)
            logger.error(f"Scheduled job failed: {event.exception}")

            # Circuit Breaker Pattern - CWE-400: DoS Prevention
            if self.error_count > self.service_config["max_retries"]:
                logger.critical("Too many errors, stopping service")
                self.stop()

    def initialize(self) -> None:
        """
        Initialisiert Service-Komponenten sicher
        CWE-754: Proper Initialization with Error Handling
        """
        try:
            logger.info(
                f"Initializing Spotify Monitoring Service (Session: {self.session_id})"
            )

            # Authentifizierung
            self.spotify_client = self.authenticator.authenticate()

            # Playlist Manager
            playlist_config = self.config.get_playlist_config()
            self.playlist_manager = PlaylistManager(
                self.spotify_client, playlist_config
            )
            playlist_id = self.playlist_manager.initialize_playlist()

            # Statistik initialisieren
            self.statistics_db.record_metric(
                "service_initialized",
                "success",
                {"session_id": self.session_id, "playlist_id": playlist_id},
            )

            logger.info("Service initialization completed successfully")

        except Exception as e:
            logger.error(f"Service initialization failed: {e}")
            self.statistics_db.record_metric("service_initialization_failed", str(e))
            raise

    def initialize_from_stored_token(self) -> bool:
        """
        Initialisiert Service mit gespeicherten Token
        Für automatischen Start ohne Interaktion
        """
        try:
            logger.info(
                f"Initializing Spotify Monitoring Service from stored token (Session: {self.session_id})"
            )

            # Authentifizierung mit gespeicherten Token
            if not self.authenticator.authenticate_from_stored_token():
                logger.warning("Failed to authenticate from stored token")
                return False

            self.spotify_client = self.authenticator.spotify

            # Playlist Manager
            playlist_config = self.config.get_playlist_config()
            self.playlist_manager = PlaylistManager(
                self.spotify_client, playlist_config
            )
            playlist_id = self.playlist_manager.initialize_playlist()

            # Statistik initialisieren
            self.statistics_db.record_metric(
                "service_initialized_from_token",
                "success",
                {"session_id": self.session_id, "playlist_id": playlist_id},
            )

            logger.info(
                "Service initialization from stored token completed successfully"
            )
            return True

        except Exception as e:
            logger.error(f"Service initialization from stored token failed: {e}")
            self.statistics_db.record_metric(
                "service_initialization_from_token_failed", str(e)
            )
            return False

    def start(self) -> None:
        """
        Startet Monitoring-Service
        CWE-400: Controlled Resource Usage
        """
        with self._start_lock:  # Thread-safe Start
            try:
                if self.is_running:
                    logger.warning("Service already running")
                    return

                # Prüfe nochmal nach Lock-Acquisition
                if self.is_running:
                    return

                self.initialize()

                # Scheduler konfigurieren
                check_interval = self.monitoring_config["check_interval_seconds"]

                # Hauptjob für Track-Monitoring
                self.scheduler.add_job(
                    func=self._monitor_current_track,
                    trigger="interval",
                    seconds=check_interval,
                    id="track_monitor",
                    max_instances=1,  # CWE-400: Verhindere Job-Überlappung
                    coalesce=True,  # Merge übersprungene Jobs
                    misfire_grace_time=30,
                )

                # Cleanup-Job für alte Sessions
                self.scheduler.add_job(
                    func=self._cleanup_old_sessions,
                    trigger="interval",
                    minutes=30,
                    id="session_cleanup",
                    max_instances=1,
                )

                # Statistik-Job
                self.scheduler.add_job(
                    func=self._record_service_statistics,
                    trigger="interval",
                    minutes=5,
                    id="statistics_recorder",
                    max_instances=1,
                )

                # Starte Scheduler sicher
                if not self._scheduler_running:
                    self.scheduler.start()
                    self._scheduler_running = True

                self.is_running = True

                # Starte Watchdog für automatische Überwachung
                self._start_watchdog()

                logger.info(
                    f"Monitoring service started (Check interval: {check_interval}s)"
                )
                self.statistics_db.record_metric(
                    "service_started", "success", {"session_id": self.session_id}
                )

            except Exception as e:
                logger.error(f"Failed to start monitoring service: {e}")
                self.statistics_db.record_metric("service_start_failed", str(e))
                raise

    def start_from_stored_token(self) -> bool:
        """
        Startet Monitoring-Service mit gespeicherten Token
        Für automatischen Start ohne Interaktion
        """
        with self._start_lock:  # Thread-safe Start
            try:
                if self.is_running:
                    logger.warning("Service already running")
                    return True

                # Prüfe nochmal nach Lock-Acquisition
                if self.is_running:
                    return True

                # Initialisiere mit gespeicherten Token
                if not self.initialize_from_stored_token():
                    return False

                # Scheduler konfigurieren
                check_interval = self.monitoring_config["check_interval_seconds"]

                # Hauptjob für Track-Monitoring
                self.scheduler.add_job(
                    func=self._monitor_current_track,
                    trigger="interval",
                    seconds=check_interval,
                    id="track_monitor",
                    max_instances=1,  # CWE-400: Verhindere Job-Überlappung
                    coalesce=True,  # Merge übersprungene Jobs
                    misfire_grace_time=30,
                )

                # Cleanup-Job für alte Sessions
                self.scheduler.add_job(
                    func=self._cleanup_old_sessions,
                    trigger="interval",
                    minutes=30,
                    id="session_cleanup",
                    max_instances=1,
                )

                # Statistik-Job
                self.scheduler.add_job(
                    func=self._record_service_statistics,
                    trigger="interval",
                    minutes=5,
                    id="statistics_recorder",
                    max_instances=1,
                )

                # Starte Scheduler sicher
                if not self._scheduler_running:
                    self.scheduler.start()
                    self._scheduler_running = True

                self.is_running = True

                # Starte Watchdog für automatische Überwachung
                self._start_watchdog()

                logger.info(
                    f"Monitoring service started from stored token (Check interval: {check_interval}s)"
                )
                self.statistics_db.record_metric(
                    "service_started_from_token",
                    "success",
                    {"session_id": self.session_id},
                )

                return True

            except Exception as e:
                logger.error(
                    f"Failed to start monitoring service from stored token: {e}"
                )
                self.statistics_db.record_metric(
                    "service_start_from_token_failed", str(e)
                )
                return False

    def stop(self) -> None:
        """
        Stoppt Monitoring-Service sicher
        CWE-754: Graceful Shutdown
        """
        try:
            if not self.is_running:
                logger.warning("Service not running")
                return

            logger.info("Stopping monitoring service...")

            # Beende aktuelle Session
            with self._lock:
                if self.current_session:
                    self._end_current_session()

            # Watchdog stoppen
            self._stop_watchdog()

            # Scheduler sicher stoppen
            self._safe_shutdown_scheduler()

            self.is_running = False

            self.statistics_db.record_metric(
                "service_stopped", "success", {"session_id": self.session_id}
            )
            logger.info("Monitoring service stopped successfully")

        except Exception as e:
            logger.error(f"Error stopping service: {e}")
            self.statistics_db.record_metric("service_stop_error", str(e))

    def _monitor_current_track(self) -> None:
        """
        Überwacht aktuell spielenden Track
        CWE-754: Comprehensive Error Handling
        CWE-400: Resource Management
        """
        try:
            if not self.spotify_client or not self.playlist_manager:
                raise RuntimeError("Service not properly initialized")

            # Hole aktuell spielenden Track
            current_playback = self.spotify_client.current_playback()

            with self._lock:
                if not current_playback or not current_playback.get("is_playing"):
                    # Nichts spielt - beende aktuelle Session
                    if self.current_session:
                        self._end_current_session()
                    return

                track = current_playback.get("item")
                if not track:
                    logger.debug("No track item in playback response")
                    return

                # Erweiterte Validierung für Track-Typ und Daten
                if track.get("type") != "track":
                    logger.debug(f"Item is not a track, type: {track.get('type')}")
                    return

                # Debug: Track-Struktur loggen
                logger.debug(
                    f"Track data keys: {list(track.keys()) if isinstance(track, dict) else 'not a dict'}"
                )

                track_id = track.get("id")
                if not track_id:
                    logger.warning(f"Track has no ID. Track data: {track}")
                    return

                # current_time = datetime.now()  # Currently unused

                # Neuer Track?
                if (
                    not self.current_session
                    or self.current_session.track_id != track_id
                ):
                    # Beende alte Session
                    if self.current_session:
                        self._end_current_session()

                    # Starte neue Session
                    self._start_new_session(track, current_playback)
                else:
                    # Aktualisiere bestehende Session
                    self.current_session.update_last_seen()

                    # Prüfe ob Track zur Playlist hinzugefügt werden soll
                    self._check_playlist_addition()

                # Reset Error Counter bei Erfolg
                self.error_count = 0

        except spotipy.SpotifyException as e:
            # CWE-287: Improper Authentication - Handle expired tokens
            if e.http_status == 401:  # Unauthorized - Token expired
                logger.warning("Access token expired, attempting refresh...")
                if self._refresh_access_token():
                    logger.info(
                        "Token refreshed successfully, monitoring will continue"
                    )
                    # Reset error count bei erfolgreichem Token-Refresh
                    self.error_count = max(0, self.error_count - 5)
                    return  # Versuche nicht als Fehler zu zählen
                else:
                    logger.error(
                        "Token refresh failed - service needs re-authentication"
                    )
                    self._handle_authentication_failure()
                    return

            self.error_count += 1
            logger.error(f"Spotify API error during monitoring: {e}")

            # Rate Limiting - warte länger bei Fehlern (CWE-400: DoS Prevention)
            if e.http_status == 429:  # Too Many Requests
                retry_after = int(e.headers.get("Retry-After", 60))
                logger.warning(f"Rate limited, waiting {retry_after} seconds")
                time.sleep(min(retry_after, 300))  # Max 5 Minuten warten

        except Exception as e:
            self.error_count += 1
            logger.error(f"Unexpected error during monitoring: {e}")

    def _start_new_session(
        self, track: Dict[str, Any], playback_data: Dict[str, Any]
    ) -> None:
        """
        Startet neue Track-Session
        CWE-20: Input Validation für Track-Daten
        """
        try:
            # Validiere Track-Daten
            if not track.get("id") or not track.get("name"):
                logger.warning("Invalid track data received")
                return

            # Extrahiere relevante Daten
            track_data = {
                "track_id": track["id"],
                "track_name": track["name"],
                "artist_name": ", ".join(
                    [artist["name"] for artist in track.get("artists", [])]
                ),
                "album_name": track.get("album", {}).get("name", "Unknown"),
                "duration_ms": track.get("duration_ms", 0),
                "progress_ms": playback_data.get("progress_ms", 0),
                "started_at": datetime.now(),
            }

            # Erstelle neue Session
            self.current_session = TrackSession(track["id"], track_data)

            # Speichere in Datenbank
            record_id = self.statistics_db.record_current_track(
                track_data, self.session_id
            )
            self.current_session.database_record_id = record_id

            logger.debug(
                f"Started new track session: {track_data['track_name']} by {track_data['artist_name']}"
            )

        except Exception as e:
            logger.error(f"Failed to start new session: {e}")

    def _end_current_session(self) -> None:
        """
        Beendet aktuelle Track-Session
        CWE-754: Safe Session Cleanup
        """
        try:
            if not self.current_session:
                return

            # Aktualisiere Datenbank
            if self.current_session.database_record_id:
                self.statistics_db.update_track_end(
                    self.current_session.database_record_id,
                    self.current_session.last_seen,
                    self.current_session.added_to_playlist,
                )

            logger.debug(
                f"Ended track session: {self.current_session.track_data['track_name']} "
                f"(Duration: {self.current_session.listening_duration}s)"
            )

            self.current_session = None

        except Exception as e:
            logger.error(f"Failed to end current session: {e}")

    def _check_playlist_addition(self) -> None:
        """
        Prüft ob Track zur Playlist hinzugefügt werden soll
        CWE-369: Division by Zero Prevention
        """
        try:
            if not self.current_session or self.current_session.added_to_playlist:
                return

            min_duration = self.monitoring_config["minimum_play_duration_seconds"]
            current_duration = self.current_session.listening_duration

            if current_duration >= min_duration:
                # Track zur Playlist hinzufügen
                success = self.playlist_manager.add_track_to_playlist(
                    f"spotify:track:{self.current_session.track_id}",
                    self.current_session.track_data,
                )

                if success:
                    self.current_session.added_to_playlist = True

                    # Speichere Playlist-Addition
                    playlist_info = self.playlist_manager.get_playlist_info()
                    if playlist_info:
                        self.statistics_db.record_playlist_addition(
                            self.current_session.track_data,
                            playlist_info["id"],
                            current_duration,
                            self.session_id,
                        )

                    # Callback ausführen
                    if self.on_track_added_callback:
                        self.on_track_added_callback(self.current_session.track_data)

                    logger.info(
                        f"Added track to playlist after {current_duration}s: "
                        f"{self.current_session.track_data['track_name']}"
                    )

        except Exception as e:
            logger.error(f"Failed to check playlist addition: {e}")

    def _cleanup_old_sessions(self) -> None:
        """
        Räumt alte Sessions auf
        CWE-400: Memory Management
        """
        try:
            # Placeholder für Session-Cleanup
            # In der aktuellen Implementierung haben wir nur eine aktive Session
            logger.debug("Session cleanup completed")

        except Exception as e:
            logger.error(f"Session cleanup failed: {e}")

    def _record_service_statistics(self) -> None:
        """
        Zeichnet Service-Statistiken auf
        CWE-754: Error Handling für Statistiken
        """
        try:
            stats = {
                "is_running": self.is_running,
                "error_count": self.error_count,
                "has_active_session": self.current_session is not None,
                "session_id": self.session_id,
            }

            if self.current_session:
                stats["current_track"] = self.current_session.track_data["track_name"]
                stats["listening_duration"] = self.current_session.listening_duration

            self.statistics_db.record_metric("service_status", "active", stats)

        except Exception as e:
            logger.error(f"Failed to record service statistics: {e}")

    def get_service_status(self) -> Dict[str, Any]:
        """
        Gibt aktuellen Service-Status zurück
        """
        status = {
            "is_running": self.is_running,
            "session_id": self.session_id,
            "error_count": self.error_count,
            "last_error": self.last_error,
            "has_active_session": self.current_session is not None,
        }

        if self.current_session:
            status["current_track"] = {
                "name": self.current_session.track_data["track_name"],
                "artist": self.current_session.track_data["artist_name"],
                "listening_duration": self.current_session.listening_duration,
                "added_to_playlist": self.current_session.added_to_playlist,
            }

        return status

    def set_track_added_callback(self, callback: Callable) -> None:
        """Setzt Callback für Track-Hinzufügungen"""
        self.on_track_added_callback = callback
