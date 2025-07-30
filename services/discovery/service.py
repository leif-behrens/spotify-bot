"""
Spotify Auto-Discovery Service
Mikroservice für automatische Musik-Entdeckung basierend auf Hörverhalten

CWE-754: Error Handling - Comprehensive exception handling
CWE-400: Resource Management - Proper resource cleanup
CWE-20: Input Validation - Track data sanitization
CWE-532: Information Exposure Prevention - Secure logging
Bandit: B101, B104, B322
"""

import logging
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import spotipy

from core.service_base import BaseSpotifyService

# Füge src-Verzeichnis zum Pfad hinzu
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root / "src"))

from statistics import StatisticsDatabase

from config import ConfigManager
from playlist_manager import PlaylistManager
from spotify_auth import SpotifyAuthenticator


class TrackSession:
    """
    Sichere Track-Session Verwaltung
    CWE-754: Proper State Management
    CWE-20: Input Validation für Track-Daten
    """

    def __init__(self, track_id: str, track_data: Dict[str, Any]):
        # Input Validation - CWE-20
        if not isinstance(track_id, str) or len(track_id.strip()) == 0:
            raise ValueError("Track ID must be non-empty string")

        if not isinstance(track_data, dict):
            raise TypeError("Track data must be dictionary")

        self.track_id = track_id.strip()
        self.track_data = self._sanitize_track_data(track_data)
        self.started_at = datetime.now()
        self.last_seen = datetime.now()
        self.database_record_id: Optional[int] = None
        self.added_to_playlist = False

    def _sanitize_track_data(self, track_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Sanitisiert Track-Daten für sichere Verarbeitung
        CWE-20: Input Validation
        CWE-532: Information Exposure Prevention
        """
        sanitized = {}

        # Sichere String-Felder mit Längenbegrenzung
        safe_string_fields = ["name", "artist", "album", "id"]
        for field in safe_string_fields:
            value = track_data.get(field, "")
            if isinstance(value, str):
                sanitized[field] = value.strip()[:200]  # Längenbegrenzung
            else:
                sanitized[field] = str(value)[:200] if value else ""

        # Sichere numerische Felder
        duration_ms = track_data.get("duration_ms", 0)
        try:
            sanitized["duration_ms"] = max(0, min(int(duration_ms), 3600000))  # Max 1h
        except (ValueError, TypeError):
            sanitized["duration_ms"] = 0

        return sanitized

    @property
    def listening_duration(self) -> int:
        """Gibt Hördauer in Sekunden zurück"""
        return int((self.last_seen - self.started_at).total_seconds())

    def update_last_seen(self) -> None:
        """Aktualisiert letzten Zeitpunkt"""
        self.last_seen = datetime.now()


class SpotifyDiscoveryService(BaseSpotifyService):
    """
    Sicherer Spotify Auto-Discovery Mikroservice

    Sicherheitsfeatures:
    - CWE-754: Comprehensive Error Handling in allen Methoden
    - CWE-400: Resource Management mit Rate Limiting
    - CWE-20: Input Validation für alle externen Daten
    - CWE-532: Sichere Logging-Praktiken ohne sensible Daten
    - CWE-369: Division by Zero Prevention
    """

    def __init__(self, service_name: str, config, **kwargs):
        """
        Initialisiert Discovery Service sicher
        CWE-20: Input Validation durch parent class
        """
        # Flexiblere Typ-Prüfung
        if not hasattr(config, "get_monitoring_config"):
            raise TypeError("Config must have get_monitoring_config method")

        super().__init__(service_name, config, **kwargs)

        # Service-spezifische Konfiguration
        self.monitoring_config = config.get_monitoring_config()
        self.service_config = config.get_service_config()

        # Spotify-Komponenten
        self.authenticator = SpotifyAuthenticator(config)
        self.spotify_client: Optional[spotipy.Spotify] = None
        self.playlist_manager: Optional[PlaylistManager] = None
        self.statistics_db = StatisticsDatabase()

        # Session Management
        self.session_id = str(uuid.uuid4())
        self.current_session: Optional[TrackSession] = None

        # Rate Limiting - CWE-400: Resource Management
        self.last_api_call = 0
        self.min_api_interval = max(
            1.0, self.monitoring_config.get("check_interval_seconds", 5)
        )

        self.logger.info(
            f"Discovery Service initialized with session: {self.session_id[:8]}"
        )

    def _initialize_service(self) -> bool:
        """
        Service-spezifische Initialisierung
        CWE-754: Exception Handling
        """
        try:
            self.logger.info("Initializing Spotify Discovery Service")

            # Spotify-Authentifizierung
            if not self.authenticator.is_authenticated():
                self.logger.error("Spotify authentication required")
                return False

            # Spotify Client erstellen
            token_info = self.authenticator.get_cached_token()
            if not token_info:
                self.logger.error("No valid Spotify token available")
                return False

            self.spotify_client = spotipy.Spotify(
                auth=token_info.get("access_token"),
                requests_timeout=10,  # Timeout für Requests
                retries=2,  # Retry-Logik
            )

            # Playlist Manager initialisieren
            self.playlist_manager = PlaylistManager(self.config)
            if not self.playlist_manager.initialize(self.spotify_client):
                self.logger.error("Failed to initialize playlist manager")
                return False

            # Test API Connection
            try:
                user_profile = self.spotify_client.current_user()
                user_name = user_profile.get("display_name", "Unknown")
                self.logger.info(f"Connected to Spotify as: {user_name[:20]}")
            except Exception as e:
                self.logger.error(f"Spotify API test failed: {e}")
                return False

            self.logger.info("Discovery Service initialization completed")
            return True

        except Exception as e:
            self.logger.error(f"Service initialization failed: {e}")
            self.health.mark_unhealthy(str(e))
            return False

    def _run_service_loop(self) -> None:
        """
        Hauptservice-Loop für Discovery
        CWE-754: Exception Handling in Main Loop
        CWE-400: Resource Management mit Rate Limiting
        """
        self.logger.info("Starting Discovery Service main loop")

        consecutive_errors = 0
        max_consecutive_errors = 5

        while not self.should_stop():
            try:
                # Rate Limiting - CWE-400
                current_time = time.time()
                time_since_last_call = current_time - self.last_api_call

                if time_since_last_call < self.min_api_interval:
                    sleep_time = self.min_api_interval - time_since_last_call
                    if not self.wait_or_stop(sleep_time):
                        break

                # Hauptlogik ausführen
                self._check_current_track()
                self.last_api_call = time.time()

                # Error Counter zurücksetzen bei Erfolg
                consecutive_errors = 0
                self.health.mark_healthy()

                # Standard-Wartezeit
                if not self.wait_or_stop(self.min_api_interval):
                    break

            except Exception as e:
                consecutive_errors += 1
                self.logger.error(f"Error in discovery loop: {e}")
                self.health.mark_unhealthy(str(e))

                # Bei zu vielen Fehlern Service stoppen
                if consecutive_errors >= max_consecutive_errors:
                    self.logger.error(
                        f"Too many consecutive errors ({consecutive_errors}), stopping service"
                    )
                    break

                # Exponential backoff bei Fehlern
                backoff_time = min(60, 2**consecutive_errors)
                if not self.wait_or_stop(backoff_time):
                    break

        self.logger.info("Discovery Service main loop ended")

    def _check_current_track(self) -> None:
        """
        Prüft aktuell spielenden Track
        CWE-754: Exception Handling
        CWE-532: Sichere Logging-Praktiken
        """
        try:
            if not self.spotify_client:
                raise RuntimeError("Spotify client not initialized")

            # Aktuellen Track abrufen
            current_playback = self.spotify_client.current_playback()

            if not current_playback or not current_playback.get("is_playing"):
                # Kein Track spielt - Session beenden falls aktiv
                if self.current_session:
                    self._end_current_session()
                return

            track = current_playback.get("item")
            if not track or track.get("type") != "track":
                return

            track_id = track.get("id")
            if not track_id:
                return

            # Track-Daten sanitisieren
            track_data = self._extract_track_data(track)

            # Session-Management
            if self.current_session and self.current_session.track_id == track_id:
                # Bestehende Session aktualisieren
                self.current_session.update_last_seen()
            else:
                # Neue Session starten
                if self.current_session:
                    self._end_current_session()
                self._start_new_session(track_id, track_data)

            # Prüfe ob Track zur Playlist hinzugefügt werden soll
            self._check_track_for_playlist_addition()

        except spotipy.SpotifyException as e:
            if e.http_status == 401:
                self.logger.error("Spotify token expired, reauthentication needed")
                self.health.mark_unhealthy("Authentication expired")
            else:
                self.logger.error(f"Spotify API error: {e}")
                self.health.mark_unhealthy(f"Spotify API error: {e.http_status}")
        except Exception as e:
            self.logger.error(f"Error checking current track: {e}")
            self.health.mark_unhealthy(str(e))

    def _extract_track_data(self, track: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extrahiert und sanitisiert Track-Daten
        CWE-20: Input Validation
        CWE-532: Information Exposure Prevention
        """
        try:
            # Basis Track-Informationen
            track_data = {
                "id": track.get("id", ""),
                "name": track.get("name", ""),
                "duration_ms": track.get("duration_ms", 0),
            }

            # Artist-Informationen (erster Artist)
            artists = track.get("artists", [])
            if artists and isinstance(artists, list) and len(artists) > 0:
                artist = artists[0]
                track_data["artist"] = (
                    artist.get("name", "") if isinstance(artist, dict) else ""
                )
            else:
                track_data["artist"] = ""

            # Album-Informationen
            album = track.get("album", {})
            if isinstance(album, dict):
                track_data["album"] = album.get("name", "")
            else:
                track_data["album"] = ""

            return track_data

        except Exception as e:
            self.logger.error(f"Error extracting track data: {e}")
            return {
                "id": track.get("id", "") if isinstance(track, dict) else "",
                "name": "Unknown",
                "artist": "Unknown",
                "album": "Unknown",
                "duration_ms": 0,
            }

    def _start_new_session(self, track_id: str, track_data: Dict[str, Any]) -> None:
        """
        Startet neue Track-Session
        CWE-754: Exception Handling
        """
        try:
            self.current_session = TrackSession(track_id, track_data)

            # Session in Datenbank speichern
            self.current_session.database_record_id = (
                self.statistics_db.record_track_play(
                    track_id=track_id,
                    track_name=track_data.get("name", ""),
                    artist_name=track_data.get("artist", ""),
                    album_name=track_data.get("album", ""),
                    duration_ms=track_data.get("duration_ms", 0),
                )
            )

            # Sicheres Logging ohne sensible Daten
            track_name = track_data.get("name", "Unknown")[:30]
            artist_name = track_data.get("artist", "Unknown")[:30]
            self.logger.info(f"Started session for: {track_name} by {artist_name}")

        except Exception as e:
            self.logger.error(f"Error starting new session: {e}")

    def _end_current_session(self) -> None:
        """
        Beendet aktuelle Track-Session
        CWE-754: Exception Handling
        """
        try:
            if not self.current_session:
                return

            # Session-Daten aktualisieren
            listening_duration = self.current_session.listening_duration

            if self.current_session.database_record_id:
                self.statistics_db.update_listening_duration(
                    self.current_session.database_record_id, listening_duration
                )

            # Sicheres Logging
            track_name = self.current_session.track_data.get("name", "Unknown")[:30]
            self.logger.info(
                f"Ended session for: {track_name} (Duration: {listening_duration}s)"
            )

            self.current_session = None

        except Exception as e:
            self.logger.error(f"Error ending session: {e}")

    def _check_track_for_playlist_addition(self) -> None:
        """
        Prüft ob Track zur Playlist hinzugefügt werden soll
        CWE-754: Exception Handling
        CWE-369: Division by Zero Prevention
        """
        try:
            if not self.current_session or self.current_session.added_to_playlist:
                return

            if not self.playlist_manager:
                return

            # Konfiguration laden
            min_duration = self.monitoring_config.get(
                "minimum_play_duration_seconds", 30
            )
            listening_duration = self.current_session.listening_duration

            if listening_duration < min_duration:
                return

            # Track zur Playlist hinzufügen
            success = self.playlist_manager.add_track_to_playlist(
                self.current_session.track_id
            )

            if success:
                self.current_session.added_to_playlist = True

                # Statistik aktualisieren
                if self.current_session.database_record_id:
                    self.statistics_db.mark_track_added_to_playlist(
                        self.current_session.database_record_id
                    )

                # Sicheres Logging
                track_name = self.current_session.track_data.get("name", "Unknown")[:30]
                self.logger.info(f"Added to playlist: {track_name}")

        except Exception as e:
            self.logger.error(f"Error checking track for playlist addition: {e}")

    def _cleanup_service(self) -> None:
        """
        Service-spezifisches Cleanup
        CWE-400: Resource Management
        """
        try:
            self.logger.info("Cleaning up Discovery Service")

            # Aktuelle Session beenden
            if self.current_session:
                self._end_current_session()

            # Spotify Client cleanup
            self.spotify_client = None
            self.playlist_manager = None

            self.logger.info("Discovery Service cleanup completed")

        except Exception as e:
            self.logger.error(f"Error during service cleanup: {e}")

    def get_current_track_info(self) -> Optional[Dict[str, Any]]:
        """
        Gibt Informationen zum aktuellen Track zurück
        CWE-200: Information Exposure Prevention
        """
        if not self.current_session:
            return None

        try:
            return {
                "track_name": self.current_session.track_data.get("name", "")[:50],
                "artist_name": self.current_session.track_data.get("artist", "")[:50],
                "listening_duration": self.current_session.listening_duration,
                "added_to_playlist": self.current_session.added_to_playlist,
            }
        except Exception as e:
            self.logger.error(f"Error getting current track info: {e}")
            return None
