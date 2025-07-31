"""
Sicherer Spotify Auto-Discovery Service
Produziert sichere, CWE-konforme Musik-Entdeckung

Sicherheitsfeatures:
- CWE-20: Input Validation für alle Spotify API-Daten
- CWE-400: Resource Management mit Rate Limiting
- CWE-754: Comprehensive Error Handling
- CWE-532: Information Exposure Prevention - Sichere Logging-Praktiken
"""

import os
import time
from typing import Any, Dict, Optional

import spotipy

from ..auth.oauth_manager import SpotifyOAuthManager
from ..core.config import ConfigManager
from ..utils.logging_setup import LoggingSetup

# Initialize logging
logger = LoggingSetup.get_logger("discovery")


class SpotifyDiscoveryService:
    """
    Sicherer Auto-Discovery Service für Spotify

    Sicherheitsfeatures:
    - CWE-20: Input Validation für alle API-Daten
    - CWE-400: Resource Management und Rate Limiting
    - CWE-754: Comprehensive Error Handling
    - CWE-532: Sichere Logging-Praktiken
    """

    def __init__(self):
        self.config = ConfigManager()
        self.oauth_manager = SpotifyOAuthManager()
        self.spotify_client: Optional[spotipy.Spotify] = None
        self.playlist_id: Optional[str] = None
        self.is_running = False

    def get_playlist_id(self) -> Optional[str]:
        """Sichere Playlist-ID-Ermittlung"""
        try:
            # Versuche aus Environment Variable zu laden
            playlist_id = os.environ.get("SPOTIFY_PLAYLIST_ID")
            if playlist_id:
                # Input Validation - CWE-20
                if isinstance(playlist_id, str) and len(playlist_id) == 22:
                    logger.info("Playlist ID aus Environment Variable geladen")
                    return playlist_id
                else:
                    logger.warning("Ungültige Playlist ID in Environment Variable")

            # Fallback: Verwende bekannte ID (temporär für Migration)
            fallback_id = "6IzmE9sUfYmzRIwwgXldDD"
            logger.warning(
                "Fallback zu hardcoded Playlist ID - sollte in Environment Variable verschoben werden"
            )
            return fallback_id

        except Exception as e:
            logger.error(f"Fehler beim Laden der Playlist ID: {e}")
            return None

    def verify_playlist(self, playlist_id: str) -> bool:
        """Sichere Playlist-Verifikation"""
        try:
            # Input Validation - CWE-20
            if not isinstance(playlist_id, str) or len(playlist_id) != 22:
                logger.error("Ungültige Playlist ID")
                return False

            playlist = self.spotify_client.playlist(playlist_id)

            # Validiere API-Antwort - CWE-20
            if not playlist or not isinstance(playlist, dict):
                logger.error("Ungültige Playlist-Antwort von API")
                return False

            playlist_name = playlist.get("name", "Unknown")
            owner_name = playlist.get("owner", {}).get("display_name", "Unknown")
            track_count = playlist.get("tracks", {}).get("total", 0)

            # Sichere String-Ausgabe - CWE-532: Information Exposure Prevention
            safe_name = (
                playlist_name[:50] if isinstance(playlist_name, str) else "Unknown"
            )
            safe_owner = owner_name[:30] if isinstance(owner_name, str) else "Unknown"

            logger.info(
                f"Playlist gefunden: {safe_name} (Owner: {safe_owner}, Tracks: {track_count})"
            )
            return True

        except spotipy.SpotifyException as e:
            logger.error(f"Spotify API Fehler bei Playlist-Verifikation: {e}")
            return False
        except Exception as e:
            logger.error(f"Unerwarteter Fehler bei Playlist-Verifikation: {e}")
            return False

    def sanitize_track_data(self, track_data: Dict[str, Any]) -> Dict[str, str]:
        """Sichere Track-Daten-Sanitisierung"""
        try:
            # Sichere Extraktion und Validierung - CWE-20
            track_id = track_data.get("id", "")
            if not isinstance(track_id, str) or len(track_id) != 22:
                track_id = "unknown"

            track_name = track_data.get("name", "Unknown")
            if not isinstance(track_name, str):
                track_name = "Unknown"
            # Längenbegrenzung gegen DoS - CWE-400
            track_name = track_name[:100]

            # Artist-Daten sicher extrahieren
            artists = track_data.get("artists", [])
            artist_name = "Unknown"
            if isinstance(artists, list) and len(artists) > 0:
                first_artist = artists[0]
                if isinstance(first_artist, dict):
                    artist_name = first_artist.get("name", "Unknown")
                    if isinstance(artist_name, str):
                        artist_name = artist_name[:50]  # Längenbegrenzung
                    else:
                        artist_name = "Unknown"

            return {"id": track_id, "name": track_name, "artist": artist_name}

        except Exception as e:
            logger.error(f"Fehler bei Track-Daten-Sanitisierung: {e}")
            return {"id": "unknown", "name": "Unknown", "artist": "Unknown"}

    def add_track_to_playlist(self, track_data: Dict[str, str]) -> bool:
        """Sichere Track-Addition mit vollständiger Duplikats-Prüfung"""
        try:
            track_id = track_data["id"]
            track_name = track_data["name"]
            artist_name = track_data["artist"]

            # Input Validation - CWE-20
            if not isinstance(track_id, str) or len(track_id) != 22:
                logger.error("Ungültige Track ID")
                return False

            logger.info(f"Prüfe Duplikate für: {track_name[:30]}...")

            # Vollständige Duplikats-Prüfung - CWE-400: Efficient Resource Usage
            offset = 0
            limit = 100  # Batch-Größe für API-Effizienz
            total_checked = 0

            while True:
                try:
                    # Rate Limiting - CWE-400: Resource Management
                    time.sleep(0.1)  # Spotify API Schutz

                    tracks = self.spotify_client.playlist_tracks(
                        self.playlist_id, limit=limit, offset=offset
                    )

                    # Validiere API-Antwort - CWE-20
                    if not tracks or not isinstance(tracks, dict):
                        logger.error("Ungültige API-Antwort bei Playlist-Tracks")
                        break

                    items = tracks.get("items", [])
                    if not isinstance(items, list):
                        logger.error("Ungültige Items in API-Antwort")
                        break

                    # Prüfe aktuellen Batch auf Duplikate
                    for item in items:
                        total_checked += 1
                        if (
                            isinstance(item, dict)
                            and item.get("track")
                            and isinstance(item["track"], dict)
                            and item["track"].get("id") == track_id
                        ):
                            logger.info(
                                f"Track bereits in Playlist (Position {total_checked})"
                            )
                            return True

                    # Prüfe ob mehr Tracks vorhanden
                    if len(items) < limit:
                        break

                    offset += limit

                    # Sicherheits-Limit gegen unendliche Schleifen - CWE-835
                    if offset > 50000:  # Max 50k Tracks
                        logger.warning("Sicherheits-Limit erreicht, füge Track hinzu")
                        break

                except spotipy.SpotifyException as e:
                    logger.error(f"Spotify API Fehler bei Duplikats-Prüfung: {e}")
                    break
                except Exception as e:
                    logger.error(f"Unerwarteter Fehler bei Duplikats-Prüfung: {e}")
                    break

            # Track nicht gefunden, hinzufügen
            logger.info(
                f"Track nicht gefunden ({total_checked} Tracks geprüft), füge hinzu"
            )

            # Sichere URI-Konstruktion - CWE-20: Input Validation
            track_uri = f"spotify:track:{track_id}"
            if not track_uri.startswith("spotify:track:") or len(track_uri) != 36:
                logger.error("Ungültige Track URI")
                return False

            # Rate Limiting vor API-Call - CWE-400
            time.sleep(0.2)

            self.spotify_client.playlist_add_items(self.playlist_id, [track_uri])
            logger.info(f"Track hinzugefügt: {track_name[:30]} von {artist_name[:30]}")
            return True

        except spotipy.SpotifyException as e:
            logger.error(f"Spotify API Fehler beim Hinzufügen: {e}")
            return False
        except Exception as e:
            logger.error(f"Unerwarteter Fehler beim Hinzufügen: {e}")
            return False

    def initialize(self) -> bool:
        """Sichere Service-Initialisierung"""
        try:
            logger.info("Initialisiere sicheren Spotify Auto-Discovery Service")

            # Sichere Token-Verwaltung
            logger.info("Checking Spotify authentication...")

            if not self.oauth_manager.ensure_valid_token():
                logger.error("Spotify-Authentifizierung fehlgeschlagen")
                logger.info(
                    "Bitte führen Sie 'python main.py auth' aus, um die Authentifizierung durchzuführen"
                )
                return False

            logger.info("Spotify authentication successful")

            # Token abrufen und Spotify Client erstellen
            token_info = self.oauth_manager.get_valid_token()
            if not token_info:
                logger.error("Kein gültiger Token verfügbar")
                return False

            access_token = token_info.get("access_token")
            if not isinstance(access_token, str) or len(access_token) < 10:
                logger.error("Ungültiger Access Token")
                return False

            # Spotify Client mit sicherer Konfiguration
            self.spotify_client = spotipy.Spotify(
                auth=access_token,
                requests_timeout=10,  # Timeout Prevention - CWE-400
                retries=2,  # Resilience
            )

            # Benutzer-Verifikation - CWE-20: Input Validation
            user = self.spotify_client.current_user()
            if not user or not isinstance(user, dict):
                logger.error("Ungültige Benutzer-Daten")
                return False

            user_name = user.get("display_name", "Unknown")[:30]  # Sichere Ausgabe
            logger.info(f"Verbunden als: {user_name}")

            # Sichere Playlist-ID-Ermittlung
            self.playlist_id = self.get_playlist_id()
            if not self.playlist_id:
                logger.error("Keine Playlist ID verfügbar")
                return False

            # Playlist verifizieren
            if not self.verify_playlist(self.playlist_id):
                logger.error("Playlist-Verifikation fehlgeschlagen")
                return False

            logger.info("Service-Initialisierung erfolgreich abgeschlossen")
            return True

        except Exception as e:
            logger.error(f"Fehler bei Service-Initialisierung: {e}")
            return False

    def run(self) -> None:
        """Hauptfunktion des sicheren Discovery Service"""
        try:
            if not self.initialize():
                logger.error("Service-Initialisierung fehlgeschlagen")
                return

            # Monitoring-Konfiguration laden - CWE-20: Input Validation
            monitoring_config = self.config.get_monitoring_config()
            if not isinstance(monitoring_config, dict):
                logger.error("Ungültige Monitoring-Konfiguration")
                return

            min_duration = monitoring_config.get("minimum_play_duration_seconds", 30)
            check_interval = monitoring_config.get("check_interval_seconds", 5)

            # Validiere Konfigurationswerte - CWE-20
            if (
                not isinstance(min_duration, int)
                or min_duration < 5
                or min_duration > 300
            ):
                min_duration = 30
                logger.warning("Ungültige min_duration, verwende Standard: 30s")

            if (
                not isinstance(check_interval, int)
                or check_interval < 1
                or check_interval > 60
            ):
                check_interval = 5
                logger.warning("Ungültiges check_interval, verwende Standard: 5s")

            # Monitoring-Variablen
            current_track_id = None
            start_time = None
            self.is_running = True

            logger.info(f"Monitoring gestartet - Mindest-Spielzeit: {min_duration}s")

            # Hauptschleife mit sicherer Fehlerbehandlung
            consecutive_errors = 0
            max_consecutive_errors = 5

            while self.is_running:
                try:
                    # Rate Limiting - CWE-400
                    time.sleep(check_interval)

                    # Aktuelle Wiedergabe abrufen
                    playback = self.spotify_client.current_playback()

                    # Validiere API-Antwort - CWE-20
                    if not playback or not isinstance(playback, dict):
                        if current_track_id:
                            current_track_id = None
                            start_time = None
                        continue

                    # Prüfe Wiedergabe-Status
                    if not playback.get("is_playing", False):
                        if current_track_id:
                            current_track_id = None
                            start_time = None
                        continue

                    # Track-Daten extrahieren und validieren
                    track = playback.get("item")
                    if (
                        not track
                        or not isinstance(track, dict)
                        or track.get("type") != "track"
                    ):
                        continue

                    # Track-Daten sicher sanitisieren
                    track_data = self.sanitize_track_data(track)
                    track_id = track_data["id"]

                    if track_id == "unknown":
                        continue

                    # Neuer Track erkannt
                    if track_id != current_track_id:
                        current_track_id = track_id
                        start_time = time.time()

                        # Sichere Ausgabe - CWE-532: Information Exposure Prevention
                        logger.info(
                            f"Neuer Track: {track_data['name'][:30]} von {track_data['artist'][:30]}"
                        )

                    # Prüfe ob Track zur Playlist hinzugefügt werden soll
                    if start_time and (time.time() - start_time) >= min_duration:
                        played_time = int(time.time() - start_time)
                        logger.info(
                            f"Füge Track zur Playlist hinzu (gespielt: {played_time}s)"
                        )

                        success = self.add_track_to_playlist(track_data)
                        if success:
                            consecutive_errors = 0  # Reset error counter

                        start_time = None  # Reset to avoid re-adding

                except spotipy.SpotifyException as e:
                    consecutive_errors += 1
                    logger.error(f"Spotify API Fehler: {e}")

                    # Bei zu vielen Fehlern Service beenden - CWE-754
                    if consecutive_errors >= max_consecutive_errors:
                        logger.error(
                            "Zu viele aufeinanderfolgende Fehler, Service wird beendet"
                        )
                        break

                    # Exponential Backoff - CWE-400: Resource Management
                    time.sleep(min(60, 2**consecutive_errors))

                except Exception as e:
                    consecutive_errors += 1
                    logger.error(f"Unerwarteter Fehler: {e}")

                    if consecutive_errors >= max_consecutive_errors:
                        logger.error(
                            "Zu viele aufeinanderfolgende Fehler, Service wird beendet"
                        )
                        break

                    time.sleep(min(60, 2**consecutive_errors))

        except KeyboardInterrupt:
            logger.info("Service durch Benutzer beendet")
        except Exception as e:
            logger.error(f"Fataler Fehler: {e}")
        finally:
            self.is_running = False
            logger.info("Spotify Auto-Discovery Service beendet")

    def stop(self) -> None:
        """Stoppt den Service sicher"""
        logger.info("Service-Stop angefordert")
        self.is_running = False
