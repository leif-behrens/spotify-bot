"""
Sichere Playlist-Verwaltung für Spotify Bot
CWE-20: Input Validation, CWE-400: Resource Exhaustion Prevention
Bandit: B101, B322
"""

import logging
import time
from typing import Any, Dict, Optional

import spotipy

from .logging_setup import LoggingSetup

logger = LoggingSetup.get_logger(__name__)


class PlaylistManager:
    """
    Sichere Playlist-Verwaltung
    - CWE-20: Input Validation für alle Spotify-Daten
    - CWE-400: Rate Limiting und Resource Management
    - CWE-754: Proper Error Handling
    """

    def __init__(
        self, spotify_client: spotipy.Spotify, playlist_config: Dict[str, str]
    ):
        self.spotify = spotify_client
        self.playlist_name = playlist_config["name"]
        self.playlist_description = playlist_config.get("description", "")
        self.auto_playlist_id: Optional[str] = None
        self.rate_limit_delay = 1.0  # Sekunden zwischen API-Calls

        # Input Validation für Playlist-Konfiguration
        self._validate_playlist_config()

    def _validate_playlist_config(self) -> None:
        """
        Validiert Playlist-Konfiguration
        CWE-20: Input Validation
        """
        if not self.playlist_name or len(self.playlist_name.strip()) == 0:
            raise ValueError("Playlist name cannot be empty")

        if len(self.playlist_name) > 100:
            raise ValueError("Playlist name too long (max 100 characters)")

        # Sanitize playlist name - entferne potentiell gefährliche Zeichen
        forbidden_chars = ["<", ">", '"', "|", ":", "*", "?", "\\", "/"]
        for char in forbidden_chars:
            if char in self.playlist_name:
                raise ValueError(f"Playlist name contains forbidden character: {char}")

        if len(self.playlist_description) > 300:
            raise ValueError("Playlist description too long (max 300 characters)")

    def _rate_limit_sleep(self) -> None:
        """
        Rate Limiting für Spotify API
        CWE-400: Resource Exhaustion Prevention
        """
        time.sleep(self.rate_limit_delay)

    def _validate_track_data(self, track_data: Dict[str, Any]) -> bool:
        """
        Validiert Track-Daten von Spotify API
        CWE-20: Input Validation
        """
        try:
            # Debug: Zeige verfügbare Felder
            logger.debug(f"Validating track data with keys: {list(track_data.keys())}")

            # Prüfe essential Track-Felder mit flexibler Validierung
            if "track_id" in track_data:
                # Interne Datenstruktur (von monitoring_service)
                required_fields = ["track_id", "track_name", "artist_name"]
                track_id = track_data["track_id"]
                track_name = track_data["track_name"]
            elif "id" in track_data:
                # Direkte Spotify API-Datenstruktur
                required_fields = ["id", "name"]
                track_id = track_data["id"]
                track_name = track_data["name"]
            else:
                logger.warning(
                    f"Track missing ID field. Available fields: {list(track_data.keys())}"
                )
                return False

            # Validiere required fields
            for field in required_fields:
                if field not in track_data or not track_data[field]:
                    logger.warning(f"Track missing or empty required field: {field}")
                    return False

            # Validiere Track ID Format (sollte nicht leer sein und Spotify-Format)
            if not isinstance(track_id, str) or len(track_id) < 10:
                logger.warning(f"Invalid track ID format: {track_id}")
                return False

            # Validiere Track Name
            if not isinstance(track_name, str) or len(track_name.strip()) == 0:
                logger.warning(f"Invalid track name: {track_name}")
                return False

            # Validiere URI Format (falls vorhanden)
            if "uri" in track_data and track_data["uri"]:
                if not track_data["uri"].startswith("spotify:track:"):
                    logger.warning(f"Invalid track URI format: {track_data['uri']}")
                    return False

            # Validiere Artist-Daten (falls vorhanden)
            if "artists" in track_data:
                if (
                    not isinstance(track_data["artists"], list)
                    or len(track_data["artists"]) == 0
                ):
                    logger.warning("Track has no valid artists")
                    return False
            elif "artist_name" in track_data:
                if (
                    not isinstance(track_data["artist_name"], str)
                    or len(track_data["artist_name"].strip()) == 0
                ):
                    logger.warning("Track has no valid artist name")
                    return False

            logger.debug(f"Track validation successful for: {track_name}")
            return True

        except Exception as e:
            logger.error(f"Track validation error: {e}")
            return False

    def initialize_playlist(self) -> str:
        """
        Erstellt oder findet die Auto-Discovery Playlist
        CWE-754: Error Handling, CWE-400: Resource Management
        """
        try:
            user_id = self.spotify.current_user()["id"]

            # Suche nach existierender Playlist
            self.auto_playlist_id = self._find_existing_playlist(user_id)

            if self.auto_playlist_id:
                logger.info(f"Found existing playlist: {self.playlist_name}")
                return self.auto_playlist_id

            # Erstelle neue Playlist
            self._rate_limit_sleep()
            playlist = self.spotify.user_playlist_create(
                user=user_id,
                name=self.playlist_name,
                public=False,  # Privacy by default
                collaborative=False,
                description=self.playlist_description,
            )

            self.auto_playlist_id = playlist["id"]
            logger.info(
                f"Created new playlist: {self.playlist_name} (ID: {self.auto_playlist_id})"
            )

            return self.auto_playlist_id

        except spotipy.SpotifyException as e:
            logger.error(f"Spotify API error during playlist initialization: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error during playlist initialization: {e}")
            raise

    def _find_existing_playlist(self, user_id: str) -> Optional[str]:
        """
        Sucht nach existierender Auto-Discovery Playlist
        CWE-400: Pagination und Resource Management
        """
        try:
            offset = 0
            limit = 50  # Spotify API Limit

            while True:
                self._rate_limit_sleep()
                playlists = self.spotify.user_playlists(
                    user_id, limit=limit, offset=offset
                )

                for playlist in playlists["items"]:
                    if playlist["name"] == self.playlist_name:
                        return playlist["id"]

                # Prüfe ob mehr Playlists vorhanden
                if len(playlists["items"]) < limit:
                    break

                offset += limit

                # Safety: Maximal 1000 Playlists durchsuchen
                if offset > 1000:
                    logger.warning("Stopped playlist search after 1000 items")
                    break

            return None

        except Exception as e:
            logger.error(f"Error searching for existing playlist: {e}")
            return None

    def add_track_to_playlist(self, track_uri: str, track_info: Dict[str, Any]) -> bool:
        """
        Fügt Track sicher zur Playlist hinzu
        CWE-20: Input Validation, CWE-400: Rate Limiting
        """
        try:
            if not self.auto_playlist_id:
                raise RuntimeError("Playlist not initialized")

            # Validiere Track URI
            if not track_uri.startswith("spotify:track:"):
                logger.error(f"Invalid track URI format: {track_uri}")
                return False

            # Validiere Track-Daten
            if not self._validate_track_data(track_info):
                logger.error("Track data validation failed")
                return False

            # Prüfe ob Track bereits in Playlist
            if self._is_track_in_playlist(track_uri):
                # Flexible Namensauflösung
                track_name = track_info.get("track_name") or track_info.get(
                    "name", "Unknown"
                )
                logger.info(f"Track already in playlist: {track_name}")
                return True

            # Füge Track zur Playlist hinzu
            self._rate_limit_sleep()
            self.spotify.playlist_add_items(
                playlist_id=self.auto_playlist_id, items=[track_uri]
            )

            # Flexible Namensauflösung für Logging
            track_name = track_info.get("track_name") or track_info.get(
                "name", "Unknown"
            )
            artist_name = track_info.get("artist_name", "Unknown")
            if not artist_name and "artists" in track_info and track_info["artists"]:
                artist_name = track_info["artists"][0].get("name", "Unknown")

            logger.info(f"Added track to playlist: {track_name} by {artist_name}")
            return True

        except spotipy.SpotifyException as e:
            logger.error(f"Spotify API error adding track: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error adding track: {e}")
            return False

    def _is_track_in_playlist(self, track_uri: str) -> bool:
        """
        Prüft ob Track bereits in Playlist vorhanden
        CWE-400: Efficient Resource Usage
        """
        try:
            offset = 0
            limit = 100  # Spotify API Limit

            while True:
                self._rate_limit_sleep()
                tracks = self.spotify.playlist_tracks(
                    playlist_id=self.auto_playlist_id,
                    limit=limit,
                    offset=offset,
                    fields="items(track(uri))",  # Nur URI laden für Effizienz
                )

                for item in tracks["items"]:
                    if item["track"] and item["track"]["uri"] == track_uri:
                        return True

                # Prüfe ob mehr Tracks vorhanden
                if len(tracks["items"]) < limit:
                    break

                offset += limit

                # Safety: Maximal 10000 Tracks durchsuchen
                if offset > 10000:
                    logger.warning("Stopped duplicate check after 10000 tracks")
                    break

            return False

        except Exception as e:
            logger.error(f"Error checking for duplicate track: {e}")
            return False

    def get_playlist_info(self) -> Optional[Dict[str, Any]]:
        """
        Gibt Playlist-Informationen zurück
        CWE-754: Error Handling
        """
        try:
            if not self.auto_playlist_id:
                return None

            self._rate_limit_sleep()
            playlist = self.spotify.playlist(self.auto_playlist_id)

            return {
                "id": playlist["id"],
                "name": playlist["name"],
                "description": playlist["description"],
                "track_count": playlist["tracks"]["total"],
                "public": playlist["public"],
                "url": playlist["external_urls"]["spotify"],
            }

        except Exception as e:
            logger.error(f"Error getting playlist info: {e}")
            return None
