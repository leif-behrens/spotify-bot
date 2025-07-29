"""
Sichere Statistik-Datenbank für Spotify Bot
CWE-89: SQL Injection Prevention, CWE-312: Secure Storage
Bandit: B608, B703
"""

import sqlite3
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
import threading
from contextlib import contextmanager
import json

logger = logging.getLogger(__name__)

class StatisticsDatabase:
    """
    Sichere SQLite-Datenbank für Statistiken
    - CWE-89: SQL Injection Prevention durch Prepared Statements
    - CWE-312: Sichere Datenspeicherung
    - CWE-400: Resource Management
    """
    
    def __init__(self, db_path: str = "data/spotify_bot.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        
        # Initialisiere Datenbank-Schema
        self._initialize_database()
    
    def _initialize_database(self) -> None:
        """
        Erstellt sichere Datenbank-Tabellen
        CWE-89: SQL Injection Prevention durch DDL ohne User Input
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Tabelle für aktuell spielende Songs
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS current_tracks (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        track_id TEXT NOT NULL,
                        track_name TEXT NOT NULL,
                        artist_name TEXT NOT NULL,
                        album_name TEXT NOT NULL,
                        started_at TIMESTAMP NOT NULL,
                        ended_at TIMESTAMP,
                        duration_ms INTEGER,
                        progress_ms INTEGER,
                        added_to_playlist BOOLEAN DEFAULT FALSE,
                        session_id TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Tabelle für zur Playlist hinzugefügte Songs
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS playlist_additions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        track_id TEXT NOT NULL,
                        track_name TEXT NOT NULL,
                        artist_name TEXT NOT NULL,
                        album_name TEXT NOT NULL,
                        playlist_id TEXT NOT NULL,
                        added_at TIMESTAMP NOT NULL,
                        listening_duration_seconds INTEGER,
                        session_id TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Tabelle für allgemeine Statistiken
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS statistics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        metric_name TEXT NOT NULL,
                        metric_value TEXT NOT NULL,
                        recorded_at TIMESTAMP NOT NULL,
                        metadata TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Indizes für Performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_current_tracks_track_id ON current_tracks(track_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_current_tracks_started_at ON current_tracks(started_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_playlist_additions_track_id ON playlist_additions(track_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_playlist_additions_added_at ON playlist_additions(added_at)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_statistics_metric_name ON statistics(metric_name)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_statistics_recorded_at ON statistics(recorded_at)")
                
                conn.commit()
                logger.info("Database initialized successfully")
                
        except sqlite3.Error as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    @contextmanager
    def _get_connection(self):
        """
        Thread-sichere Datenbankverbindung
        CWE-400: Resource Management, CWE-703: Error Handling
        """
        conn = None
        try:
            with self._lock:
                conn = sqlite3.connect(
                    self.db_path,
                    timeout=30.0,  # Timeout für Deadlock-Prevention
                    check_same_thread=False
                )
                conn.row_factory = sqlite3.Row  # Dict-like access
                conn.execute("PRAGMA foreign_keys = ON")  # Referentielle Integrität
                conn.execute("PRAGMA journal_mode = WAL")  # Performance
                yield conn
        except sqlite3.Error as e:
            if conn:
                conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            if conn:
                conn.close()
    
    def record_current_track(self, track_data: Dict[str, Any], session_id: str) -> int:
        """
        Zeichnet aktuell spielenden Track auf
        CWE-89: SQL Injection Prevention durch Prepared Statements
        CWE-20: Input Validation
        """
        try:
            # Input Validation
            required_fields = ['track_id', 'track_name', 'artist_name', 'album_name', 'started_at']
            for field in required_fields:
                if field not in track_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # Sanitize String-Eingaben
            track_name = str(track_data['track_name'])[:200]  # Längen-Begrenzung
            artist_name = str(track_data['artist_name'])[:200]
            album_name = str(track_data['album_name'])[:200]
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Prepared Statement - CWE-89 Prevention
                cursor.execute("""
                    INSERT INTO current_tracks 
                    (track_id, track_name, artist_name, album_name, started_at, 
                     duration_ms, progress_ms, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    track_data['track_id'],
                    track_name,
                    artist_name,
                    album_name,
                    track_data['started_at'],
                    track_data.get('duration_ms', 0),
                    track_data.get('progress_ms', 0),
                    session_id
                ))
                
                conn.commit()
                record_id = cursor.lastrowid
                logger.debug(f"Recorded current track: {track_name} (ID: {record_id})")
                return record_id
                
        except Exception as e:
            logger.error(f"Failed to record current track: {e}")
            raise
    
    def update_track_end(self, record_id: int, ended_at: datetime, added_to_playlist: bool = False) -> None:
        """
        Aktualisiert Track-Ende
        CWE-89: SQL Injection Prevention
        """
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    UPDATE current_tracks 
                    SET ended_at = ?, added_to_playlist = ?
                    WHERE id = ?
                """, (ended_at, added_to_playlist, record_id))
                
                conn.commit()
                logger.debug(f"Updated track end for record {record_id}")
                
        except Exception as e:
            logger.error(f"Failed to update track end: {e}")
            raise
    
    def record_playlist_addition(self, track_data: Dict[str, Any], playlist_id: str, 
                               listening_duration: int, session_id: str) -> int:
        """
        Zeichnet Playlist-Hinzufügung auf
        CWE-89: SQL Injection Prevention, CWE-20: Input Validation
        """
        try:
            # Input Validation
            required_fields = ['track_id', 'track_name', 'artist_name', 'album_name']
            for field in required_fields:
                if field not in track_data:
                    raise ValueError(f"Missing required field: {field}")
            
            # Validiere Playlist ID Format
            if not playlist_id or len(playlist_id) < 10:
                raise ValueError("Invalid playlist ID")
            
            # Sanitize Eingaben
            track_name = str(track_data['track_name'])[:200]
            artist_name = str(track_data['artist_name'])[:200]
            album_name = str(track_data['album_name'])[:200]
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO playlist_additions 
                    (track_id, track_name, artist_name, album_name, playlist_id, 
                     added_at, listening_duration_seconds, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    track_data['track_id'],
                    track_name,
                    artist_name,
                    album_name,
                    playlist_id,
                    datetime.now(),
                    listening_duration,
                    session_id
                ))
                
                conn.commit()
                record_id = cursor.lastrowid
                logger.info(f"Recorded playlist addition: {track_name} (Duration: {listening_duration}s)")
                return record_id
                
        except Exception as e:
            logger.error(f"Failed to record playlist addition: {e}")
            raise
    
    def record_metric(self, metric_name: str, metric_value: Any, metadata: Optional[Dict] = None) -> None:
        """
        Zeichnet allgemeine Metriken auf
        CWE-89: SQL Injection Prevention
        """
        try:
            # Input Validation
            if not metric_name or len(metric_name) > 100:
                raise ValueError("Invalid metric name")
            
            # Konvertiere Wert zu String für Storage
            value_str = str(metric_value)[:500]  # Längenbegrenzung
            
            # Serialisiere Metadata sicher
            metadata_json = None
            if metadata:
                metadata_json = json.dumps(metadata)[:1000]  # Längenbegrenzung
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    INSERT INTO statistics (metric_name, metric_value, recorded_at, metadata)
                    VALUES (?, ?, ?, ?)
                """, (metric_name, value_str, datetime.now(), metadata_json))
                
                conn.commit()
                logger.debug(f"Recorded metric: {metric_name} = {value_str}")
                
        except Exception as e:
            logger.error(f"Failed to record metric: {e}")
            raise
    
    def get_listening_statistics(self, days: int = 7) -> Dict[str, Any]:
        """
        Gibt Hör-Statistiken zurück
        CWE-89: SQL Injection Prevention durch Prepared Statements
        """
        try:
            since_date = datetime.now() - timedelta(days=days)
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Gesamtzahl gehörter Tracks
                cursor.execute("""
                    SELECT COUNT(*) as total_tracks
                    FROM current_tracks 
                    WHERE started_at >= ?
                """, (since_date,))
                total_tracks = cursor.fetchone()['total_tracks']
                
                # Zur Playlist hinzugefügte Tracks
                cursor.execute("""
                    SELECT COUNT(*) as added_tracks
                    FROM playlist_additions 
                    WHERE added_at >= ?
                """, (since_date,))
                added_tracks = cursor.fetchone()['added_tracks']
                
                # Top Artists
                cursor.execute("""
                    SELECT artist_name, COUNT(*) as play_count
                    FROM current_tracks 
                    WHERE started_at >= ?
                    GROUP BY artist_name 
                    ORDER BY play_count DESC 
                    LIMIT 10
                """, (since_date,))
                top_artists = [dict(row) for row in cursor.fetchall()]
                
                # Durchschnittliche Hördauer
                cursor.execute("""
                    SELECT AVG(listening_duration_seconds) as avg_duration
                    FROM playlist_additions 
                    WHERE added_at >= ?
                """, (since_date,))
                avg_duration = cursor.fetchone()['avg_duration'] or 0
                
                return {
                    'period_days': days,
                    'total_tracks_played': total_tracks,
                    'tracks_added_to_playlist': added_tracks,
                    'discovery_rate': (added_tracks / total_tracks * 100) if total_tracks > 0 else 0,
                    'top_artists': top_artists,
                    'average_listening_duration_seconds': round(avg_duration, 2)
                }
                
        except Exception as e:
            logger.error(f"Failed to get listening statistics: {e}")
            return {}
    
    def get_daily_activity(self, days: int = 30) -> List[Dict[str, Any]]:
        """
        Gibt tägliche Aktivitätsstatistiken zurück
        CWE-89: SQL Injection Prevention
        """
        try:
            since_date = datetime.now() - timedelta(days=days)
            
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                cursor.execute("""
                    SELECT 
                        DATE(started_at) as date,
                        COUNT(*) as tracks_played,
                        COUNT(CASE WHEN added_to_playlist = 1 THEN 1 END) as tracks_added
                    FROM current_tracks 
                    WHERE started_at >= ?
                    GROUP BY DATE(started_at)
                    ORDER BY date DESC
                """, (since_date,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get daily activity: {e}")
            return []