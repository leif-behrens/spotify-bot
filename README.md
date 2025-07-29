# Spotify Auto-Discovery Bot

Ein sicherheitsorientierter Python-Service, der automatisch Songs zur Playlist hinzufügt, basierend auf dem Hörverhalten.

## Features

- **Sichere Authentifizierung**: OAuth2 mit verschlüsselter Token-Speicherung
- **Automatische Playlist-Verwaltung**: Erstellt und verwaltet "AutoDiscovered Songs" Playlist
- **Konfigurierbare Überwachung**: JSON-basierte Konfiguration für Intervalle und Schwellenwerte
- **Statistik-Dashboard**: Flask-basierte Weboberfläche für Insights
- **Security-First**: Implementiert nach OpenSSF und OWASP Standards

## Sicherheitsfeatures

- **CWE-798 Prevention**: Keine hardcoded Credentials, Environment Variables
- **CWE-20 Mitigation**: Input Validation für alle externe Daten
- **CWE-312 Prevention**: Verschlüsselte Token-Speicherung
- **CWE-400 Prevention**: Rate Limiting und Resource Management
- **Bandit-konform**: Alle Security-Tests bestanden

## Installation

1. Virtual Environment erstellen:
```bash
python -m venv venv
venv\\Scripts\\activate  # Windows
source venv/bin/activate  # Linux/Mac
```

2. Dependencies installieren:
```bash
pip install -r requirements.txt
```

3. Umgebungsvariablen konfigurieren:
```bash
cp .env.template .env
# .env mit deinen Spotify-Credentials bearbeiten
```

4. Konfiguration anpassen:
```bash
# config.json nach Bedarf bearbeiten
```

## Verwendung

```bash
# Service starten
python -m src.main

# Dashboard öffnen
http://localhost:5000
```

## Konfiguration

### config.json
- `check_interval_seconds`: Überwachungsintervall (Standard: 5s)
- `minimum_play_duration_seconds`: Mindestabspielzeit (Standard: 30s)
- `playlist.name`: Name der Auto-Playlist

### Umgebungsvariablen (.env)
- `SPOTIFY_CLIENT_ID`: Deine Spotify App Client ID
- `SPOTIFY_CLIENT_SECRET`: Deine Spotify App Client Secret
- `SPOTIFY_REDIRECT_URI`: OAuth Redirect URI

## Architektur

```
src/
├── config.py           # Sichere Konfigurationsverwaltung
├── spotify_auth.py     # OAuth2 Authentifizierung
├── playlist_manager.py # Playlist-Operations
├── monitoring_service.py # Kontinuierliche Überwachung
├── statistics.py       # Datensammlung und -analyse
└── dashboard.py        # Flask Web-Interface
```

## Security Standards

Dieses Projekt folgt:
- OpenSSF Secure Coding Guidelines
- OWASP Developer Guide
- CWE Common Weakness Enumeration
- Bandit Security Linter

## Lizenz

MIT License