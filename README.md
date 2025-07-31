# Spotify Auto-Discovery Bot - Microservices Edition

Ein sicherer Spotify Bot, der automatisch Songs zu einer Playlist hinzufügt, basierend auf Ihrem Hörverhalten. Implementiert als Microservices-Architektur mit Security-First Ansatz.

## 🚀 Features

- **Automatische Song-Erkennung**: Überwacht Spotify-Wiedergabe und fügt Songs automatisch zu einer Playlist hinzu
- **Sichere Authentifizierung**: OAuth2-basierte Spotify-Authentifizierung mit verschlüsselter Token-Speicherung
- **Microservices-Architektur**: Separate Services für verschiedene Funktionen
- **Web Dashboard**: Benutzerfreundliches Interface zur Service-Verwaltung
- **Security-First**: Implementiert nach OWASP und OpenSSF Security Standards

## 🏗️ Architektur

### Services

1. **Callback Service** (`services/callback/`)
   - Port: 4444
   - Handles Spotify OAuth callbacks
   - Provides authentication tokens

2. **Discovery Service** (`services/discovery/`)
   - Monitors Spotify playback
   - Adds tracks to target playlist
   - Requires authentication

3. **Dashboard** (`dashboard.py`)
   - Port: 5000
   - Web-based service management
   - Real-time status monitoring

## 📋 Voraussetzungen

- Python 3.8+
- Spotify Developer Account
- Spotify Premium Account (für Playbook-Monitoring)

## ⚙️ Installation & Setup

### 1. Repository klonen und Dependencies installieren

```bash
git clone <repository-url>
cd spotify-bot
pip install -r requirements.txt
```

### 2. Spotify App erstellen

1. Gehen Sie zu [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
2. Erstellen Sie eine neue App
3. Notieren Sie sich Client ID und Client Secret
4. Fügen Sie `http://127.0.0.1:4444/callback` als Redirect URI hinzu

### 3. Environment Variables konfigurieren

Bearbeiten Sie `.env`:

```env
# Spotify API Credentials
SPOTIFY_CLIENT_ID=your_client_id_here
SPOTIFY_CLIENT_SECRET=your_client_secret_here
SPOTIFY_REDIRECT_URI=http://127.0.0.1:4444/callback

# Flask Configuration
FLASK_SECRET_KEY=your_secure_secret_key_here
FLASK_HOST=127.0.0.1
FLASK_PORT=5000
FLASK_DEBUG=False
```

## 🚀 Schnellstart

### Process-basierte Mikroservice-Architektur (Neu!)

**Services als eigenständige Prozesse - unabhängig vom Dashboard:**

```bash
# 1. Service-Daemon starten (läuft dauerhaft)
python service_controller.py start discovery

# 2. Dashboard starten (nur UI - optional)
python dashboard_app.py

# Dashboard öffnen: http://localhost:5000
```

**Service-Management per CLI:**
```bash
python service_controller.py list      # Services auflisten
python service_controller.py start discovery  # Service starten
python service_controller.py stop discovery   # Service stoppen
python service_controller.py status discovery # Service-Status
```

### In-Process Architektur (Legacy)

```bash
# Alle Services in einem Prozess (alte Architektur)
python app.py
```

### Alte Monolith-Anwendung (deprecated)

```bash
# Fallback zur ursprünglichen Anwendung
python -m src.main
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

## 🏗️ Mikroservice-Architektur Evolution

### 🆕 **Process-basierte Architektur (Empfohlen)**
```
📁 Echte Mikroservices - Services als separate Prozesse
├── service_controller.py     # CLI für Service-Management
├── dashboard_app.py          # Dashboard-Only Application
├── ipc/                      # Inter-Process Communication
│   ├── communication.py      # IPC Protocol (TCP Sockets)
│   └── service_registry.json # Persistent Service State
├── services/
│   └── discovery/
│       ├── service.py        # Service-Logik
│       └── daemon.py         # Service als Daemon-Prozess
└── dashboard/templates/      # Dashboard UI

Vorteile:
✅ Services laufen unabhängig vom Dashboard
✅ Dashboard-Crash stoppt keine Services
✅ Services können remote verwaltet werden
✅ Bessere Skalierbarkeit und Isolation
```

### 📦 **In-Process Architektur (Legacy)**
```
📁 Services in einem Prozess (Alte Architektur)
├── app.py                    # Hauptanwendung
├── core/                     # Kern-Framework
│   ├── service_base.py       # Basis-Klasse für Services
│   └── service_manager.py    # Service Registry & Manager
└── dashboard/                # Management-Dashboard
    ├── service_control.py    # Dashboard-Controller
    └── templates/            # HTML-Templates
```

### 🗂️ **Monolith (Deprecated)**
```
📁 Original Single-Application
└── src/                      # Alte Monolith-Architektur
    ├── main.py               # Ursprüngliche Anwendung
    ├── dashboard.py          # Altes Dashboard
    └── ...                   # Legacy-Code
```

## 🔒 Security Standards

Diese Mikroservice-Plattform implementiert:
- **OpenSSF Secure Coding Guidelines**: Sichere Entwicklungspraktiken
- **OWASP Developer Guide**: Web-Security Best Practices
- **CWE Common Weakness Enumeration**: Schwachstellen-Prävention
- **Bandit Security Linter**: Automatisierte Sicherheitstests
- **DevSecOps Integration**: CI/CD Pipeline mit Security Scanning

### Neue Security Features in der Mikroservice-Architektur
- **Service Isolation**: Jeder Service läuft isoliert mit eigener Fehlerbehandlung
- **Centralized Logging**: Sichere, strukturierte Logs ohne sensible Daten
- **Health Monitoring**: Automatische Überwachung und Restart bei Fehlern
- **Input Sanitization**: Umfassende Validierung aller Service-Parameter

## Lizenz

MIT License
