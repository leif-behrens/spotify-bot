# Spotify Mikroservice-Plattform

Eine sicherheitsorientierte Mikroservice-Architektur für Spotify-basierte Services mit zentralem Management-Dashboard.

## 🎵 Services

### Verfügbare Services
- **Discovery Service**: Automatische Musik-Entdeckung basierend auf Hörverhalten
- **Playlist Sync** *(Coming Soon)*: Playlist-Synchronisation zwischen Konten
- **Mood Analyzer** *(Coming Soon)*: Stimmungsanalyse der Musik
- **Recommendation Engine** *(Coming Soon)*: KI-basierte Musikempfehlungen

### Service Management Dashboard
- **Start/Stop/Restart**: Einfache Service-Steuerung per Klick
- **Real-time Monitoring**: Live-Status und Gesundheitsprüfung
- **Error Tracking**: Fehleranzahl und letzte Fehlermeldungen pro Service
- **Uptime Monitoring**: Laufzeit-Verfolgung für jeden Service

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
