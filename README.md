# 🎵 Spotify Auto-Discovery Bot

Ein sicherer DevSecOps-kompatibler Spotify Bot, der automatisch Songs zu einer Playlist hinzufügt basierend auf deinem Hörverhalten. Entwickelt mit Security-First Ansatz und modernen CI/CD Praktiken.

## ✨ Features

- 🎯 **Automatische Song-Erkennung**: Überwacht Spotify-Wiedergabe und fügt Songs automatisch zu einer Playlist hinzu
- 🔒 **DevSecOps Pipeline**: Vollständige CI/CD mit Sicherheitsscans (Bandit, Safety, CodeQL)
- 🛡️ **Security-First**: OpenSSF-konform mit CWE-Präventionsmaßnahmen
- 🤖 **Service-Architektur**: Discovery, Callback und Watchdog Services
- 📱 **Headless-Ready**: Funktioniert auf Raspberry Pi ohne Desktop
- 🔄 **Auto-Recovery**: Watchdog überwacht Services und startet sie bei Bedarf neu
- 📧 **Email-Benachrichtigungen**: Optional für Service-Ausfälle
- 📊 **Konfigurierbare Logs**: Service-spezifisches Logging mit verschiedenen Levels

## 🏗️ Architektur

### Services
- **Discovery Service**: Überwacht Spotify-Wiedergabe und fügt Tracks zur Playlist hinzu
- **Callback Service**: Behandelt Spotify OAuth-Callbacks  
- **Watchdog Service**: Überwacht andere Services und startet sie bei Ausfällen neu

### Security Features
- 🔐 OAuth2-basierte Spotify-Authentifizierung mit verschlüsselter Token-Speicherung
- 🛡️ CWE-20 Input Validation, CWE-22 Path Traversal Prevention
- 🔒 CWE-532 Information Exposure Prevention in Logs
- 🚫 CWE-798 Hard-coded Credentials Prevention
- 📋 Bandit, Safety, CodeQL Security Scanning

## 📋 Voraussetzungen

- **Python 3.11+**
- **Spotify Developer Account** (kostenlos)
- **Spotify Premium Account** (für Playback-Monitoring)
- **Raspberry Pi** (empfohlen) oder Linux/Windows/macOS

## ⚙️ Spotify App Setup

1. Gehe zu [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
2. Erstelle eine neue App
3. Notiere dir **Client ID** und **Client Secret**
4. Füge diese **Redirect URI** hinzu: `http://localhost:4444/callback`

## 🚀 Installation

### Option 1: Raspberry Pi Deployment (Empfohlen)

```bash
# 1. Repository klonen
git clone https://github.com/YOUR-USERNAME/spotify-bot.git
cd spotify-bot

# 2. Lokales Deployment ausführen
chmod +x deploy/local-deploy.sh
sudo ./deploy/local-deploy.sh
```

Das Deployment-Script:
- ✅ Erstellt `/opt/spotify-bot/` mit sicheren Berechtigungen
- ✅ Richtet Python Virtual Environment ein
- ✅ Installiert alle Dependencies
- ✅ Erstellt systemd Service für automatischen Start
- ✅ Erstellt `.env` Template für Credentials

### Option 2: Manuelle Installation

```bash
# Repository klonen und Dependencies installieren
git clone https://github.com/YOUR-USERNAME/spotify-bot.git
cd spotify-bot
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows
pip install -r requirements.txt
```

## 🔧 Konfiguration

### 1. Environment Variables (.env)
```bash
# Nach Deployment bearbeiten:
sudo nano /opt/spotify-bot/.env

# Oder bei manueller Installation:
cp .env.template .env
nano .env
```

```env
# Spotify API Credentials (Erforderlich)
SPOTIFY_CLIENT_ID=deine_client_id_hier
SPOTIFY_CLIENT_SECRET=dein_client_secret_hier  
SPOTIFY_REDIRECT_URI=http://localhost:4444/callback

# Email Benachrichtigungen (Optional)
SENDER_EMAIL=deine_email@gmail.com
SENDER_PASSWORD=dein_app_passwort_hier
RECIPIENT_EMAIL=benachrichtigung@gmail.com
```

### 2. Config.json Anpassungen (Optional)
```bash
sudo nano /opt/spotify-bot/config/config.json
```

Wichtige Einstellungen:
- `monitoring.check_interval_seconds`: Überwachungsintervall (Standard: 5s)
- `monitoring.minimum_play_duration_seconds`: Mindestspielzeit (Standard: 30s)
- `playlist.name`: Name der Auto-Playlist
- `logging.services`: Log-Level pro Service

## 🎵 Spotify Autorisierung

### Headless (Raspberry Pi)
```bash
cd /opt/spotify-bot
sudo -u $USER ./venv/bin/python main.py auth
```

Bei headless Systemen:
1. **URL kopieren** und in Browser auf Computer/Handy öffnen
2. **Spotify autorisieren**
3. **Komplette Redirect-URL** zurück ins Terminal kopieren
4. ✅ **Automatische Token-Extraktion**

### Mit Desktop
Der Browser öffnet sich automatisch zur Autorisierung.

## 🎮 Service Management

### Systemd Services (Nach Deployment)
```bash
# Service Status prüfen
sudo systemctl status spotify-bot

# Service steuern
sudo systemctl start spotify-bot
sudo systemctl stop spotify-bot
sudo systemctl restart spotify-bot

# Logs ansehen
sudo journalctl -u spotify-bot -f
tail -f /opt/spotify-bot/logs/*.log
```

### Manuelle Steuerung
```bash
cd /opt/spotify-bot  # oder dein Projekt-Ordner

# Services einzeln starten
./venv/bin/python main.py start discovery
./venv/bin/python main.py start callback  
./venv/bin/python main.py start watchdog

# Status prüfen
./venv/bin/python main.py status

# Services stoppen
./venv/bin/python main.py stop discovery
./venv/bin/python main.py stop callback
./venv/bin/python main.py stop watchdog
```

## 🔄 Updates

### Automatisches Update (Raspberry Pi)
```bash
cd ~/spotify-bot
git pull origin main
sudo ./deploy/local-deploy.sh  # Führt automatisches Update durch
```

### Manuelles Update
```bash
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
# Services neustarten
```

## 🛡️ DevSecOps Pipeline

Bei jedem Git Push werden automatisch ausgeführt:

### 🔒 Security & Quality Phase
- **Bandit**: Python Security Scanner
- **Safety**: Dependency Vulnerability Scanner  
- **Flake8**: Code Style & Quality
- **MyPy**: Type Checking

### 🔨 Build & Test Phase
- **Configuration Loading**: Validierung aller Configs
- **Service Import Tests**: Überprüfung aller Module
- **Virtual Environment**: Build-Test

### 🚀 Deployment Phase
- **Lokale Netzwerke**: Deployment wird übersprungen (wie bei deinem Pi)
- **Public Hosts**: Automatisches Deployment via SSH (falls konfiguriert)

## 📁 Projekt-Struktur

```
spotify-bot/
├── 🚀 main.py                     # Haupt-CLI Interface
├── 📊 config/
│   ├── config.json               # Haupt-Konfiguration
│   └── config.production.json    # Produktions-Config
├── 🔧 src/
│   ├── auth/                     # OAuth & Token Management
│   ├── services/                 # Discovery, Callback, Watchdog
│   ├── core/                     # Config & Base Classes
│   └── utils/                    # Logging, Email, Helpers
├── 🚀 deploy/
│   ├── local-deploy.sh          # Raspberry Pi Deployment
│   └── deploy.sh                # Remote SSH Deployment
├── 🔒 .github/workflows/
│   ├── devsecops.yml           # Haupt CI/CD Pipeline
│   └── codeql-analysis.yml     # Security Code Analysis
└── 📋 requirements.txt
```

## 🆘 Troubleshooting

### Service startet nicht
```bash
# Detaillierte Logs ansehen
sudo journalctl -u spotify-bot --no-pager -l

# Konfiguration testen
cd /opt/spotify-bot
./venv/bin/python -c "from src.core.config import ConfigManager; ConfigManager()"
```

### OAuth-Probleme
```bash
# Token-Status prüfen
./venv/bin/python -c "
from src.auth.oauth_manager import SpotifyOAuthManager
oauth = SpotifyOAuthManager()
print('Valid token:', oauth._has_valid_token())
"

# Neue Autorisierung erzwingen
./venv/bin/python main.py auth
```

### Port bereits belegt
```bash
sudo lsof -i :4444
sudo pkill -f "python.*main.py"
```

### Permission-Fehler
```bash
sudo chown -R $USER:$USER /opt/spotify-bot
```

## 🎯 Nächste Schritte nach Installation

1. **✅ Spotify Credentials konfigurieren** (`.env` bearbeiten)
2. **🔐 OAuth Autorisierung durchführen** (`main.py auth`)
3. **▶️ Services starten** (automatisch via systemd oder manuell)
4. **🎵 Spotify abspielen** und beobachten wie Songs automatisch hinzugefügt werden!

## 🔗 Links

- [Spotify Developer Dashboard](https://developer.spotify.com/dashboard)
- [OpenSSF Secure Coding Guidelines](https://github.com/ossf/wg-best-practices-os-developers)
- [OWASP Developer Guide](https://owasp.org/www-project-developer-guide/)

## 📄 Lizenz

MIT License - Siehe [LICENSE](LICENSE) für Details.

---

**🚀 Entwickelt mit DevSecOps Best Practices | 🛡️ Security-First Approach | 🤖 CI/CD Ready**