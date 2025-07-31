# 🚀 Spotify Bot - CI/CD Deployment Guide

Dieser Guide erklärt das automatische Deployment des Spotify Bots auf deinen Raspberry Pi mit GitHub Actions.

## 📋 Übersicht

Das Deployment-System bietet:
- **Automatisches Deployment** bei Git-Push auf `main`/`master`
- **Sichere SSH-basierte Übertragung** mit rsync
- **Systemd-Service** für automatischen Start/Neustart
- **Security-Checks** mit Bandit und Safety
- **Rollback-Funktionalität** bei Fehlern
- **Produktions-Konfiguration** mit Secrets-Management

## 🛠️ Ersteinrichtung

### 1. SSH-Zugang zum Raspberry Pi einrichten

```bash
# SSH-Key generieren (falls noch nicht vorhanden)
ssh-keygen -t ed25519 -C "deployment@spotify-bot"

# SSH-Key auf Raspberry Pi kopieren
ssh-copy-id pi@your-raspberry-pi.local

# Verbindung testen
ssh pi@your-raspberry-pi.local
```

### 2. GitHub Repository einrichten

1. **Repository auf GitHub erstellen/pushen:**
```bash
git remote add origin https://github.com/yourusername/spotify-bot.git
git branch -M main
git push -u origin main
```

2. **GitHub Secrets konfigurieren:**

   Gehe zu: `Settings` → `Secrets and variables` → `Actions`

   **Erforderliche Secrets:**
   ```
   DEPLOY_HOST          = your-raspberry-pi.local (oder IP-Adresse)
   DEPLOY_SSH_KEY       = Private SSH-Key für Deployment
   SMTP_PASSWORD        = Gmail App-Passwort für E-Mail-Benachrichtigungen
   SENDER_EMAIL         = Gmail-Adresse für Benachrichtigungen
   RECIPIENT_EMAIL      = E-Mail-Adresse für Alerts
   APP_URL              = http://your-raspberry-pi.local:4444 (optional)
   ```

### 3. Raspberry Pi vorbereiten

```bash
# SSH zum Raspberry Pi
ssh pi@your-raspberry-pi.local

# System aktualisieren
sudo apt update && sudo apt upgrade -y

# Python 3.11 installieren (falls nicht vorhanden)
sudo apt install python3.11 python3.11-venv python3-pip -y

# Systemd-Service-Verzeichnis vorbereiten
sudo mkdir -p /opt/spotify-bot
sudo chown pi:pi /opt/spotify-bot
```

## 🚀 Deployment-Prozess

### Automatisches Deployment

Das Deployment startet automatisch bei:
- **Push auf `main`/`master` Branch**
- **Merged Pull Request**
- **Manueller Trigger** über GitHub Actions UI

### Manuelles Deployment

```bash
# Lokal deployen (für Tests)
chmod +x deploy/deploy.sh
DEPLOY_HOST=your-raspberry-pi.local ./deploy/deploy.sh
```

### Deployment-Schritte im Detail

1. **Security & Quality Checks**
   - Bandit Security Scanner
   - Safety Vulnerability Check
   - Code Style (flake8)
   - Type Checking (mypy)

2. **Build & Test**
   - Virtual Environment erstellen
   - Dependencies installieren
   - Konfiguration testen
   - Logging-System testen

3. **Deploy**
   - SSH-Verbindung testen
   - Dateien mit rsync synchronisieren
   - Python-Environment aktualisieren
   - Systemd-Service installieren/aktualisieren
   - Produktions-Konfiguration deployen
   - Service neu starten

4. **Verify**
   - Service-Status prüfen
   - Logs auf Fehler überprüfen
   - Deployment-Summary erstellen

## 🔧 Service-Management auf dem Raspberry Pi

```bash
# Service-Status prüfen
sudo systemctl status spotify-bot

# Service starten/stoppen/neustarten
sudo systemctl start spotify-bot
sudo systemctl stop spotify-bot
sudo systemctl restart spotify-bot

# Logs anzeigen
sudo journalctl -u spotify-bot -f          # Live-Logs
sudo journalctl -u spotify-bot --since=today  # Heutige Logs

# Application-Logs
tail -f /opt/spotify-bot/logs/*.log
```

## 📝 Konfiguration

### Produktions-Konfiguration

Die Produktions-Konfiguration wird automatisch erstellt und unterscheidet sich von der Entwicklungs-Config:

- **Debug-Modus**: Deaktiviert
- **Log-Level**: INFO statt DEBUG
- **Console-Logging**: Deaktiviert (nur File-Logging)
- **E-Mail-Credentials**: Aus GitHub Secrets geladen

### Environment-spezifische Konfiguration

```bash
# Manuelle Konfiguration bearbeiten
ssh pi@your-raspberry-pi.local
sudo nano /opt/spotify-bot/config/config.production.json
sudo systemctl restart spotify-bot
```

## 🔒 Sicherheits-Features

### Systemd-Service Security

- **NoNewPrivileges**: Verhindert Privilege-Escalation
- **PrivateTmp**: Isoliertes temporäres Verzeichnis
- **ProtectSystem**: Schreibschutz für System-Verzeichnisse
- **ProtectHome**: Schutz vor Home-Directory-Zugriff
- **CapabilityBoundingSet**: Minimale Capabilities

### File-Permissions

```
/opt/spotify-bot/           750 (pi:pi)
├── config/                 644 (pi:pi)
├── data/                   700 (pi:pi)
├── logs/                   755 (pi:pi)
├── src/                    644 (pi:pi)
└── venv/                   750 (pi:pi)
```

### SSH-Security

- **Key-based Authentication**: Keine Passwort-Authentifizierung
- **Host Key Verification**: Automatische known_hosts-Verwaltung
- **Connection Timeout**: 10 Sekunden Timeout

## 🔄 Rollback

Bei Deployment-Fehlern erfolgt automatisch ein Rollback:

```bash
# Manueller Rollback (falls nötig)
ssh pi@your-raspberry-pi.local
cd /opt
sudo systemctl stop spotify-bot
sudo rm -rf spotify-bot
sudo mv spotify-bot.backup spotify-bot
sudo systemctl start spotify-bot
```

## 📊 Monitoring & Debugging

### Deployment-Status überwachen

- **GitHub Actions**: Deployment-Status in der Actions-Tab
- **Service-Status**: `systemctl status spotify-bot`
- **Application-Logs**: Service-spezifische Logs in `/opt/spotify-bot/logs/`

### Häufige Probleme

1. **SSH-Verbindung fehlgeschlagen**
   ```
   Lösung: SSH-Key in GitHub Secrets überprüfen
   Test: ssh pi@your-raspberry-pi.local
   ```

2. **Service startet nicht**
   ```
   Debug: sudo journalctl -u spotify-bot --no-pager -l
   Lösung: Konfiguration prüfen, Python-Dependencies überprüfen
   ```

3. **E-Mail-Benachrichtigungen funktionieren nicht**
   ```
   Debug: tail -f /opt/spotify-bot/logs/email_notifier.log
   Lösung: Gmail App-Passwort überprüfen, SMTP-Konfiguration validieren
   ```

## 🎯 Nächste Schritte

Nach dem ersten Deployment:

1. **Spotify-Authentifizierung einrichten:**
   ```bash
   ssh pi@your-raspberry-pi.local
   cd /opt/spotify-bot
   ./venv/bin/python main.py auth
   ```

2. **Services starten:**
   ```bash
   ./venv/bin/python main.py service start discovery
   ./venv/bin/python main.py service start callback
   ./venv/bin/python main.py service start watchdog
   ```

3. **Monitoring einrichten:**
   - Log-Rotation überwachen
   - E-Mail-Alerts testen
   - Service-Gesundheit überwachen

## 🆘 Support

Bei Problemen:
1. **GitHub Actions Logs** überprüfen
2. **Service-Logs** auf dem Raspberry Pi analysieren
3. **SSH-Verbindung** und **Permissions** überprüfen
4. **Produktions-Konfiguration** validieren

---

**🎉 Viel Erfolg mit dem automatischen Deployment!**
