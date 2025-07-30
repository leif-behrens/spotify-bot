# 🚀 Deployment auf Raspberry Pi 4 mit Docker Compose

## 📋 Voraussetzungen

### Hardware
- **Raspberry Pi 4** (mindestens 2GB RAM empfohlen)
- **SD-Karte** (mindestens 32GB, Class 10)
- **Internetverbindung**

### Software
- **Raspberry Pi OS** (64-bit empfohlen)
- **Docker** und **Docker Compose**

## 🔧 Setup-Anleitung

### 1. Raspberry Pi vorbereiten

```bash
# System aktualisieren
sudo apt update && sudo apt upgrade -y

# Docker installieren
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Docker Compose installieren
sudo apt install -y docker-compose

# Neustart für Gruppen-Änderungen
sudo reboot
```

### 2. Projekt auf Raspberry Pi übertragen

**Option A: Git Clone**
```bash
git clone <your-repo-url> spotify-bot
cd spotify-bot
```

**Option B: Dateien kopieren**
```bash
# Erstelle Projektverzeichnis
mkdir -p ~/spotify-bot
cd ~/spotify-bot

# Kopiere alle Projektdateien hierher
# (via scp, rsync oder USB-Stick)
```

### 3. Environment-Variablen konfigurieren

```bash
# Kopiere Template
cp .env.docker .env

# Bearbeite Konfiguration
nano .env
```

**Wichtige Änderungen in `.env`:**
```bash
# Ihre echten Spotify Credentials
SPOTIFY_CLIENT_ID=ihr_echter_client_id
SPOTIFY_CLIENT_SECRET=ihr_echter_client_secret

# Generieren Sie einen sicheren Secret Key
FLASK_SECRET_KEY=$(openssl rand -hex 32)

# IP-Adresse Ihres Raspberry Pi
RASPBERRY_PI_IP=192.168.1.XXX
```

### 4. Spotify App konfigurieren

Gehen Sie zu https://developer.spotify.com/dashboard und:

1. **Öffnen Sie Ihre App**: "Automated_Playlist"
2. **Bearbeiten Sie Settings**
3. **Fügen Sie Redirect URI hinzu**:
   ```
   https://IHR_RASPBERRY_PI_IP:443/callback
   ```
   Beispiel: `https://192.168.1.100:443/callback`

### 5. Docker Compose starten

```bash
# Container builden und starten
docker-compose up --build -d

# Logs anzeigen
docker-compose logs -f

# Status prüfen
docker-compose ps
```

## 🌐 Zugriff auf die Anwendung

### HTTPS (Empfohlen)
```
https://IHR_RASPBERRY_PI_IP
```

### HTTP (wird zu HTTPS umgeleitet)
```
http://IHR_RASPBERRY_PI_IP
```

### Lokaler Zugriff auf dem Pi
```
https://localhost
```

## 🔒 SSL-Zertifikat

Das System generiert automatisch ein **self-signed SSL-Zertifikat**.

**Browser-Warnung:**
- Ihr Browser wird eine Sicherheitswarnung anzeigen
- Klicken Sie auf "Erweitert" → "Trotzdem fortfahren"
- Dies ist sicher für private Nutzung

## 📊 Monitoring und Logs

### Container-Status prüfen
```bash
docker-compose ps
docker-compose logs spotify-bot
docker-compose logs nginx
```

### Anwendungs-Logs
```bash
# Live-Logs anzeigen
docker-compose logs -f spotify-bot

# Logs der letzten 100 Zeilen
docker-compose logs --tail 100 spotify-bot
```

### Health Checks
```bash
# Container-Gesundheit prüfen
docker ps --format "table {{.Names}}\t{{.Status}}"

# API-Status prüfen
curl -k https://localhost/api/status
```

## 🔄 Wartung

### Container neu starten
```bash
docker-compose restart
```

### Updates anwenden
```bash
# Code-Änderungen
docker-compose down
git pull  # oder Dateien aktualisieren
docker-compose up --build -d

# Nur Container neu starten
docker-compose restart
```

### Daten sichern
```bash
# Datenbank und Logs sichern
docker run --rm -v spotify-bot_spotify_data:/data -v $(pwd):/backup alpine tar czf /backup/spotify-data-backup.tar.gz /data
docker run --rm -v spotify-bot_spotify_logs:/logs -v $(pwd):/backup alpine tar czf /backup/spotify-logs-backup.tar.gz /logs
```

## 🐛 Troubleshooting

### Container startet nicht
```bash
# Detaillierte Logs
docker-compose logs

# Container-Status
docker-compose ps

# Einzelnen Service neu starten
docker-compose restart spotify-bot
```

### SSL-Probleme
```bash
# SSL-Zertifikat neu generieren
docker-compose down
docker volume rm spotify-bot_ssl_certs
docker-compose up -d
```

### Spotify-Authentifizierung fehlschlägt
1. Prüfen Sie die Redirect URI in der Spotify App
2. Stellen Sie sicher, dass HTTPS verwendet wird
3. Prüfen Sie die Environment-Variablen

### Performance-Probleme
```bash
# Ressourcenverbrauch prüfen
docker stats

# Container-Ressourcen begrenzen (in docker-compose.yml)
services:
  spotify-bot:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '1.0'
```

## 🔧 Konfiguration anpassen

### Port ändern
Bearbeiten Sie `docker-compose.yml`:
```yaml
services:
  nginx:
    ports:
      - "8080:80"    # HTTP auf Port 8080
      - "8443:443"   # HTTPS auf Port 8443
```

### Überwachungsintervall ändern
Bearbeiten Sie `config.json`:
```json
{
  "monitoring": {
    "check_interval_seconds": 10,
    "minimum_play_duration_seconds": 45
  }
}
```

## 📱 Remote-Zugriff

### Port-Forwarding im Router
1. Router-Webinterface öffnen
2. Port-Forwarding konfigurieren:
   - Port 443 (HTTPS) → Raspberry Pi IP:443
   - Optional: Port 80 (HTTP) → Raspberry Pi IP:80

### DynDNS (Optional)
Für externen Zugriff mit dynamischer IP:
1. DynDNS-Service einrichten (z.B. No-IP, DuckDNS)
2. Spotify App Redirect URI aktualisieren

## 🔐 Sicherheitshinweise

### Für Produktionseinsatz
1. **Echtes SSL-Zertifikat** verwenden (Let's Encrypt)
2. **Firewall** konfigurieren
3. **Regelmäßige Updates** durchführen
4. **Starke Passwörter** verwenden
5. **Monitoring** einrichten

### Netzwerk-Sicherheit
```bash
# Firewall-Regeln (UFW)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

## 📞 Support

Bei Problemen:
1. Prüfen Sie die Logs: `docker-compose logs`
2. Überprüfen Sie die Konfiguration
3. Starten Sie die Container neu: `docker-compose restart`

## 🎯 Fertig!

Ihre Spotify Auto-Discovery Bot läuft jetzt sicher auf Ihrem Raspberry Pi mit:
- ✅ HTTPS-Verschlüsselung
- ✅ Automatischen Backups
- ✅ Health Monitoring
- ✅ Production-ready WSGI
- ✅ Nginx Reverse Proxy
