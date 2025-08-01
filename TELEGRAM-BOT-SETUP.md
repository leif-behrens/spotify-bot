# 🤖 Secure Telegram Command Bot Setup

## 🛡️ Security-First Telegram Bot für Remote Management

Dieses Setup ermöglicht sichere Remote-Verwaltung deines Spotify Bots über Telegram mit DevSecOps-konformen Sicherheitsmaßnahmen.

## 🔒 Sicherheitsfeatures

- **CWE-287**: Starke Benutzer-Authentifizierung mit Whitelist
- **CWE-20**: Umfassende Input-Validierung für alle Commands
- **CWE-78**: Command Injection Prevention via Allowlist
- **CWE-400**: Rate Limiting pro Benutzer (20 Commands/Stunde)
- **CWE-532**: Sichere Protokollierung ohne Credential-Exposure
- **Bandit B322**: Input-Validierung mit Regex
- **Bandit B607**: Sichere Command-Ausführung ohne Shell

## 📋 Voraussetzungen

1. **Telegram Bot Token** (von @BotFather)
2. **Telegram Chat ID** (deine User-ID)
3. **Admin User IDs** (autorisierte Benutzer)

## 🚀 1. Telegram Bot erstellen

### Schritt 1: Bot bei @BotFather erstellen
```
1. Öffne Telegram und suche @BotFather
2. Sende: /start
3. Sende: /newbot
4. Wähle einen Bot-Namen (z.B. "MySpotifyBot")
5. Wähle einen Username (z.B. "my_spotify_bot")
6. Kopiere das Bot Token (Format: XXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX)
```

### Schritt 2: Chat ID ermitteln
```bash
# Sende eine Nachricht an deinen Bot, dann:
curl "https://api.telegram.org/bot<BOT_TOKEN>/getUpdates"

# Suche in der Antwort nach:
# "chat":{"id":XXXXXXXXX,"first_name":"Your Name","type":"private"}
# Die Zahl ist deine Chat ID
```

### Schritt 3: Admin User IDs ermitteln
```bash
# Für jeden autorisierten Benutzer:
# 1. Benutzer sendet Nachricht an Bot
# 2. Führe getUpdates aus
# 3. Notiere "from":{"id":XXXXXXXXX} - das ist die User ID
```

## 🔧 2. Sichere Konfiguration

### Environment Variables (.env)
```bash
# Bearbeite deine .env Datei:
nano .env

# Füge diese Werte hinzu (NIEMALS ins GitHub repo!):
TELEGRAM_BOT_TOKEN=YOUR_BOT_TOKEN_FROM_BOTFATHER
TELEGRAM_CHAT_ID=YOUR_TELEGRAM_CHAT_ID
TELEGRAM_ADMIN_USERS=YOUR_USER_ID_1,YOUR_USER_ID_2
TELEGRAM_WEBHOOK_SECRET=your_random_secret_here_min_32_chars
```

### Config.json Einstellungen
```json
{
  "telegram_notifications": {
    "enabled": true,
    "command_bot_enabled": true,
    "max_commands_per_hour": 20,
    "command_timeout_seconds": 30
  }
}
```

## 🔐 3. Sicherheitskonfiguration

### Admin-Benutzer konfigurieren
```bash
# Nur diese User IDs können Commands ausführen:
export TELEGRAM_ADMIN_USERS="YOUR_USER_ID_1,YOUR_USER_ID_2"

# Pro-Tipp: Nutze Telegram-Gruppen für Team-Management
# Gruppenmitglieder können dann alle Commands ausführen
```

### Rate Limiting anpassen
```json
{
  "telegram_notifications": {
    "max_commands_per_hour": 10,  // Weniger für höhere Sicherheit
    "command_timeout_seconds": 15  // Kürzer für bessere Performance
  }
}
```

## 🎮 4. Bot starten und testen

### Test-Konfiguration
```bash
# Teste Bot-Konfiguration:
python main.py test-telegram-bot

# Erwartete Ausgabe:
# ✅ Telegram Command Bot configuration is valid
# ✅ Test message sent successfully
```

### Bot als Service starten
```bash
# Als Background-Service:
python main.py start telegram-bot

# Im Vordergrund (für Debugging):
python main.py telegram-bot
```

### Verfügbare Commands testen
```
# In Telegram an deinen Bot senden:
/help           # Zeigt alle verfügbaren Commands
/status         # Status aller Services
/status discovery # Status des Discovery Service
/start discovery  # Discovery Service starten
/stop discovery   # Discovery Service stoppen
/restart discovery # Discovery Service neustarten
/auth           # OAuth-Status prüfen
/cleanup        # Orphaned Processes aufräumen
```

## 🚨 5. Systemd Service Setup (Raspberry Pi)

### Service-Datei erstellen
```bash
sudo nano /etc/systemd/system/spotify-bot-telegram.service
```

```ini
[Unit]
Description=Spotify Bot Telegram Command Bot
After=network.target
Requires=network.target

[Service]
Type=simple
User=pi
WorkingDirectory=/opt/spotify-bot
Environment=PATH=/opt/spotify-bot/venv/bin
ExecStart=/opt/spotify-bot/venv/bin/python main.py telegram-bot
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/opt/spotify-bot/logs /opt/spotify-bot/data

[Install]
WantedBy=multi-user.target
```

### Service aktivieren
```bash
sudo systemctl daemon-reload
sudo systemctl enable spotify-bot-telegram
sudo systemctl start spotify-bot-telegram

# Status prüfen:
sudo systemctl status spotify-bot-telegram
sudo journalctl -u spotify-bot-telegram -f
```

## 📊 6. Monitoring und Logs

### Log-Dateien überwachen
```bash
# Telegram Bot Logs:
tail -f /opt/spotify-bot/logs/telegram_bot.log

# Alle Bot-Aktivitäten:
grep "telegram_bot" /opt/spotify-bot/logs/*.log
```

### Command-Ausführung überwachen
```bash
# Sicherheits-Audit der Commands:
grep "Executing command" /opt/spotify-bot/logs/telegram_bot.log
grep "Unauthorized" /opt/spotify-bot/logs/telegram_bot.log
grep "Rate limit" /opt/spotify-bot/logs/telegram_bot.log
```

## 🛡️ 7. Sicherheits-Best Practices

### Regelmäßige Sicherheitschecks
```bash
# 1. Admin-User regelmäßig überprüfen
echo $TELEGRAM_ADMIN_USERS

# 2. Rate-Limiting-Logs prüfen
grep "Rate limit exceeded" logs/telegram_bot.log

# 3. Unauthorized-Access-Versuche prüfen
grep "Unauthorized command attempt" logs/telegram_bot.log

# 4. Token-Gültigkeit testen
python main.py test-telegram-bot
```

### Incident Response
```bash
# Bei verdächtiger Aktivität:
# 1. Bot sofort stoppen
python main.py stop telegram-bot

# 2. Logs analysieren
grep -i "suspicious\|unauthorized\|attack" logs/telegram_bot.log

# 3. Admin-User überprüfen und ggf. entfernen
# 4. Bot Token regenerieren bei Kompromittierung
```

## 🔄 8. Updates und Wartung

### Bot-Updates
```bash
# Code-Updates:
git pull origin main
pip install -r requirements.txt

# Service neustarten:
sudo systemctl restart spotify-bot-telegram
```

### Backup wichtiger Daten
```bash
# .env Backup (sicher speichern!):
cp .env .env.backup.$(date +%Y%m%d)

# Config Backup:
cp config/config.json config/config.backup.$(date +%Y%m%d).json
```

## 🆘 9. Troubleshooting

### Bot antwortet nicht
```bash
# 1. Service-Status prüfen:
sudo systemctl status spotify-bot-telegram

# 2. Logs prüfen:
tail -50 logs/telegram_bot.log

# 3. Konfiguration testen:
python main.py test-telegram-bot

# 4. Bot Token prüfen:
curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getMe"
```

### Unauthorized-Fehler
```bash
# 1. User ID prüfen:
echo $TELEGRAM_ADMIN_USERS

# 2. User ID in Telegram ermitteln:
curl "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/getUpdates"

# 3. .env aktualisieren und Service neustarten
```

### Rate Limiting zu streng
```bash
# Config anpassen:
nano config/config.json
# "max_commands_per_hour": 30

# Service neustarten:
sudo systemctl restart spotify-bot-telegram
```

## 📚 10. Verfügbare Commands

| Command | Parameter | Beschreibung | Beispiel |
|---------|-----------|--------------|----------|
| `/help` | - | Zeigt alle Commands | `/help` |
| `/status` | [service] | Service-Status anzeigen | `/status discovery` |
| `/start` | service | Service starten | `/start discovery` |
| `/stop` | service | Service stoppen | `/stop watchdog` |
| `/restart` | service | Service neustarten | `/restart callback` |
| `/auth` | - | OAuth-Status prüfen | `/auth` |
| `/cleanup` | - | Processes aufräumen | `/cleanup` |

**Verfügbare Services**: `discovery`, `callback`, `watchdog`

## ⚠️ Wichtige Sicherheitshinweise

1. **Niemals** Bot Token oder Admin User IDs in Git committen
2. **Regelmäßig** Logs auf verdächtige Aktivitäten prüfen
3. **Rate Limits** nicht zu hoch setzen (DoS-Schutz)
4. **Admin Users** nur bei vertrauenswürdigen Personen
5. **Webhook Secret** für zusätzliche Sicherheit nutzen
6. **Bot Token** bei Verdacht sofort regenerieren

---

**🚀 Entwickelt mit DevSecOps Best Practices | 🛡️ Security-First Approach | 🤖 Production-Ready**
