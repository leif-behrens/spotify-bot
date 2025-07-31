# 🚀 Spotify Bot - Quick Start Deployment

**Deine App ist bereit für das Deployment!** Hier ist die **5-Minuten-Anleitung**:

## **⚡ Schnellstart (5 Schritte)**

### **1️⃣ Raspberry Pi IP herausfinden**
```bash
# Auf deinem Raspberry Pi oder via Router-Interface
hostname -I
# Oder: ip addr show | grep inet
# Notiere die IP: z.B. 192.168.1.100
```

### **2️⃣ GitHub Repository erstellen**
```bash
# In deinem Projekt-Verzeichnis
git remote add origin https://github.com/DEIN-USERNAME/spotify-bot.git
git push -u origin main
```

### **3️⃣ GitHub Secrets konfigurieren**
**GitHub Repository → Settings → Secrets and variables → Actions**

**Füge diese 4 Secrets hinzu:**
```
DEPLOY_HOST = 192.168.1.100  (deine Pi IP)
DEPLOY_SSH_KEY = [siehe unten]
SENDER_EMAIL = deine@gmail.com  
RECIPIENT_EMAIL = empfaenger@email.com
```

**SSH-Key generieren für DEPLOY_SSH_KEY:**
```bash
# SSH-Key erstellen
ssh-keygen -t ed25519 -C "spotify-bot-deployment"

# Öffentlichen Key auf Pi kopieren  
ssh-copy-id pi@192.168.1.100

# Privaten Key für GitHub kopieren
cat ~/.ssh/id_ed25519
# Kompletten Inhalt als DEPLOY_SSH_KEY einfügen
```

### **4️⃣ Gmail App-Passwort erstellen**
1. **Google Account → Security → 2-Step Verification** aktivieren
2. **App passwords → Generate → Mail → Other: "Spotify Bot"**
3. **16-stelliges Passwort** als **SMTP_PASSWORD** Secret hinzufügen

### **5️⃣ Deployment starten**
```bash
# Änderung machen und pushen = automatisches Deployment!
git add .
git commit -m "Start deployment"
git push origin main

# GitHub Actions macht alles automatisch! 🎉
```

---

## **📊 Deployment Status verfolgen**

1. **GitHub → Actions Tab** - Live-Logs ansehen
2. **Bei Erfolg:** Grüner Haken ✅
3. **Service prüfen:** SSH zum Pi und `sudo systemctl status spotify-bot`

---

## **🎵 Spotify einrichten (nach Deployment)**

```bash
# SSH zum Raspberry Pi
ssh pi@192.168.1.100
cd /opt/spotify-bot

# Spotify OAuth
./venv/bin/python main.py auth
# Folge den Browser-Anweisungen

# Services starten
sudo systemctl start spotify-bot
sudo systemctl enable spotify-bot  # Autostart

# Status prüfen
sudo systemctl status spotify-bot
./venv/bin/python main.py status
```

---

## **🔧 Wichtige Befehle**

```bash
# Service-Management
sudo systemctl start/stop/restart spotify-bot
sudo systemctl status spotify-bot

# Logs ansehen
sudo journalctl -u spotify-bot -f
tail -f /opt/spotify-bot/logs/*.log

# E-Mail testen
cd /opt/spotify-bot
./venv/bin/python main.py test-email

# Service-Status
./venv/bin/python main.py status
```

---

## **🚨 Troubleshooting**

### **Deployment schlägt fehl:**
- **SSH-Key:** Stelle sicher, dass der private Key komplett in DEPLOY_SSH_KEY steht
- **SSH-Zugang:** Teste `ssh pi@192.168.1.100` von deinem PC
- **GitHub Secrets:** Alle 4 Secrets korrekt eingetragen?

### **Service startet nicht:**
```bash
# Detaillierte Logs
sudo journalctl -u spotify-bot --no-pager -l

# Konfiguration testen
cd /opt/spotify-bot
./venv/bin/python -c "from src.core.config import ConfigManager; ConfigManager()"
```

### **E-Mail funktioniert nicht:**
- **Gmail:** App-Passwort statt normalem Passwort verwenden
- **2FA:** Muss aktiviert sein für App-Passwörter
- **Test:** `./venv/bin/python main.py test-email`

---

## **✅ Erfolgskontrolle**

**Du weißt, dass alles läuft, wenn:**

✅ GitHub Actions zeigt grünen Haken  
✅ `sudo systemctl status spotify-bot` = "active (running)"  
✅ `./venv/bin/python main.py status` = alle Services "running"  
✅ E-Mail-Test funktioniert  
✅ Spotify-Auth erfolgreich  

---

## **🔄 Updates deployen**

**Super einfach - einfach Code ändern und pushen:**

```bash
git add .
git commit -m "Feature XYZ added"
git push origin main
# GitHub Actions deployed automatisch! 🚀
```

**🎉 Fertig! Dein Spotify Bot läuft vollautomatisch mit CI/CD!**

---

📖 **Detaillierte Anleitung:** Siehe `DEPLOYMENT.md`  
🔒 **Security Features:** Vollständige DevSecOps-Pipeline mit Bandit, Safety, Semgrep  
🛡️ **Monitoring:** Automatische Watchdog-Services mit E-Mail-Alerts