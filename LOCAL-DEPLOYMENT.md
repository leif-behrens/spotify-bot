# 🏠 Lokales Deployment auf Raspberry Pi

Da dein Raspberry Pi in deinem lokalen Netzwerk läuft, kann GitHub Actions nicht automatisch deployen. Hier ist die **einfache lokale Lösung**:

## **🚀 Schnell-Deployment (2 Minuten)**

### **Auf deinem Raspberry Pi ausführen:**

```bash
# 1. Repository klonen/aktualisieren
cd ~ 
git clone https://github.com/DEIN-USERNAME/spotify-bot.git || (cd spotify-bot && git pull)
cd spotify-bot

# 2. Lokales Deployment
chmod +x deploy/deploy.sh
sudo DEPLOY_HOST=localhost DEPLOY_USER=$USER ./deploy/deploy.sh
```

**Das war's!** 🎉

---

## **📋 Was das Script macht:**

1. **Python Environment** einrichten
2. **Dependencies** installieren
3. **Systemd Service** erstellen
4. **Logging** konfigurieren
5. **Service** starten

---

## **🔧 Service-Management:**

```bash
# Service starten/stoppen/neustarten
sudo systemctl start spotify-bot
sudo systemctl stop spotify-bot
sudo systemctl restart spotify-bot

# Status prüfen
sudo systemctl status spotify-bot

# Logs ansehen
sudo journalctl -u spotify-bot -f
tail -f ~/spotify-bot/logs/*.log
```

---

## **🎵 Spotify einrichten:**

```bash
cd ~/spotify-bot

# OAuth-Flow starten
./venv/bin/python main.py auth
# Folge den Browser-Anweisungen

# Services einzeln testen
./venv/bin/python main.py service start discovery
./venv/bin/python main.py service start callback
./venv/bin/python main.py service start watchdog

# Gesamtstatus
./venv/bin/python main.py status
```

---

## **🔄 Updates deployen:**

### **Automatisch (empfohlen):**
```bash
# Einfach Script erneut ausführen
cd ~/spotify-bot
git pull origin main
sudo DEPLOY_HOST=localhost DEPLOY_USER=$USER ./deploy/deploy.sh
```

### **Manuell:**
```bash
cd ~/spotify-bot
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
sudo systemctl restart spotify-bot
```

---

## **📊 Workflow-Integration:**

**GitHub Actions macht:**
✅ Security-Scans (Bandit, Safety)  
✅ Code Quality (Flake8, MyPy)  
✅ Build & Test  
ℹ️ Deployment Skipped (Local Network)  

**Du machst lokal:**
🚀 Deployment auf Raspberry Pi  

**Best of both worlds!** 🎯

---

## **🆘 Troubleshooting:**

### **Permission-Fehler:**
```bash
sudo chown -R $USER:$USER ~/spotify-bot
```

### **Service startet nicht:**
```bash
sudo journalctl -u spotify-bot --no-pager -l
cd ~/spotify-bot
./venv/bin/python -c "from src.core.config import ConfigManager; ConfigManager()"
```

### **Port bereits belegt:**
```bash
sudo lsof -i :4444
sudo pkill -f "python.*main.py"
```

---

## **🎉 Vorteile des lokalen Deployments:**

✅ **Schneller** - Keine Internet-Latenz  
✅ **Sicherer** - Keine externe Exposition  
✅ **Flexibler** - Direkte Kontrolle  
✅ **Effizienter** - Weniger komplexe Infrastruktur  

**GitHub Actions + Lokales Deployment = Perfekte Kombination!** 🚀