# 🔗 Telegram Webhook Setup (Optional)

## Wann Webhooks verwenden?

**Polling (Standard):**
- ✅ Einfach, funktioniert überall
- ✅ Keine Netzwerk-Konfiguration nötig
- ⚠️ Etwas höhere Latenz (2-5 Sekunden)

**Webhooks (Erweitert):**
- ✅ Sehr schnell (< 1 Sekunde)
- ✅ Weniger Server-Load
- ❌ Braucht öffentliche HTTPS-URL
- ❌ Komplizierter zu konfigurieren

## Webhook Setup (für VPS/Cloud Server)

### 1. HTTPS-URL einrichten
```bash
# Mit ngrok (für Testing):
ngrok http 8443

# Oder mit Let's Encrypt (Production):
certbot --nginx -d your-domain.com
```

### 2. Webhook in Telegram registrieren
```bash
# Bot Token aus .env nehmen
BOT_TOKEN="8090653802:AAH5i90kruJ5ObNcFyeAFyDXEPS7nu6MfzU"
WEBHOOK_URL="https://your-domain.com/webhook/$BOT_TOKEN"
SECRET="MySecureWebhookSecret2024_MinLength32Chars!"

# Webhook setzen:
curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/setWebhook" \
  -H "Content-Type: application/json" \
  -d "{
    \"url\": \"$WEBHOOK_URL\",
    \"secret_token\": \"$SECRET\",
    \"allowed_updates\": [\"message\"]
  }"
```

### 3. Bot für Webhooks starten
```python
# In main.py erweitern:
elif args.command == "telegram-webhook":
    # Webhook-Modus starten
    bot.start_webhook_listener(host="0.0.0.0", port=8443)
```

### 4. Webhook-Status prüfen
```bash
curl "https://api.telegram.org/bot$BOT_TOKEN/getWebhookInfo"
```

## Für Raspberry Pi (nur bei öffentlicher IP)

### 1. Router konfigurieren
```
Port Forwarding: 8443 -> Raspberry Pi IP:8443
```

### 2. SSL-Zertifikat
```bash
# Self-signed für Testing:
openssl req -newkey rsa:2048 -sha256 -nodes -keyout private.key -x509 -days 365 -out public.pem

# Oder Let's Encrypt:
sudo certbot --standalone -d your-domain.com
```

## Sicherheitshinweise

1. **Immer HTTPS verwenden** (Telegram Requirement)
2. **Webhook Secret validieren** (verhindert Fake-Requests)
3. **Rate Limiting beibehalten** (auch bei Webhooks)
4. **IP-Whitelist** für Telegram IPs (optional)

```python
# Telegram IP-Ranges (optional in Firewall):
TELEGRAM_IPS = [
    "149.154.160.0/20",
    "91.108.4.0/22"
]
```

## Zurück zu Polling wechseln

```bash
# Webhook deaktivieren:
curl -X POST "https://api.telegram.org/bot$BOT_TOKEN/deleteWebhook"

# Dann normal starten:
python main.py telegram-bot
```
