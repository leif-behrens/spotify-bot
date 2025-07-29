# Spotify App Setup - Fehlerbehebung

## Problem: HTTP 401 - Permissions missing

Dieser Fehler tritt auf, wenn die Spotify App nicht korrekt konfiguriert ist oder die Berechtigungen fehlen.

## ✅ Lösung:

### 1. Spotify App-Einstellungen prüfen

Gehen Sie zu: https://developer.spotify.com/dashboard

**Ihre App: "Automated_Playlist"**

**Wichtige Einstellungen:**
- ✅ **Redirect URI**: `http://127.0.0.1:4444/callback` (exakt wie eingetragen)
- ✅ **App Type**: Web API
- ✅ **Status**: Sollte nicht "In Development Mode" sein für vollständige Berechtigungen

### 2. Alte Token löschen (bereits gemacht)
Die alten Token wurden gelöscht, eine neue Authentifizierung ist erforderlich.

### 3. Erweiterte Berechtigungen
Der Code wurde aktualisiert und fordert jetzt folgende Scopes an:
- `user-read-currently-playing` - Aktuell spielenden Song lesen
- `user-read-playback-state` - Playback-Status lesen  
- `playlist-modify-public` - Öffentliche Playlists bearbeiten
- `playlist-modify-private` - Private Playlists bearbeiten
- `playlist-read-private` - Private Playlists lesen
- `user-library-read` - Bibliothek lesen

### 4. App neu starten

```bash
cd "G:\OneDrive\Dokumente\Eigene Dateien\IT\spotify-bot"
python run.py
```

### 5. Neue Authentifizierung durchführen

- Öffnen Sie den angezeigten Spotify-Link
- **Wichtig**: Klicken Sie auf "ALLE BERECHTIGUNGEN ANZEIGEN" 
- Bestätigen Sie ALLE Berechtigungen
- Kopieren Sie die komplette Callback-URL ins Terminal

### 6. Spotify muss aktiv laufen

**Wichtig**: Spotify muss auf einem Gerät aktiv Musik abspielen:
- Spotify Desktop App, Handy, oder Web Player
- Ein Song muss tatsächlich laufen (nicht pausiert)
- Das Gerät muss online und aktiv sein

## 🔍 Debug-Hilfe

Wenn immer noch Fehler auftreten, prüfen Sie:

1. **Spotify App Status**: Ist die App im "Development Mode"?
2. **Gerät aktiv**: Läuft Spotify wirklich und spielt Musik?
3. **Client ID/Secret**: Sind diese korrekt in der .env Datei?
4. **Redirect URI**: Exakt wie in der Spotify App eingetragen?

## 🚨 Häufige Probleme

- **401 Error**: Meist fehlerhafte Scopes oder App-Konfiguration
- **No device active**: Spotify läuft nicht aktiv
- **Token expired**: Wird automatisch refreshed
- **Rate limiting**: App wartet automatisch

## 💡 Test

Nach erfolgreicher Authentifizierung sollten Sie sehen:
- Dashboard: http://localhost:5000 zeigt Status
- Terminal: "Successfully authenticated as: [Ihr Name]"
- Monitoring startet automatisch