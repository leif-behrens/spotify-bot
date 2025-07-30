#!/bin/sh
# Self-Signed SSL-Zertifikat Generator für Spotify Bot
# CWE-295: Certificate Validation - Sichere Zertifikatsgenerierung

set -e

CERT_DIR="/certs"
CERT_FILE="$CERT_DIR/server.crt"
KEY_FILE="$CERT_DIR/server.key"
CSR_FILE="$CERT_DIR/server.csr"
CONFIG_FILE="$CERT_DIR/openssl.conf"

# Prüfe ob Zertifikat bereits existiert und gültig ist
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "SSL-Zertifikat bereits vorhanden, prüfe Gültigkeit..."

    # Prüfe Ablaufdatum (mindestens 30 Tage gültig)
    if openssl x509 -checkend 2592000 -noout -in "$CERT_FILE" 2>/dev/null; then
        echo "Existierendes Zertifikat ist noch mindestens 30 Tage gültig"
        exit 0
    else
        echo "Zertifikat läuft bald ab oder ist ungültig, erstelle neues..."
    fi
fi

# Installiere OpenSSL falls nicht vorhanden
if ! command -v openssl >/dev/null 2>&1; then
    echo "Installiere OpenSSL..."
    apk update && apk add --no-cache openssl
fi

# Erstelle Verzeichnis falls nicht vorhanden
mkdir -p "$CERT_DIR"

echo "Generiere SSL-Zertifikat für Spotify Bot..."

# OpenSSL-Konfigurationsdatei erstellen
cat > "$CONFIG_FILE" << EOF
[req]
default_bits = 4096
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
C=DE
ST=Germany
L=Local
O=Spotify Auto-Discovery Bot
OU=Development
CN=localhost

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = raspberrypi
DNS.4 = *.raspberrypi
DNS.5 = raspberrypi.local
DNS.6 = *.raspberrypi.local
IP.1 = 127.0.0.1
IP.2 = ::1
IP.3 = 192.168.1.100
IP.4 = 192.168.0.100
EOF

# Generiere Private Key (4096-bit für bessere Sicherheit)
echo "Generiere Private Key..."
openssl genrsa -out "$KEY_FILE" 4096

# Setze sichere Berechtigungen für Private Key
chmod 600 "$KEY_FILE"

# Generiere Certificate Signing Request
echo "Generiere Certificate Signing Request..."
openssl req -new -key "$KEY_FILE" -out "$CSR_FILE" -config "$CONFIG_FILE"

# Generiere Self-Signed Certificate (gültig für 365 Tage)
echo "Generiere Self-Signed Certificate..."
openssl x509 -req -in "$CSR_FILE" -signkey "$KEY_FILE" -out "$CERT_FILE" \
    -days 365 -extensions req_ext -extfile "$CONFIG_FILE"

# Setze Berechtigungen
chmod 644 "$CERT_FILE"
chmod 600 "$KEY_FILE"

# Aufräumen
rm -f "$CSR_FILE" "$CONFIG_FILE"

# Zertifikat-Informationen anzeigen
echo "SSL-Zertifikat erfolgreich generiert!"
echo "Zertifikat-Details:"
openssl x509 -in "$CERT_FILE" -text -noout | grep -E "(Subject:|Not Before|Not After|DNS:|IP Address:)"

echo ""
echo "Zertifikat-Dateien:"
echo "Certificate: $CERT_FILE"
echo "Private Key: $KEY_FILE"
echo ""
echo "Hinweis: Dies ist ein self-signed Zertifikat für Development/Testing."
echo "Browser werden eine Sicherheitswarnung anzeigen - diese kann sicher akzeptiert werden."
echo ""

# Validiere generiertes Zertifikat
if openssl verify -CAfile "$CERT_FILE" "$CERT_FILE" 2>/dev/null; then
    echo "Zertifikat-Validierung: OK"
else
    echo "Zertifikat-Validierung: Self-signed (erwartetes Verhalten)"
fi

echo "SSL-Zertifikat-Generierung abgeschlossen!"
