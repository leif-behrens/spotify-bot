# Multi-stage Dockerfile für Raspberry Pi (ARM64)
# Optimiert für Sicherheit und Performance

FROM python:3.11-slim as builder

# Security: Erstelle non-root User
RUN groupadd -r spotifybot && useradd -r -g spotifybot spotifybot

# Update system und installiere build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Erstelle virtuelle Umgebung
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Kopiere requirements und installiere Dependencies
COPY requirements.txt /tmp/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /tmp/requirements.txt

# Production Stage
FROM python:3.11-slim

# Security: Installiere nur nötige System-Pakete
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Erstelle non-root User
RUN groupadd -r spotifybot && useradd -r -g spotifybot spotifybot

# Kopiere virtuelle Umgebung
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Arbeitsverzeichnis
WORKDIR /app

# Kopiere Application Code
COPY --chown=spotifybot:spotifybot src/ ./src/
COPY --chown=spotifybot:spotifybot config.json ./
COPY --chown=spotifybot:spotifybot run.py ./
COPY --chown=spotifybot:spotifybot wsgi.py ./
COPY --chown=spotifybot:spotifybot gunicorn.conf.py ./
COPY --chown=spotifybot:spotifybot callback_server.py ./
COPY --chown=spotifybot:spotifybot start_servers.sh ./

# Erstelle notwendige Verzeichnisse mit korrekten Berechtigungen
RUN mkdir -p /app/data /app/logs && \
    chown -R spotifybot:spotifybot /app && \
    chmod 755 /app && \
    chmod -R 750 /app/data /app/logs && \
    chmod +x /app/start_servers.sh

# Security: Wechsele zu non-root User
USER spotifybot

# Exponiere Ports für Gunicorn und Callback Server
EXPOSE 8000 4444

# Health Check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/api/status', timeout=5)"

# Start both servers using start script
CMD ["./start_servers.sh"]