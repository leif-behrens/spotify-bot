#!/usr/bin/env python3
"""
Gunicorn Konfiguration für Spotify Bot
Optimiert für Raspberry Pi 4 und Sicherheit
CWE-400: Resource Management, CWE-20: Input Validation
"""

import multiprocessing
import os

# Bind-Adresse
bind = "0.0.0.0:8000"

# Worker-Konfiguration (Single-Worker für MonitoringService-Stabilität)
workers = 1  # Nur ein Worker für gemeinsamen Service-State
worker_class = "sync"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50

# Timeout-Konfiguration - CWE-400: DoS Prevention
timeout = 30
keepalive = 2
graceful_timeout = 30

# Security Konfiguration
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Logging
loglevel = os.environ.get('LOG_LEVEL', 'info').lower()
accesslog = '-'  # Log to stdout
errorlog = '-'   # Log to stderr
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process-Namen für besseres Monitoring
proc_name = 'spotify-bot'

# Preload Application für bessere Performance
preload_app = True

# User/Group (läuft bereits als spotifybot in Container)
# user = "spotifybot"
# group = "spotifybot"

# Hook-Funktionen für Lifecycle-Management
def on_starting(server):
    """Called just before the master process is initialized."""
    server.log.info("Starting Spotify Auto-Discovery Bot WSGI Server")

def on_reload(server):
    """Called to recycle workers during a reload via SIGHUP."""
    server.log.info("Reloading Spotify Bot workers")

def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT."""
    worker.log.info("Worker received INT or QUIT signal")

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    server.log.info(f"Worker {worker.pid} forked")

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info(f"Worker {worker.pid} spawned")

def post_worker_init(worker):
    """Called just after a worker has initialized the application."""
    worker.log.info(f"Worker {worker.pid} initialized")

def worker_exit(server, worker):
    """Called just before a worker exits."""
    worker.log.info(f"Worker {worker.pid} exiting - cleaning up resources")
    
    # Importiere und stoppe MonitoringService falls läuft
    try:
        from wsgi import app
        if hasattr(app, 'monitoring_service'):
            service = app.monitoring_service
            if service and service.is_running:
                worker.log.info("Stopping monitoring service before worker exit")
                service.stop()
    except Exception as e:
        worker.log.warning(f"Error during worker cleanup: {e}")

def worker_abort(worker):
    """Called when a worker receives a SIGABRT signal."""
    worker.log.info(f"Worker {worker.pid} received SIGABRT signal")

# SSL/TLS-Konfiguration (wird von Nginx übernommen)
# keyfile = "/app/certs/server.key"
# certfile = "/app/certs/server.crt"

# Environment Variables Validation
def validate_environment():
    """Validiert kritische Umgebungsvariablen"""
    required_vars = [
        'SPOTIFY_CLIENT_ID',
        'SPOTIFY_CLIENT_SECRET',
        'SPOTIFY_REDIRECT_URI'
    ]
    
    missing_vars = []
    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)
    
    if missing_vars:
        raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")

# Validiere Environment beim Start
try:
    validate_environment()
except ValueError as e:
    print(f"Configuration Error: {e}")
    exit(1)