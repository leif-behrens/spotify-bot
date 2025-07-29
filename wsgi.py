#!/usr/bin/env python3
"""
WSGI Entry Point für Spotify Auto-Discovery Bot
Konfiguriert für Production-Umgebung mit Gunicorn
"""

import sys
import os
import logging
from pathlib import Path

# Füge src-Verzeichnis zum Python-Pfad hinzu
sys.path.insert(0, str(Path(__file__).parent / "src"))

# Umgebungsvariablen für Production setzen
os.environ.setdefault('FLASK_ENV', 'production')
os.environ.setdefault('FLASK_DEBUG', 'False')

def create_app():
    """
    Application Factory für WSGI
    """
    try:
        from config import ConfigManager
        from monitoring_service import SpotifyMonitoringService
        from dashboard import SecureDashboard
        
        # Konfiguration laden
        config_manager = ConfigManager()
        
        # Monitoring Service erstellen (jetzt nur ein Worker)
        monitoring_service = SpotifyMonitoringService(config_manager)
        
        # Dashboard erstellen
        dashboard = SecureDashboard(config_manager, monitoring_service)
        
        # Monitoring Service als App-Attribut verfügbar machen für Worker-Cleanup
        dashboard.app.monitoring_service = monitoring_service
        
        # Monitoring Service wird nur manuell über Dashboard gestartet
        # Automatischer Start entfernt um Container-Start-Probleme zu vermeiden
        logging.info("Dashboard ready - monitoring service can be started manually")
        
        return dashboard.app
        
    except Exception as e:
        logging.error(f"Failed to create app: {e}")
        raise

# Erstelle Application-Instanz
app = create_app()

if __name__ == "__main__":
    # Für lokales Testing
    app.run(host='0.0.0.0', port=8000, debug=False)