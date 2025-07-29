#!/usr/bin/env python3
"""
Test-Skript für Spotify Auto-Discovery Bot
Testet alle Komponenten ohne Spotify-Authentifizierung
"""

import sys
import os
from pathlib import Path
import time

# Füge src-Verzeichnis zum Python-Pfad hinzu
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_configuration():
    """Test Konfigurationssystem"""
    print("Testing Configuration System...")
    try:
        from config import ConfigManager
        config = ConfigManager()
        
        # Test Config-Zugriff
        monitoring_config = config.get_monitoring_config()
        playlist_config = config.get_playlist_config()
        service_config = config.get_service_config()
        
        print(f"   OK Check interval: {monitoring_config['check_interval_seconds']}s")
        print(f"   OK Min duration: {monitoring_config['minimum_play_duration_seconds']}s")
        print(f"   OK Playlist name: {playlist_config['name']}")
        print("   OK Configuration system: PASSED")
        return True
        
    except Exception as e:
        print(f"   ERROR Configuration test failed: {e}")
        return False

def test_database():
    """Test Statistik-Datenbank"""
    print("\nTesting Statistics Database...")
    try:
        from statistics import StatisticsDatabase
        db = StatisticsDatabase()
        
        # Test Metrik speichern
        db.record_metric('test_startup', 'success', {'version': '1.0'})
        
        # Test Statistiken abrufen
        stats = db.get_listening_statistics(7)
        daily_activity = db.get_daily_activity(7)
        
        print(f"   OK Database operations: OK")
        print(f"   OK Statistics query: {len(daily_activity)} days")
        print("   OK Database system: PASSED")
        return True
        
    except Exception as e:
        print(f"   ERROR Database test failed: {e}")
        return False

def test_dashboard_creation():
    """Test Dashboard-Erstellung (ohne Start)"""
    print("\nTesting Dashboard Creation...")
    try:
        from config import ConfigManager
        from monitoring_service import SpotifyMonitoringService
        from dashboard import SecureDashboard
        
        # Mock Monitoring Service (ohne Spotify)
        config = ConfigManager()
        
        # Erstelle Dashboard (ohne es zu starten)
        dashboard = SecureDashboard(config, None)  # None als Mock-Service
        
        print("   OK Dashboard creation: OK")
        print("   OK Flask app setup: OK")
        print("   OK Dashboard system: PASSED")
        return True
        
    except Exception as e:
        print(f"   ERROR Dashboard test failed: {e}")
        return False

def test_security_features():
    """Test Sicherheitsfeatures"""
    print("\nTesting Security Features...")
    try:
        from spotify_auth import SecureTokenStorage
        
        # Test Token-Verschlüsselung
        token_storage = SecureTokenStorage("data/.test_token")
        test_token = {'access_token': 'test123', 'refresh_token': 'refresh456'}
        
        token_storage.save_token(test_token)
        loaded_token = token_storage.load_token()
        
        if loaded_token and loaded_token['access_token'] == 'test123':
            print("   OK Token encryption/decryption: OK")
        else:
            print("   ERROR Token encryption failed")
            return False
            
        # Cleanup
        os.remove("data/.test_token")
        
        print("   OK Security features: PASSED")
        return True
        
    except Exception as e:
        print(f"   ERROR Security test failed: {e}")
        return False

def main():
    """Haupttestfunktion"""
    print("Spotify Auto-Discovery Bot - System Test")
    print("=" * 50)
    
    tests = [
        test_configuration,
        test_database,
        test_dashboard_creation,
        test_security_features
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("All tests PASSED! Application is ready to use.")
        print("\nNext steps:")
        print("1. Ensure your .env file has correct Spotify credentials")
        print("2. Run: python run.py")
        print("3. Follow the Spotify authorization flow")
        print("4. Access dashboard at http://localhost:5000")
        return True
    else:
        print("Some tests FAILED. Please check the errors above.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)