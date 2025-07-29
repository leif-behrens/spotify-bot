#!/usr/bin/env python3
"""
Spotify Auto-Discovery Bot - Startskript
Einfacher Einstiegspunkt für die Anwendung
"""

import sys
from pathlib import Path

# Füge src-Verzeichnis zum Python-Pfad hinzu
sys.path.insert(0, str(Path(__file__).parent / "src"))

from main import main

if __name__ == "__main__":
    main()