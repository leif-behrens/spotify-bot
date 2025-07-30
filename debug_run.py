#!/usr/bin/env python3
"""
Debug-Version des Spotify Bots mit erweitertem Logging
"""

import logging
import os
import sys
from pathlib import Path

# Debug-Logging aktivieren
os.environ["LOG_LEVEL"] = "DEBUG"

# Füge src-Verzeichnis zum Python-Pfad hinzu
sys.path.insert(0, str(Path(__file__).parent / "src"))

from main import main

if __name__ == "__main__":
    # Setze Console-Handler auf Debug-Level
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    # Reduziere externe Library-Logs
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("requests").setLevel(logging.WARNING)

    print("🔍 Starting Spotify Bot in DEBUG mode...")
    print("This will show detailed information about track processing.")
    print("-" * 60)

    main()
