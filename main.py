#!/usr/bin/env python3
"""
Spotify Auto-Discovery Bot - Haupteinstiegspunkt
Sichere, benutzerfreundliche CLI für alle Bot-Funktionen
"""

import argparse
import sys
import time
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.auth.oauth_manager import SpotifyOAuthManager
from src.services.discovery_service import SpotifyDiscoveryService
from src.services.service_manager import SpotifyServiceManager


def handle_auth():
    """Handle authentication command"""
    try:
        print("Spotify Authentication")
        print("=" * 40)

        oauth_manager = SpotifyOAuthManager()

        if oauth_manager.ensure_valid_token():
            print("\n[SUCCESS] Spotify authorization is ready!")
            print("You can now start the Discovery Service with: python main.py start")
            return True
        else:
            print("\n[ERROR] Spotify authorization failed!")
            print("Please check your configuration and try again.")
            return False

    except KeyboardInterrupt:
        print("\n\nAuthorization cancelled by user.")
        return False
    except Exception as e:
        print(f"\n[ERROR] Authentication failed: {e}")
        return False


def handle_service_command(command: str):
    """Handle service management commands"""
    manager = SpotifyServiceManager()

    try:
        if command == "start":
            success = manager.start()
            print(f"Discovery Service: {'started' if success else 'failed to start'}")

        elif command == "stop":
            success = manager.stop()
            print(f"Discovery Service: {'stopped' if success else 'failed to stop'}")

        elif command == "status":
            status = manager.status()
            print(f"Discovery Service: {status['status']}")
            if status.get("pid"):
                print(f"PID: {status['pid']}")

        elif command == "restart":
            print("Stopping Discovery Service...")
            manager.stop()
            time.sleep(2)
            print("Starting Discovery Service...")
            success = manager.start()
            print(
                f"Discovery Service: {'restarted' if success else 'failed to restart'}"
            )

        elif command == "cleanup":
            count = manager.cleanup()
            print(f"Cleaned up {count} orphaned processes")

        elif command == "run":
            # Run Discovery Service directly (foreground)
            print("Starting Discovery Service in foreground...")
            print("Press Ctrl+C to stop")
            service = SpotifyDiscoveryService()
            service.run()

    except KeyboardInterrupt:
        print("\nShutting down...")
        manager.stop()
    except Exception as e:
        print(f"Service command failed: {e}")
        sys.exit(1)


def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(
        description="Spotify Auto-Discovery Bot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py auth          # Authenticate with Spotify
  python main.py start         # Start Discovery Service
  python main.py stop          # Stop Discovery Service
  python main.py status        # Check service status
  python main.py restart       # Restart Discovery Service
  python main.py run           # Run Discovery Service in foreground
  python main.py cleanup       # Clean up orphaned processes
        """,
    )

    parser.add_argument(
        "command",
        choices=["auth", "start", "stop", "status", "restart", "run", "cleanup"],
        help="Command to execute",
    )

    args = parser.parse_args()

    # Handle commands
    if args.command == "auth":
        success = handle_auth()
        sys.exit(0 if success else 1)
    else:
        handle_service_command(args.command)


if __name__ == "__main__":
    main()
