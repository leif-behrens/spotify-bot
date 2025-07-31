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
from src.services.callback_server import SpotifyCallbackServer
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


def handle_service_command(command: str, service_name: str = None):
    """Handle service management commands"""
    manager = SpotifyServiceManager()

    try:
        if command == "start":
            if service_name:
                success = manager.start(service_name)
                service_desc = manager.services[service_name]["description"]
                print(f"{service_desc}: {'started' if success else 'failed to start'}")
            else:
                success = manager.start_all()
                print(
                    f"All services: {'started' if success else 'some failed to start'}"
                )

        elif command == "stop":
            if service_name:
                success = manager.stop(service_name)
                service_desc = manager.services[service_name]["description"]
                print(f"{service_desc}: {'stopped' if success else 'failed to stop'}")
            else:
                success = manager.stop_all()
                print(
                    f"All services: {'stopped' if success else 'some failed to stop'}"
                )

        elif command == "status":
            if service_name:
                status = manager.status(service_name)
                print(f"{status['description']}: {status['status']}")
                if status.get("pid"):
                    print(f"PID: {status['pid']}")
            else:
                all_status = manager.get_all_status()
                for svc_name, status in all_status.items():
                    print(f"{status['description']}: {status['status']}")
                    if status.get("pid"):
                        print(f"  PID: {status['pid']}")

        elif command == "restart":
            if service_name:
                service_desc = manager.services[service_name]["description"]
                print(f"Stopping {service_desc}...")
                manager.stop(service_name)
                time.sleep(2)
                print(f"Starting {service_desc}...")
                success = manager.start(service_name)
                print(
                    f"{service_desc}: {'restarted' if success else 'failed to restart'}"
                )
            else:
                print("Stopping all services...")
                manager.stop_all()
                time.sleep(2)
                print("Starting all services...")
                success = manager.start_all()
                print(
                    f"All services: {'restarted' if success else 'some failed to restart'}"
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

        elif command == "callback":
            # Run Callback Server directly (foreground)
            print("Starting Callback Server in foreground...")
            print("Press Ctrl+C to stop")
            server = SpotifyCallbackServer()
            server._run_server()

    except KeyboardInterrupt:
        print("\nShutting down...")
        if service_name:
            manager.stop(service_name)
        else:
            manager.stop_all()
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
  python main.py auth                    # Authenticate with Spotify
  python main.py start                   # Start all services
  python main.py start discovery         # Start Discovery Service only
  python main.py start callback          # Start Callback Server only
  python main.py stop                    # Stop all services
  python main.py stop discovery          # Stop Discovery Service only
  python main.py stop callback           # Stop Callback Server only
  python main.py status                  # Check status of all services
  python main.py status discovery        # Check Discovery Service status
  python main.py restart                 # Restart all services
  python main.py restart callback        # Restart Callback Server only
  python main.py run                     # Run Discovery Service in foreground
  python main.py callback               # Run Callback Server in foreground
  python main.py cleanup                # Clean up orphaned processes
        """,
    )

    parser.add_argument(
        "command",
        choices=[
            "auth",
            "start",
            "stop",
            "status",
            "restart",
            "run",
            "callback",
            "cleanup",
        ],
        help="Command to execute",
    )

    parser.add_argument(
        "service",
        nargs="?",
        choices=["discovery", "callback"],
        help="Service to manage (optional - if not specified, applies to all services)",
    )

    args = parser.parse_args()

    # Handle commands
    if args.command == "auth":
        success = handle_auth()
        sys.exit(0 if success else 1)
    else:
        handle_service_command(args.command, args.service)


if __name__ == "__main__":
    main()
