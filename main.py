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
from src.services.watchdog_service import SpotifyWatchdogService
from src.utils.logging_setup import LoggingSetup

# Initialize main application logger
logger = LoggingSetup.get_logger("main")


def handle_auth():
    """Handle authentication command"""
    try:
        print("Spotify Authentication")
        print("=" * 40)

        oauth_manager = SpotifyOAuthManager()

        if oauth_manager.ensure_valid_token():
            print("\n[SUCCESS] Spotify authorization is ready!")
            print("You can now start services with: python main.py start <service>")
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
            if not service_name:
                print("Error: Service name is required for start command")
                print(
                    "Usage: python main.py start {discovery|callback|watchdog|telegram-bot}"
                )
                sys.exit(1)
            success = manager.start(service_name)
            service_desc = manager.services[service_name]["description"]
            print(f"{service_desc}: {'started' if success else 'failed to start'}")

        elif command == "stop":
            if not service_name:
                print("Error: Service name is required for stop command")
                print(
                    "Usage: python main.py stop {discovery|callback|watchdog|telegram-bot}"
                )
                sys.exit(1)
            success = manager.stop(service_name)
            service_desc = manager.services[service_name]["description"]
            print(f"{service_desc}: {'stopped' if success else 'failed to stop'}")

        elif command == "status":
            if service_name:
                # Show specific service status
                status = manager.status(service_name)
                print(f"{status['description']}: {status['status']}")
                if status.get("pid"):
                    print(f"PID: {status['pid']}")
            else:
                # Show all services status
                all_status = manager.get_all_status()
                for svc_name, status in all_status.items():
                    print(f"{status['description']}: {status['status']}")
                    if status.get("pid"):
                        print(f"  PID: {status['pid']}")

        elif command == "restart":
            if not service_name:
                print("Error: Service name is required for restart command")
                print(
                    "Usage: python main.py restart {discovery|callback|watchdog|telegram-bot}"
                )
                sys.exit(1)
            service_desc = manager.services[service_name]["description"]
            print(f"Stopping {service_desc}...")
            manager.stop(service_name)
            time.sleep(2)
            print(f"Starting {service_desc}...")
            success = manager.start(service_name)
            print(f"{service_desc}: {'restarted' if success else 'failed to restart'}")

    except KeyboardInterrupt:
        print("\nShutting down...")
        if service_name:
            manager.stop(service_name)
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
  python main.py start discovery         # Start Discovery Service
  python main.py start callback          # Start Callback Server
  python main.py start watchdog          # Start Watchdog Service
  python main.py start telegram-bot      # Start Telegram Command Bot
  python main.py stop discovery          # Stop Discovery Service
  python main.py stop callback           # Stop Callback Server
  python main.py stop watchdog           # Stop Watchdog Service
  python main.py stop telegram-bot       # Stop Telegram Command Bot
  python main.py status                  # Check status of all services
  python main.py status discovery        # Check Discovery Service status only
  python main.py status callback         # Check Callback Server status only
  python main.py status watchdog         # Check Watchdog Service status only
  python main.py status telegram-bot     # Check Telegram Command Bot status only
  python main.py restart discovery       # Restart Discovery Service
  python main.py restart callback        # Restart Callback Server
  python main.py restart watchdog        # Restart Watchdog Service
  python main.py restart telegram-bot    # Restart Telegram Command Bot
  python main.py run                     # Run Discovery Service in foreground
  python main.py callback               # Run Callback Server in foreground
  python main.py watchdog               # Run Watchdog Service in foreground
  python main.py telegram-bot           # Run Telegram Command Bot in foreground
  python main.py cleanup                # Clean up orphaned processes
  python main.py test-email             # Test email notification configuration
  python main.py test-telegram-bot      # Test Telegram Command Bot configuration
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
            "watchdog",
            "telegram-bot",
            "cleanup",
            "test-email",
            "test-telegram-bot",
        ],
        help="Command to execute",
    )

    parser.add_argument(
        "service",
        nargs="?",
        choices=["discovery", "callback", "watchdog", "telegram-bot"],
        help="Service to manage (required for start/stop/restart, optional for status)",
    )

    args = parser.parse_args()

    # Handle commands
    if args.command == "auth":
        success = handle_auth()
        sys.exit(0 if success else 1)
    elif args.command in ["start", "stop", "status", "restart"]:
        handle_service_command(args.command, args.service)
    elif args.command == "cleanup":
        manager = SpotifyServiceManager()
        count = manager.cleanup()
        print(f"Cleaned up {count} orphaned processes")
    elif args.command == "run":
        # Run Discovery Service directly (foreground)
        print("Starting Discovery Service in foreground...")
        print("Press Ctrl+C to stop")
        service = SpotifyDiscoveryService()
        service.run()
    elif args.command == "callback":
        # Run Callback Server directly (foreground)
        print("Starting Callback Server in foreground...")
        print("Press Ctrl+C to stop")
        server = SpotifyCallbackServer()
        server._run_server()
    elif args.command == "watchdog":
        # Run Watchdog Service directly (foreground)
        print("Starting Watchdog Service in foreground...")
        print("Press Ctrl+C to stop")
        watchdog = SpotifyWatchdogService()
        watchdog.start()
        try:
            while watchdog.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down Watchdog...")
            watchdog.stop()
    elif args.command == "telegram-bot":
        # Run Telegram Command Bot directly (foreground)
        print("Starting Telegram Command Bot in foreground...")
        print("Press Ctrl+C to stop")
        from src.core.config import ConfigManager
        from src.services.telegram_command_bot import TelegramCommandBot

        config_manager = ConfigManager()
        bot = TelegramCommandBot(config_manager)

        if not bot.enabled:
            print("ERROR: Telegram Command Bot is disabled or misconfigured")
            print("Please check your configuration and environment variables:")
            print("- TELEGRAM_BOT_TOKEN")
            print("- TELEGRAM_CHAT_ID")
            print("- TELEGRAM_ADMIN_USERS (comma-separated user IDs)")
            sys.exit(1)

        try:
            print("Telegram Command Bot is running...")
            print("Send /help to the bot for available commands")
            bot.start_polling()
        except KeyboardInterrupt:
            print("\nShutting down Telegram Command Bot...")
    elif args.command == "test-telegram-bot":
        # Test Telegram Command Bot configuration
        print("Testing Telegram Command Bot configuration...")
        from src.core.config import ConfigManager
        from src.services.telegram_command_bot import TelegramCommandBot

        config_manager = ConfigManager()
        bot = TelegramCommandBot(config_manager)

        if bot.enabled:
            print("SUCCESS: Telegram Command Bot configuration is valid")
            print(f"   Admin users: {len(bot.admin_user_ids)}")
            print(f"   Available commands: {len(bot.allowed_commands)}")
            print(f"   Rate limit: {bot.max_commands_per_hour} commands/hour")

            # Send test message to verify connectivity
            if bot._send_response(
                int(bot.chat_id),
                "Test: Telegram Command Bot test message - Configuration OK!",
            ):
                print("SUCCESS: Test message sent successfully")
            else:
                print(
                    "ERROR: Failed to send test message - check bot token and chat ID"
                )
                sys.exit(1)
        else:
            print("ERROR: Telegram Command Bot is disabled or misconfigured")
            sys.exit(1)
    elif args.command == "test-email":
        # Test email configuration
        from src.utils.email_notifier import EmailNotifier

        notifier = EmailNotifier()
        if notifier.test_email_configuration():
            print("Email test successful!")
        else:
            print("Email test failed. Check configuration and logs.")


if __name__ == "__main__":
    main()
