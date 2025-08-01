#!/usr/bin/env python3
"""
Test script for Telegram Bot integration
Security: CWE-532 Information Exposure Prevention, CWE-20 Input Validation
Usage: python scripts/test_telegram.py
"""

import logging
import os
import sys

# Add project root and src to path for imports
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, "src"))

# Load environment variables from .env file
from dotenv import load_dotenv

env_file = os.path.join(project_root, ".env")
load_dotenv(env_file, override=True)

from src.core.config import ConfigManager
from src.services.telegram_service import TelegramMessage, TelegramService


def setup_test_logging():
    """Setup basic logging for test script"""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )


def check_environment():
    """Check if required environment variables are set"""
    print("🔍 Checking environment variables...")

    required_vars = [
        "TELEGRAM_BOT_TOKEN",
        "TELEGRAM_CHAT_ID",
        "SPOTIFY_CLIENT_ID",
        "SPOTIFY_CLIENT_SECRET",
        "SPOTIFY_REDIRECT_URI",
    ]

    missing_vars = []
    for var in required_vars:
        if not os.environ.get(var):
            missing_vars.append(var)

    if missing_vars:
        print(f"❌ Missing environment variables: {', '.join(missing_vars)}")
        print("\\nPlease set the following in your .env file:")
        for var in missing_vars:
            if var.startswith("TELEGRAM"):
                print(
                    f"   {var}=your_telegram_{var.lower().replace('telegram_', '').replace('_', '_')}_here"
                )
            else:
                print(f"   {var}=your_{var.lower()}_here")
        return False

    # Validate format without exposing values
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "")

    if ":" not in bot_token:
        print("❌ TELEGRAM_BOT_TOKEN format invalid (should contain ':')")
        return False

    if not chat_id.lstrip("-").isdigit():
        print("❌ TELEGRAM_CHAT_ID format invalid (should be numeric)")
        return False

    print("✅ All environment variables are set and valid")
    return True


def test_configuration():
    """Test configuration loading"""
    print("\\n🔧 Testing configuration...")

    try:
        config_manager = ConfigManager()
        telegram_config = config_manager.get_telegram_notifications_config()

        print(f"✅ Configuration loaded successfully")
        print(f"   - Enabled: {telegram_config.get('enabled', False)}")
        print(f"   - Timeout: {telegram_config.get('timeout_seconds')}s")
        print(f"   - Max retries: {telegram_config.get('retry_attempts')}")

        return config_manager

    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return None


def test_telegram_service(config_manager):
    """Test Telegram service initialization and functionality"""
    print("\\n📱 Testing Telegram service...")

    try:
        telegram_service = TelegramService(config_manager)

        if not telegram_service.enabled:
            print("❌ Telegram service is disabled (check credentials)")
            return False

        print("✅ Telegram service initialized successfully")

        # Test service status
        status = telegram_service.get_status()
        print(f"   - Rate limit remaining: {status['rate_limit_remaining']}")
        print(f"   - Configuration: {status['configuration']}")

        return telegram_service

    except Exception as e:
        print(f"❌ Telegram service initialization failed: {e}")
        return None


def test_message_sending(telegram_service):
    """Test sending messages"""
    print("\\n📨 Testing message sending...")

    # Test basic message
    print("Testing basic notification...")
    test_message = TelegramMessage(
        text="🧪 This is a test message from your Spotify Bot!\\n\\nIf you see this, the Telegram integration is working correctly.",
        priority="normal",
    )

    if telegram_service.send_message(test_message):
        print("✅ Basic message sent successfully")
    else:
        print("❌ Failed to send basic message")
        return False

    # Test watchdog failure message
    print("Testing watchdog failure notification...")
    if telegram_service.send_watchdog_failure("test_service", 2, 3):
        print("✅ Watchdog failure message sent successfully")
    else:
        print("❌ Failed to send watchdog failure message")

    # Test recovery message
    print("Testing service recovery notification...")
    if telegram_service.send_service_recovery("test_service", 5):
        print("✅ Service recovery message sent successfully")
    else:
        print("❌ Failed to send service recovery message")

    return True


def main():
    """Main test function"""
    print("🤖 Telegram Bot Integration Test")
    print("=" * 50)

    setup_test_logging()

    # Step 1: Check environment
    if not check_environment():
        print(
            "\\n❌ Environment check failed. Please fix the issues above and try again."
        )
        return 1

    # Step 2: Test configuration
    config_manager = test_configuration()
    if not config_manager:
        print("\\n❌ Configuration test failed.")
        return 1

    # Step 3: Test Telegram service
    telegram_service = test_telegram_service(config_manager)
    if not telegram_service:
        print("\\n❌ Telegram service test failed.")
        return 1

    # Step 4: Test message sending
    if not test_message_sending(telegram_service):
        print("\\n❌ Message sending test failed.")
        return 1

    print("\\n🎉 All tests passed successfully!")
    print("\\n📱 Check your Telegram chat - you should have received test messages.")
    print("\\n✅ Your Telegram Bot integration is ready!")

    return 0


if __name__ == "__main__":
    exit(main())
