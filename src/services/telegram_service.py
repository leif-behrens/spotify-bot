"""
Secure Telegram Bot Service for Spotify Bot Monitoring
Security: CWE-20 Input Validation, CWE-532 Information Exposure Prevention, CWE-798 Hard-coded Credentials Prevention
Bandit: B101, B113, B322, B605
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.core.config import ConfigManager
from src.utils.logging_setup import SecureLoggingSetup


@dataclass
class TelegramMessage:
    """Secure message data structure for Telegram notifications"""

    text: str
    priority: str = "normal"  # normal, high, critical
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

        # CWE-20: Input validation for message content
        if not isinstance(self.text, str):
            raise ValueError("Message text must be string")
        if len(self.text) > 4096:  # Telegram message limit
            self.text = self.text[:4093] + "..."

        # Validate priority level
        if self.priority not in ["normal", "high", "critical"]:
            self.priority = "normal"


class TelegramService:
    """
    Secure Telegram Bot Service for monitoring notifications

    Security features:
    - CWE-532: No token logging or exposure in error messages
    - CWE-20: Input validation for all parameters
    - CWE-798: Credentials loaded from environment variables
    - Bandit B113: HTTPS with certificate verification
    - Bandit B322: Secure input validation
    - Rate limiting to prevent API abuse
    """

    def __init__(self, config_manager: ConfigManager):
        self.config_manager = config_manager
        self.logger = SecureLoggingSetup.get_logger("telegram", config_manager)

        # Load configuration
        self.config = config_manager.get_telegram_notifications_config()
        self.enabled = self.config.get("enabled", False)

        if not self.enabled:
            self.logger.info("Telegram notifications are disabled")
            return

        # Load credentials from environment (CWE-798 prevention)
        self.bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
        self.chat_id = os.environ.get("TELEGRAM_CHAT_ID")

        if not self.bot_token or not self.chat_id:
            self.logger.error("Telegram credentials not found in environment variables")
            self.enabled = False
            return

        # Validate credentials format (CWE-20)
        if not self._validate_credentials():
            self.logger.error("Invalid Telegram credentials format")
            self.enabled = False
            return

        # API configuration
        self.api_base_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.timeout = self.config.get("timeout_seconds", 30)
        self.retry_attempts = self.config.get("retry_attempts", 3)
        self.retry_delay = self.config.get("retry_delay_seconds", 5)
        self.rate_limit_window = self.config.get("rate_limit_seconds", 60)

        # Rate limiting tracking
        self.last_message_time = 0
        self.message_count_window = 0
        self.rate_limit_messages = 20  # Max messages per window

        # Setup HTTP session with retries (Bandit B113)
        self.session = requests.Session()
        retry_strategy = Retry(
            total=self.retry_attempts,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

        self.logger.info("Telegram service initialized successfully")

    def _validate_credentials(self) -> bool:
        """
        Validate Telegram credentials format
        CWE-20: Input validation, CWE-532: No credential logging
        """
        try:
            # Basic token format validation (bot_id:token)
            if not isinstance(self.bot_token, str) or ":" not in self.bot_token:
                return False

            token_parts = self.bot_token.split(":")
            if len(token_parts) != 2 or not token_parts[0].isdigit():
                return False

            # Chat ID validation (should be numeric)
            if (
                not isinstance(self.chat_id, str)
                or not self.chat_id.lstrip("-").isdigit()
            ):
                return False

            return True

        except Exception:
            return False

    def _check_rate_limit(self) -> bool:
        """
        Check if rate limit allows sending message
        Implements sliding window rate limiting
        """
        current_time = time.time()

        # Reset window if enough time has passed
        if current_time - self.last_message_time > self.rate_limit_window:
            self.message_count_window = 0

        # Check if within rate limit
        if self.message_count_window >= self.rate_limit_messages:
            return False

        return True

    def _format_message(self, message: TelegramMessage) -> str:
        """
        Format message with emoji and timestamp based on priority
        CWE-20: Input validation for message formatting
        """
        try:
            # Priority-based emoji mapping
            emoji_map = {"normal": "ℹ️", "high": "⚠️", "critical": "🚨"}

            emoji = emoji_map.get(message.priority, "ℹ️")
            timestamp = message.timestamp.strftime("%Y-%m-%d %H:%M:%S")

            # Use simple formatting that works reliably
            formatted_text = f"{emoji} *Spotify Bot Alert*\n\n"
            formatted_text += f"*Time:* {timestamp}\n"
            formatted_text += f"*Priority:* {message.priority.upper()}\n\n"
            formatted_text += f"{message.text}"

            return formatted_text

        except Exception as e:
            self.logger.warning(f"Message formatting failed, using plain text")
            return f"Spotify Bot Alert: {message.text}"

    def send_message(self, message: TelegramMessage) -> bool:
        """
        Send message to Telegram chat

        Security measures:
        - CWE-532: No token exposure in logs
        - CWE-20: Input validation
        - Bandit B113: HTTPS with verification
        - Rate limiting protection

        Returns:
            bool: True if message sent successfully, False otherwise
        """

        if not self.enabled:
            self.logger.debug("Telegram service disabled, message not sent")
            return False

        # Rate limiting check
        if not self._check_rate_limit():
            self.logger.warning("Rate limit exceeded, message not sent")
            return False

        try:
            # Format message
            formatted_text = self._format_message(message)

            # Prepare API request payload - try Markdown first, fallback to plain text
            payload = {
                "chat_id": self.chat_id,
                "text": formatted_text,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            }

            # Send message via Telegram Bot API (Bandit B113: HTTPS with verification)
            response = self.session.post(
                f"{self.api_base_url}/sendMessage",
                json=payload,
                timeout=self.timeout,
                verify=True,  # SSL certificate verification
            )

            if response.status_code == 200:
                # Update rate limiting counters
                self.last_message_time = time.time()
                self.message_count_window += 1

                self.logger.info(
                    f"Telegram message sent successfully (priority: {message.priority})"
                )
                return True
            else:
                # Try fallback with plain text if formatting failed
                if response.status_code == 400 and payload.get("parse_mode"):
                    self.logger.info(
                        "Markdown formatting failed, retrying with plain text"
                    )
                    payload["text"] = f"Spotify Bot Alert: {message.text}"
                    payload.pop("parse_mode", None)  # Remove markdown formatting

                    # Retry request with plain text
                    response = self.session.post(
                        f"{self.api_base_url}/sendMessage",
                        json=payload,
                        timeout=self.timeout,
                        verify=True,
                    )

                    if response.status_code == 200:
                        self.last_message_time = time.time()
                        self.message_count_window += 1
                        self.logger.info(
                            f"Telegram message sent successfully (plain text fallback)"
                        )
                        return True

                # Log error with more details for debugging
                try:
                    error_response = response.json()
                    error_description = error_response.get(
                        "description", "Unknown error"
                    )
                    self.logger.error(
                        f"Telegram API error: HTTP {response.status_code} - {error_description}"
                    )
                except:
                    self.logger.error(
                        f"Telegram API error: HTTP {response.status_code}"
                    )
                return False

        except requests.exceptions.Timeout:
            self.logger.error("Telegram API request timeout")
            return False
        except requests.exceptions.ConnectionError:
            self.logger.error("Telegram API connection error")
            return False
        except requests.exceptions.RequestException as e:
            self.logger.error("Telegram API request failed")
            return False
        except Exception as e:
            self.logger.error("Unexpected error sending Telegram message")
            return False

    def send_watchdog_failure(
        self, service_name: str, failure_count: int, max_retries: int
    ) -> bool:
        """
        Send watchdog failure notification

        Args:
            service_name: Name of the failed service
            failure_count: Current failure count
            max_retries: Maximum retry attempts

        Returns:
            bool: True if notification sent successfully
        """
        if not self.enabled:
            return False

        # Determine priority based on failure count
        if failure_count >= max_retries:
            priority = "critical"
            status = "FAILED PERMANENTLY"
        elif failure_count >= max_retries // 2:
            priority = "high"
            status = "MULTIPLE FAILURES"
        else:
            priority = "normal"
            status = "FAILURE DETECTED"

        message_text = (
            f"🔧 *Service Monitor Alert*\n\n"
            f"*Service:* `{service_name}`\n"
            f"*Status:* {status}\n"
            f"*Failure Count:* {failure_count}/{max_retries}\n\n"
        )

        if failure_count >= max_retries:
            message_text += (
                f"❌ Service has exceeded maximum retry attempts. "
                f"Manual intervention required."
            )
        else:
            message_text += (
                f"⚙️ Attempting automatic restart. "
                f"{max_retries - failure_count} attempts remaining."
            )

        message = TelegramMessage(text=message_text, priority=priority)
        return self.send_message(message)

    def send_service_recovery(self, service_name: str, downtime_minutes: int) -> bool:
        """
        Send service recovery notification

        Args:
            service_name: Name of the recovered service
            downtime_minutes: How long the service was down

        Returns:
            bool: True if notification sent successfully
        """
        if not self.enabled:
            return False

        message_text = (
            f"✅ *Service Recovery*\n\n"
            f"*Service:* `{service_name}`\n"
            f"*Status:* RECOVERED\n"
            f"*Downtime:* {downtime_minutes} minutes\n\n"
            f"🎉 Service is now running normally."
        )

        message = TelegramMessage(text=message_text, priority="normal")
        return self.send_message(message)

    def send_test_message(self) -> bool:
        """
        Send test message to verify Telegram integration

        Returns:
            bool: True if test message sent successfully
        """
        message_text = (
            f"🧪 *Test Message*\n\n"
            f"Telegram integration is working correctly!\n"
            f"Bot is ready to send monitoring alerts."
        )

        message = TelegramMessage(text=message_text, priority="normal")
        return self.send_message(message)

    def get_status(self) -> Dict[str, Any]:
        """
        Get current status of Telegram service

        Returns:
            Dict with service status information
        """
        return {
            "enabled": self.enabled,
            "rate_limit_remaining": max(
                0, self.rate_limit_messages - self.message_count_window
            ),
            "last_message_time": self.last_message_time,
            "configuration": {
                "timeout_seconds": self.timeout,
                "retry_attempts": self.retry_attempts,
                "rate_limit_window": self.rate_limit_window,
                "rate_limit_messages": self.rate_limit_messages,
            },
        }


def main():
    """Main function for running Telegram service as standalone microservice"""
    try:
        # Initialize configuration
        config_manager = ConfigManager()

        # Initialize Telegram service
        telegram_service = TelegramService(config_manager)

        if not telegram_service.enabled:
            print("❌ Telegram service is disabled or misconfigured")
            return

        print("🚀 Telegram service starting up...")

        # Send startup notification
        startup_message = TelegramMessage(
            text="🚀 Spotify Bot Telegram Service started successfully. Ready to send monitoring alerts.",
            priority="normal",
        )

        if telegram_service.send_message(startup_message):
            print("✅ Startup notification sent")
        else:
            print("❌ Failed to send startup notification")

        print("📱 Telegram service is running and ready to receive notifications")
        print("Press Ctrl+C to stop...")

        # Keep service running (in real implementation, this would handle message queue)
        try:
            while True:
                time.sleep(60)  # Check every minute for any pending messages
        except KeyboardInterrupt:
            print("\n🛑 Shutting down Telegram service...")

            # Send shutdown notification
            shutdown_message = TelegramMessage(
                text="🛑 Spotify Bot Telegram Service is shutting down.",
                priority="normal",
            )
            telegram_service.send_message(shutdown_message)

    except Exception as e:
        print(f"❌ Critical error in Telegram service: {e}")
        return


if __name__ == "__main__":
    main()
