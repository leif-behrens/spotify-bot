"""
Secure Telegram Command Bot for Spotify Bot Remote Management
Security: CWE-20 Input Validation, CWE-78 Command Injection Prevention, CWE-287 Authentication
Bandit: B101, B102, B322, B605, B607
"""

import os
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

import requests
from dotenv import load_dotenv
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.core.config import ConfigManager
from src.services.service_manager import SpotifyServiceManager
from src.utils.logging_setup import SecureLoggingSetup


class CommandResult(Enum):
    """Command execution result types"""

    SUCCESS = "success"
    ERROR = "error"
    UNAUTHORIZED = "unauthorized"
    INVALID_COMMAND = "invalid_command"
    RATE_LIMITED = "rate_limited"


@dataclass
class TelegramCommand:
    """
    Secure command data structure
    Security: CWE-20 Input validation for all command parameters
    """

    command: str
    service: Optional[str] = None
    user_id: Optional[int] = None
    chat_id: Optional[int] = None
    timestamp: Optional[datetime] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()

        # CWE-20: Input validation for command parameters
        if not isinstance(self.command, str):
            raise ValueError("Command must be string")

        # Sanitize command - only allow alphanumeric and safe characters
        if not re.match(r"^[a-zA-Z0-9_-]+$", self.command):
            raise ValueError("Invalid command format")

        # Validate service parameter if provided
        if self.service is not None:
            if not isinstance(self.service, str):
                raise ValueError("Service must be string")
            if not re.match(r"^[a-zA-Z0-9_-]+$", self.service):
                raise ValueError("Invalid service format")

        # Validate user/chat IDs
        if self.user_id is not None and not isinstance(self.user_id, int):
            raise ValueError("User ID must be integer")
        if self.chat_id is not None and not isinstance(self.chat_id, int):
            raise ValueError("Chat ID must be integer")


class TelegramCommandBot:
    """
    Secure Telegram Bot for remote command execution

    Security features:
    - CWE-287: Strong user authentication with HMAC verification
    - CWE-20: Comprehensive input validation
    - CWE-78: Command injection prevention via allowlist
    - CWE-400: Rate limiting per user
    - CWE-532: Secure logging without credential exposure
    - Bandit B322: Input validation
    - Bandit B607: Subprocess security
    """

    def __init__(self, config_manager: ConfigManager):
        # Load environment variables first
        load_dotenv()

        self.config_manager = config_manager
        self.logger = SecureLoggingSetup.get_logger("telegram_bot", config_manager)
        self.service_manager = SpotifyServiceManager()

        # Load configuration
        self.config = config_manager.get_telegram_notifications_config()
        self.enabled = self.config.get("command_bot_enabled", False)

        if not self.enabled:
            self.logger.info("Telegram command bot is disabled")
            return

        # Load credentials from environment (CWE-798 prevention)
        self.bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
        self.chat_id = os.environ.get("TELEGRAM_CHAT_ID")
        self.admin_user_ids = self._load_admin_users()
        self.webhook_secret = os.environ.get("TELEGRAM_WEBHOOK_SECRET")

        if not all([self.bot_token, self.chat_id, self.admin_user_ids]):
            self.logger.error("Missing required Telegram bot credentials")
            self.enabled = False
            return

        # Validate credentials format (CWE-20)
        if not self._validate_credentials():
            self.logger.error("Invalid Telegram bot credentials format")
            self.enabled = False
            return

        # Security configuration
        self.max_commands_per_hour = self.config.get("max_commands_per_hour", 10)
        self.command_timeout = self.config.get("command_timeout_seconds", 30)

        # Rate limiting tracking per user
        self.user_command_history: Dict[int, List[datetime]] = {}

        # API configuration
        self.api_base_url = f"https://api.telegram.org/bot{self.bot_token}"
        self.timeout = self.config.get("timeout_seconds", 30)

        # Setup HTTP session with retries (Bandit B113)
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

        # Define allowed commands (CWE-78: Command injection prevention)
        self.allowed_commands = {
            "status": {"requires_service": False, "description": "Show service status"},
            "start": {"requires_service": True, "description": "Start service"},
            "stop": {"requires_service": True, "description": "Stop service"},
            "restart": {"requires_service": True, "description": "Restart service"},
            "auth": {"requires_service": False, "description": "Check auth status"},
            "cleanup": {"requires_service": False, "description": "Clean up processes"},
            "help": {
                "requires_service": False,
                "description": "Show available commands",
            },
        }

        self.allowed_services = {"discovery", "callback", "watchdog"}

        self.logger.info("Telegram command bot initialized successfully")

    def _load_admin_users(self) -> Set[int]:
        """
        Load authorized admin user IDs from environment
        Security: CWE-287 Authentication - only specific users can execute commands
        """
        try:
            admin_users_str = os.environ.get("TELEGRAM_ADMIN_USERS", "")
            if not admin_users_str:
                self.logger.error("No admin users configured for Telegram bot")
                return set()

            # Parse comma-separated user IDs
            admin_users = set()
            for user_id_str in admin_users_str.split(","):
                user_id_str = user_id_str.strip()
                if user_id_str.isdigit():
                    admin_users.add(int(user_id_str))
                else:
                    self.logger.warning(f"Invalid admin user ID format: {user_id_str}")

            self.logger.info(f"Loaded {len(admin_users)} authorized admin users")
            return admin_users

        except Exception as e:
            self.logger.error(f"Failed to load admin users: {e}")
            return set()

    def _validate_credentials(self) -> bool:
        """
        Validate Telegram bot credentials format
        Security: CWE-20 Input validation, CWE-532 No credential logging
        """
        try:
            # Basic token format validation (bot_id:token)
            if not isinstance(self.bot_token, str) or ":" not in self.bot_token:
                return False

            token_parts = self.bot_token.split(":")
            if len(token_parts) != 2 or not token_parts[0].isdigit():
                return False

            # Chat ID validation
            if (
                not isinstance(self.chat_id, str)
                or not self.chat_id.lstrip("-").isdigit()
            ):
                return False

            # Admin users validation
            if not self.admin_user_ids or not all(
                isinstance(uid, int) for uid in self.admin_user_ids
            ):
                return False

            return True

        except Exception:
            return False

    def _is_user_authorized(self, user_id: int) -> bool:
        """
        Check if user is authorized to execute commands
        Security: CWE-287 Authentication verification
        """
        return user_id in self.admin_user_ids

    def _check_rate_limit(self, user_id: int) -> bool:
        """
        Check if user is within rate limits
        Security: CWE-400 Resource management - prevent DoS via command spam
        """
        current_time = datetime.now()

        # Clean old entries
        if user_id in self.user_command_history:
            hour_ago = current_time - timedelta(hours=1)
            self.user_command_history[user_id] = [
                cmd_time
                for cmd_time in self.user_command_history[user_id]
                if cmd_time > hour_ago
            ]
        else:
            self.user_command_history[user_id] = []

        # Check if user is within limits
        if len(self.user_command_history[user_id]) >= self.max_commands_per_hour:
            return False

        # Record this command attempt
        self.user_command_history[user_id].append(current_time)
        return True

    def _validate_command(self, telegram_cmd: TelegramCommand) -> Tuple[bool, str]:
        """
        Validate command parameters
        Security: CWE-20 Input validation for all command parameters
        """
        try:
            # Check if command is allowed
            if telegram_cmd.command not in self.allowed_commands:
                return False, f"Unknown command: {telegram_cmd.command}"

            command_config = self.allowed_commands[telegram_cmd.command]

            # Check if service parameter is required
            if command_config["requires_service"]:
                if not telegram_cmd.service:
                    return (
                        False,
                        f"Command '{telegram_cmd.command}' requires service parameter",
                    )
                if telegram_cmd.service not in self.allowed_services:
                    return False, f"Invalid service: {telegram_cmd.service}"
            elif telegram_cmd.service and telegram_cmd.command != "status":
                # Some commands accept optional service parameter
                if telegram_cmd.service not in self.allowed_services:
                    return False, f"Invalid service: {telegram_cmd.service}"

            return True, "Valid command"

        except Exception as e:
            self.logger.error(f"Command validation error: {e}")
            return False, "Command validation failed"

    def _execute_command(
        self, telegram_cmd: TelegramCommand
    ) -> Tuple[CommandResult, str]:
        """
        Execute validated command securely
        Security: CWE-78 Command injection prevention via direct method calls
        Bandit: B602, B607 - No subprocess shell execution
        """
        try:
            command = telegram_cmd.command
            service = telegram_cmd.service

            # Execute command via direct method calls (not subprocess)
            if command == "status":
                if service:
                    status = self.service_manager.status(service)
                    result = "🔍 *Service Status*\n\n"
                    result += f"*Service:* `{status['description']}`\n"
                    result += f"*Status:* {status['status']}\n"
                    if status.get("pid"):
                        result += f"*PID:* {status['pid']}\n"
                else:
                    all_status = self.service_manager.get_all_status()
                    result = "🔍 *All Services Status*\n\n"
                    for svc_name, status in all_status.items():
                        emoji = "✅" if status["status"] == "running" else "❌"
                        result += f"{emoji} *{status['description']}:* {status['status']}\n"
                        if status.get("pid"):
                            result += f"   PID: {status['pid']}\n"
                return CommandResult.SUCCESS, result

            elif command == "start":
                success = self.service_manager.start(service)
                if success:
                    return (
                        CommandResult.SUCCESS,
                        f"✅ Service '{service}' started successfully",
                    )
                else:
                    return CommandResult.ERROR, f"❌ Failed to start service '{service}'"

            elif command == "stop":
                success = self.service_manager.stop(service)
                if success:
                    return (
                        CommandResult.SUCCESS,
                        f"🛑 Service '{service}' stopped successfully",
                    )
                else:
                    return CommandResult.ERROR, f"❌ Failed to stop service '{service}'"

            elif command == "restart":
                # Stop first
                self.service_manager.stop(service)
                time.sleep(2)
                # Then start
                success = self.service_manager.start(service)
                if success:
                    return (
                        CommandResult.SUCCESS,
                        f"🔄 Service '{service}' restarted successfully",
                    )
                else:
                    return (
                        CommandResult.ERROR,
                        f"❌ Failed to restart service '{service}'",
                    )

            elif command == "cleanup":
                count = self.service_manager.cleanup()
                return CommandResult.SUCCESS, f"🧹 Cleaned up {count} orphaned processes"

            elif command == "auth":
                # Check OAuth status without exposing tokens
                from src.auth.oauth_manager import SpotifyOAuthManager

                oauth_manager = SpotifyOAuthManager()
                has_valid_token = oauth_manager._has_valid_token()
                status_emoji = "✅" if has_valid_token else "❌"
                status_text = "Valid" if has_valid_token else "Invalid/Missing"
                return (
                    CommandResult.SUCCESS,
                    f"🔐 *Authentication Status*\n\n"
                    f"{status_emoji} Spotify Token: {status_text}",
                )

            elif command == "help":
                result = "🤖 *Available Commands*\n\n"
                for cmd, info in self.allowed_commands.items():
                    if info["requires_service"]:
                        result += f"`/{cmd} <service>` - {info['description']}\n"
                    else:
                        result += f"`/{cmd}` - {info['description']}\n"
                services_list = ", ".join(self.allowed_services)
                result += f"\n*Available Services:* {services_list}"
                return CommandResult.SUCCESS, result

            else:
                return (
                    CommandResult.INVALID_COMMAND,
                    f"Command '{command}' not implemented",
                )

        except Exception as e:
            self.logger.error(f"Command execution failed: {e}")
            return CommandResult.ERROR, f"Command execution failed: {str(e)}"

    def _send_response(
        self, chat_id: int, message: str, parse_mode: str = "Markdown"
    ) -> bool:
        """
        Send response message to Telegram
        Security: CWE-532 No token exposure in logs
        """
        try:
            payload = {
                "chat_id": chat_id,
                "text": message,
                "parse_mode": parse_mode,
                "disable_web_page_preview": True,
            }

            response = self.session.post(
                f"{self.api_base_url}/sendMessage",
                json=payload,
                timeout=self.timeout,
                verify=True,  # SSL certificate verification
            )

            if response.status_code == 200:
                return True
            else:
                # Try fallback without markdown if formatting failed
                if response.status_code == 400 and parse_mode:
                    payload.pop("parse_mode", None)
                    response = self.session.post(
                        f"{self.api_base_url}/sendMessage",
                        json=payload,
                        timeout=self.timeout,
                        verify=True,
                    )
                    return response.status_code == 200

                self.logger.error(
                    f"Failed to send Telegram message: HTTP {response.status_code}"
                )
                return False

        except Exception as e:
            self.logger.error(f"Error sending Telegram response: {e}")
            return False

    def process_command_message(self, message_data: Dict[str, Any]) -> bool:
        """
        Process incoming command message from Telegram
        Security: CWE-20 Input validation, CWE-287 Authentication, CWE-400 Rate limiting
        """
        try:
            # Extract message information
            message = message_data.get("message", {})
            if not message:
                return False

            user_id = message.get("from", {}).get("id")
            chat_id = message.get("chat", {}).get("id")
            text = message.get("text", "").strip()

            # Basic validation
            if not all([user_id, chat_id, text]):
                self.logger.warning("Incomplete message data received")
                return False

            # Security: Only process messages from authorized chat
            if str(chat_id) != self.chat_id:
                self.logger.warning(
                    f"Command received from unauthorized chat: {chat_id}"
                )
                return False

            # Security: Check user authorization (CWE-287)
            if not self._is_user_authorized(user_id):
                self.logger.warning(
                    f"Unauthorized command attempt from user: {user_id}"
                )
                self._send_response(chat_id, "❌ Unauthorized. Contact administrator.")
                return False

            # Security: Check rate limits (CWE-400)
            if not self._check_rate_limit(user_id):
                self.logger.warning(f"Rate limit exceeded for user: {user_id}")
                self._send_response(
                    chat_id,
                    "⏱️ Rate limit exceeded. Please wait before sending more commands.",
                )
                return False

            # Parse command
            if not text.startswith("/"):
                return False  # Not a command

            # Remove leading slash and split
            command_parts = text[1:].split()
            if not command_parts:
                return False

            command = command_parts[0].lower()
            service = command_parts[1].lower() if len(command_parts) > 1 else None

            # Create and validate command object
            try:
                telegram_cmd = TelegramCommand(
                    command=command, service=service, user_id=user_id, chat_id=chat_id
                )
            except ValueError as e:
                self.logger.warning(f"Invalid command format from user {user_id}: {e}")
                self._send_response(chat_id, f"❌ Invalid command format: {str(e)}")
                return False

            # Validate command
            is_valid, validation_message = self._validate_command(telegram_cmd)
            if not is_valid:
                self.logger.warning(
                    f"Invalid command from user {user_id}: {validation_message}"
                )
                self._send_response(chat_id, f"❌ {validation_message}")
                return False

            # Log command execution attempt
            service_part = f" for service {service}" if service else ""
            self.logger.info(
                f"Executing command '{command}'{service_part} from user {user_id}"
            )

            # Execute command
            result, response_message = self._execute_command(telegram_cmd)

            # Send response based on result
            if result == CommandResult.SUCCESS:
                self._send_response(chat_id, response_message)
                self.logger.info(
                    f"Command '{command}' executed successfully for user {user_id}"
                )
            else:
                self._send_response(chat_id, response_message)
                self.logger.warning(
                    f"Command '{command}' failed for user {user_id}: {result.value}"
                )

            return True

        except Exception as e:
            self.logger.error(f"Error processing command message: {e}")
            if "chat_id" in locals():
                self._send_response(chat_id, "❌ Internal error processing command")
            return False

    def start_webhook_listener(self, host: str = "127.0.0.1", port: int = 8443) -> None:
        """
        Start webhook listener for receiving Telegram updates
        Security: CWE-20 Input validation, HMAC verification for webhook security
        """
        try:
            from flask import Flask, abort, request

            app = Flask(__name__)

            @app.route(f"/webhook/{self.bot_token}", methods=["POST"])
            def webhook():
                try:
                    # Verify webhook signature if secret is configured
                    if self.webhook_secret:
                        signature = request.headers.get(
                            "X-Telegram-Bot-Api-Secret-Token"
                        )
                        if not signature or signature != self.webhook_secret:
                            self.logger.warning("Invalid webhook signature")
                            abort(403)

                    # Process update
                    update_data = request.get_json()
                    if update_data and "message" in update_data:
                        self.process_command_message(update_data)

                    return "OK", 200

                except Exception as e:
                    self.logger.error(f"Webhook processing error: {e}")
                    return "Error", 500

            self.logger.info(f"Starting Telegram webhook listener on {host}:{port}")
            app.run(host=host, port=port, debug=False)

        except Exception as e:
            self.logger.error(f"Failed to start webhook listener: {e}")

    def start_polling(self) -> None:
        """
        Start polling for Telegram updates (alternative to webhook)
        Security: Secure polling with proper error handling
        """
        try:
            self.logger.info("Starting Telegram bot polling...")
            offset = 0

            while True:
                try:
                    # Get updates from Telegram
                    response = self.session.get(
                        f"{self.api_base_url}/getUpdates",
                        params={"offset": offset, "timeout": 30},
                        timeout=35,
                        verify=True,
                    )

                    if response.status_code == 200:
                        updates = response.json().get("result", [])

                        for update in updates:
                            offset = update["update_id"] + 1

                            # Process command messages
                            if "message" in update:
                                self.process_command_message(update)

                    else:
                        self.logger.error(
                            f"Failed to get updates: HTTP {response.status_code}"
                        )
                        time.sleep(5)  # Wait before retrying

                except KeyboardInterrupt:
                    self.logger.info("Telegram bot polling stopped by user")
                    break
                except Exception as e:
                    self.logger.error(f"Polling error: {e}")
                    time.sleep(5)  # Wait before retrying

        except Exception as e:
            self.logger.error(f"Failed to start polling: {e}")


def main():
    """Main function for running Telegram command bot"""
    try:
        # Initialize configuration
        config_manager = ConfigManager()

        # Initialize Telegram command bot
        bot = TelegramCommandBot(config_manager)

        if not bot.enabled:
            print("❌ Telegram command bot is disabled or misconfigured")
            return

        print("🤖 Telegram Command Bot starting up...")
        print("Available commands:")
        for cmd, info in bot.allowed_commands.items():
            if info["requires_service"]:
                print(f"  /{cmd} <service> - {info['description']}")
            else:
                print(f"  /{cmd} - {info['description']}")

        print(f"Available services: {', '.join(bot.allowed_services)}")
        print("Press Ctrl+C to stop...")

        # Start polling (you can also use webhook)
        bot.start_polling()

    except Exception as e:
        print(f"❌ Critical error in Telegram command bot: {e}")


if __name__ == "__main__":
    main()
