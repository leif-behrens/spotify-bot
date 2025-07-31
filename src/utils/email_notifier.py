"""
E-Mail Notification System für Spotify Bot
CWE-319: Secure Communications, CWE-798: Hard-coded Credentials Prevention
"""

import smtplib
import socket
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Optional

from ..core.config import ConfigManager
from .logging_setup import LoggingSetup

logger = LoggingSetup.get_logger("email_notifier")


class EmailNotifier:
    """
    Sichere E-Mail-Benachrichtigungen für Service-Ausfälle

    Security Features:
    - CWE-319: Verschlüsselte SMTP-Verbindung (TLS)
    - CWE-798: Keine hardcoded Credentials
    - Sichere Fehlerbehandlung ohne Credential-Leaks
    - Rate-Limiting für Spam-Schutz
    """

    def __init__(self):
        self.config_manager = ConfigManager()
        self.email_config = self.config_manager.get_email_notifications_config()
        self.last_notification_times: Dict[str, datetime] = {}
        self.min_notification_interval = 300  # 5 Minuten zwischen gleichen Meldungen

    def is_enabled(self) -> bool:
        """Prüft ob E-Mail-Benachrichtigungen aktiviert sind"""
        return self.email_config.get("enabled", False)

    def can_send_notification(self, notification_key: str) -> bool:
        """
        Rate-Limiting: Verhindert Spam bei wiederholten Fehlern
        """
        if not self.is_enabled():
            return False

        now = datetime.now()
        last_sent = self.last_notification_times.get(notification_key)

        if last_sent is None:
            return True

        time_diff = (now - last_sent).total_seconds()
        return time_diff >= self.min_notification_interval

    def send_service_failure_notification(
        self,
        service_name: str,
        failure_reason: str,
        restart_attempts: int,
        max_attempts: int,
    ) -> bool:
        """
        Sendet Benachrichtigung über Service-Ausfall
        """
        notification_key = f"service_failure_{service_name}"

        if not self.can_send_notification(notification_key):
            logger.debug(f"Rate-limited: Skipping notification for {service_name}")
            return False

        try:
            subject = (
                f"{self.email_config['subject_prefix']} Service Failure: {service_name}"
            )

            # E-Mail-Inhalt erstellen
            body = self._create_service_failure_body(
                service_name, failure_reason, restart_attempts, max_attempts
            )

            success = self._send_email(subject, body)

            if success:
                self.last_notification_times[notification_key] = datetime.now()
                logger.info(f"Service failure notification sent for {service_name}")

            return success

        except Exception as e:
            logger.error(f"Failed to send service failure notification: {e}")
            return False

    def send_service_recovery_notification(self, service_name: str) -> bool:
        """
        Sendet Benachrichtigung über Service-Wiederherstellung
        """
        notification_key = f"service_recovery_{service_name}"

        if not self.can_send_notification(notification_key):
            return False

        try:
            subject = f"{self.email_config['subject_prefix']} Service Recovered: {service_name}"

            body = self._create_service_recovery_body(service_name)

            success = self._send_email(subject, body)

            if success:
                self.last_notification_times[notification_key] = datetime.now()
                logger.info(f"Service recovery notification sent for {service_name}")

            return success

        except Exception as e:
            logger.error(f"Failed to send service recovery notification: {e}")
            return False

    def _create_service_failure_body(
        self,
        service_name: str,
        failure_reason: str,
        restart_attempts: int,
        max_attempts: int,
    ) -> str:
        """Erstellt E-Mail-Inhalt für Service-Ausfall"""
        hostname = socket.gethostname()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return f"""
Spotify Bot Service Failure Alert

Service: {service_name}
Status: FAILED
Timestamp: {timestamp}
Host: {hostname}

Failure Details:
- Reason: {failure_reason}
- Restart Attempts: {restart_attempts}/{max_attempts}
- Action: {"Service will be retried" if restart_attempts < max_attempts else "Max attempts reached - manual intervention required"}

System Information:
- Bot Version: Spotify Auto-Discovery Bot
- Configuration: Production
- Location: {hostname}

This is an automated notification from the Spotify Bot Watchdog service.
Please check the service logs for more detailed information.

---
Spotify Bot Monitoring System
        """.strip()

    def _create_service_recovery_body(self, service_name: str) -> str:
        """Erstellt E-Mail-Inhalt für Service-Wiederherstellung"""
        hostname = socket.gethostname()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return f"""
Spotify Bot Service Recovery Notification

Service: {service_name}
Status: RECOVERED
Timestamp: {timestamp}
Host: {hostname}

The service has been successfully restarted and is now running normally.

System Information:
- Bot Version: Spotify Auto-Discovery Bot
- Configuration: Production
- Location: {hostname}

This is an automated notification from the Spotify Bot Watchdog service.

---
Spotify Bot Monitoring System
        """.strip()

    def _send_email(self, subject: str, body: str) -> bool:
        """
        Sendet E-Mail über SMTP
        CWE-319: Sichere SMTP-Verbindung mit TLS
        """
        try:
            # Validiere Konfiguration
            if not self._validate_email_config():
                logger.error("Invalid email configuration - cannot send email")
                return False

            # E-Mail-Message erstellen
            msg = MIMEMultipart()
            msg["From"] = self.email_config["sender_email"]
            msg["To"] = self.email_config["recipient_email"]
            msg["Subject"] = subject

            # Body hinzufügen
            msg.attach(MIMEText(body, "plain", "utf-8"))

            # SMTP-Verbindung aufbauen
            logger.info(
                f"Connecting to SMTP server: {self.email_config['smtp_server']}:{self.email_config['smtp_port']}"
            )
            server = smtplib.SMTP(
                self.email_config["smtp_server"], self.email_config["smtp_port"]
            )

            # TLS-Verschlüsselung aktivieren - CWE-319
            if self.email_config.get("use_tls", True):
                logger.info("Starting TLS encryption")
                server.starttls()

            # Authentifizierung
            logger.info(
                f"Authenticating with email: {self.email_config['sender_email']}"
            )
            server.login(
                self.email_config["sender_email"], self.email_config["sender_password"]
            )
            logger.info("SMTP authentication successful")

            # E-Mail senden
            logger.info(f"Sending email to: {self.email_config['recipient_email']}")
            server.send_message(msg)
            server.quit()

            logger.info("Email sent successfully")
            return True

        except smtplib.SMTPAuthenticationError as e:
            logger.error(f"SMTP authentication failed - check email credentials")
            logger.error(f"Authentication error details: {str(e)}")
            logger.error("Possible causes:")
            logger.error("1. Wrong email/password combination")
            logger.error("2. Need to use App Password instead of regular password")
            logger.error("3. 2-Factor Authentication not enabled")
            logger.error("4. Account settings don't allow less secure apps")
            return False
        except smtplib.SMTPRecipientsRefused as e:
            logger.error(f"SMTP recipients refused: {e}")
            logger.error("Check if recipient email address is valid")
            return False
        except smtplib.SMTPSenderRefused as e:
            logger.error(f"SMTP sender refused: {e}")
            logger.error(
                "Check if sender email address is valid and has permission to send"
            )
            return False
        except smtplib.SMTPServerDisconnected as e:
            logger.error(f"SMTP server disconnected: {e}")
            logger.error("Server connection lost during operation")
            return False
        except smtplib.SMTPConnectError as e:
            logger.error(f"SMTP connection error: {e}")
            logger.error("Cannot connect to SMTP server")
            logger.error("Check server address, port, and internet connection")
            return False
        except smtplib.SMTPException as e:
            logger.error(f"SMTP error occurred: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            return False
        except socket.gaierror as e:
            logger.error(f"DNS/Network error: {e}")
            logger.error("Cannot resolve SMTP server hostname")
            return False
        except socket.timeout as e:
            logger.error(f"Connection timeout: {e}")
            logger.error("SMTP server did not respond in time")
            return False
        except Exception as e:
            logger.error(f"Unexpected error sending email: {e}")
            logger.error(f"Error type: {type(e).__name__}")
            logger.error("Please check your email configuration")
            return False

    def _validate_email_config(self) -> bool:
        """
        Validiert E-Mail-Konfiguration
        CWE-20: Input Validation
        """
        required_fields = [
            "smtp_server",
            "smtp_port",
            "sender_email",
            "sender_password",
            "recipient_email",
        ]

        for field in required_fields:
            value = self.email_config.get(field)
            if not value or (isinstance(value, str) and not value.strip()):
                logger.error(
                    f"Email configuration validation failed: '{field}' is missing or empty"
                )
                if field == "sender_password":
                    logger.error(
                        "For Gmail, you need an App Password, not your regular password"
                    )
                    logger.error(
                        "Generate one at: https://myaccount.google.com/apppasswords"
                    )
                return False

        # Basic E-Mail-Format-Validierung
        sender = self.email_config["sender_email"]
        recipient = self.email_config["recipient_email"]

        if "@" not in sender or "@" not in recipient:
            logger.error("Invalid email address format")
            return False

        return True

    def test_email_configuration(self) -> bool:
        """
        Testet E-Mail-Konfiguration durch Senden einer Test-Nachricht
        """
        if not self.is_enabled():
            logger.info("Email notifications are disabled")
            return False

        try:
            subject = f"{self.email_config['subject_prefix']} Configuration Test"
            body = f"""
This is a test message to verify your Spotify Bot email configuration.

If you receive this message, email notifications are working correctly.

Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Host: {socket.gethostname()}

---
Spotify Bot Monitoring System
            """.strip()

            success = self._send_email(subject, body)

            if success:
                logger.info("Test email sent successfully")
            else:
                logger.error("Test email failed")

            return success

        except Exception as e:
            logger.error(f"Email configuration test failed: {e}")
            return False
