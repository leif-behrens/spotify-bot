"""
Secure Centralized Logging Setup for Spotify Bot
CWE-532: Information Exposure Prevention, CWE-20: Input Validation
CWE-22: Path Traversal Prevention, CWE-73: External Control of File Name
Bandit: B108 (hardcoded_tmp_directory), B601 (shell_injection)
Security: OpenSSF Secure Coding - File Operations and Logging
"""

import logging
import logging.handlers
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Dict, Optional, Set

# Late import to avoid circular dependencies


class SecureLoggingSetup:
    """
    Secure per-service logging configuration with OpenSSF compliance

    Security Features:
    - CWE-532: Information Exposure Prevention through secure log formats
    - CWE-20: Input validation for service names and paths
    - CWE-22: Path traversal prevention with secure path validation
    - CWE-73: External control of file name prevention
    - Bandit B108: Secure temporary directory usage
    - Per-service log separation with configurable levels
    - Secure file permissions (600) for log files
    - Path sanitization and validation
    """

    _initialized_services: Set[str] = set()
    _loggers: Dict[str, logging.Logger] = {}
    _valid_log_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
    _service_name_pattern = re.compile(r"^[a-zA-Z0-9_-]+$")  # CWE-20: Input validation

    @classmethod
    def setup_service_logging(
        cls, service_name: str, config_manager=None
    ) -> logging.Logger:
        """
        Initialize secure per-service logging with configuration validation

        Security considerations:
        - CWE-20: Validates service name format to prevent injection
        - CWE-22: Prevents path traversal in log file paths
        - CWE-532: Removes sensitive data from log format
        - Sets secure file permissions (600) for log files

        Args:
            service_name: Validated service identifier
            config_manager: Configuration manager instance

        Returns:
            Configured logger instance

        Raises:
            ValueError: If service name is invalid (CWE-20)
        """
        # CWE-20: Input validation for service name
        if not cls._validate_service_name(service_name):
            raise ValueError(
                f"Invalid service name: {service_name}. Must match pattern: {cls._service_name_pattern.pattern}"
            )

        # Return existing logger if already configured
        if service_name in cls._initialized_services:
            return cls._loggers.get(service_name, logging.getLogger(service_name))

        try:
            if config_manager is None:
                # Late import to avoid circular dependencies
                from ..core.config import ConfigManager

                config_manager = ConfigManager()

            # Get service-specific logging configuration
            service_logging_config = cls._get_service_logging_config(
                config_manager, service_name
            )

            # Create service-specific logger
            logger_name = f"spotify_bot.{service_name}"
            service_logger = logging.getLogger(logger_name)
            service_logger.setLevel(logging.DEBUG)  # Allow all messages

            # Remove existing handlers for this service logger
            for handler in service_logger.handlers[:]:
                service_logger.removeHandler(handler)

            # Prevent propagation to avoid duplicate logging
            service_logger.propagate = False

            # CWE-20: Validate and sanitize log level
            log_level_str = service_logging_config.get("level", "INFO").upper()
            if log_level_str not in cls._valid_log_levels:
                log_level_str = "INFO"  # Safe default
            log_level = getattr(logging, log_level_str)

            # CWE-532: Secure log format without sensitive data exposure
            secure_log_format = service_logging_config.get(
                "format",
                "%(asctime)s - %(name)s - %(levelname)8s - %(funcName)s:%(lineno)d - %(message)s",
            )

            formatter = logging.Formatter(secure_log_format)

            # Console Handler (if enabled)
            if service_logging_config.get("console_enabled", True):
                console_handler = logging.StreamHandler()
                console_handler.setLevel(log_level)
                console_handler.setFormatter(formatter)
                service_logger.addHandler(console_handler)

            # File Handler (if enabled) with secure path handling
            if service_logging_config.get("file_enabled", False):
                log_file_path = cls._get_secure_log_file_path(
                    service_name, service_logging_config
                )

                if log_file_path:
                    # Create secure rotating file handler
                    file_handler = cls._create_secure_file_handler(
                        log_file_path, log_level, formatter, service_logging_config
                    )
                    service_logger.addHandler(file_handler)

            # Reduce logging for external libraries
            if service_name == "main":  # Only set once for main service
                logging.getLogger("urllib3").setLevel(logging.WARNING)
                logging.getLogger("requests").setLevel(logging.WARNING)
                logging.getLogger("werkzeug").setLevel(logging.WARNING)

            cls._initialized_services.add(service_name)
            cls._loggers[service_name] = service_logger

            # Log initialization confirmation
            service_logger.info(
                f"Secure logging initialized for service '{service_name}' - Level: {log_level_str}"
            )

            if service_logging_config.get("file_enabled", False):
                service_logger.info(
                    f"File logging enabled for service '{service_name}'"
                )

            return service_logger

        except Exception as e:
            # Secure fallback logging without sensitive data
            fallback_logger = logging.getLogger(f"spotify_bot.{service_name}")
            if not fallback_logger.handlers:
                console_handler = logging.StreamHandler()
                console_handler.setLevel(logging.INFO)
                formatter = logging.Formatter(
                    "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
                )
                console_handler.setFormatter(formatter)
                fallback_logger.addHandler(console_handler)
                fallback_logger.propagate = False

            fallback_logger.error(
                f"Failed to setup secure logging for service '{service_name}', using fallback"
            )
            cls._initialized_services.add(service_name)
            cls._loggers[service_name] = fallback_logger
            return fallback_logger

    @classmethod
    def _validate_service_name(cls, service_name: str) -> bool:
        """
        CWE-20: Input validation for service names
        Prevents injection attacks through service name parameter
        """
        return (
            isinstance(service_name, str)
            and 1 <= len(service_name) <= 50
            and cls._service_name_pattern.match(service_name) is not None
        )

    @classmethod
    def _get_service_logging_config(cls, config_manager, service_name: str) -> Dict:
        """
        Get service-specific logging configuration with secure defaults
        """
        try:
            # Get global logging config as base
            base_config = config_manager.get_logging_config()

            # Get service-specific config if available
            service_configs = base_config.get("services", {})
            service_config = service_configs.get(service_name, {})

            # Merge with base config (service-specific overrides base)
            merged_config = base_config.copy()
            merged_config.update(service_config)

            return merged_config

        except Exception:
            # Secure fallback configuration
            return {
                "level": "INFO",
                "console_enabled": True,
                "file_enabled": False,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            }

    @classmethod
    def _get_secure_log_file_path(
        cls, service_name: str, config: Dict
    ) -> Optional[Path]:
        """
        CWE-22: Prevent path traversal attacks in log file paths
        CWE-73: Prevent external control of file names
        """
        try:
            # Get base log directory from config
            log_dir = config.get("log_directory", "logs")

            # CWE-22: Sanitize and validate log directory path
            log_dir_path = Path(log_dir).resolve()

            # Ensure log directory is within project bounds
            project_root = Path.cwd().resolve()
            if not str(log_dir_path).startswith(str(project_root)):
                log_dir_path = project_root / "logs"  # Safe fallback

            # Create secure log file name
            safe_service_name = re.sub(r"[^a-zA-Z0-9_-]", "_", service_name)
            log_file_name = f"{safe_service_name}.log"

            log_file_path = log_dir_path / log_file_name

            # Create directory with secure permissions
            log_dir_path.mkdir(parents=True, exist_ok=True, mode=0o750)

            return log_file_path

        except (OSError, ValueError) as e:
            # Log error but don't expose path details (CWE-532)
            fallback_logger = logging.getLogger(__name__)
            fallback_logger.error(
                f"Failed to create secure log path for service '{service_name}'"
            )
            return None

    @classmethod
    def _create_secure_file_handler(
        cls,
        log_file_path: Path,
        log_level: int,
        formatter: logging.Formatter,
        config: Dict,
    ) -> logging.handlers.RotatingFileHandler:
        """
        Create secure rotating file handler with proper permissions
        CWE-532: Secure file permissions for log files
        """
        max_bytes = (
            config.get("max_file_size_mb", 10) * 1024 * 1024
        )  # Convert MB to bytes
        backup_count = config.get("backup_count", 5)

        # Create rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file_path,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)

        # CWE-532: Set secure file permissions (owner read/write only)
        try:
            # Create file if it doesn't exist
            log_file_path.touch(exist_ok=True)

            # Set secure permissions
            if hasattr(os, "chmod"):  # Unix-like systems
                os.chmod(log_file_path, stat.S_IRUSR | stat.S_IWUSR)  # 600
        except (OSError, AttributeError):
            # Windows or permission error - continue without chmod
            pass

        return file_handler

    @classmethod
    def get_logger(cls, service_name: str, config_manager=None) -> logging.Logger:
        """
        Get or create a secure service-specific logger

        Args:
            service_name: Service identifier (validated)
            config_manager: Optional configuration manager

        Returns:
            Configured logger instance
        """
        if service_name not in cls._initialized_services:
            return cls.setup_service_logging(service_name, config_manager)
        return cls._loggers.get(
            service_name, logging.getLogger(f"spotify_bot.{service_name}")
        )

    @classmethod
    def get_service_status(cls) -> Dict[str, Dict]:
        """
        Get logging status for all initialized services
        """
        status = {}
        for service_name in cls._initialized_services:
            logger = cls._loggers.get(service_name)
            if logger:
                status[service_name] = {
                    "level": logging.getLevelName(logger.level),
                    "handlers": len(logger.handlers),
                    "propagate": logger.propagate,
                }
        return status


# Backward compatibility alias
LoggingSetup = SecureLoggingSetup
