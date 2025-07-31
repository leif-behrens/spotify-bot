"""
Simple Service Manager for Spotify Discovery Service
CWE-78: OS Command Injection Prevention, CWE-754: Comprehensive Error Handling
Security: Follows OpenSSF Secure Coding Guidelines
"""

import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import psutil

from ..utils.logging_setup import LoggingSetup

# Initialize logging
logger = LoggingSetup.get_logger(__name__)


class SpotifyServiceManager:
    """
    Service manager for Discovery Service and Callback Server

    Security features:
    - CWE-78: OS Command Injection Prevention
    - CWE-754: Comprehensive Error Handling
    - CWE-400: Resource Management
    """

    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent

        # Service configurations
        self.services = {
            "discovery": {
                "pid_file": self.project_root / "data" / "discovery.pid",
                "module": "main.py",
                "args": ["run"],
                "description": "Discovery Service",
            },
            "callback": {
                "pid_file": self.project_root / "data" / "callback.pid",
                "module": "main.py",
                "args": ["callback"],
                "description": "Callback Server",
            },
        }

        # Ensure data directory exists
        data_dir = self.project_root / "data"
        data_dir.mkdir(parents=True, exist_ok=True)

    def _get_pid(self, service_name: str) -> Optional[int]:
        """Get PID from file if exists"""
        try:
            pid_file = self.services[service_name]["pid_file"]
            if pid_file.exists():
                with open(pid_file, "r") as f:
                    return int(f.read().strip())
        except (ValueError, FileNotFoundError, KeyError):
            pass
        return None

    def _save_pid(self, service_name: str, pid: int) -> None:
        """Save PID to file"""
        try:
            pid_file = self.services[service_name]["pid_file"]
            with open(pid_file, "w") as f:
                f.write(str(pid))
            os.chmod(pid_file, 0o600)  # Secure permissions
        except Exception as e:
            logger.error(f"Failed to save PID for {service_name}: {e}")

    def _remove_pid(self, service_name: str) -> None:
        """Remove PID file"""
        try:
            pid_file = self.services[service_name]["pid_file"]
            if pid_file.exists():
                pid_file.unlink()
        except Exception as e:
            logger.error(f"Failed to remove PID file for {service_name}: {e}")

    def is_running(self, service_name: str) -> bool:
        """Check if service is running"""
        try:
            if service_name not in self.services:
                logger.error(f"Unknown service: {service_name}")
                return False

            pid = self._get_pid(service_name)
            if not pid:
                return False

            # Check if process exists and is our service
            try:
                process = psutil.Process(pid)
                if not process.is_running():
                    self._remove_pid(service_name)
                    return False

                # Verify it's our service
                cmdline = process.cmdline()
                service_config = self.services[service_name]
                expected_args = service_config["args"]

                if not any(
                    service_config["module"] in str(cmd)
                    or any(arg in str(cmd) for arg in expected_args)
                    for cmd in cmdline
                ):
                    self._remove_pid(service_name)
                    return False

                return True

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self._remove_pid(service_name)
                return False

        except Exception as e:
            logger.error(f"Error checking {service_name} service status: {e}")
            return False

    def start(self, service_name: str) -> bool:
        """Start specified service"""
        try:
            if service_name not in self.services:
                logger.error(f"Unknown service: {service_name}")
                return False

            service_config = self.services[service_name]

            # Check if already running
            if self.is_running(service_name):
                logger.info(f"{service_config['description']} is already running")
                return True

            # CWE-78: Command Injection Prevention - use validated paths
            python_exe = sys.executable
            if not os.path.isfile(python_exe):
                logger.error(f"Python executable not found: {python_exe}")
                return False

            # Build secure command
            cmd = [python_exe, service_config["module"]] + service_config["args"]

            logger.info(f"Starting {service_config['description']}...")

            # Start process with security measures
            process = subprocess.Popen(
                cmd,
                cwd=self.project_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,  # CWE-78: Prevent shell injection
                env=os.environ.copy(),
            )

            # Save PID
            self._save_pid(service_name, process.pid)

            # Give service time to start
            time.sleep(2)

            # Check if process is still running
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                logger.error(f"{service_config['description']} failed to start")
                logger.error(f"STDERR: {stderr}")
                self._remove_pid(service_name)
                return False

            logger.info(
                f"{service_config['description']} started successfully (PID: {process.pid})"
            )
            return True

        except Exception as e:
            logger.error(f"Failed to start {service_name} service: {e}")
            return False

    def stop(self, service_name: str) -> bool:
        """Stop specified service"""
        try:
            if service_name not in self.services:
                logger.error(f"Unknown service: {service_name}")
                return False

            service_config = self.services[service_name]
            pid = self._get_pid(service_name)

            if not pid:
                logger.info(f"{service_config['description']} is not running")
                return True

            try:
                process = psutil.Process(pid)
                if not process.is_running():
                    logger.info(f"{service_config['description']} is already stopped")
                    self._remove_pid(service_name)
                    return True

                logger.info(f"Stopping {service_config['description']} (PID: {pid})")

                # Graceful shutdown
                process.terminate()
                try:
                    process.wait(timeout=10)
                except psutil.TimeoutExpired:
                    logger.warning(
                        f"{service_config['description']} did not stop gracefully, forcing kill"
                    )
                    process.kill()
                    process.wait()

                self._remove_pid(service_name)
                logger.info(f"{service_config['description']} stopped successfully")
                return True

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.info(f"{service_config['description']} process not found")
                self._remove_pid(service_name)
                return True

        except Exception as e:
            logger.error(f"Failed to stop {service_name} service: {e}")
            return False

    def status(self, service_name: str) -> dict:
        """Get service status"""
        try:
            if service_name not in self.services:
                return {
                    "service": service_name,
                    "status": "unknown",
                    "error": "Unknown service",
                }

            service_config = self.services[service_name]
            is_running = self.is_running(service_name)
            pid = self._get_pid(service_name) if is_running else None

            return {
                "service": service_name,
                "description": service_config["description"],
                "status": "running" if is_running else "stopped",
                "pid": pid,
            }

        except Exception as e:
            logger.error(f"Error getting {service_name} service status: {e}")
            return {"service": service_name, "status": "error", "error": str(e)}

    def get_all_status(self) -> dict:
        """Get status of all services"""
        return {
            service_name: self.status(service_name)
            for service_name in self.services.keys()
        }

    def start_all(self) -> bool:
        """Start all services"""
        success = True
        for service_name in self.services.keys():
            if not self.start(service_name):
                success = False
        return success

    def stop_all(self) -> bool:
        """Stop all services"""
        success = True
        for service_name in self.services.keys():
            if not self.stop(service_name):
                success = False
        return success

    def cleanup(self) -> int:
        """Clean up orphaned service processes"""
        cleanup_count = 0
        try:
            # Find all Python processes running our services
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    if (
                        proc.info["name"]
                        and "python" in proc.info["name"].lower()
                        and proc.info["cmdline"]
                        and any(
                            "main.py" in str(cmd)
                            and any(
                                arg in str(cmd)
                                for service_config in self.services.values()
                                for arg in service_config["args"]
                            )
                            for cmd in proc.info["cmdline"]
                        )
                    ):
                        # Check if it's not one of our known processes
                        known_pids = {
                            self._get_pid(svc) for svc in self.services.keys()
                        }
                        known_pids.discard(None)  # Remove None values

                        if proc.info["pid"] not in known_pids:
                            logger.info(
                                f"Found orphaned service process: PID {proc.info['pid']}"
                            )
                            proc.terminate()
                            cleanup_count += 1

                except (
                    psutil.NoSuchProcess,
                    psutil.AccessDenied,
                    psutil.TimeoutExpired,
                ):
                    pass

            if cleanup_count > 0:
                logger.info(f"Cleaned up {cleanup_count} orphaned processes")

            return cleanup_count

        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            return 0
