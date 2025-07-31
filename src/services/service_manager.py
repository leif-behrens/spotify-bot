"""
Simple Service Manager for Spotify Discovery Service
CWE-78: OS Command Injection Prevention, CWE-754: Comprehensive Error Handling
Security: Follows OpenSSF Secure Coding Guidelines
"""

import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

import psutil

# Logging setup - CWE-532: Information Exposure Prevention
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class SpotifyServiceManager:
    """
    Simple service manager for Discovery Service only

    Security features:
    - CWE-78: OS Command Injection Prevention
    - CWE-754: Comprehensive Error Handling
    - CWE-400: Resource Management
    """

    def __init__(self):
        self.project_root = Path(__file__).parent.parent.parent
        self.pid_file = self.project_root / "data" / "discovery.pid"
        self.service_module = "main.py"
        self.service_args = ["run"]

        # Ensure data directory exists
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)

    def _get_pid(self) -> Optional[int]:
        """Get PID from file if exists"""
        try:
            if self.pid_file.exists():
                with open(self.pid_file, "r") as f:
                    return int(f.read().strip())
        except (ValueError, FileNotFoundError):
            pass
        return None

    def _save_pid(self, pid: int) -> None:
        """Save PID to file"""
        try:
            with open(self.pid_file, "w") as f:
                f.write(str(pid))
            os.chmod(self.pid_file, 0o600)  # Secure permissions
        except Exception as e:
            logger.error(f"Failed to save PID: {e}")

    def _remove_pid(self) -> None:
        """Remove PID file"""
        try:
            if self.pid_file.exists():
                self.pid_file.unlink()
        except Exception as e:
            logger.error(f"Failed to remove PID file: {e}")

    def is_running(self) -> bool:
        """Check if Discovery Service is running"""
        try:
            pid = self._get_pid()
            if not pid:
                return False

            # Check if process exists and is our service
            try:
                process = psutil.Process(pid)
                if not process.is_running():
                    self._remove_pid()
                    return False

                # Verify it's our service
                cmdline = process.cmdline()
                if not any(
                    self.service_module in str(cmd) or "run" in str(cmd)
                    for cmd in cmdline
                ):
                    self._remove_pid()
                    return False

                return True

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                self._remove_pid()
                return False

        except Exception as e:
            logger.error(f"Error checking service status: {e}")
            return False

    def start(self) -> bool:
        """Start Discovery Service"""
        try:
            # Check if already running
            if self.is_running():
                logger.info("Discovery Service is already running")
                return True

            # CWE-78: Command Injection Prevention - use validated paths
            python_exe = sys.executable
            if not os.path.isfile(python_exe):
                logger.error(f"Python executable not found: {python_exe}")
                return False

            # Build secure command
            cmd = [python_exe, self.service_module] + self.service_args

            logger.info("Starting Discovery Service...")

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
            self._save_pid(process.pid)

            # Give service time to start
            time.sleep(2)

            # Check if process is still running
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                logger.error("Discovery Service failed to start")
                logger.error(f"STDERR: {stderr}")
                self._remove_pid()
                return False

            logger.info(f"Discovery Service started successfully (PID: {process.pid})")
            return True

        except Exception as e:
            logger.error(f"Failed to start Discovery Service: {e}")
            return False

    def stop(self) -> bool:
        """Stop Discovery Service"""
        try:
            pid = self._get_pid()
            if not pid:
                logger.info("Discovery Service is not running")
                return True

            try:
                process = psutil.Process(pid)
                if not process.is_running():
                    logger.info("Discovery Service is already stopped")
                    self._remove_pid()
                    return True

                logger.info(f"Stopping Discovery Service (PID: {pid})")

                # Graceful shutdown
                process.terminate()
                try:
                    process.wait(timeout=10)
                except psutil.TimeoutExpired:
                    logger.warning(
                        "Discovery Service did not stop gracefully, forcing kill"
                    )
                    process.kill()
                    process.wait()

                self._remove_pid()
                logger.info("Discovery Service stopped successfully")
                return True

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.info("Discovery Service process not found")
                self._remove_pid()
                return True

        except Exception as e:
            logger.error(f"Failed to stop Discovery Service: {e}")
            return False

    def status(self) -> dict:
        """Get Discovery Service status"""
        try:
            is_running = self.is_running()
            pid = self._get_pid() if is_running else None

            return {
                "service": "discovery",
                "status": "running" if is_running else "stopped",
                "pid": pid,
            }

        except Exception as e:
            logger.error(f"Error getting service status: {e}")
            return {"service": "discovery", "status": "error", "error": str(e)}

    def cleanup(self) -> int:
        """Clean up orphaned Discovery Service processes"""
        cleanup_count = 0
        try:
            # Find all Python processes running Discovery Service
            for proc in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    if (
                        proc.info["name"]
                        and "python" in proc.info["name"].lower()
                        and proc.info["cmdline"]
                        and any(
                            self.service_module in str(cmd) or "run" in str(cmd)
                            for cmd in proc.info["cmdline"]
                        )
                    ):
                        # Check if it's not our known process
                        pid = self._get_pid()
                        if proc.info["pid"] != pid:
                            logger.info(
                                f"Found orphaned Discovery Service process: PID {proc.info['pid']}"
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
