"""
Inter-Process Communication für Spotify Mikroservices
Sichere Kommunikation zwischen Dashboard und Services

CWE-754: Error Handling - Comprehensive exception handling
CWE-400: Resource Management - Connection pooling and cleanup
CWE-20: Input Validation - Message validation
CWE-311: Missing Encryption - Secure local communication
Bandit: B101, B104, B108
"""

import json
import logging
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class ServiceMessage:
    """
    Sichere Nachrichtenstruktur für Service-Kommunikation
    CWE-20: Input Validation
    """

    def __init__(self, command: str, service_name: str, data: Optional[Dict] = None):
        # Input Validation - CWE-20
        if not isinstance(command, str) or len(command.strip()) == 0:
            raise ValueError("Command must be non-empty string")

        if not isinstance(service_name, str) or len(service_name.strip()) == 0:
            raise ValueError("Service name must be non-empty string")

        self.command = command.strip()[:50]  # Längenbegrenzung
        self.service_name = service_name.strip()[:50]
        self.data = data if isinstance(data, dict) else {}
        self.timestamp = datetime.now().isoformat()
        self.message_id = (
            f"{int(time.time())}-{hash(self.command + self.service_name) % 10000}"
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialisiert Nachricht zu Dictionary"""
        return {
            "command": self.command,
            "service_name": self.service_name,
            "data": self.data,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ServiceMessage":
        """
        Erstellt ServiceMessage aus Dictionary
        CWE-20: Input Validation
        """
        if not isinstance(data, dict):
            raise ValueError("Data must be dictionary")

        required_fields = ["command", "service_name"]
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required field: {field}")

        msg = cls(data["command"], data["service_name"], data.get("data"))
        msg.timestamp = data.get("timestamp", msg.timestamp)
        msg.message_id = data.get("message_id", msg.message_id)
        return msg


class ServiceRegistry:
    """
    Persistent Service Registry für Process-Management
    CWE-754: Exception Handling
    CWE-400: Resource Management
    """

    def __init__(self, registry_file: str = "ipc/service_registry.json"):
        self.registry_file = Path(registry_file)
        self.registry_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.logger = logging.getLogger(f"{__name__}.ServiceRegistry")

    def _load_registry(self) -> Dict[str, Any]:
        """
        Lädt Service Registry aus Datei
        CWE-754: Exception Handling
        """
        try:
            if self.registry_file.exists():
                with open(self.registry_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        return data
            return {}
        except Exception as e:
            self.logger.error(f"Failed to load registry: {e}")
            return {}

    def _save_registry(self, data: Dict[str, Any]) -> bool:
        """
        Speichert Service Registry in Datei
        CWE-754: Exception Handling
        """
        try:
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            self.logger.error(f"Failed to save registry: {e}")
            return False

    def register_service(
        self, service_name: str, pid: int, port: int, status: str = "running"
    ) -> bool:
        """
        Registriert Service in Registry
        CWE-20: Input Validation
        """
        try:
            # Input Validation
            if not isinstance(service_name, str) or len(service_name.strip()) == 0:
                return False

            if not isinstance(pid, int) or pid <= 0:
                return False

            if not isinstance(port, int) or port < 1024 or port > 65535:
                return False

            with self._lock:
                registry = self._load_registry()
                registry[service_name] = {
                    "pid": pid,
                    "port": port,
                    "status": status,
                    "registered_at": datetime.now().isoformat(),
                    "last_heartbeat": datetime.now().isoformat(),
                }
                return self._save_registry(registry)

        except Exception as e:
            self.logger.error(f"Failed to register service {service_name}: {e}")
            return False

    def unregister_service(self, service_name: str) -> bool:
        """Entfernt Service aus Registry"""
        try:
            with self._lock:
                registry = self._load_registry()
                if service_name in registry:
                    del registry[service_name]
                    return self._save_registry(registry)
                return True
        except Exception as e:
            self.logger.error(f"Failed to unregister service {service_name}: {e}")
            return False

    def get_service_info(self, service_name: str) -> Optional[Dict[str, Any]]:
        """Gibt Service-Informationen zurück"""
        try:
            registry = self._load_registry()
            return registry.get(service_name)
        except Exception as e:
            self.logger.error(f"Failed to get service info for {service_name}: {e}")
            return None

    def list_services(self) -> Dict[str, Dict[str, Any]]:
        """Listet alle registrierten Services"""
        try:
            return self._load_registry()
        except Exception as e:
            self.logger.error(f"Failed to list services: {e}")
            return {}

    def update_heartbeat(self, service_name: str) -> bool:
        """Aktualisiert Heartbeat für Service"""
        try:
            with self._lock:
                registry = self._load_registry()
                if service_name in registry:
                    registry[service_name][
                        "last_heartbeat"
                    ] = datetime.now().isoformat()
                    return self._save_registry(registry)
                return False
        except Exception as e:
            self.logger.error(f"Failed to update heartbeat for {service_name}: {e}")
            return False


class IPCClient:
    """
    IPC Client für Kommunikation mit Services
    CWE-400: Resource Management
    CWE-754: Exception Handling
    """

    def __init__(self, timeout: int = 10):
        self.timeout = max(1, min(timeout, 60))  # 1-60 Sekunden
        self.logger = logging.getLogger(f"{__name__}.IPCClient")

    def send_command(
        self, service_name: str, command: str, data: Optional[Dict] = None
    ) -> Optional[Dict]:
        """
        Sendet Kommando an Service
        CWE-754: Exception Handling
        CWE-400: Resource Management
        """
        try:
            # Service Registry prüfen
            registry = ServiceRegistry()
            service_info = registry.get_service_info(service_name)

            if not service_info:
                self.logger.error(f"Service {service_name} not found in registry")
                return None

            port = service_info.get("port")
            if not port:
                self.logger.error(f"No port found for service {service_name}")
                return None

            # Nachricht erstellen
            message = ServiceMessage(command, service_name, data)

            # TCP-Verbindung aufbauen
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)

                try:
                    sock.connect(("127.0.0.1", port))

                    # Nachricht senden
                    message_data = json.dumps(message.to_dict()).encode("utf-8")
                    message_length = len(message_data)

                    # Length-prefixed Protocol
                    sock.sendall(message_length.to_bytes(4, byteorder="big"))
                    sock.sendall(message_data)

                    # Antwort empfangen
                    response_length_bytes = sock.recv(4)
                    if len(response_length_bytes) != 4:
                        raise ConnectionError("Invalid response length")

                    response_length = int.from_bytes(
                        response_length_bytes, byteorder="big"
                    )
                    if response_length > 1024 * 1024:  # Max 1MB Response
                        raise ValueError("Response too large")

                    response_data = b""
                    while len(response_data) < response_length:
                        chunk = sock.recv(
                            min(response_length - len(response_data), 4096)
                        )
                        if not chunk:
                            break
                        response_data += chunk

                    # Response parsen
                    response_json = json.loads(response_data.decode("utf-8"))
                    return response_json

                except socket.timeout:
                    self.logger.error(f"Timeout connecting to service {service_name}")
                    return None
                except ConnectionRefusedError:
                    self.logger.error(f"Connection refused to service {service_name}")
                    return None

        except Exception as e:
            self.logger.error(f"Failed to send command to {service_name}: {e}")
            return None

    def get_service_status(self, service_name: str) -> Optional[Dict]:
        """Fragt Service-Status ab"""
        return self.send_command(service_name, "status")

    def start_service(self, service_name: str) -> bool:
        """Startet Service"""
        response = self.send_command(service_name, "start")
        return response and response.get("success", False)

    def stop_service(self, service_name: str) -> bool:
        """Stoppt Service"""
        response = self.send_command(service_name, "stop")
        return response and response.get("success", False)

    def restart_service(self, service_name: str) -> bool:
        """Startet Service neu"""
        response = self.send_command(service_name, "restart")
        return response and response.get("success", False)


class IPCServer:
    """
    IPC Server für Service-Daemon
    CWE-400: Resource Management
    CWE-754: Exception Handling
    """

    def __init__(self, service_name: str, port: int):
        # Input Validation
        if not isinstance(service_name, str) or len(service_name.strip()) == 0:
            raise ValueError("Service name must be non-empty string")

        if not isinstance(port, int) or port < 1024 or port > 65535:
            raise ValueError("Port must be between 1024-65535")

        self.service_name = service_name.strip()
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.is_running = False
        self.command_handlers = {}
        self.logger = logging.getLogger(f"{__name__}.IPCServer.{self.service_name}")

    def register_handler(self, command: str, handler_func):
        """Registriert Command Handler"""
        if isinstance(command, str) and callable(handler_func):
            self.command_handlers[command] = handler_func

    def start(self) -> bool:
        """
        Startet IPC Server
        CWE-400: Resource Management
        """
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(("127.0.0.1", self.port))
            self.server_socket.listen(5)

            self.is_running = True
            self.logger.info(f"IPC Server started on port {self.port}")

            # Accept Loop in separatem Thread
            threading.Thread(target=self._accept_loop, daemon=True).start()

            return True

        except Exception as e:
            self.logger.error(f"Failed to start IPC server: {e}")
            return False

    def stop(self) -> bool:
        """Stoppt IPC Server"""
        try:
            self.is_running = False
            if self.server_socket:
                self.server_socket.close()
                self.server_socket = None
            self.logger.info("IPC Server stopped")
            return True
        except Exception as e:
            self.logger.error(f"Error stopping IPC server: {e}")
            return False

    def _accept_loop(self) -> None:
        """
        Accept Loop für eingehende Verbindungen
        CWE-754: Exception Handling
        """
        while self.is_running and self.server_socket:
            try:
                client_socket, address = self.server_socket.accept()
                # Handle Client in separatem Thread
                threading.Thread(
                    target=self._handle_client, args=(client_socket,), daemon=True
                ).start()

            except OSError:
                # Socket geschlossen
                break
            except Exception as e:
                self.logger.error(f"Error in accept loop: {e}")

    def _handle_client(self, client_socket: socket.socket) -> None:
        """
        Behandelt Client-Verbindung
        CWE-754: Exception Handling
        CWE-400: Resource Management
        """
        try:
            with client_socket:
                client_socket.settimeout(30)  # 30s Timeout

                # Message Length empfangen
                length_bytes = client_socket.recv(4)
                if len(length_bytes) != 4:
                    return

                message_length = int.from_bytes(length_bytes, byteorder="big")
                if message_length > 1024 * 1024:  # Max 1MB
                    return

                # Message Data empfangen
                message_data = b""
                while len(message_data) < message_length:
                    chunk = client_socket.recv(
                        min(message_length - len(message_data), 4096)
                    )
                    if not chunk:
                        return
                    message_data += chunk

                # Message parsen
                message_dict = json.loads(message_data.decode("utf-8"))
                message = ServiceMessage.from_dict(message_dict)

                # Command verarbeiten
                response = self._process_command(message)

                # Response senden
                response_data = json.dumps(response).encode("utf-8")
                response_length = len(response_data)

                client_socket.sendall(response_length.to_bytes(4, byteorder="big"))
                client_socket.sendall(response_data)

        except Exception as e:
            self.logger.error(f"Error handling client: {e}")

    def _process_command(self, message: ServiceMessage) -> Dict[str, Any]:
        """
        Verarbeitet eingehende Commands
        CWE-754: Exception Handling
        """
        try:
            command = message.command

            if command in self.command_handlers:
                handler = self.command_handlers[command]
                result = handler(message)

                if isinstance(result, dict):
                    return result
                else:
                    return {"success": True, "result": result}
            else:
                return {
                    "success": False,
                    "error": f"Unknown command: {command}",
                    "available_commands": list(self.command_handlers.keys()),
                }

        except Exception as e:
            self.logger.error(f"Error processing command {message.command}: {e}")
            return {"success": False, "error": str(e)}
