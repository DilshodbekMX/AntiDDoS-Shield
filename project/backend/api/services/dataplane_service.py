"""
Data Plane Communication Service

Handles communication with the DPDK data plane via Unix domain socket
for real-time configuration updates.

This service sends commands to the C data plane for:
- IP list updates (whitelist, blacklist, protected)
- Configuration changes
- Stage enable/disable
"""

import socket
import struct
import logging
import ipaddress
from typing import Optional, Tuple
from threading import Lock

logger = logging.getLogger(__name__)

# Control socket path (must match C code in control_socket.h)
CONTROL_SOCKET_PATH = "/var/run/antiddos/control.sock"

# Command types (must match backend/rules.py and control_socket.h)
CMD_ADD_WHITELIST = 0x01
CMD_DEL_WHITELIST = 0x02
CMD_ADD_BLACKLIST = 0x03
CMD_DEL_BLACKLIST = 0x04
CMD_ADD_PROTECTED = 0x05
CMD_DEL_PROTECTED = 0x06
CMD_CLEAR_WHITELIST = 0x10
CMD_CLEAR_BLACKLIST = 0x11
CMD_CLEAR_PROTECTED = 0x12
CMD_GET_STATS = 0x20
CMD_RELOAD_CONFIG = 0x30
CMD_UPDATE_STAGE = 0x31

# Extended commands for policy management
CMD_POLICY_ADD = 0x50
CMD_POLICY_UPDATE = 0x51
CMD_POLICY_DELETE = 0x52
CMD_POLICY_ENABLE = 0x53
CMD_POLICY_DISABLE = 0x54

# Extended commands for configuration
CMD_CONFIG_UPDATE = 0x60
CMD_CONFIG_LAYER1 = 0x61
CMD_CONFIG_LAYER2 = 0x62

# Response codes
RESP_OK = 0x00
RESP_ERROR = 0x01
RESP_INVALID_CMD = 0x02
RESP_INVALID_IP = 0x03
RESP_RATE_LIMITED = 0x04
RESP_NOT_FOUND = 0x05
RESP_ALREADY_EXISTS = 0x06


class DataPlaneService:
    """
    Service for communicating with the DPDK data plane.

    Uses Unix domain socket to send commands and receive responses.
    Thread-safe and handles reconnection on socket errors.
    """

    def __init__(self, socket_path: str = CONTROL_SOCKET_PATH):
        self._socket_path = socket_path
        self._lock = Lock()
        self._connected = False
        self._socket: Optional[socket.socket] = None
        self._timeout = 5.0  # Socket timeout in seconds

    def _connect(self) -> bool:
        """Establish connection to the control socket."""
        if self._connected and self._socket:
            return True

        try:
            self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._socket.settimeout(self._timeout)
            self._socket.connect(self._socket_path)
            self._connected = True
            logger.info(f"Connected to data plane at {self._socket_path}")
            return True
        except (socket.error, OSError) as e:
            logger.warning(f"Failed to connect to data plane: {e}")
            self._connected = False
            self._socket = None
            return False

    def _disconnect(self):
        """Close the socket connection."""
        if self._socket:
            try:
                self._socket.close()
            except OSError:
                pass
        self._socket = None
        self._connected = False

    def _send_command(self, cmd: int, ip: int = 0, prefix_len: int = 32) -> Tuple[bool, int]:
        """
        Send a command to the data plane.

        Args:
            cmd: Command type
            ip: IP address in network byte order (0 for non-IP commands)
            prefix_len: CIDR prefix length (32 for exact match)

        Returns:
            Tuple of (success, response_code)
        """
        with self._lock:
            if not self._connect():
                return False, RESP_ERROR

            try:
                # Pack command: 1 byte cmd + 4 bytes IP + 1 byte prefix_len (6 bytes total)
                packet = struct.pack('<BIB', cmd, ip, prefix_len)
                self._socket.sendall(packet)

                # Receive response: 1 byte status + 3 bytes reserved
                response = self._socket.recv(4)
                if len(response) < 1:
                    return False, RESP_ERROR

                status = response[0]
                return status == RESP_OK, status

            except (socket.error, OSError, struct.error) as e:
                logger.warning(f"Data plane communication error: {e}")
                self._disconnect()
                return False, RESP_ERROR

    def _send_extended_command(self, cmd: int, data: bytes = b"") -> Tuple[bool, int]:
        """
        Send an extended command to the data plane.

        Args:
            cmd: Command type
            data: Additional payload data

        Returns:
            Tuple of (success, response_code)
        """
        with self._lock:
            if not self._connect():
                return False, RESP_ERROR

            try:
                # Pack command: 1 byte cmd + 2 bytes data length + data
                header = struct.pack('<BH', cmd, len(data))
                packet = header + data

                self._socket.sendall(packet)

                # Receive response
                response = self._socket.recv(4)
                if len(response) < 1:
                    return False, RESP_ERROR

                status = response[0]
                return status == RESP_OK, status

            except (socket.error, OSError, struct.error) as e:
                logger.warning(f"Data plane communication error: {e}")
                self._disconnect()
                return False, RESP_ERROR

    def _ip_to_int(self, ip_str: str) -> int:
        """Convert IP string to integer (network byte order)."""
        try:
            addr = ipaddress.ip_address(ip_str)
            if isinstance(addr, ipaddress.IPv4Address):
                return int(addr)
            else:
                # IPv6 not fully supported yet
                logger.warning(f"IPv6 address {ip_str} not supported in data plane")
                return 0
        except ValueError:
            return 0

    # ==================== IP List Commands ====================

    def add_to_whitelist(self, ip: str, prefix_len: int = 32) -> bool:
        """Add an IP or CIDR to the whitelist."""
        ip_int = self._ip_to_int(ip)
        if ip_int == 0:
            return False
        success, _ = self._send_command(CMD_ADD_WHITELIST, ip_int, prefix_len)
        if success:
            logger.info(f"Added {ip}/{prefix_len} to whitelist")
        return success

    def remove_from_whitelist(self, ip: str, prefix_len: int = 32) -> bool:
        """Remove an IP or CIDR from the whitelist."""
        ip_int = self._ip_to_int(ip)
        if ip_int == 0:
            return False
        success, _ = self._send_command(CMD_DEL_WHITELIST, ip_int, prefix_len)
        if success:
            logger.info(f"Removed {ip}/{prefix_len} from whitelist")
        return success

    def add_to_blacklist(self, ip: str, prefix_len: int = 32) -> bool:
        """Add an IP or CIDR to the blacklist."""
        ip_int = self._ip_to_int(ip)
        if ip_int == 0:
            return False
        success, _ = self._send_command(CMD_ADD_BLACKLIST, ip_int, prefix_len)
        if success:
            logger.info(f"Added {ip}/{prefix_len} to blacklist")
        return success

    def remove_from_blacklist(self, ip: str, prefix_len: int = 32) -> bool:
        """Remove an IP or CIDR from the blacklist."""
        ip_int = self._ip_to_int(ip)
        if ip_int == 0:
            return False
        success, _ = self._send_command(CMD_DEL_BLACKLIST, ip_int, prefix_len)
        if success:
            logger.info(f"Removed {ip}/{prefix_len} from blacklist")
        return success

    def add_to_protected(self, ip: str, prefix_len: int = 32) -> bool:
        """Add an IP or CIDR to the protected list."""
        ip_int = self._ip_to_int(ip)
        if ip_int == 0:
            return False
        success, _ = self._send_command(CMD_ADD_PROTECTED, ip_int, prefix_len)
        if success:
            logger.info(f"Added {ip}/{prefix_len} to protected list")
        return success

    def remove_from_protected(self, ip: str, prefix_len: int = 32) -> bool:
        """Remove an IP or CIDR from the protected list."""
        ip_int = self._ip_to_int(ip)
        if ip_int == 0:
            return False
        success, _ = self._send_command(CMD_DEL_PROTECTED, ip_int, prefix_len)
        if success:
            logger.info(f"Removed {ip}/{prefix_len} from protected list")
        return success

    def clear_whitelist(self) -> bool:
        """Clear all whitelist entries."""
        success, _ = self._send_command(CMD_CLEAR_WHITELIST)
        if success:
            logger.info("Cleared whitelist")
        return success

    def clear_blacklist(self) -> bool:
        """Clear all blacklist entries."""
        success, _ = self._send_command(CMD_CLEAR_BLACKLIST)
        if success:
            logger.info("Cleared blacklist")
        return success

    def clear_protected(self) -> bool:
        """Clear all protected list entries."""
        success, _ = self._send_command(CMD_CLEAR_PROTECTED)
        if success:
            logger.info("Cleared protected list")
        return success

    # ==================== Configuration Commands ====================

    def reload_config(self) -> bool:
        """Request data plane to reload configuration from file."""
        success, _ = self._send_command(CMD_RELOAD_CONFIG)
        if success:
            logger.info("Requested config reload")
        return success

    def update_stage(self, stage_id: int, enabled: bool) -> bool:
        """Enable or disable a protection stage."""
        # Use IP field to pass stage_id, prefix_len for enabled flag
        success, _ = self._send_command(CMD_UPDATE_STAGE, stage_id, 1 if enabled else 0)
        if success:
            logger.info(f"Updated stage {stage_id} enabled={enabled}")
        return success

    # ==================== Policy Commands ====================

    def add_policy(self, policy_id: int, policy_data: bytes) -> bool:
        """Add a policy to the data plane."""
        data = struct.pack('<I', policy_id) + policy_data
        success, _ = self._send_extended_command(CMD_POLICY_ADD, data)
        if success:
            logger.info(f"Added policy {policy_id}")
        return success

    def update_policy(self, policy_id: int, policy_data: bytes) -> bool:
        """Update a policy in the data plane."""
        data = struct.pack('<I', policy_id) + policy_data
        success, _ = self._send_extended_command(CMD_POLICY_UPDATE, data)
        if success:
            logger.info(f"Updated policy {policy_id}")
        return success

    def delete_policy(self, policy_id: int) -> bool:
        """Delete a policy from the data plane."""
        data = struct.pack('<I', policy_id)
        success, _ = self._send_extended_command(CMD_POLICY_DELETE, data)
        if success:
            logger.info(f"Deleted policy {policy_id}")
        return success

    def enable_policy(self, policy_id: int) -> bool:
        """Enable a policy."""
        data = struct.pack('<I', policy_id)
        success, _ = self._send_extended_command(CMD_POLICY_ENABLE, data)
        if success:
            logger.info(f"Enabled policy {policy_id}")
        return success

    def disable_policy(self, policy_id: int) -> bool:
        """Disable a policy."""
        data = struct.pack('<I', policy_id)
        success, _ = self._send_extended_command(CMD_POLICY_DISABLE, data)
        if success:
            logger.info(f"Disabled policy {policy_id}")
        return success

    # ==================== Configuration Push Commands ====================

    def push_layer1_config(self, config: dict) -> bool:
        """Push Layer 1 configuration."""
        import json
        config_json = json.dumps(config).encode('utf-8')
        success, _ = self._send_extended_command(CMD_CONFIG_LAYER1, config_json)
        if success:
            logger.info("Pushed Layer 1 config")
        return success

    def push_layer2_config(self, config: dict) -> bool:
        """Push Layer 2 configuration."""
        import json
        config_json = json.dumps(config).encode('utf-8')
        success, _ = self._send_extended_command(CMD_CONFIG_LAYER2, config_json)
        if success:
            logger.info("Pushed Layer 2 config")
        return success

    def push_full_config(self, layer1: dict = None, layer2: dict = None) -> bool:
        """Push full configuration."""
        import json
        config = {}
        if layer1:
            config["layer1"] = layer1
        if layer2:
            config["layer2"] = layer2

        config_json = json.dumps(config).encode('utf-8')
        success, _ = self._send_extended_command(CMD_CONFIG_UPDATE, config_json)
        if success:
            logger.info("Pushed full config")
        return success

    # ==================== Status ====================

    def is_connected(self) -> bool:
        """Check if connected to data plane."""
        with self._lock:
            return self._connected

    def ping(self) -> bool:
        """Test connection to data plane."""
        success, _ = self._send_command(CMD_GET_STATS)
        return success

    def get_health_status(self) -> dict:
        """Get data plane health status."""
        connected = self.ping()
        return {
            "connected": connected,
            "socket_path": self._socket_path,
            "status": "healthy" if connected else "disconnected"
        }


# Singleton instance
_dataplane_service: Optional[DataPlaneService] = None


def get_dataplane_service() -> DataPlaneService:
    """Get or create the singleton data plane service instance."""
    global _dataplane_service
    if _dataplane_service is None:
        _dataplane_service = DataPlaneService()
    return _dataplane_service
