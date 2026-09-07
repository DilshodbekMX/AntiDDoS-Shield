"""
Telemetry Forwarder Service

Reads binary telemetry data from local DPDK sockets (stats:9999, traffic:9998)
and forwards them to a configurable remote destination over TCP or UDP.

Configured via the telemetry.forwarding section of single_org_config.json.
The dashboard UI lets users pick bind IP, destination IP/port, and protocol.
"""

import json
import logging
import socket
import struct
import threading
import time
from pathlib import Path
from typing import Optional, Dict

logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "single_org_config.json"

# Local DPDK socket addresses
LOCAL_STATS_ADDR = ("127.0.0.1", 9999)
LOCAL_TRAFFIC_ADDR = ("127.0.0.1", 9998)

# Magics for packet identification
STATS_MAGIC = 0x44504B53
SYSMON_MAGIC = 0x53595354
ANOMALY_MAGIC = 0x414E4F4D
PER_IP_FEATURES_MAGIC = 0x50495046
PER_IP_ANOMALY_MAGIC = 0x50455250
PER_IP_BASELINE_MAGIC = 0x5049424C
TRAFFIC_MAGIC = 0x5452464B

MAGIC_TO_STREAM = {
    STATS_MAGIC: "stats",
    TRAFFIC_MAGIC: "traffic",
    SYSMON_MAGIC: "sysmon",
    ANOMALY_MAGIC: "anomaly",
    PER_IP_FEATURES_MAGIC: "per_ip_features",
    PER_IP_ANOMALY_MAGIC: "per_ip_features",  # same stream filter
    PER_IP_BASELINE_MAGIC: "per_ip_features",
}


class TelemetryForwarder:
    """Reads from local DPDK sockets and forwards to a remote destination."""

    def __init__(self):
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._config: Dict = {}
        self._reload_event = threading.Event()
        self._load_config()

        # Counters (atomic via threading lock)
        self._lock = threading.Lock()
        self._packets_sent = 0
        self._bytes_sent = 0
        self._send_errors = 0
        self._last_send_ts = 0.0
        self._last_error = ""
        self._connected_to_remote = False
        self._connected_to_stats = False
        self._connected_to_traffic = False

    def _load_config(self):
        """Load forwarding config from single_org_config.json."""
        try:
            data = json.loads(CONFIG_PATH.read_text())
            self._config = data.get("telemetry", {}).get("forwarding", {})
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning("Failed to load forwarding config: %s", e)
            self._config = {}

    def reload_config(self):
        """Signal the forwarder to reload config (called from API endpoint)."""
        self._load_config()
        self._reload_event.set()
        logger.info("Telemetry forwarder config reload requested")

    def start(self):
        """Start the forwarder background thread."""
        if self._thread and self._thread.is_alive():
            return
        self._running = True
        self._thread = threading.Thread(target=self._run, daemon=True, name="telemetry-fwd")
        self._thread.start()
        logger.info("Telemetry forwarder started")

    def stop(self):
        """Stop the forwarder."""
        self._running = False
        self._reload_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Telemetry forwarder stopped")

    def _run(self):
        """Main forwarder loop."""
        while self._running:
            self._load_config()

            if not self._config.get("enabled"):
                # Wait until reload signals us or 5 seconds
                self._reload_event.wait(timeout=5.0)
                self._reload_event.clear()
                continue

            dest_ip = self._config.get("dest_ip", "")
            dest_port = self._config.get("dest_port", 9999)
            protocol = self._config.get("protocol", "tcp")
            bind_ip = self._config.get("bind_ip", "")
            interval_ms = self._config.get("interval_ms", 500)
            streams = self._config.get("streams", {})

            if not dest_ip:
                logger.warning("Forwarding enabled but no dest_ip configured")
                self._reload_event.wait(timeout=5.0)
                self._reload_event.clear()
                continue

            logger.info("Starting forwarding to %s:%d/%s (bind=%s, interval=%dms)",
                        dest_ip, dest_port, protocol, bind_ip or "auto", interval_ms)

            try:
                self._forward_loop(dest_ip, dest_port, protocol, bind_ip, interval_ms, streams)
            except Exception as e:
                logger.error("Forwarder error: %s", e)
                time.sleep(2)

    def _forward_loop(self, dest_ip: str, dest_port: int, protocol: str,
                      bind_ip: str, interval_ms: int, streams: Dict):
        """Connect to local sockets and forward to remote destination."""
        # Create outbound socket
        if protocol == "udp":
            out_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            out_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if bind_ip:
            out_sock.bind((bind_ip, 0))

        out_sock.settimeout(5.0)

        if protocol == "tcp":
            try:
                out_sock.connect((dest_ip, dest_port))
                with self._lock:
                    self._connected_to_remote = True
                logger.info("Connected to remote %s:%d/tcp", dest_ip, dest_port)
            except (ConnectionRefusedError, OSError) as e:
                with self._lock:
                    self._connected_to_remote = False
                    self._last_error = f"Cannot connect to {dest_ip}:{dest_port}: {e}"
                logger.warning("Cannot connect to %s:%d: %s", dest_ip, dest_port, e)
                out_sock.close()
                time.sleep(5)
                return

        # Connect to local stats socket
        stats_sock = None
        traffic_sock = None

        need_stats = any(streams.get(s, False) for s in ["stats", "anomaly", "per_ip_features", "sysmon"])
        need_traffic = streams.get("traffic", False)

        if need_stats:
            stats_sock = self._connect_local(LOCAL_STATS_ADDR)
            with self._lock:
                self._connected_to_stats = stats_sock is not None
        if need_traffic:
            traffic_sock = self._connect_local(LOCAL_TRAFFIC_ADDR)
            with self._lock:
                self._connected_to_traffic = traffic_sock is not None

        if not stats_sock and not traffic_sock:
            logger.warning("Cannot connect to any local DPDK socket")
            out_sock.close()
            time.sleep(5)
            return

        interval_sec = interval_ms / 1000.0
        max_drain = 32  # Max packets to drain per socket per iteration

        try:
            while self._running and not self._reload_event.is_set():
                drained = 0

                # Drain all available packets from stats socket
                if stats_sock:
                    for _ in range(max_drain):
                        data = self._recv_packet(stats_sock)
                        if data is None:
                            # Socket dead -- reconnect
                            stats_sock.close()
                            stats_sock = self._connect_local(LOCAL_STATS_ADDR)
                            with self._lock:
                                self._connected_to_stats = stats_sock is not None
                            break
                        if data is self._NO_DATA:
                            break  # No more data available right now
                        # Got a real packet
                        if self._should_forward(data, streams):
                            self._send_data(out_sock, data, dest_ip, dest_port, protocol)
                        drained += 1

                # Drain all available packets from traffic socket
                if traffic_sock:
                    for _ in range(max_drain):
                        data = self._recv_packet(traffic_sock)
                        if data is None:
                            traffic_sock.close()
                            traffic_sock = self._connect_local(LOCAL_TRAFFIC_ADDR)
                            with self._lock:
                                self._connected_to_traffic = traffic_sock is not None
                            break
                        if data is self._NO_DATA:
                            break
                        if self._should_forward(data, streams):
                            self._send_data(out_sock, data, dest_ip, dest_port, protocol)
                        drained += 1

                time.sleep(interval_sec)
        finally:
            self._reload_event.clear()
            with self._lock:
                self._connected_to_remote = False
                self._connected_to_stats = False
                self._connected_to_traffic = False
            if stats_sock:
                stats_sock.close()
            if traffic_sock:
                traffic_sock.close()
            out_sock.close()
            logger.info("Forwarding loop ended")

    def _connect_local(self, addr: tuple) -> Optional[socket.socket]:
        """Connect to a local DPDK TCP socket."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect(addr)
            s.settimeout(0.1)  # Short timeout for drain loop reads
            logger.info("Connected to local %s:%d", addr[0], addr[1])
            return s
        except (ConnectionRefusedError, OSError) as e:
            logger.debug("Cannot connect to local %s:%d: %s", addr[0], addr[1], e)
            return None

    # Sentinel to distinguish "no data available" from "socket dead"
    _NO_DATA = b''

    def _recv_packet(self, sock: socket.socket):
        """Read a complete binary packet from local socket.
        Returns bytes on success, _NO_DATA on timeout (no data), None on error."""
        try:
            header = self._recv_exact(sock, 8)
            if header is None:
                return self._NO_DATA  # Timeout -- no data available
            if len(header) < 8:
                return None  # Socket closed or broken
            magic, length = struct.unpack("<II", header)
            if length < 8 or length > 1024 * 1024:  # Sanity check: max 1MB
                return None  # Corrupt -- treat as error
            remaining = length - 8
            if remaining > 0:
                body = self._recv_exact(sock, remaining)
                if body is None or len(body) < remaining:
                    return None  # Partial read failure
                return header + body
            return header
        except socket.timeout:
            return self._NO_DATA
        except OSError:
            return None

    def _recv_exact(self, sock: socket.socket, n: int) -> Optional[bytes]:
        """Receive exactly n bytes.
        Returns bytes on success, None on timeout (no data), empty bytes on socket close."""
        data = bytearray()
        retries = 0
        while len(data) < n:
            try:
                chunk = sock.recv(n - len(data))
                if not chunk:
                    return b''  # Socket closed (peer disconnected)
                data.extend(chunk)
                retries = 0
            except socket.timeout:
                if not data:
                    return None  # No data at all -- nothing available
                retries += 1
                if retries > 10:  # Give up after ~1s of retries on partial read
                    return b''  # Treat as broken
                continue
        return bytes(data)

    def _should_forward(self, data: bytes, streams: Dict) -> bool:
        """Check if this packet's stream type is enabled for forwarding."""
        if len(data) < 4:
            return False
        magic = struct.unpack("<I", data[:4])[0]
        stream_name = MAGIC_TO_STREAM.get(magic)
        if stream_name is None:
            return True  # Unknown magic -- forward anyway
        return streams.get(stream_name, False)

    def _send_data(self, sock: socket.socket, data: bytes,
                   dest_ip: str, dest_port: int, protocol: str):
        """Send data to the remote destination."""
        try:
            if protocol == "udp":
                sock.sendto(data, (dest_ip, dest_port))
            else:
                sock.sendall(data)
            with self._lock:
                self._packets_sent += 1
                self._bytes_sent += len(data)
                self._last_send_ts = time.time()
        except (BrokenPipeError, ConnectionResetError, OSError) as e:
            with self._lock:
                self._send_errors += 1
                self._last_error = str(e)
                self._connected_to_remote = False
            logger.debug("Forward send error: %s", e)
            raise  # Let the loop reconnect

    @property
    def is_active(self) -> bool:
        return self._running and self._config.get("enabled", False)

    @property
    def status(self) -> Dict:
        with self._lock:
            last_send_ago = round(time.time() - self._last_send_ts, 1) if self._last_send_ts > 0 else None
            return {
                "running": self._running,
                "enabled": self._config.get("enabled", False),
                "dest_ip": self._config.get("dest_ip", ""),
                "dest_port": self._config.get("dest_port", 0),
                "protocol": self._config.get("protocol", "tcp"),
                "connected_to_remote": self._connected_to_remote,
                "connected_to_stats": self._connected_to_stats,
                "connected_to_traffic": self._connected_to_traffic,
                "packets_sent": self._packets_sent,
                "bytes_sent": self._bytes_sent,
                "send_errors": self._send_errors,
                "last_send_ago_sec": last_send_ago,
                "last_error": self._last_error,
            }


# Singleton
_forwarder: Optional[TelemetryForwarder] = None


def get_forwarder() -> Optional[TelemetryForwarder]:
    return _forwarder


def init_forwarder() -> TelemetryForwarder:
    global _forwarder
    _forwarder = TelemetryForwarder()
    _forwarder.start()
    return _forwarder


def stop_forwarder():
    global _forwarder
    if _forwarder:
        _forwarder.stop()
        _forwarder = None
