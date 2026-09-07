"""
Layer 3 (ML Attribution) data parsers.

Reads Layer 3 data from shared memory:
- Dynamic signatures generated at runtime
- Per-source-IP statistics (top attackers)
- Attribution engine stats
"""

import struct
import mmap
import os
from typing import Dict, List, Optional, Any
from datetime import datetime

# Shared memory path
POSIX_SHMEM_PATH = "/dev/shm/antiddos_layer1_shmem"

# ============================================================================
# Shared Memory Layout Constants (must match C headers)
# These sizes are verified with sizeof() and offsetof() from C code
# ============================================================================

# =============================================================================
# CRITICAL: All offsets are taken directly from C offsetof() output.
# DO NOT calculate offsets - use the verified values from C compilation.
# See layer3/feature_reader.py for the canonical offset definitions.
# =============================================================================

# Dynamic signature table
MAX_DYNAMIC_SIGNATURES = 256
DYNAMIC_SIGNATURE_SIZE = 128
DYNAMIC_SIG_TABLE_ENTRIES_OFFSET = 64  # Entries start at offset 64 (64-byte aligned)
DYNAMIC_SIG_TABLE_FOOTER_OFFSET = 32832  # Offset to footer (after entries)
DYNAMIC_SIG_TABLE_SIZE = 32896  # sizeof(struct dynamic_signature_table)

# Packet ring
PACKET_RING_ENTRIES = 65536
PACKET_SAMPLE_SIZE = 64
PACKET_RING_METADATA = 128
PACKET_RING_SIZE = (PACKET_SAMPLE_SIZE * PACKET_RING_ENTRIES) + PACKET_RING_METADATA

# Source IP export
MAX_SRC_IP_EXPORT = 4096  # Updated from 1024 to match C MAX_SRC_IP_EXPORT
SRC_IP_ENTRY_SIZE = 128
SRC_IP_EXPORT_HEADER_SIZE = 32
SRC_IP_EXPORT_ENTRIES_SIZE = SRC_IP_ENTRY_SIZE * MAX_SRC_IP_EXPORT

# =============================================================================
# Direct offsets from C offsetof() - AUTHORITATIVE VALUES
# These MUST match the actual C struct layout verified via compilation
# =============================================================================
OFFSET_POLICIES = 0
OFFSET_REPUTATION = 640128
OFFSET_FEEDBACK = 3840256
OFFSET_GLOBAL_STATE = 4480320
OFFSET_L2_FEATURES = 4480448
OFFSET_L2_PER_IP = 4480640
OFFSET_DYNAMIC_SIGS = 5791424    # offsetof(struct layer1_shared_memory, dynamic_sigs)
OFFSET_PACKET_RING = 5824320     # offsetof(struct layer1_shared_memory, packet_ring)
OFFSET_SRC_IP_EXPORT = 10018752  # offsetof(struct layer1_shared_memory, src_ip_export)

# Policy actions
POLICY_ACTION_NAMES = {
    0: 'ALLOW',
    1: 'DROP',
    2: 'RATE_LIMIT',
    3: 'CHALLENGE',
    4: 'LOG',
    5: 'REDIRECT',
}

# Protocol names
PROTO_NAMES = {
    0: 'ANY',
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
}

# Source IP flags
SRC_IP_FLAG_ACTIVE = 0x0001
SRC_IP_FLAG_ATTACKER = 0x0002
SRC_IP_FLAG_TRUSTED = 0x0004
SRC_IP_FLAG_RATE_LIMITED = 0x0008
SRC_IP_FLAG_CHALLENGED = 0x0010
SRC_IP_FLAG_BLOCKED = 0x0020
SRC_IP_FLAG_NEW = 0x0040


def ip_int_to_str(ip_int: int) -> str:
    """Convert IP integer (network byte order) to string."""
    if ip_int == 0:
        return "0.0.0.0"
    # Network byte order: most significant byte first
    return f"{(ip_int >> 24) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 8) & 0xFF}.{ip_int & 0xFF}"


def ip_int_to_str_le(ip_int: int) -> str:
    """Convert IP integer (little-endian / DPDK format) to string."""
    if ip_int == 0:
        return "0.0.0.0"
    # Swap bytes for DPDK format
    return f"{ip_int & 0xFF}.{(ip_int >> 8) & 0xFF}.{(ip_int >> 16) & 0xFF}.{(ip_int >> 24) & 0xFF}"


class Layer3DataReader:
    """Reads Layer 3 data from shared memory."""

    def __init__(self, shmem_path: str = POSIX_SHMEM_PATH):
        self.path = shmem_path
        self.fd: Optional[int] = None
        self.mm: Optional[mmap.mmap] = None
        self.connected = False

    def connect(self) -> bool:
        """Connect to shared memory."""
        try:
            if not os.path.exists(self.path):
                return False

            self.fd = os.open(self.path, os.O_RDONLY)
            file_size = os.fstat(self.fd).st_size

            if file_size < OFFSET_SRC_IP_EXPORT:
                os.close(self.fd)
                return False

            self.mm = mmap.mmap(self.fd, file_size, access=mmap.ACCESS_READ)
            self.connected = True
            return True

        except Exception as e:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
            return False

    def close(self):
        """Close connection."""
        if self.mm:
            self.mm.close()
            self.mm = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.connected = False

    def get_dynamic_signatures(self) -> Dict[str, Any]:
        """Get dynamic signatures from shared memory."""
        if not self.connected:
            if not self.connect():
                return {"error": "Not connected", "signatures": [], "stats": {}}

        try:
            self.mm.seek(OFFSET_DYNAMIC_SIGS)
            version = struct.unpack("<Q", self.mm.read(8))[0]
            count = struct.unpack("<I", self.mm.read(4))[0]
            self.mm.read(4)  # pad

            signatures = []
            entries_offset = OFFSET_DYNAMIC_SIGS + DYNAMIC_SIG_TABLE_ENTRIES_OFFSET

            for i in range(min(count, MAX_DYNAMIC_SIGNATURES)):
                offset = entries_offset + (i * DYNAMIC_SIGNATURE_SIZE)
                self.mm.seek(offset)
                data = self.mm.read(DYNAMIC_SIGNATURE_SIZE)

                # Parse dynamic_signature struct (128 bytes)
                # id(4), enabled(4), created_ns(8), expires_ns(8),
                # protocol(1), protocol_match(1), pad(2), dst_ip(4), dst_ip_mask(4),
                # dst_port_min(2), dst_port_max(2), src_port_min(2), src_port_max(2),
                # pkt_size_min(2), pkt_size_max(2), ttl_min(1), ttl_max(1),
                # tcp_flags_mask(1), tcp_flags_value(1), tcp_mss_min(2), tcp_mss_max(2),
                # tcp_wscale_min(1), tcp_wscale_max(1), tcp_window_min(2), tcp_window_max(2),
                # payload_pattern(16), payload_pattern_len(1), payload_match_offset(1),
                # action(1), pad(1), rate_limit_pps(4),
                # match_count(8), last_match_ns(8),
                # attack_type(1), confidence(1), priority(2), pad(6)

                sig_id, enabled, created_ns, expires_ns = struct.unpack_from("<IIQQ", data, 0)

                if sig_id == 0 and enabled == 0:
                    continue

                protocol = data[24]
                dst_ip = struct.unpack_from("<I", data, 28)[0]
                dst_port_min, dst_port_max = struct.unpack_from("<HH", data, 36)
                src_port_min, src_port_max = struct.unpack_from("<HH", data, 40)
                pkt_size_min, pkt_size_max = struct.unpack_from("<HH", data, 44)
                ttl_min, ttl_max = data[48], data[49]
                tcp_flags_mask, tcp_flags_value = data[50], data[51]

                # Offsets after payload pattern (16 bytes at offset 62):
                # payload_pattern_len(1) at 78, payload_match_offset(1) at 79
                # action(1) at 80, pad(1) at 81, pad(2) implicit, rate_limit_pps(4) at 84
                # match_count(8) at 88, last_match_ns(8) at 96
                # attack_type(1) at 104, confidence(1) at 105, priority(2) at 106
                action = data[80]
                rate_limit_pps = struct.unpack_from("<I", data, 84)[0]
                match_count = struct.unpack_from("<Q", data, 88)[0]
                last_match_ns = struct.unpack_from("<Q", data, 96)[0]
                attack_type, confidence, priority = struct.unpack_from("<BBH", data, 104)

                # Calculate remaining TTL
                now_ns = int(datetime.now().timestamp() * 1e9)
                remaining_ns = expires_ns - now_ns if expires_ns > 0 else 0
                remaining_sec = max(0, remaining_ns // 1_000_000_000)

                sig = {
                    "id": sig_id,
                    "enabled": bool(enabled),
                    "protocol": PROTO_NAMES.get(protocol, str(protocol)),
                    "protocol_num": protocol,
                    "dst_ip": ip_int_to_str_le(dst_ip) if dst_ip else "ANY",
                    "dst_port": f"{dst_port_min}-{dst_port_max}" if dst_port_max > dst_port_min else (str(dst_port_min) if dst_port_min else "ANY"),
                    "src_port": f"{src_port_min}-{src_port_max}" if src_port_max > src_port_min else (str(src_port_min) if src_port_min else "ANY"),
                    "pkt_size": f"{pkt_size_min}-{pkt_size_max}" if pkt_size_max > pkt_size_min else ("ANY" if pkt_size_min == 0 else str(pkt_size_min)),
                    "ttl": f"{ttl_min}-{ttl_max}" if ttl_max > ttl_min else ("ANY" if ttl_min == 0 else str(ttl_min)),
                    "tcp_flags": f"mask=0x{tcp_flags_mask:02x},val=0x{tcp_flags_value:02x}" if tcp_flags_mask else "ANY",
                    "action": POLICY_ACTION_NAMES.get(action, str(action)),
                    "rate_limit_pps": rate_limit_pps if action == 2 else None,
                    "confidence": confidence,
                    "priority": priority,
                    "match_count": match_count,
                    "last_match": datetime.fromtimestamp(last_match_ns / 1e9).isoformat() if last_match_ns > 0 else None,
                    "created": datetime.fromtimestamp(created_ns / 1e9).isoformat() if created_ns > 0 else None,
                    "expires_in_sec": remaining_sec,
                    "expired": remaining_sec == 0 and expires_ns > 0,
                }
                signatures.append(sig)

            # Read stats from footer (starts at offset 32832 from table start)
            footer_offset = OFFSET_DYNAMIC_SIGS + DYNAMIC_SIG_TABLE_FOOTER_OFFSET
            self.mm.seek(footer_offset)
            total_matches = struct.unpack("<Q", self.mm.read(8))[0]
            total_dropped = struct.unpack("<Q", self.mm.read(8))[0]
            last_update_ns = struct.unpack("<Q", self.mm.read(8))[0]

            return {
                "version": version,
                "count": len(signatures),
                "signatures": signatures,
                "stats": {
                    "total_matches": total_matches,
                    "total_dropped": total_dropped,
                    "last_update": datetime.fromtimestamp(last_update_ns / 1e9).isoformat() if last_update_ns > 0 else None,
                }
            }

        except Exception as e:
            return {"error": str(e), "signatures": [], "stats": {}}

    def get_top_attackers(self, limit: int = 50) -> Dict[str, Any]:
        """Get top source IPs by PPS (potential attackers)."""
        if not self.connected:
            if not self.connect():
                return {"error": "Not connected", "attackers": [], "stats": {}}

        try:
            self.mm.seek(OFFSET_SRC_IP_EXPORT)
            version = struct.unpack("<Q", self.mm.read(8))[0]

            # Check for write in progress
            if version & 1:
                return {"error": "Data being updated", "attackers": [], "stats": {}}

            entry_count = struct.unpack("<I", self.mm.read(4))[0]
            total_tracked = struct.unpack("<I", self.mm.read(4))[0]
            last_update_ns = struct.unpack("<Q", self.mm.read(8))[0]
            window_start_ns = struct.unpack("<Q", self.mm.read(8))[0]

            attackers = []
            entries_offset = OFFSET_SRC_IP_EXPORT + SRC_IP_EXPORT_HEADER_SIZE

            for i in range(min(entry_count, limit, MAX_SRC_IP_EXPORT)):
                offset = entries_offset + (i * SRC_IP_ENTRY_SIZE)
                self.mm.seek(offset)
                data = self.mm.read(SRC_IP_ENTRY_SIZE)

                # Parse src_ip_entry_export struct (128 bytes)
                src_ip, flags = struct.unpack_from("<II", data, 0)

                if src_ip == 0:
                    continue

                first_seen_ns, last_seen_ns = struct.unpack_from("<QQ", data, 8)
                packets_window, bytes_window, flows_window = struct.unpack_from("<III", data, 24)
                packets_total, bytes_total = struct.unpack_from("<QQ", data, 36)

                tcp_pkt, udp_pkt, icmp_pkt, other_pkt = struct.unpack_from("<HHHH", data, 52)
                syn_count, synack_count, ack_count, rst_count, fin_count, incomplete = struct.unpack_from("<HHHHHH", data, 60)

                unique_dst_ports, unique_dst_ips = data[72], data[73]
                min_pkt_size, max_pkt_size, avg_pkt_size = struct.unpack_from("<HHH", data, 74)
                min_ttl, max_ttl = data[80], data[81]

                pps_current, bps_current = struct.unpack_from("<II", data, 88)
                action, score, rate_limited, challenged = data[96], data[97], data[98], data[99]

                # Calculate ratios
                total_pkts = tcp_pkt + udp_pkt + icmp_pkt + other_pkt
                tcp_ratio = (tcp_pkt / total_pkts * 100) if total_pkts > 0 else 0
                udp_ratio = (udp_pkt / total_pkts * 100) if total_pkts > 0 else 0
                icmp_ratio = (icmp_pkt / total_pkts * 100) if total_pkts > 0 else 0

                syn_ratio = (syn_count / tcp_pkt * 100) if tcp_pkt > 0 else 0
                incomplete_ratio = (incomplete / syn_count * 100) if syn_count > 0 else 0

                # Determine primary protocol
                if tcp_ratio >= 80:
                    primary_proto = "TCP"
                elif udp_ratio >= 80:
                    primary_proto = "UDP"
                elif icmp_ratio >= 80:
                    primary_proto = "ICMP"
                else:
                    primary_proto = "MIXED"

                # Flag interpretation
                flag_strs = []
                if flags & SRC_IP_FLAG_ATTACKER:
                    flag_strs.append("ATTACKER")
                if flags & SRC_IP_FLAG_TRUSTED:
                    flag_strs.append("TRUSTED")
                if flags & SRC_IP_FLAG_BLOCKED:
                    flag_strs.append("BLOCKED")
                if flags & SRC_IP_FLAG_RATE_LIMITED:
                    flag_strs.append("RATE_LIMITED")
                if flags & SRC_IP_FLAG_CHALLENGED:
                    flag_strs.append("CHALLENGED")

                attacker = {
                    "src_ip": ip_int_to_str_le(src_ip),
                    "src_ip_int": src_ip,
                    "pps": pps_current,
                    "bps": bps_current,
                    "packets_window": packets_window,
                    "bytes_window": bytes_window,
                    "packets_total": packets_total,
                    "primary_protocol": primary_proto,
                    "tcp_ratio": round(tcp_ratio, 1),
                    "udp_ratio": round(udp_ratio, 1),
                    "icmp_ratio": round(icmp_ratio, 1),
                    "syn_ratio": round(syn_ratio, 1),
                    "incomplete_handshake_ratio": round(incomplete_ratio, 1),
                    "syn_count": syn_count,
                    "incomplete_handshakes": incomplete,
                    "unique_dst_ports": unique_dst_ports,
                    "unique_dst_ips": unique_dst_ips,
                    "avg_pkt_size": avg_pkt_size,
                    "ttl_range": f"{min_ttl}-{max_ttl}",
                    "score": score,
                    "action": POLICY_ACTION_NAMES.get(action, str(action)),
                    "flags": flag_strs,
                    "is_attacker": bool(flags & SRC_IP_FLAG_ATTACKER),
                    "is_blocked": bool(flags & SRC_IP_FLAG_BLOCKED),
                    "is_rate_limited": bool(flags & SRC_IP_FLAG_RATE_LIMITED),
                    "first_seen": datetime.fromtimestamp(first_seen_ns / 1e9).isoformat() if first_seen_ns > 0 else None,
                    "last_seen": datetime.fromtimestamp(last_seen_ns / 1e9).isoformat() if last_seen_ns > 0 else None,
                }
                attackers.append(attacker)

            return {
                "version": version,
                "entry_count": entry_count,
                "total_tracked": total_tracked,
                "attackers": attackers,
                "last_update": datetime.fromtimestamp(last_update_ns / 1e9).isoformat() if last_update_ns > 0 else None,
            }

        except Exception as e:
            return {"error": str(e), "attackers": [], "stats": {}}

    def get_packet_ring_stats(self) -> Dict[str, Any]:
        """Get packet ring buffer statistics."""
        if not self.connected:
            if not self.connect():
                return {"error": "Not connected"}

        try:
            header_offset = OFFSET_PACKET_RING + (PACKET_SAMPLE_SIZE * PACKET_RING_ENTRIES)
            self.mm.seek(header_offset)

            write_idx = struct.unpack("<Q", self.mm.read(8))[0]
            packets_written = struct.unpack("<Q", self.mm.read(8))[0]
            packets_dropped = struct.unpack("<Q", self.mm.read(8))[0]
            read_idx = struct.unpack("<Q", self.mm.read(8))[0]
            packets_read = struct.unpack("<Q", self.mm.read(8))[0]
            sampling_rate = struct.unpack("<I", self.mm.read(4))[0]
            sample_counter = struct.unpack("<I", self.mm.read(4))[0]
            enabled = struct.unpack("<I", self.mm.read(4))[0]
            target_dst_ip = struct.unpack("<I", self.mm.read(4))[0]
            target_protocol = self.mm.read(1)[0]
            self.mm.read(1)  # target_proto_cat
            target_dst_port = struct.unpack("<H", self.mm.read(2))[0]

            available = (write_idx - read_idx) if write_idx >= read_idx else 0

            return {
                "enabled": bool(enabled),
                "sampling_rate": f"1:{sampling_rate}" if sampling_rate > 0 else "disabled",
                "sampling_rate_value": sampling_rate,
                "packets_written": packets_written,
                "packets_read": packets_read,
                "packets_dropped": packets_dropped,
                "available": min(available, PACKET_RING_ENTRIES),
                "buffer_size": PACKET_RING_ENTRIES,
                "filter": {
                    "dst_ip": ip_int_to_str_le(target_dst_ip) if target_dst_ip else "ALL",
                    "protocol": PROTO_NAMES.get(target_protocol, "ALL") if target_protocol else "ALL",
                    "dst_port": target_dst_port if target_dst_port else "ALL",
                }
            }

        except Exception as e:
            return {"error": str(e)}

    def get_layer3_summary(self) -> Dict[str, Any]:
        """Get Layer 3 summary for dashboard."""
        signatures = self.get_dynamic_signatures()
        attackers = self.get_top_attackers(limit=10)
        packet_ring = self.get_packet_ring_stats()

        active_sigs = len([s for s in signatures.get("signatures", []) if s.get("enabled") and not s.get("expired")])
        total_attackers = len([a for a in attackers.get("attackers", []) if a.get("is_attacker")])
        blocked_ips = len([a for a in attackers.get("attackers", []) if a.get("is_blocked")])

        return {
            "status": "active" if active_sigs > 0 or total_attackers > 0 else "idle",
            "dynamic_signatures": {
                "active": active_sigs,
                "total": signatures.get("count", 0),
                "total_matches": signatures.get("stats", {}).get("total_matches", 0),
                "total_dropped": signatures.get("stats", {}).get("total_dropped", 0),
            },
            "source_ips": {
                "tracked": attackers.get("total_tracked", 0),
                "top_talkers": attackers.get("entry_count", 0),
                "flagged_attackers": total_attackers,
                "blocked": blocked_ips,
            },
            "packet_sampling": {
                "enabled": packet_ring.get("enabled", False),
                "rate": packet_ring.get("sampling_rate", "disabled"),
                "available": packet_ring.get("available", 0),
                "filter_active": packet_ring.get("filter", {}).get("dst_ip") != "ALL",
            },
            "top_attackers": attackers.get("attackers", [])[:5],
        }


# Global instance
_reader: Optional[Layer3DataReader] = None


def get_reader() -> Layer3DataReader:
    """Get or create Layer 3 data reader."""
    global _reader
    if _reader is None:
        _reader = Layer3DataReader()
    return _reader


class DynamicSignatureWriter:
    """Writes dynamic signatures to shared memory."""

    # Signature struct: 128 bytes
    # id(4), enabled(4), created_ns(8), expires_ns(8) = 24
    # protocol(1), protocol_match(1), pad(2), dst_ip(4), dst_ip_mask(4) = 12
    # dst_port_min(2), dst_port_max(2), src_port_min(2), src_port_max(2) = 8
    # pkt_size_min(2), pkt_size_max(2), ttl_min(1), ttl_max(1) = 6
    # tcp_flags_mask(1), tcp_flags_value(1) = 2
    # tcp_mss_min(2), tcp_mss_max(2), tcp_wscale_min(1), tcp_wscale_max(1) = 6
    # tcp_window_min(2), tcp_window_max(2) = 4
    # payload_pattern(16), payload_pattern_len(1), payload_match_offset(1) = 18
    # action(1), pad(1), rate_limit_pps(4) = 6
    # match_count(8), last_match_ns(8) = 16
    # attack_type(1), confidence(1), priority(2), pad(6) = 10
    # Total: 112 bytes + padding to 128

    SIGNATURE_FORMAT = '<II QQ BxH II HH HH HH BB HH BB HH 16s BB Bx I QQ BB H 6x'
    SIGNATURE_SIZE = 128

    def __init__(self, shmem_path: str = POSIX_SHMEM_PATH):
        self.path = shmem_path
        self.fd: Optional[int] = None
        self.mm: Optional[mmap.mmap] = None
        self.connected = False
        self._next_id = 1

    def connect(self) -> bool:
        """Connect to shared memory for writing."""
        try:
            if not os.path.exists(self.path):
                print(f"DynamicSignatureWriter: Shared memory not found at {self.path}")
                print("  -> Layer 1 (DPDK) must be running to create shared memory")
                return False

            self.fd = os.open(self.path, os.O_RDWR)
            file_size = os.fstat(self.fd).st_size

            if file_size < OFFSET_DYNAMIC_SIGS + DYNAMIC_SIG_TABLE_SIZE:
                os.close(self.fd)
                print(f"DynamicSignatureWriter: Shared memory too small ({file_size} bytes)")
                return False

            self.mm = mmap.mmap(self.fd, file_size, access=mmap.ACCESS_WRITE)
            self.connected = True

            # Initialize _next_id from existing signatures to avoid duplicates
            max_id = 0
            for i in range(MAX_DYNAMIC_SIGNATURES):
                offset = OFFSET_DYNAMIC_SIGS + DYNAMIC_SIG_TABLE_ENTRIES_OFFSET + (i * DYNAMIC_SIGNATURE_SIZE)
                self.mm.seek(offset)
                entry_id = struct.unpack('<I', self.mm.read(4))[0]
                if entry_id > max_id:
                    max_id = entry_id
            self._next_id = max_id + 1

            print(f"DynamicSignatureWriter: Connected to {self.path} successfully (next_id={self._next_id})")
            return True

        except PermissionError as e:
            print(f"DynamicSignatureWriter: Permission denied accessing {self.path}")
            print("  -> Run 'sudo chmod 666 /dev/shm/antiddos_layer1_shmem' to fix")
            print("  -> Or restart Layer 1 (DPDK) with the latest build")
            self.connected = False
            return False
        except Exception as e:
            print(f"DynamicSignatureWriter connect error: {e}")
            self.connected = False
            return False

    def disconnect(self):
        """Disconnect from shared memory."""
        if self.mm:
            self.mm.close()
            self.mm = None
        if self.fd:
            os.close(self.fd)
            self.fd = None
        self.connected = False

    def _find_empty_slot(self) -> int:
        """Find first empty signature slot. Returns -1 if full."""
        if not self.connected:
            return -1

        for i in range(MAX_DYNAMIC_SIGNATURES):
            offset = OFFSET_DYNAMIC_SIGS + DYNAMIC_SIG_TABLE_ENTRIES_OFFSET + (i * DYNAMIC_SIGNATURE_SIZE)
            self.mm.seek(offset)
            sig_id, enabled = struct.unpack('<II', self.mm.read(8))
            if sig_id == 0 or enabled == 0:
                return i

        return -1

    def add_signature(self, sig: Dict[str, Any]) -> int:
        """
        Add a dynamic signature.

        Args:
            sig: Dictionary with signature fields:
                - protocol: 0=any, 6=TCP, 17=UDP, 1=ICMP
                - dst_ip: Destination IP string or int (0=any)
                - dst_port: Destination port or (min, max) tuple (0=any)
                - src_port: Source port or (min, max) tuple (0=any)
                - pkt_size: Packet size or (min, max) tuple (0=any)
                - ttl: TTL or (min, max) tuple (0=any)
                - tcp_flags: (mask, value) tuple for TCP flags (0=any)
                - action: 0=ALLOW, 1=DROP, 2=RATE_LIMIT
                - rate_limit_pps: PPS limit if action=2
                - ttl_seconds: Signature lifetime (default: 300)
                - attack_type: Attack type ID
                - confidence: Confidence 0-100
                - priority: Higher = checked first

        Returns:
            Signature ID on success, -1 on error
        """
        if not self.connected:
            if not self.connect():
                return -1

        slot = self._find_empty_slot()
        if slot < 0:
            return -1

        # Allocate signature ID
        sig_id = self._next_id
        self._next_id += 1

        now_ns = int(datetime.now().timestamp() * 1e9)
        ttl_seconds = sig.get('ttl_seconds', 300)
        expires_ns = now_ns + (ttl_seconds * 1_000_000_000) if ttl_seconds > 0 else 0

        # Parse destination IP (handle None)
        dst_ip = sig.get('dst_ip') or 0
        if isinstance(dst_ip, str) and dst_ip and dst_ip != '0.0.0.0':
            parts = dst_ip.split('.')
            if len(parts) == 4:
                # Store in little-endian (DPDK format)
                dst_ip = int(parts[0]) | (int(parts[1]) << 8) | (int(parts[2]) << 16) | (int(parts[3]) << 24)
            else:
                dst_ip = 0
        elif not isinstance(dst_ip, int):
            dst_ip = 0
        dst_ip_mask = 0xFFFFFFFF if dst_ip else 0

        # Parse port ranges (handle None values)
        # NOTE: In C code, min=0/max=65535 is wildcard; min=0/max=0 means "port 0 only"
        dst_port = sig.get('dst_port')
        if isinstance(dst_port, tuple):
            dst_port_min, dst_port_max = dst_port
        elif dst_port:
            dst_port_min = dst_port_max = int(dst_port)
        else:
            # Wildcard: 0-65535 means "any port"
            dst_port_min, dst_port_max = 0, 65535

        src_port = sig.get('src_port')
        if isinstance(src_port, tuple):
            src_port_min, src_port_max = src_port
        elif src_port:
            src_port_min = src_port_max = int(src_port)
        else:
            # Wildcard: 0-65535 means "any port"
            src_port_min, src_port_max = 0, 65535

        # Parse size range (handle None values)
        # Wildcard: 0-65535 means "any size"
        pkt_size = sig.get('pkt_size')
        if isinstance(pkt_size, tuple):
            pkt_size_min, pkt_size_max = pkt_size
        elif pkt_size:
            pkt_size_min = pkt_size_max = int(pkt_size)
        else:
            pkt_size_min, pkt_size_max = 0, 65535

        # Parse TTL range (handle None values)
        # Wildcard: 0-255 means "any TTL"
        ttl = sig.get('ttl')
        if isinstance(ttl, tuple):
            ttl_min, ttl_max = ttl
        elif ttl:
            ttl_min = ttl_max = int(ttl)
        else:
            ttl_min, ttl_max = 0, 255

        # TCP flags
        tcp_flags = sig.get('tcp_flags', (0, 0))
        if isinstance(tcp_flags, tuple):
            tcp_flags_mask, tcp_flags_value = tcp_flags
        else:
            tcp_flags_mask = tcp_flags_value = 0

        # Convert protocol string to number if needed
        protocol = sig.get('protocol', 0)
        if isinstance(protocol, str):
            protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'any': 0, '': 0}
            protocol = protocol_map.get(protocol.lower(), 0)

        # Convert action string to number if needed
        action = sig.get('action', 1)
        if isinstance(action, str):
            action_map = {'allow': 0, 'drop': 1, 'rate_limit': 2, 'challenge': 3, 'log': 4}
            action = action_map.get(action.lower(), 1)

        # Pack signature data
        # Format: id(4), enabled(4), created_ns(8), expires_ns(8),
        #         protocol(1), protocol_match(1), pad(2), dst_ip(4), dst_ip_mask(4),
        #         dst_port_min(2), dst_port_max(2), src_port_min(2), src_port_max(2),
        #         pkt_size_min(2), pkt_size_max(2), ttl_min(1), ttl_max(1),
        #         tcp_flags_mask(1), tcp_flags_value(1), tcp_mss_min(2), tcp_mss_max(2),
        #         tcp_wscale_min(1), tcp_wscale_max(1), tcp_window_min(2), tcp_window_max(2)
        data = struct.pack(
            '<II QQ BBH II HH HH HH BB BB HH BB HH',
            sig_id,                          # id (I)
            1,                               # enabled (I)
            now_ns,                          # created_ns (Q)
            expires_ns,                      # expires_ns (Q)
            protocol,                        # protocol (B)
            0,                               # protocol_match (B)
            0,                               # pad (H)
            dst_ip,                          # dst_ip (I)
            dst_ip_mask,                     # dst_ip_mask (I)
            dst_port_min,                    # dst_port_min (H)
            dst_port_max,                    # dst_port_max (H)
            src_port_min,                    # src_port_min (H)
            src_port_max,                    # src_port_max (H)
            pkt_size_min,                    # pkt_size_min (H)
            pkt_size_max,                    # pkt_size_max (H)
            ttl_min,                         # ttl_min (B)
            ttl_max,                         # ttl_max (B)
            tcp_flags_mask,                  # tcp_flags_mask (B)
            tcp_flags_value,                 # tcp_flags_value (B)
            0, 65535,                        # tcp_mss_min, tcp_mss_max (HH) - wildcard
            255, 255,                        # tcp_wscale_min, tcp_wscale_max (BB) - wildcard
            0, 65535,                        # tcp_window_min, tcp_window_max (HH) - wildcard
        )

        # Add payload pattern (16 bytes) + len + offset
        data += b'\x00' * 16  # payload_pattern
        data += struct.pack('<BB', 0, 0)  # payload_pattern_len, payload_match_offset

        # Action and rate limit
        data += struct.pack('<BxI',
            action,                          # action (1=DROP)
            sig.get('rate_limit_pps', 0),    # rate_limit_pps
        )

        # Match stats (zeroed)
        data += struct.pack('<QQ', 0, 0)  # match_count, last_match_ns

        # Attack classification
        data += struct.pack('<BBH6x',
            sig.get('attack_type', 0),       # attack_type
            sig.get('confidence', 80),       # confidence
            sig.get('priority', 100),        # priority
        )

        # Pad to 128 bytes
        while len(data) < self.SIGNATURE_SIZE:
            data += b'\x00'

        # Write to shared memory
        offset = OFFSET_DYNAMIC_SIGS + DYNAMIC_SIG_TABLE_ENTRIES_OFFSET + (slot * DYNAMIC_SIGNATURE_SIZE)
        self.mm.seek(offset)
        self.mm.write(data[:self.SIGNATURE_SIZE])

        # Update header: version and count
        # Header layout: version(8) + count(4) + pad(4) = 16 bytes
        self.mm.seek(OFFSET_DYNAMIC_SIGS)
        version = struct.unpack('<Q', self.mm.read(8))[0]
        count = struct.unpack('<I', self.mm.read(4))[0]

        # Increment count if this is a new slot
        new_count = max(count, slot + 1)

        # Write updated header
        self.mm.seek(OFFSET_DYNAMIC_SIGS)
        self.mm.write(struct.pack('<QI', version + 2, new_count))  # version + 2 (keep even), new count

        # Flush to ensure visibility
        self.mm.flush()

        print(f"DynamicSignatureWriter: Wrote signature {sig_id} to slot {slot}, count now {new_count}")
        return sig_id

    def _find_signature_slot(self, sig_id: int) -> int:
        """Find the slot containing a signature by ID. Returns -1 if not found."""
        if not self.connected:
            if not self.connect():
                return -1

        for i in range(MAX_DYNAMIC_SIGNATURES):
            offset = OFFSET_DYNAMIC_SIGS + DYNAMIC_SIG_TABLE_ENTRIES_OFFSET + (i * DYNAMIC_SIGNATURE_SIZE)
            self.mm.seek(offset)
            entry_id = struct.unpack('<I', self.mm.read(4))[0]
            # Match by ID only (sig_id > 0 means valid signature, regardless of enabled state)
            if entry_id == sig_id:
                return i

        return -1

    def set_signature_enabled(self, sig_id: int, enabled: bool) -> bool:
        """
        Enable or disable a signature.

        Args:
            sig_id: Signature ID to modify
            enabled: True to enable, False to disable

        Returns:
            True if successful, False if signature not found
        """
        if not self.connected:
            if not self.connect():
                return False

        slot = self._find_signature_slot(sig_id)
        if slot < 0:
            print(f"DynamicSignatureWriter: Signature {sig_id} not found")
            return False

        # Update the enabled field (offset 4 bytes into the signature)
        offset = OFFSET_DYNAMIC_SIGS + DYNAMIC_SIG_TABLE_ENTRIES_OFFSET + (slot * DYNAMIC_SIGNATURE_SIZE)
        self.mm.seek(offset + 4)  # Skip past sig_id to enabled field
        self.mm.write(struct.pack('<I', 1 if enabled else 0))

        # Update version to signal change
        self.mm.seek(OFFSET_DYNAMIC_SIGS)
        version = struct.unpack('<Q', self.mm.read(8))[0]
        self.mm.seek(OFFSET_DYNAMIC_SIGS)
        self.mm.write(struct.pack('<Q', version + 2))

        self.mm.flush()
        print(f"DynamicSignatureWriter: Signature {sig_id} {'enabled' if enabled else 'disabled'}")
        return True

    def remove_signature(self, sig_id: int) -> bool:
        """
        Remove a signature by clearing its slot.

        Args:
            sig_id: Signature ID to remove

        Returns:
            True if successful, False if signature not found
        """
        if not self.connected:
            if not self.connect():
                return False

        slot = self._find_signature_slot(sig_id)
        if slot < 0:
            print(f"DynamicSignatureWriter: Signature {sig_id} not found for removal")
            return False

        # Clear the entire slot
        offset = OFFSET_DYNAMIC_SIGS + DYNAMIC_SIG_TABLE_ENTRIES_OFFSET + (slot * DYNAMIC_SIGNATURE_SIZE)
        self.mm.seek(offset)
        self.mm.write(b'\x00' * DYNAMIC_SIGNATURE_SIZE)

        # Update version to signal change
        self.mm.seek(OFFSET_DYNAMIC_SIGS)
        version = struct.unpack('<Q', self.mm.read(8))[0]
        self.mm.seek(OFFSET_DYNAMIC_SIGS)
        self.mm.write(struct.pack('<Q', version + 2))

        self.mm.flush()
        print(f"DynamicSignatureWriter: Signature {sig_id} removed from slot {slot}")
        return True


def generate_attack_signature(attack_target: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Generate a dynamic signature based on attack target info.

    Args:
        attack_target: Dict with ip, protocol, attack_type, dst_port, etc.

    Returns:
        Signature dict ready for add_signature(), or None if can't generate
    """
    protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'ALL': 0, 'OTHER': 0}
    protocol = protocol_map.get(attack_target.get('protocol', 'ALL'), 0)

    # TCP SYN flood - match SYN packets without ACK
    if attack_target.get('attack_type') == 'SYN_FLOOD':
        return {
            'protocol': 6,  # TCP
            'dst_ip': attack_target.get('ip', '0.0.0.0'),
            'dst_port': attack_target.get('dst_port', 0),
            'tcp_flags': (0x12, 0x02),  # Check SYN and ACK, expect SYN only
            'action': 2,  # RATE_LIMIT
            'rate_limit_pps': 1000,  # 1K SYN/sec per source
            'ttl_seconds': 300,
            'attack_type': 1,  # ATTACK_TYPE_SYN_FLOOD
            'confidence': 90,
            'priority': 200,
        }

    # UDP flood - rate limit all UDP to target
    elif attack_target.get('attack_type') == 'UDP_FLOOD':
        return {
            'protocol': 17,  # UDP
            'dst_ip': attack_target.get('ip', '0.0.0.0'),
            'dst_port': attack_target.get('dst_port', 0),
            'action': 2,  # RATE_LIMIT
            'rate_limit_pps': 10000,
            'ttl_seconds': 300,
            'attack_type': 2,  # ATTACK_TYPE_UDP_FLOOD
            'confidence': 85,
            'priority': 150,
        }

    # ICMP flood - rate limit ICMP to target
    elif attack_target.get('attack_type') == 'ICMP_FLOOD':
        return {
            'protocol': 1,  # ICMP
            'dst_ip': attack_target.get('ip', '0.0.0.0'),
            'action': 2,  # RATE_LIMIT
            'rate_limit_pps': 100,
            'ttl_seconds': 300,
            'attack_type': 3,  # ATTACK_TYPE_ICMP_FLOOD
            'confidence': 85,
            'priority': 150,
        }

    # DNS amplification - rate limit DNS responses
    elif attack_target.get('attack_type') == 'DNS_AMP':
        return {
            'protocol': 17,  # UDP
            'dst_ip': attack_target.get('ip', '0.0.0.0'),
            'src_port': 53,  # DNS source port
            'pkt_size': (512, 65535),  # Large DNS responses
            'action': 2,  # RATE_LIMIT
            'rate_limit_pps': 500,
            'ttl_seconds': 300,
            'attack_type': 4,  # ATTACK_TYPE_DNS_AMP
            'confidence': 90,
            'priority': 180,
        }

    # Generic - rate limit by protocol (including ANY/ALL with protocol=0)
    else:
        # For UNKNOWN attacks or when protocol is ALL/0, create a generic
        # rate limit signature targeting the protected IP
        return {
            'protocol': protocol,  # 0 = match any protocol
            'dst_ip': attack_target.get('ip', '0.0.0.0'),
            'dst_port': attack_target.get('dst_port', 0),
            'action': 2,  # RATE_LIMIT
            'rate_limit_pps': 5000,  # Conservative default
            'ttl_seconds': 300,
            'attack_type': 0,  # UNKNOWN
            'confidence': 60,  # Lower confidence for unclassified
            'priority': 50,    # Lower priority than specific signatures
        }


# Global signature writer instance
_writer: Optional[DynamicSignatureWriter] = None


def get_writer() -> DynamicSignatureWriter:
    """Get or create Layer 3 signature writer."""
    global _writer
    if _writer is None:
        _writer = DynamicSignatureWriter()
    return _writer
