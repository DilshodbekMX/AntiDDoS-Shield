#!/usr/bin/env python3
"""
POSIX Shared Memory Interface for Layer 1 Anti-DDoS System

This module provides Python access to the shared memory region created by
the DPDK-based Layer 1 packet processor. It allows Layer 3 (Attribution Engine)
and Layer 4 (Reputation System) to read/write policies and reputation data.

Usage:
    from posix_shmem import Layer1SharedMemory

    shmem = Layer1SharedMemory()
    if shmem.connect():
        # Read reputation
        rep = shmem.get_reputation(ip_to_int("192.168.1.100"))

        # Add policy
        shmem.add_policy(
            src_ip=ip_to_int("10.0.0.1"),
            dst_ip=0,  # wildcard
            dst_port=80,
            protocol=6,  # TCP
            action=PolicyAction.RATE_LIMIT,
            rate_limit_pps=1000
        )

        shmem.close()
"""

import os
import mmap
import struct
import ctypes
from enum import IntEnum
from typing import Optional, Tuple, List, NamedTuple
import socket

# ==================== Constants ====================

POSIX_SHMEM_NAME = "/antiddos_layer1_shmem"
POSIX_SHMEM_PATH = f"/dev/shm{POSIX_SHMEM_NAME}"

# Table sizes (must match C header)
MAX_POLICIES = 10000
MAX_REPUTATION_ENTRIES = 100000
MAX_FEEDBACK_EVENTS = 10000

# Magic and version
SHMEM_MAGIC = 0x4C315348  # "L1SH"
SHMEM_ABI_VERSION = 1


# ==================== Enums ====================

class PolicyAction(IntEnum):
    ALLOW = 0
    CHALLENGE = 1
    RATE_LIMIT = 2
    DROP = 3


class AnomalyLevel(IntEnum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class FeedbackEventType(IntEnum):
    SYN_FLOOD = 1
    RATE_LIMIT_EXCEEDED = 2
    INVALID_PACKET = 3
    CONNECTION_LIMIT = 4
    ATTACK_MITIGATED = 5


# ==================== Data Structures ====================
# These MUST match the C structures exactly (including padding)

class PolicyEntry(ctypes.Structure):
    """Matches struct policy_entry in shared_memory.h"""
    _pack_ = 1
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("_pad1", ctypes.c_uint8),
        ("action", ctypes.c_uint32),  # enum policy_action
        ("rate_limit_pps", ctypes.c_uint32),
        ("rate_limit_bps", ctypes.c_uint32),
        ("priority", ctypes.c_uint32),
        ("expiry_timestamp", ctypes.c_uint64),
        ("version", ctypes.c_uint64),
        ("_pad2", ctypes.c_uint8 * 8),
    ]

# Verify alignment
assert ctypes.sizeof(PolicyEntry) == 64, f"PolicyEntry size mismatch: {ctypes.sizeof(PolicyEntry)}"


class ReputationEntry(ctypes.Structure):
    """Matches struct reputation_entry in shared_memory.h"""
    _pack_ = 1
    _fields_ = [
        ("ip", ctypes.c_uint32),
        ("score", ctypes.c_uint16),
        ("confidence", ctypes.c_uint16),
        ("last_updated_ns", ctypes.c_uint64),
        ("packet_count", ctypes.c_uint32),
        ("attack_count", ctypes.c_uint32),
        ("flags", ctypes.c_uint8),
        ("_pad", ctypes.c_uint8 * 7),
    ]

assert ctypes.sizeof(ReputationEntry) == 32, f"ReputationEntry size mismatch: {ctypes.sizeof(ReputationEntry)}"


class FeedbackEvent(ctypes.Structure):
    """Matches struct feedback_event in shared_memory.h"""
    _pack_ = 1
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("dst_ip", ctypes.c_uint32),
        ("dst_port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint8),
        ("event_type", ctypes.c_uint8),
        ("timestamp_ns", ctypes.c_uint64),
        ("packet_count", ctypes.c_uint32),
        ("severity", ctypes.c_uint32),
        ("_pad", ctypes.c_uint8 * 8),
    ]

assert ctypes.sizeof(FeedbackEvent) == 32, f"FeedbackEvent size mismatch: {ctypes.sizeof(FeedbackEvent)}"


class GlobalState(ctypes.Structure):
    """Matches struct global_state in shared_memory.h"""
    _pack_ = 1
    _fields_ = [
        ("anomaly_active", ctypes.c_uint32),
        ("anomaly_level", ctypes.c_uint32),
        ("anomaly_start_ns", ctypes.c_uint64),
        ("last_anomaly_update_ns", ctypes.c_uint64),
        ("total_pps", ctypes.c_uint64),
        ("total_bps", ctypes.c_uint64),
        ("baseline_pps", ctypes.c_uint64),
        ("baseline_bps", ctypes.c_uint64),
        ("rate_limit_pct", ctypes.c_uint32),
        ("_pad", ctypes.c_uint8 * 28),
    ]

assert ctypes.sizeof(GlobalState) == 64, f"GlobalState size mismatch: {ctypes.sizeof(GlobalState)}"


# ==================== Offset Calculations ====================
# Calculate byte offsets for each section

POLICY_ENTRY_SIZE = 64
REPUTATION_ENTRY_SIZE = 32
FEEDBACK_EVENT_SIZE = 32

# Policy table: entries + count (4) + version (8) + pad (52) = 64 byte aligned
POLICY_TABLE_SIZE = (POLICY_ENTRY_SIZE * MAX_POLICIES) + 64

# Reputation table: entries + count (4) + version (8) + pad (52)
REPUTATION_TABLE_SIZE = (REPUTATION_ENTRY_SIZE * MAX_REPUTATION_ENTRIES) + 64

# Feedback queue: events + head (4) + tail (4) + pad (56)
FEEDBACK_QUEUE_SIZE = (FEEDBACK_EVENT_SIZE * MAX_FEEDBACK_EVENTS) + 64

# Global state
GLOBAL_STATE_SIZE = 64

# Offsets
OFFSET_POLICIES = 0
OFFSET_REPUTATION = POLICY_TABLE_SIZE
OFFSET_FEEDBACK = OFFSET_REPUTATION + REPUTATION_TABLE_SIZE
OFFSET_GLOBAL_STATE = OFFSET_FEEDBACK + FEEDBACK_QUEUE_SIZE

# Total size
TOTAL_SHMEM_SIZE = OFFSET_GLOBAL_STATE + GLOBAL_STATE_SIZE


# ==================== Helper Functions ====================

def ip_to_int(ip_str: str) -> int:
    """Convert IP address string to network byte order integer"""
    return struct.unpack("!I", socket.inet_aton(ip_str))[0]


def int_to_ip(ip_int: int) -> str:
    """Convert network byte order integer to IP address string"""
    return socket.inet_ntoa(struct.pack("!I", ip_int))


# ==================== Main Interface ====================

class Layer1SharedMemory:
    """Interface to Layer 1 POSIX shared memory"""

    def __init__(self, path: str = POSIX_SHMEM_PATH):
        self.path = path
        self.fd = None
        self.mm = None
        self.connected = False

    def connect(self) -> bool:
        """Connect to the shared memory region"""
        try:
            if not os.path.exists(self.path):
                print(f"Shared memory not found: {self.path}")
                print("Make sure Layer 1 is running with POSIX shared memory enabled")
                return False

            self.fd = os.open(self.path, os.O_RDWR)
            self.mm = mmap.mmap(self.fd, TOTAL_SHMEM_SIZE)
            self.connected = True
            print(f"Connected to shared memory: {self.path}")
            print(f"  Size: {TOTAL_SHMEM_SIZE:,} bytes")
            return True

        except Exception as e:
            print(f"Failed to connect to shared memory: {e}")
            return False

    def close(self):
        """Close the shared memory connection"""
        if self.mm:
            self.mm.close()
            self.mm = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None
        self.connected = False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ==================== Policy Operations ====================

    def get_policy_count(self) -> int:
        """Get current number of policies"""
        if not self.connected:
            return 0
        offset = OFFSET_POLICIES + (POLICY_ENTRY_SIZE * MAX_POLICIES)
        self.mm.seek(offset)
        return struct.unpack("<I", self.mm.read(4))[0]

    def get_policy(self, index: int) -> Optional[PolicyEntry]:
        """Get policy at index"""
        if not self.connected or index >= MAX_POLICIES:
            return None
        offset = OFFSET_POLICIES + (POLICY_ENTRY_SIZE * index)
        self.mm.seek(offset)
        data = self.mm.read(POLICY_ENTRY_SIZE)
        return PolicyEntry.from_buffer_copy(data)

    def add_policy(self, src_ip: int, dst_ip: int, dst_port: int, protocol: int,
                   action: PolicyAction, rate_limit_pps: int = 0,
                   rate_limit_bps: int = 0, priority: int = 100,
                   expiry_timestamp: int = 0) -> bool:
        """
        Add a new policy to the table.
        Note: This is a simplified implementation. In production, you'd want
        proper locking coordination with the C side.
        """
        if not self.connected:
            return False

        count = self.get_policy_count()
        if count >= MAX_POLICIES:
            return False

        # Create policy entry
        entry = PolicyEntry()
        entry.src_ip = src_ip
        entry.dst_ip = dst_ip
        entry.dst_port = dst_port
        entry.protocol = protocol
        entry.action = action
        entry.rate_limit_pps = rate_limit_pps
        entry.rate_limit_bps = rate_limit_bps
        entry.priority = priority
        entry.expiry_timestamp = expiry_timestamp
        entry.version = 1

        # Write entry
        offset = OFFSET_POLICIES + (POLICY_ENTRY_SIZE * count)
        self.mm.seek(offset)
        self.mm.write(bytes(entry))

        # Update count
        count_offset = OFFSET_POLICIES + (POLICY_ENTRY_SIZE * MAX_POLICIES)
        self.mm.seek(count_offset)
        self.mm.write(struct.pack("<I", count + 1))

        # Update version
        version_offset = count_offset + 4
        self.mm.seek(version_offset)
        old_version = struct.unpack("<Q", self.mm.read(8))[0]
        self.mm.seek(version_offset)
        self.mm.write(struct.pack("<Q", old_version + 1))

        return True

    # ==================== Reputation Operations ====================

    def get_reputation_by_index(self, index: int) -> Optional[ReputationEntry]:
        """Get reputation entry at index (for iteration)"""
        if not self.connected or index >= MAX_REPUTATION_ENTRIES:
            return None
        offset = OFFSET_REPUTATION + (REPUTATION_ENTRY_SIZE * index)
        self.mm.seek(offset)
        data = self.mm.read(REPUTATION_ENTRY_SIZE)
        entry = ReputationEntry.from_buffer_copy(data)
        if entry.ip == 0:  # Empty entry
            return None
        return entry

    # ==================== Global State ====================

    def get_anomaly_level(self) -> AnomalyLevel:
        """Get current anomaly level"""
        if not self.connected:
            return AnomalyLevel.NONE
        self.mm.seek(OFFSET_GLOBAL_STATE + 4)  # anomaly_level offset
        level = struct.unpack("<I", self.mm.read(4))[0]
        return AnomalyLevel(level) if level <= 4 else AnomalyLevel.NONE

    def set_anomaly_level(self, level: AnomalyLevel):
        """Set anomaly level"""
        if not self.connected:
            return

        # Set anomaly_active
        self.mm.seek(OFFSET_GLOBAL_STATE)
        self.mm.write(struct.pack("<I", 1 if level > 0 else 0))

        # Set anomaly_level
        self.mm.seek(OFFSET_GLOBAL_STATE + 4)
        self.mm.write(struct.pack("<I", level))

        # Calculate rate limit percentage
        rate_pct = {
            AnomalyLevel.NONE: 100,
            AnomalyLevel.LOW: 80,
            AnomalyLevel.MEDIUM: 50,
            AnomalyLevel.HIGH: 25,
            AnomalyLevel.CRITICAL: 10,
        }.get(level, 100)

        # Set rate_limit_pct (offset 56 within GlobalState)
        self.mm.seek(OFFSET_GLOBAL_STATE + 56)
        self.mm.write(struct.pack("<I", rate_pct))

    def get_traffic_stats(self) -> Tuple[int, int]:
        """Get current traffic stats (pps, bps)"""
        if not self.connected:
            return (0, 0)
        self.mm.seek(OFFSET_GLOBAL_STATE + 24)  # total_pps offset
        pps = struct.unpack("<Q", self.mm.read(8))[0]
        bps = struct.unpack("<Q", self.mm.read(8))[0]
        return (pps, bps)

    # ==================== Feedback Queue ====================

    def read_feedback_events(self, max_events: int = 100) -> List[FeedbackEvent]:
        """Read pending feedback events from the queue"""
        if not self.connected:
            return []

        events = []
        events_offset = OFFSET_FEEDBACK

        # Read head and tail
        self.mm.seek(events_offset + (FEEDBACK_EVENT_SIZE * MAX_FEEDBACK_EVENTS))
        head = struct.unpack("<I", self.mm.read(4))[0]
        tail = struct.unpack("<I", self.mm.read(4))[0]

        # Read events
        while head != tail and len(events) < max_events:
            offset = events_offset + (FEEDBACK_EVENT_SIZE * tail)
            self.mm.seek(offset)
            data = self.mm.read(FEEDBACK_EVENT_SIZE)
            event = FeedbackEvent.from_buffer_copy(data)
            events.append(event)

            tail = (tail + 1) % MAX_FEEDBACK_EVENTS

        # Update tail
        self.mm.seek(events_offset + (FEEDBACK_EVENT_SIZE * MAX_FEEDBACK_EVENTS) + 4)
        self.mm.write(struct.pack("<I", tail))

        return events


# ==================== CLI Test ====================

if __name__ == "__main__":
    print("Layer 1 Shared Memory Python Interface")
    print("=" * 50)

    with Layer1SharedMemory() as shmem:
        if shmem.connected:
            print(f"\nPolicy count: {shmem.get_policy_count()}")
            print(f"Anomaly level: {shmem.get_anomaly_level().name}")
            pps, bps = shmem.get_traffic_stats()
            print(f"Traffic: {pps:,} pps, {bps:,} bps")

            # Read feedback events
            events = shmem.read_feedback_events()
            if events:
                print(f"\nFeedback events: {len(events)}")
                for evt in events[:5]:
                    print(f"  {int_to_ip(evt.src_ip)} -> {int_to_ip(evt.dst_ip)}:{evt.dst_port} "
                          f"type={evt.event_type} severity={evt.severity}")
