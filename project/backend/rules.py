#!/usr/bin/env python3
"""
Rules Engine for Anti-DDoS System

Manages IP whitelist/blacklist rules, Layer1 configuration, and stage controls.
Communicates with the DPDK datapath through a Unix domain socket.

Supports:
- IP whitelist/blacklist management
- CIDR range rules
- Layer1 configuration management (all config sections)
- Stage enable/disable controls
- Rule persistence (JSON file)
- Real-time rule updates to datapath
"""

import json
import socket
import struct
import tempfile
import threading
import ipaddress
import os
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any
from copy import deepcopy
import logging

logger = logging.getLogger(__name__)


def _atomic_json_write(filepath, data, indent=2):
    """Write JSON atomically: write to temp file, fsync, then rename."""
    filepath = Path(filepath)
    filepath.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=str(filepath.parent), suffix='.tmp', prefix=filepath.stem + '.'
    )
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=indent)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, str(filepath))
    except BaseException:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

# Load environment variables from .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed, use os.environ directly

# Rule types
RULE_TYPE_WHITELIST = 1
RULE_TYPE_BLACKLIST = 2
RULE_TYPE_PROTECTED = 3
RULE_TYPE_CIDR_WHITELIST = 4

# Command types for datapath communication
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
CMD_RELOAD_PROFILES = 0x62

# Factory reset
CMD_L1_FACTORY_RESET = 0x70   # Clear all Layer 1 runtime state

# Default paths - configurable via environment variables
DEFAULT_RULES_FILE = os.environ.get("ANTIDDOS_RULES_FILE", "/var/lib/antiddos/rules.json")
DEFAULT_SOCKET_PATH = os.environ.get("ANTIDDOS_SOCKET_PATH", "/var/run/antiddos/control.sock")
DEFAULT_GEOIP_DB = os.environ.get("ANTIDDOS_GEOIP_DB", "/var/lib/antiddos/geoip/GeoLite2-Country.mmdb")

# Auto-detect Layer 1 config path: env var > project-local file > /etc fallback
def _resolve_layer1_config():
    env_val = os.environ.get("ANTIDDOS_LAYER1_CONFIG")
    if env_val and os.path.exists(env_val):
        return env_val
    # Check project-local path (relative to backend/ directory)
    local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "layer1", "config", "layer1_config.json")
    if os.path.exists(local_path):
        return os.path.abspath(local_path)
    # Return env var value or fallback
    return env_val or "/etc/antiddos/layer1_config.json"

def _resolve_layer2_config():
    env_val = os.environ.get("ANTIDDOS_LAYER2_CONFIG")
    if env_val and os.path.exists(env_val):
        return env_val
    local_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "layer2", "config", "layer2_config.json")
    if os.path.exists(local_path):
        return os.path.abspath(local_path)
    return env_val or "/etc/antiddos/layer2_config.json"

DEFAULT_LAYER1_CONFIG = _resolve_layer1_config()
DEFAULT_LAYER2_CONFIG_PATH = _resolve_layer2_config()

# Command types for config updates
CMD_RELOAD_CONFIG = 0x30
CMD_UPDATE_STAGE = 0x31
CMD_L2_RELOAD_CONFIG = 0x32  # Reload Layer 2 anomaly detection config
CMD_L2_LOAD_PROFILE = 0x33   # Load baseline profile (path staged by backend)
CMD_L2_SAVE_BASELINES  = 0x34  # Save baselines to disk
CMD_L2_RESET_BASELINES = 0x35  # Reset baselines, re-learn from COLD
CMD_L2_FORCE_MATURE    = 0x36  # Force learning phase to MATURE
CMD_L2_RELOAD_PER_IP_CONFIG = 0x37  # Reload per-IP L2 detection config
CMD_L2_FEEDBACK = 0x38               # Operator feedback: mode=0(FP), 1(TP), 2(flash_crowd)

# Command types for per-IP anomaly control
CMD_CLEAR_PER_IP_ANOMALY = 0x40
CMD_CLEAR_ALL_ANOMALY = 0x41
CMD_L2_UNFREEZE_BASELINES = 0x42  # Operator override -- reset poison tracker and unfreeze baselines

# Command types for geo-blocking (0x50-0x54)
CMD_GEO_ADD_COUNTRY = 0x50
CMD_GEO_DEL_COUNTRY = 0x51
CMD_GEO_CLEAR = 0x52
CMD_GEO_SET_MODE = 0x53
CMD_GEO_SET_ENABLED = 0x54
CMD_GEO_RELOAD_DB = 0x55
CMD_GEO_BLOCK_UNKNOWN = 0x56

# Default Layer1 configuration template
DEFAULT_CONFIG = {
    "ip_lists": {
        "max_whitelist_entries": 10000,
        "max_blacklist_entries": 100000,
        "max_protected_entries": 1000,
        "max_whitelist_cidrs": 1000,
        "enforce_protected_ips": False
    },
    "flow_table": {
        "max_flows": 1000000,
        "idle_timeout_sec": 60,
        "syn_timeout_sec": 5,
        "default_pps_limit": 0,
        "default_bps_limit": 0,
        "enable_syn_protection": True
    },
    "syn_proxy": {
        "enabled": True,
        "max_connections": 1000000,
        "connect_timeout_ms": 5000,
        "idle_timeout_sec": 300,
        "secret_rotation_sec": 60
    },
    "syn_cookie": {
        "enabled": True,
        "challenge_threshold": 1000
    },
    "connection_limits": {
        "max_ips": 100000,
        "max_connections_per_ip": 1000,
        "time_window_sec": 60,
        "cleanup_interval_sec": 30
    },
    "udp_gatekeeper": {
        "pps_threshold": 10000,
        "bps_threshold": 10485760,
        "cms_width": 65536,
        "cms_depth": 4,
        "window_sec": 1,
        "check_reputation": True,
        "reputation_threshold": 200,
        "check_blacklist": True,
        "attack_pps_divisor": 4,
        "attack_bps_divisor": 4
    },
    "telemetry": {
        "db_path": "/tmp/layer1_telemetry.db",
        "export_interval_sec": 5,
        "max_flow_records": 4096,
        "flow_sample_rate": 100,
        "export_packet_samples": False,
        "events_enabled": True
    },
    "validation": {
        "validate_ip_checksum": True,
        "validate_udp_checksum": True,
        "validate_tcp_checksum": False,
        "validate_icmp_checksum": True,
        "drop_invalid_src_ip": True,
        "drop_land_attack": True,
        "drop_tcp_null": True,
        "drop_tcp_xmas": True,
        "drop_zero_ttl": True,
        "drop_port_zero": True,
        "drop_syn_fragment": True,
        "drop_ip_reserved_flag": True,
        "drop_teardrop": True,
        "drop_tcp_data_offset": True,
        "drop_fragment_fin_rst": True,
        "drop_all_fragments": False,
        "drop_fragments": False,
        "decrement_ttl": False
    },
    "rate_limits": {
        "global_pps_limit": 0,
        "global_bps_limit": 0,
        "normal_pps_per_ip": 10000,
        "normal_bps_per_ip": 100000000,
        "attack_pps_per_ip": 1000,
        "attack_bps_per_ip": 10000000,
        "dynamic_enabled": True,
        "anomaly_detection_window": 10,
        "progressive_enabled": True,
        "level_low_percent": 80,
        "level_medium_percent": 50,
        "level_high_percent": 25,
        "level_critical_percent": 10,
        "spoofed_aggregate_enabled": True,
        "spoofed_adaptive_limit_pct": 150,
        "spoofed_min_dst_pps": 50000,
        "spoofed_syn_per_dst_limit": 10000,
        "spoofed_packet_multiplier": 4,
        "legitimate_table_size": 100000,
        "legitimate_ttl_sec": 300
    },
    "ports": {
        "client_facing_port": 0,
        "server_facing_port": 1
    },
    "maintenance": {
        "flow_age_interval_sec": 1,
        "secret_rotation_sec": 60,
        "stats_print_interval_sec": 0
    },
    "geo_blocking": {
        "enabled": False,
        "mode": "blacklist",
        "database_path": "data/geoip/ip2country.csv",
        "blocked_countries": [],
        "allowed_countries": [],
        "block_unknown": True,
        "log_blocked": True
    },
    "other_protocols": {
        "enabled": True,
        "default_action": "drop",
        "allowed_protocols": [47, 50, 51],
        "rate_limit_pps": 1000,
        "log_unknown": True
    },
    "signatures": {
        "enabled": True,
        "log_matches": True,
        "block_amplification": True,
        "block_scans": True
    },
    "tcp_flag_rate": {
        "enabled": True,
        "max_entries": 40000,
        "cleanup_interval_sec": 60,
        "report_violations": True,
        "syn_pps": 100,
        "syn_ack_pps": 1000,
        "ack_pps": 50000,
        "rst_pps": 500,
        "fin_pps": 500,
        "psh_pps": 10000,
        "urg_pps": 100,
        "other_pps": 5000
    },
    "tcp_abuse": {
        "enabled": True,
        "report_to_layer4": True,
        "dup_seq_threshold": 150,
        "random_seq_threshold": 45,
        "random_ack_threshold": 45,
        "zero_window_threshold": 5,
        "tiny_window_bytes": 100,
        "small_window_bytes": 2000,
        "same_window_threshold": 150,
        "same_ack_threshold": 150,
        "action_dup_seq": 1,
        "action_random_seq": 1,
        "action_random_ack": 1,
        "action_zero_window": 2,
        "action_tiny_window": 2,
        "action_small_window": 0,
        "action_same_window": 1,
        "action_same_ack": 1
    },
    "layer2_response": {
        "enabled": True,
        "auto_enable_syn_proxy_on_attack": True,
        "auto_reduce_rate_limits_on_attack": True,
        "attack_rate_limit_divisor": 4,
        "min_anomaly_level_for_response": 2,
        "response_delay_sec": 2
    },
    "l7_validation": {
        "dns_enabled": True,
        "dns_drop_invalid_opcode": True,
        "dns_drop_qr_mismatch": True,
        "dns_drop_qdcount_invalid": True,
        "dns_drop_both_port53": True,
        "dns_drop_zone_transfer": True,
        "dns_drop_label_too_long": True,
        "dns_drop_name_too_long": True,
        "dns_drop_pointer_loop": True,
        "dns_drop_too_short": True,
        "dns_max_udp_size": 512,
        "ntp_enabled": True,
        "ntp_drop_invalid_version": True,
        "ntp_drop_invalid_mode": True,
        "ntp_drop_invalid_stratum": True,
        "ntp_drop_monlist": True,
        "ntp_drop_control": False,
        "ntp_drop_size_mismatch": True,
        "ntp_drop_too_short": True,
        "http_enabled": False,
        "http_drop_invalid_method": True,
        "http_drop_invalid_version": True,
        "http_drop_line_too_long": True,
        "http_drop_non_ascii": True,
        "http_max_request_line": 8192,
        "icmp_enabled": True,
        "icmp_drop_redirect": True,
        "icmp_drop_router_advert": True,
        "icmp_drop_router_solicit": True,
        "icmp_drop_timestamp": True,
        "icmp_drop_address_mask": True,
        "icmp_drop_info": True,
        "icmp_drop_source_quench": True,
        "icmp_rate_limit_pps": 1000
    },
    "log_level": 7,
    "stats_enabled": True,
    "monitor_only": False,
    "tap_mode": False
}

# Stage dependencies: when a stage is disabled, dependent stages are also disabled
# Key = stage that others depend on, Value = list of stages that depend on it
STAGE_DEPENDENCIES = {
    # monitor_only disables ALL protection stages when enabled
    # (telemetry and stats are intentionally kept enabled for monitoring)
    "monitor_only": [
        "syn_proxy", "syn_cookie", "flow_table_syn_protection",
        "rate_limit_dynamic", "udp_reputation", "udp_blacklist",
        "validate_ip_checksum", "validate_udp_checksum", "validate_tcp_checksum",
        "drop_invalid_src_ip", "drop_land_attack", "drop_tcp_null",
        "drop_tcp_xmas", "drop_zero_ttl", "drop_fragments",
        "enforce_protected_ips", "decrement_ttl"
    ],
    # syn_proxy is required for syn_cookie to work
    "syn_proxy": ["syn_cookie"],
    # UDP gatekeeper reputation needs blacklist check to be meaningful
    "udp_blacklist": ["udp_reputation"],
}

# Reverse dependencies: stage requires these to be enabled first
STAGE_REQUIRES = {
    "syn_cookie": ["syn_proxy"],
    "udp_reputation": ["udp_blacklist"],
}

# Stage definitions with their enable keys
STAGES = {
    "monitor_only": {
        "name": "Monitor Only Mode",
        "description": "PASSTHROUGH: Accept ALL packets without any protection (for benchmarking)",
        "config_section": None,
        "enable_key": "monitor_only",
        "category": "mode"
    },
    "tap_mode": {
        "name": "Tap Mode",
        "description": "TAP/MIRROR: Receive copy of traffic on port 0 only, no forwarding",
        "config_section": None,
        "enable_key": "tap_mode",
        "category": "mode"
    },
    "syn_proxy": {
        "name": "SYN Proxy",
        "description": "Proxies TCP SYN handshakes to protect against SYN floods",
        "config_section": "syn_proxy",
        "enable_key": "enabled",
        "category": "tcp_protection",
        "depends_on": None,
        "dependents": ["syn_cookie"]
    },
    "syn_cookie": {
        "name": "SYN Cookie",
        "description": "Uses cryptographic cookies to validate TCP connections",
        "config_section": "syn_cookie",
        "enable_key": "enabled",
        "category": "tcp_protection",
        "depends_on": "syn_proxy"
    },
    "flow_table_syn_protection": {
        "name": "Flow Table SYN Protection",
        "description": "Aggressive timeout for half-open connections",
        "config_section": "flow_table",
        "enable_key": "enable_syn_protection",
        "category": "tcp_protection"
    },
    "rate_limit_dynamic": {
        "name": "Dynamic Rate Limiting",
        "description": "Automatically adjusts rate limits during attacks",
        "config_section": "rate_limits",
        "enable_key": "dynamic_enabled",
        "category": "rate_limiting"
    },
    "udp_reputation": {
        "name": "UDP Reputation Check",
        "description": "Checks IP reputation before allowing UDP traffic",
        "config_section": "udp_gatekeeper",
        "enable_key": "check_reputation",
        "category": "udp_protection"
    },
    "udp_blacklist": {
        "name": "UDP Blacklist Check",
        "description": "Checks blacklist for UDP traffic",
        "config_section": "udp_gatekeeper",
        "enable_key": "check_blacklist",
        "category": "udp_protection"
    },
    "validate_ip_checksum": {
        "name": "IP Checksum Validation",
        "description": "Validates IP header checksums",
        "config_section": "validation",
        "enable_key": "validate_ip_checksum",
        "category": "validation"
    },
    "validate_udp_checksum": {
        "name": "UDP Checksum Validation",
        "description": "Validates UDP checksums",
        "config_section": "validation",
        "enable_key": "validate_udp_checksum",
        "category": "validation"
    },
    "validate_tcp_checksum": {
        "name": "TCP Checksum Validation",
        "description": "Validates TCP checksums (usually NIC offloaded)",
        "config_section": "validation",
        "enable_key": "validate_tcp_checksum",
        "category": "validation"
    },
    "drop_invalid_src_ip": {
        "name": "Drop Invalid Source IPs",
        "description": "Drops packets from bogon/invalid source IPs",
        "config_section": "validation",
        "enable_key": "drop_invalid_src_ip",
        "category": "validation"
    },
    "drop_land_attack": {
        "name": "Drop LAND Attacks",
        "description": "Drops packets where src==dst (LAND attack)",
        "config_section": "validation",
        "enable_key": "drop_land_attack",
        "category": "validation"
    },
    "drop_tcp_null": {
        "name": "Drop TCP NULL Packets",
        "description": "Drops TCP packets with no flags set",
        "config_section": "validation",
        "enable_key": "drop_tcp_null",
        "category": "validation"
    },
    "drop_tcp_xmas": {
        "name": "Drop TCP XMAS Packets",
        "description": "Drops XMAS tree packets (all flags set)",
        "config_section": "validation",
        "enable_key": "drop_tcp_xmas",
        "category": "validation"
    },
    "drop_zero_ttl": {
        "name": "Drop Zero TTL",
        "description": "Drops packets with TTL=0",
        "config_section": "validation",
        "enable_key": "drop_zero_ttl",
        "category": "validation"
    },
    "drop_fragments": {
        "name": "Drop Fragments",
        "description": "Drops fragmented IP packets",
        "config_section": "validation",
        "enable_key": "drop_fragments",
        "category": "validation"
    },
    "decrement_ttl": {
        "name": "Decrement TTL",
        "description": "Decrement TTL on forwarding (L3 router mode)",
        "config_section": "validation",
        "enable_key": "decrement_ttl",
        "category": "forwarding"
    },
    "telemetry_events": {
        "name": "Telemetry Events",
        "description": "Record attack and security events",
        "config_section": "telemetry",
        "enable_key": "events_enabled",
        "category": "telemetry"
    },
    "telemetry_packet_samples": {
        "name": "Telemetry Packet Samples",
        "description": "Export individual packet samples",
        "config_section": "telemetry",
        "enable_key": "export_packet_samples",
        "category": "telemetry"
    },
    "enforce_protected_ips": {
        "name": "Enforce Protected IPs",
        "description": "Only allow traffic to protected server IPs",
        "config_section": "ip_lists",
        "enable_key": "enforce_protected_ips",
        "category": "access_control"
    },
    "stats_enabled": {
        "name": "Statistics Collection",
        "description": "Enable global statistics collection",
        "config_section": None,
        "enable_key": "stats_enabled",
        "category": "monitoring"
    },
    "geo_blocking": {
        "name": "Geo-Blocking",
        "description": "Block or allow traffic based on country of origin",
        "config_section": "geo_blocking",
        "enable_key": "enabled",
        "category": "access_control"
    },
    "other_protocols": {
        "name": "Other Protocols Filter",
        "description": "Handle non-TCP/UDP/ICMP protocols (GRE, ESP, etc.)",
        "config_section": "other_protocols",
        "enable_key": "enabled",
        "category": "validation"
    },
    "signatures": {
        "name": "Attack Signatures",
        "description": "L3/L4 signature-based attack detection",
        "config_section": "signatures",
        "enable_key": "enabled",
        "category": "validation"
    }
}


class Rule:
    """Represents a single IP rule."""

    def __init__(self, ip: str, rule_type: int, description: str = "",
                 expires: Optional[datetime] = None, created: Optional[datetime] = None,
                 profile_name: str = "", profile_overrides: Optional[Dict[str, Any]] = None,
                 mode: str = "bypass"):
        self.ip = ip
        self.rule_type = rule_type
        self.description = description
        self.expires = expires
        self.created = created or datetime.now()
        self.hit_count = 0
        self.last_hit = None
        self.profile_name = profile_name  # Template name (e.g., "web_server")
        self.profile_overrides = profile_overrides or {}  # Per-IP overrides
        self.mode = mode  # "bypass" or "track" (whitelist only)

        # Validate IP/CIDR
        try:
            if '/' in ip:
                self.network = ipaddress.ip_network(ip, strict=False)
                self.is_cidr = True
            else:
                self.ip_addr = ipaddress.ip_address(ip)
                self.is_cidr = False
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {ip}") from e

    def to_dict(self) -> Dict[str, Any]:
        """Serialize rule to dictionary."""
        d = {
            'ip': self.ip,
            'rule_type': self.rule_type,
            'description': self.description,
            'expires': self.expires.isoformat() if self.expires else None,
            'created': self.created.isoformat() if self.created else None,
            'hit_count': self.hit_count,
            'last_hit': self.last_hit.isoformat() if self.last_hit else None,
        }
        if self.profile_name:
            d['profile_name'] = self.profile_name
        if self.profile_overrides:
            d['profile_overrides'] = self.profile_overrides
        if self.mode and self.mode != "bypass":
            d['mode'] = self.mode
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Rule':
        """Deserialize rule from dictionary."""
        rule = cls(
            ip=data['ip'],
            rule_type=data['rule_type'],
            description=data.get('description', ''),
            expires=datetime.fromisoformat(data['expires']) if data.get('expires') else None,
            created=datetime.fromisoformat(data['created']) if data.get('created') else None,
            profile_name=data.get('profile_name', ''),
            profile_overrides=data.get('profile_overrides'),
            mode=data.get('mode', 'bypass'),
        )
        rule.hit_count = data.get('hit_count', 0)
        if data.get('last_hit'):
            rule.last_hit = datetime.fromisoformat(data['last_hit'])
        return rule

    def is_expired(self) -> bool:
        """Check if rule has expired."""
        if self.expires is None:
            return False
        return datetime.now() > self.expires


class RulesEngine:
    """
    Manages rules and communicates with DPDK datapath.

    Thread-safe operations for concurrent access from Flask routes.
    """

    def __init__(self, rules_file: str = DEFAULT_RULES_FILE,
                 socket_path: str = DEFAULT_SOCKET_PATH):
        self.rules_file = Path(rules_file)
        self.socket_path = socket_path
        self.lock = threading.RLock()

        # Rule storage by type
        self.whitelist: Dict[str, Rule] = {}
        self.blacklist: Dict[str, Rule] = {}
        self.protected: Dict[str, Rule] = {}
        self.cidr_whitelist: Dict[str, Rule] = {}

        # Stats
        self.last_sync = None
        self.sync_errors = 0

        # Ensure rules directory exists
        self.rules_file.parent.mkdir(parents=True, exist_ok=True)

        # Layer1 IP lists file path (for syncing)
        self.layer1_ip_lists_file = Path(os.environ.get(
            "ANTIDDOS_LAYER1_IP_LISTS",
            "../layer1/config/ip_lists.json"
        ))

        # Load rules from file
        self.load_rules()

        # Sync with Layer1's ip_lists.json if it exists (single source of truth)
        self.sync_from_layer1()

    def sync_from_layer1(self) -> bool:
        """Sync protected IPs from Layer1's ip_lists.json.

        This ensures the backend and Layer1 have consistent state.
        Layer1's file is considered the source of truth when DPDK is running.
        Handles both plain string entries and object entries with profiles.
        """
        try:
            if not self.layer1_ip_lists_file.exists():
                return False

            with open(self.layer1_ip_lists_file, 'r') as f:
                data = json.load(f)

            # Parse protected IPs - can be strings or objects
            layer1_entries = {}  # ip -> (profile_name, overrides)
            for entry in data.get('protected_ips', []):
                if isinstance(entry, str):
                    layer1_entries[entry] = ("", {})
                elif isinstance(entry, dict):
                    ip = entry.get("ip", "")
                    if ip:
                        profile = entry.get("profile", "")
                        # Extract override fields
                        overrides = {}
                        for key in ("pps_limit", "bps_limit", "attack_pps_limit",
                                    "attack_bps_limit", "max_conn_per_src", "max_conn_total",
                                    "syn_proxy_mode", "syn_challenge_threshold",
                                    "tcp_ports", "udp_ports"):
                            if key in entry:
                                overrides[key] = entry[key]
                        layer1_entries[ip] = (profile, overrides)

            backend_protected = set(self.protected.keys())

            # Check if sync is needed
            if set(layer1_entries.keys()) == backend_protected:
                # IPs match - check if profiles need updating
                needs_update = False
                for ip, (profile, overrides) in layer1_entries.items():
                    if ip in self.protected:
                        rule = self.protected[ip]
                        if rule.profile_name != profile or rule.profile_overrides != overrides:
                            needs_update = True
                            break
                if not needs_update:
                    return True  # Already in sync

            # Layer1 has different data - sync backend to match
            logger.info("Syncing from Layer1 ip_lists.json")

            self.protected.clear()
            for ip, (profile_name, overrides) in layer1_entries.items():
                rule = Rule(ip, RULE_TYPE_PROTECTED, "Synced from Layer1",
                           profile_name=profile_name,
                           profile_overrides=overrides if overrides else None)
                self.protected[ip] = rule

            self.save_rules()
            logger.info("Synced %d protected IPs from Layer1", len(layer1_entries))
            return True

        except Exception as e:
            logger.warning("Could not sync from Layer1: %s", e)
            return False

    def load_rules(self) -> bool:
        """Load rules from JSON file."""
        with self.lock:
            try:
                if not self.rules_file.exists():
                    return True  # No file yet, start with empty rules

                with open(self.rules_file, 'r') as f:
                    data = json.load(f)

                # Load each rule type
                for item in data.get('whitelist', []):
                    rule = Rule.from_dict(item)
                    if not rule.is_expired():
                        self.whitelist[rule.ip] = rule

                for item in data.get('blacklist', []):
                    rule = Rule.from_dict(item)
                    if not rule.is_expired():
                        self.blacklist[rule.ip] = rule

                for item in data.get('protected', []):
                    rule = Rule.from_dict(item)
                    self.protected[rule.ip] = rule

                for item in data.get('cidr_whitelist', []):
                    rule = Rule.from_dict(item)
                    if not rule.is_expired():
                        self.cidr_whitelist[rule.ip] = rule

                return True
            except Exception as e:
                logger.error("Error loading rules: %s", e)
                return False

    def sync_to_datapath(self) -> int:
        """Sync all rules to DPDK datapath.

        Call this after DPDK starts to ensure all rules are registered.
        Returns the number of rules successfully synced.
        """
        synced = 0
        with self.lock:
            for ip, rule in self.whitelist.items():
                mode_int = 2 if getattr(rule, 'mode', 'bypass') == "track" else 1
                if self._send_to_datapath(CMD_ADD_WHITELIST, ip, mode=mode_int):
                    synced += 1
            for ip in self.blacklist:
                if self._send_to_datapath(CMD_ADD_BLACKLIST, ip):
                    synced += 1
            for ip in self.protected:
                if self._send_to_datapath(CMD_ADD_PROTECTED, ip):
                    synced += 1
            for cidr, crule in self.cidr_whitelist.items():
                cmode_int = 2 if getattr(crule, 'mode', 'bypass') == "track" else 1
                if self._send_to_datapath(CMD_ADD_WHITELIST, cidr, mode=cmode_int):
                    synced += 1

        total = (len(self.whitelist) + len(self.blacklist) +
                 len(self.protected) + len(self.cidr_whitelist))
        logger.info("Synced %d/%d rules to datapath", synced, total)
        return synced

    def save_rules(self) -> bool:
        """Save rules to JSON file."""
        with self.lock:
            try:
                data = {
                    'whitelist': [r.to_dict() for r in self.whitelist.values()],
                    'blacklist': [r.to_dict() for r in self.blacklist.values()],
                    'protected': [r.to_dict() for r in self.protected.values()],
                    'cidr_whitelist': [r.to_dict() for r in self.cidr_whitelist.values()],
                    'updated': datetime.now().isoformat(),
                }

                _atomic_json_write(self.rules_file, data, indent=2)

                logger.info("Rules saved to %s", self.rules_file)
                return True
            except PermissionError as e:
                logger.error("Permission denied saving rules to %s: %s", self.rules_file, e)
                logger.error("Try: sudo chown %s:%s %s", os.getenv('USER', 'user'), os.getenv('USER', 'user'), self.rules_file)
                return False
            except Exception as e:
                logger.error("Error saving rules to %s: %s", self.rules_file, e)
                return False

    def _send_to_datapath(self, cmd: int, ip_str: str, mode: int = 0) -> bool:
        """Send rule update to DPDK datapath.

        Args:
            cmd: Command type (CMD_ADD_WHITELIST, etc.)
            ip_str: IP address or CIDR string
            mode: Whitelist mode (0=default/bypass, 1=bypass, 2=track)
        """
        try:
            # Convert IP string to integer
            if '/' in ip_str:
                # CIDR - send base address
                network = ipaddress.ip_network(ip_str, strict=False)
                ip_int = int(network.network_address)  # 192.168.2.5 -> 0xC0A80205
                prefix_len = network.prefixlen
            else:
                ip_int = int(ipaddress.ip_address(ip_str))  # 192.168.2.5 -> 0xC0A80205
                prefix_len = 32

            # Pack command: cmd (1) + IP (4) + prefix (1) + mode (1) = 7 bytes
            #
            # The C struct is packed and reads IP as uint32_t. On x86 (little-endian),
            # we need to send bytes in the order that when read as uint32_t gives the
            # numeric IP value (0xC0A80205 for 192.168.2.5).
            #
            # struct.pack('<I', 0xC0A80205) produces bytes: 05 02 A8 C0
            # C reads these as uint32_t on x86: 0xC0A80205
            # C logging shows: (0xC0A80205 >> 24) = 0xC0 = 192 -> "192.168.2.5"
            # C applies htonl(0xC0A80205) = 0x0502A8C0 for storage in network order
            packet = struct.pack('<BIB', cmd, ip_int, prefix_len)

            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(self.socket_path)
            sock.sendall(packet)

            # Wait for ACK
            response = sock.recv(4)
            sock.close()

            if len(response) >= 1 and response[0] == 0:
                self.last_sync = datetime.now()
                return True
            else:
                self.sync_errors += 1
                return False

        except socket.error as e:
            # Socket not available (datapath not running or no control socket)
            # This is expected during development/testing
            logger.error("Datapath communication failed: %s", e)
            self.sync_errors += 1
            return False
        except Exception as e:
            logger.error("Error sending to datapath: %s", e)
            self.sync_errors += 1
            return False

    # ==================== Whitelist Operations ====================

    def add_whitelist(self, ip: str, description: str = "",
                      expires: Optional[datetime] = None,
                      mode: str = "bypass") -> bool:
        """Add IP to whitelist.

        Args:
            ip: IP address or CIDR string
            description: Rule description
            expires: Expiration datetime (None = never)
            mode: "bypass" (skip all stages) or "track" (run stages, never drop)
        """
        with self.lock:
            try:
                rule = Rule(ip, RULE_TYPE_WHITELIST, description, expires, mode=mode)
                self.whitelist[ip] = rule
                if not self.save_rules():
                    del self.whitelist[ip]
                    return False
                mode_int = 2 if mode == "track" else 1  # WL_MODE_BYPASS=1, WL_MODE_TRACK=2
                self._send_to_datapath(CMD_ADD_WHITELIST, ip, mode=mode_int)
                return True
            except ValueError as e:
                logger.error("Invalid IP: %s", e)
                return False

    def remove_whitelist(self, ip: str) -> bool:
        """Remove IP from whitelist."""
        with self.lock:
            if ip in self.whitelist:
                rule = self.whitelist[ip]
                del self.whitelist[ip]
                if not self.save_rules():
                    self.whitelist[ip] = rule
                    return False
                self._send_to_datapath(CMD_DEL_WHITELIST, ip)
                return True
            return False

    def get_whitelist(self) -> List[Dict[str, Any]]:
        """Get all whitelist entries."""
        with self.lock:
            return [r.to_dict() for r in self.whitelist.values()]

    def clear_whitelist(self) -> int:
        """Clear all whitelist entries. Returns count of removed entries."""
        with self.lock:
            count = len(self.whitelist)
            backup = dict(self.whitelist)
            self.whitelist.clear()
            if not self.save_rules():
                self.whitelist = backup
                return 0
            self._send_to_datapath(CMD_CLEAR_WHITELIST, "0.0.0.0")
            return count

    # ==================== Blacklist Operations ====================

    def add_blacklist(self, ip: str, description: str = "",
                      expires: Optional[datetime] = None) -> bool:
        """Add IP to blacklist."""
        with self.lock:
            try:
                rule = Rule(ip, RULE_TYPE_BLACKLIST, description, expires)
                self.blacklist[ip] = rule
                if not self.save_rules():
                    del self.blacklist[ip]
                    return False
                self._send_to_datapath(CMD_ADD_BLACKLIST, ip)
                return True
            except ValueError as e:
                logger.error("Invalid IP: %s", e)
                return False

    def remove_blacklist(self, ip: str) -> bool:
        """Remove IP from blacklist."""
        with self.lock:
            if ip in self.blacklist:
                rule = self.blacklist[ip]
                del self.blacklist[ip]
                if not self.save_rules():
                    self.blacklist[ip] = rule
                    return False
                self._send_to_datapath(CMD_DEL_BLACKLIST, ip)
                return True
            return False

    def get_blacklist(self) -> List[Dict[str, Any]]:
        """Get all blacklist entries."""
        with self.lock:
            return [r.to_dict() for r in self.blacklist.values()]

    def clear_blacklist(self) -> int:
        """Clear all blacklist entries. Returns count of removed entries."""
        with self.lock:
            count = len(self.blacklist)
            backup = dict(self.blacklist)
            self.blacklist.clear()
            if not self.save_rules():
                self.blacklist = backup
                return 0
            self._send_to_datapath(CMD_CLEAR_BLACKLIST, "0.0.0.0")
            return count

    # ==================== Protected IP Operations ====================

    def add_protected(self, ip: str, description: str = "",
                      profile_name: str = "", profile_overrides: Optional[Dict[str, Any]] = None) -> bool:
        """Add IP to protected servers list with optional protection profile."""
        with self.lock:
            try:
                rule = Rule(ip, RULE_TYPE_PROTECTED, description,
                           profile_name=profile_name, profile_overrides=profile_overrides)
                self.protected[ip] = rule
                if not self.save_rules():
                    del self.protected[ip]
                    return False
                # Write ip_lists.json BEFORE sending commands to C layer.
                # CMD_ADD_PROTECTED adds the IP to the hash table (no profile),
                # then CMD_RELOAD_PROFILES reads ip_lists.json for profile data.
                # The JSON must exist with full profile before reload.
                self._write_ip_lists_json()
                self._send_to_datapath(CMD_ADD_PROTECTED, ip)
                # Always reload profiles so the IP gets its profile data
                self._send_to_datapath(CMD_RELOAD_PROFILES, "0.0.0.0")
                return True
            except ValueError as e:
                logger.error("Invalid IP: %s", e)
                return False

    def remove_protected(self, ip: str, auto_disable_enforcement: bool = True) -> bool:
        """Remove IP from protected servers list.

        Args:
            auto_disable_enforcement: If True (default), also disables enforce_protected_ips
                                     when the last protected IP is removed.
        """
        with self.lock:
            if ip in self.protected:
                rule = self.protected[ip]
                del self.protected[ip]
                if not self.save_rules():
                    # Rollback if save failed
                    self.protected[ip] = rule
                    return False
                self._send_to_datapath(CMD_DEL_PROTECTED, ip)
                self._write_ip_lists_json()

                # Auto-disable enforcement if list is now empty
                if auto_disable_enforcement and len(self.protected) == 0:
                    try:
                        config_mgr = get_config_manager()
                        config_mgr.update_value("ip_lists", "enforce_protected_ips", False, notify=True)
                        logger.info("Auto-disabled enforce_protected_ips (list is now empty)")
                    except Exception as e:
                        logger.warning("Could not disable enforce_protected_ips: %s", e)

                return True
            return False

    def get_protected(self) -> List[Dict[str, Any]]:
        """Get all protected server entries."""
        with self.lock:
            return [r.to_dict() for r in self.protected.values()]

    def clear_protected(self, auto_disable_enforcement: bool = True) -> int:
        """Clear all protected server entries. Returns count of removed entries.

        Args:
            auto_disable_enforcement: If True (default), also disables enforce_protected_ips
                                     to prevent all traffic from being dropped when list is empty.
        """
        with self.lock:
            count = len(self.protected)
            if count == 0:
                return 0

            backup = dict(self.protected)
            self.protected.clear()

            if not self.save_rules():
                # Rollback if save failed
                self.protected = backup
                return 0

            # Send clear command to datapath
            # CMD_CLEAR_PROTECTED = 0x12
            self._send_to_datapath(0x12, "0.0.0.0")
            self._write_ip_lists_json()

            # Auto-disable enforcement to prevent dropping all traffic
            if auto_disable_enforcement:
                try:
                    config_mgr = get_config_manager()
                    config_mgr.update_value("ip_lists", "enforce_protected_ips", False, notify=True)
                    logger.info("Auto-disabled enforce_protected_ips (list is now empty)")
                except Exception as e:
                    logger.warning("Could not disable enforce_protected_ips: %s", e)

            return count

    # ==================== Protection Profile Operations ====================

    # Default profile templates (must match C layer1_config.c defaults)
    PROFILE_TEMPLATES = {
        "web_server": {
            "name": "web_server",
            "description": "Web server (HTTP/HTTPS)",
            "pps_limit": 50000,
            "attack_pps_limit": 5000,
            "max_conn_per_src": 100000,
            "syn_proxy_mode": "always",
            "tcp_ports": [80, 443],
            "icmp_action": "rate_limit",
            "icmp_rate_limit_pps": 100,
            "other_action": "drop",
        },
        "email_server": {
            "name": "email_server",
            "description": "Email server (SMTP/IMAP/POP3)",
            "pps_limit": 10000,
            "attack_pps_limit": 1000,
            "max_conn_per_src": 50,
            "syn_proxy_mode": "threshold",
            "syn_challenge_threshold": 500,
            "tcp_ports": [25, 587, 993, 995],
            "udp_action": "drop",
            "icmp_action": "rate_limit",
            "icmp_rate_limit_pps": 100,
            "other_action": "drop",
        },
        "dns_server": {
            "name": "dns_server",
            "description": "DNS server",
            "pps_limit": 100000,
            "attack_pps_limit": 10000,
            "max_conn_per_src": 100,
            "syn_proxy_mode": "disabled",
            "tcp_ports": [53],
            "udp_ports": [53],
            "icmp_action": "rate_limit",
            "icmp_rate_limit_pps": 500,
            "other_action": "drop",
        },
        "api_server": {
            "name": "api_server",
            "description": "API server (HTTPS/custom ports)",
            "pps_limit": 20000,
            "attack_pps_limit": 2000,
            "max_conn_per_src": 500,
            "syn_proxy_mode": "always",
            "tcp_ports": [443, 8080, 8443],
            "udp_action": "drop",
            "icmp_action": "rate_limit",
            "icmp_rate_limit_pps": 100,
            "other_action": "drop",
        },
        "generic": {
            "name": "generic",
            "description": "Generic server (use global defaults)",
        },
    }

    def _write_ip_lists_json(self) -> bool:
        """Write protected IPs with profiles to Layer1's ip_lists.json.

        The C layer reads this file to load protection profiles.
        Format: protected_ips can be strings (no profile) or objects (with profile).
        """
        try:
            # Build the data in C-compatible format
            protected_entries = []
            protected_subnets = []  # CIDR aggregates: "network/depth" strings
            for ip, rule in self.protected.items():
                # CIDR protected subnets go in their own array so the C loader
                # (ip_lists_load) registers them via ip_protected_subnet_add()
                # rather than failing str_to_ip() on a "a.b.c.d/len" string.
                if getattr(rule, "is_cidr", False):
                    protected_subnets.append(ip)
                    continue
                if rule.profile_name or rule.profile_overrides:
                    entry = {"ip": ip, "profile": rule.profile_name or "generic"}
                    # Merge template + overrides for C layer
                    template = self.PROFILE_TEMPLATES.get(rule.profile_name, {})
                    merged = {}
                    for key in ("pps_limit", "bps_limit", "attack_pps_limit",
                                "attack_bps_limit", "max_conn_per_src", "max_conn_total",
                                "syn_proxy_mode", "syn_challenge_threshold",
                                "tcp_ports", "udp_ports",
                                "tcp_action", "udp_action", "icmp_action", "other_action",
                                "tcp_rate_limit_pps", "udp_rate_limit_pps",
                                "icmp_rate_limit_pps", "other_rate_limit_pps",
                                "other_allowed_protos"):
                        # Override > template > omit
                        val = rule.profile_overrides.get(key) if rule.profile_overrides else None
                        if val is None:
                            val = template.get(key)
                        if val is not None:
                            merged[key] = val
                    if merged:
                        entry.update(merged)
                    protected_entries.append(entry)
                else:
                    protected_entries.append(ip)

            # Read existing file for whitelist/blacklist
            existing = {"whitelist_ips": [], "blacklist_ips": []}
            if self.layer1_ip_lists_file.exists():
                try:
                    with open(self.layer1_ip_lists_file, 'r') as f:
                        existing = json.load(f)
                except Exception:
                    pass

            data = {
                "protected_ips": protected_entries,
                "protected_subnets": protected_subnets,
                "whitelist_ips": existing.get("whitelist_ips", []),
                "blacklist_ips": existing.get("blacklist_ips", []),
            }

            _atomic_json_write(self.layer1_ip_lists_file, data, indent=2)

            logger.info("Wrote ip_lists.json with %d protected IPs", len(protected_entries))
            return True
        except Exception as e:
            logger.error("Error writing ip_lists.json: %s", e)
            return False

    def update_protected_profile(self, ip: str, profile_name: str = "",
                                  profile_overrides: Optional[Dict[str, Any]] = None) -> bool:
        """Update protection profile for an existing protected IP."""
        with self.lock:
            if ip not in self.protected:
                return False
            rule = self.protected[ip]
            rule.profile_name = profile_name
            rule.profile_overrides = profile_overrides or {}
            if not self.save_rules():
                return False
            self._write_ip_lists_json()
            self._send_to_datapath(CMD_RELOAD_PROFILES, "0.0.0.0")
            return True

    def get_profile_templates(self) -> List[Dict[str, Any]]:
        """Get available protection profile templates."""
        return [deepcopy(t) for t in self.PROFILE_TEMPLATES.values()]

    def get_protected_profile(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get the protection profile for a specific protected IP."""
        with self.lock:
            if ip not in self.protected:
                return None
            rule = self.protected[ip]
            template = self.PROFILE_TEMPLATES.get(rule.profile_name, {})
            # Merge template defaults with overrides
            merged = deepcopy(template)
            if rule.profile_overrides:
                merged.update(rule.profile_overrides)
            merged["profile_name"] = rule.profile_name or "generic"
            return merged

    # ==================== Utility Operations ====================

    def check_ip(self, ip: str) -> Dict[str, Any]:
        """Check if IP is in any list.

        Precedence: whitelist > blacklist (explicit trust overrides block).
        If an IP is in both lists, effective_action = 'allow'.
        """
        with self.lock:
            result = {
                'ip': ip,
                'whitelisted': ip in self.whitelist,
                'blacklisted': ip in self.blacklist,
                'protected': ip in self.protected,
            }

            # Check CIDR ranges
            try:
                ip_addr = ipaddress.ip_address(ip)
                for cidr, rule in self.cidr_whitelist.items():
                    if ip_addr in rule.network:
                        result['whitelisted'] = True
                        result['whitelist_cidr'] = cidr
                        break
            except ValueError:
                pass

            # Determine effective action with documented precedence
            if result['whitelisted']:
                result['effective_action'] = 'allow'
                if result['blacklisted']:
                    result['conflict'] = True
            elif result['blacklisted']:
                result['effective_action'] = 'block'
            else:
                result['effective_action'] = 'default'

            return result

    def get_stats(self) -> Dict[str, Any]:
        """Get rules engine statistics."""
        with self.lock:
            return {
                'whitelist_count': len(self.whitelist),
                'blacklist_count': len(self.blacklist),
                'protected_count': len(self.protected),
                'cidr_whitelist_count': len(self.cidr_whitelist),
                'total_rules': (len(self.whitelist) + len(self.blacklist) +
                               len(self.protected) + len(self.cidr_whitelist)),
                'last_sync': self.last_sync.isoformat() if self.last_sync else None,
                'sync_errors': self.sync_errors,
            }

    def cleanup_expired(self) -> int:
        """Remove expired rules. Returns count of removed rules."""
        with self.lock:
            removed = 0

            for ip in list(self.whitelist.keys()):
                if self.whitelist[ip].is_expired():
                    del self.whitelist[ip]
                    self._send_to_datapath(CMD_DEL_WHITELIST, ip)
                    removed += 1

            for ip in list(self.blacklist.keys()):
                if self.blacklist[ip].is_expired():
                    del self.blacklist[ip]
                    self._send_to_datapath(CMD_DEL_BLACKLIST, ip)
                    removed += 1

            for ip in list(self.cidr_whitelist.keys()):
                if self.cidr_whitelist[ip].is_expired():
                    del self.cidr_whitelist[ip]
                    removed += 1

            if removed > 0:
                self.save_rules()

            return removed


class ConfigManager:
    """
    Manages Layer1 configuration.

    Thread-safe operations for concurrent access from Flask routes.
    Handles reading/writing config file and notifying datapath of changes.
    """

    def __init__(self, config_path: str = DEFAULT_LAYER1_CONFIG,
                 socket_path: str = DEFAULT_SOCKET_PATH):
        self.config_path = Path(config_path)
        self.socket_path = socket_path
        self.lock = threading.RLock()
        self.config: Dict[str, Any] = {}
        self.last_modified = None

        # Load initial config
        self.load_config()
        logger.info("Using config: %s", self.config_path)

        # Sync dynamic settings to datapath on startup
        self.sync_geo_to_datapath()

    def load_config(self) -> bool:
        """Load configuration from JSON file, merging missing keys from defaults."""
        with self.lock:
            try:
                if self.config_path.exists():
                    with open(self.config_path, 'r') as f:
                        self.config = json.load(f)
                    self.last_modified = datetime.fromtimestamp(
                        os.path.getmtime(self.config_path)
                    )
                    # Backfill missing keys from defaults so new config
                    # options work without requiring a manual file edit
                    merged = False
                    for section, defaults in DEFAULT_CONFIG.items():
                        if isinstance(defaults, dict):
                            if section not in self.config:
                                self.config[section] = deepcopy(defaults)
                                merged = True
                            else:
                                for key, val in defaults.items():
                                    if key not in self.config[section]:
                                        self.config[section][key] = deepcopy(val)
                                        merged = True
                        elif section not in self.config:
                            self.config[section] = deepcopy(defaults)
                            merged = True
                    if merged:
                        self.save_config(description="auto-merge missing defaults")
                else:
                    # Use defaults if file doesn't exist
                    self.config = deepcopy(DEFAULT_CONFIG)
                    self.save_config()
                return True
            except Exception as e:
                logger.error("Error loading config: %s", e)
                self.config = deepcopy(DEFAULT_CONFIG)
                return False

    def save_config(self, description: str = None) -> bool:
        """Save configuration to JSON file and create DB snapshot."""
        with self.lock:
            try:
                _atomic_json_write(self.config_path, self.config, indent=4)

                self.last_modified = datetime.now()

                # Save snapshot to DB for versioning/rollback
                self._save_snapshot(description)
                return True
            except Exception as e:
                logger.error("Error saving config: %s", e)
                return False

    def _save_snapshot(self, description: str = None):
        """Save a config snapshot and update SystemConfigDB."""
        try:
            from api.database.connection import db_session
            from api.database.models import ConfigSnapshot, SystemConfigDB
            from sqlalchemy import func as sa_func

            with db_session() as db:
                # Update live SystemConfigDB row
                sys_config = db.query(SystemConfigDB).filter(
                    SystemConfigDB.id == 1
                ).first()
                if sys_config is None:
                    sys_config = SystemConfigDB(id=1)
                    db.add(sys_config)
                sys_config.layer1 = deepcopy(self.config)
                sys_config.version = (sys_config.version or 0) + 1
                sys_config.updated_at = datetime.now()

                # Get next snapshot version number
                max_ver = db.query(sa_func.max(ConfigSnapshot.version)).scalar()
                version = (max_ver or 0) + 1

                snapshot = ConfigSnapshot(
                    version=version,
                    config_data=deepcopy(self.config),
                    description=description or "layer1 config update",
                )
                db.add(snapshot)

                # Keep max 50 snapshots, prune oldest
                count = db.query(ConfigSnapshot).count()
                if count > 50:
                    oldest = db.query(ConfigSnapshot).order_by(
                        ConfigSnapshot.id.asc()
                    ).limit(count - 50).all()
                    for old in oldest:
                        db.delete(old)
        except Exception as e:
            # DB failure must not break config save
            logger.warning("Snapshot save failed (non-fatal): %s", e)

    def get_config_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Get config version history from DB."""
        try:
            from api.database.connection import db_session
            from api.database.models import ConfigSnapshot

            with db_session() as db:
                snapshots = db.query(ConfigSnapshot).order_by(
                    ConfigSnapshot.id.desc()
                ).limit(limit).all()
                return [
                    {
                        "id": s.id,
                        "version": s.version,
                        "description": s.description,
                        "created_at": s.created_at.isoformat() if s.created_at else None,
                    }
                    for s in snapshots
                ]
        except Exception as e:
            logger.error("Error getting history: %s", e)
            return []

    def restore_snapshot(self, snapshot_id: int, notify: bool = True) -> bool:
        """Restore config from a previous snapshot."""
        try:
            from api.database.connection import db_session
            from api.database.models import ConfigSnapshot

            with db_session() as db:
                snapshot = db.query(ConfigSnapshot).filter(
                    ConfigSnapshot.id == snapshot_id
                ).first()
                if not snapshot:
                    return False

                with self.lock:
                    self.config = deepcopy(snapshot.config_data)
                    if self.save_config(f"Restored from version {snapshot.version}") and notify:
                        self._notify_datapath()
                    return True
        except Exception as e:
            logger.error("Error restoring snapshot: %s", e)
            return False

    def get_snapshot_config(self, snapshot_id: int) -> Optional[Dict[str, Any]]:
        """Get the config data from a specific snapshot."""
        try:
            from api.database.connection import db_session
            from api.database.models import ConfigSnapshot

            with db_session() as db:
                snapshot = db.query(ConfigSnapshot).filter(
                    ConfigSnapshot.id == snapshot_id
                ).first()
                if not snapshot:
                    return None
                return deepcopy(snapshot.config_data)
        except Exception as e:
            logger.error("Error getting snapshot: %s", e)
            return None

    def _notify_datapath(self, cmd: int = CMD_RELOAD_CONFIG) -> bool:
        """Notify datapath to reload configuration."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(self.socket_path)

            # Send reload command (must match control_cmd struct: cmd + ip + prefix_len)
            # For config reload, ip and prefix_len are unused but must be present
            packet = struct.pack('<BIB', cmd, 0, 0)
            sock.sendall(packet)

            # Wait for ACK
            response = sock.recv(4)
            sock.close()

            return len(response) >= 1 and response[0] == 0
        except socket.error:
            # Socket not available - datapath not running (expected during dev)
            return False
        except Exception as e:
            logger.error("Error notifying datapath: %s", e)
            return False

    def get_config(self) -> Dict[str, Any]:
        """Get full configuration."""
        with self.lock:
            return deepcopy(self.config)

    def get_section(self, section: str) -> Optional[Dict[str, Any]]:
        """Get a specific configuration section."""
        with self.lock:
            if section in self.config:
                return deepcopy(self.config[section])
            return None

    def update_section(self, section: str, values: Dict[str, Any],
                       notify: bool = True) -> bool:
        """Update a configuration section."""
        with self.lock:
            try:
                if section not in self.config:
                    return False

                # Update only provided keys
                for key, value in values.items():
                    if key in self.config[section]:
                        self.config[section][key] = value

                if self.save_config() and notify:
                    self._notify_datapath()
                return True
            except Exception as e:
                logger.error("Error updating section: %s", e)
                return False

    def update_value(self, section: str, key: str, value: Any,
                     notify: bool = True):
        """Update a single configuration value.

        Returns dict {'saved': True, 'applied': bool} on success, False on failure.
        Non-empty dict is truthy so callers using ``if update_value(...)`` still work.
        """
        with self.lock:
            try:
                if section is None:
                    # Top-level config value
                    if key in self.config:
                        self.config[key] = value
                    else:
                        return False
                else:
                    if section not in self.config:
                        return False
                    if key not in self.config[section]:
                        return False
                    self.config[section][key] = value

                saved = self.save_config()
                if not saved:
                    return False
                applied = self._notify_datapath() if notify else False
                return {'saved': True, 'applied': applied}
            except Exception as e:
                logger.error("Error updating value: %s", e)
                return False

    def update_top_level(self, key: str, value: Any, notify: bool = True) -> bool:
        """Update a top-level configuration value (log_level, stats_enabled, monitor_only, tap_mode)."""
        allowed_keys = ['log_level', 'stats_enabled', 'monitor_only', 'tap_mode']
        if key not in allowed_keys:
            return False
        return self.update_value(None, key, value, notify)

    def reset_to_defaults(self, notify: bool = True) -> bool:
        """Reset configuration to defaults."""
        with self.lock:
            self.config = deepcopy(DEFAULT_CONFIG)
            if self.save_config() and notify:
                self._notify_datapath()
            return True

    def reset_section(self, section: str, notify: bool = True) -> bool:
        """Reset a specific section to defaults."""
        with self.lock:
            if section in DEFAULT_CONFIG:
                self.config[section] = deepcopy(DEFAULT_CONFIG[section])
                if self.save_config() and notify:
                    self._notify_datapath()
                return True
            return False

    # ==================== Stage Controls ====================

    def get_stages(self) -> List[Dict[str, Any]]:
        """Get all stage definitions with current status."""
        with self.lock:
            stages = []
            for stage_id, stage_def in STAGES.items():
                section = stage_def["config_section"]
                key = stage_def["enable_key"]

                if section is None:
                    enabled = self.config.get(key, False)
                else:
                    enabled = self.config.get(section, {}).get(key, False)

                stages.append({
                    "id": stage_id,
                    "name": stage_def["name"],
                    "description": stage_def["description"],
                    "category": stage_def["category"],
                    "enabled": enabled
                })
            return stages

    def get_stages_by_category(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get stages grouped by category."""
        stages = self.get_stages()
        categories = {}
        for stage in stages:
            cat = stage["category"]
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(stage)
        return categories

    def _set_stage_value(self, stage_id: str, enabled: bool) -> bool:
        """Internal helper to set a single stage value without saving."""
        if stage_id not in STAGES:
            return False

        stage_def = STAGES[stage_id]
        section = stage_def["config_section"]
        key = stage_def["enable_key"]

        if section is None:
            self.config[key] = enabled
        else:
            if section not in self.config:
                return False
            if key not in self.config[section]:
                return False
            self.config[section][key] = enabled

        return True

    def set_stage_enabled(self, stage_id: str, enabled: bool,
                          notify: bool = True) -> bool:
        """
        Enable or disable a stage.

        When enabling monitor_only: disables all protection stages.
        When disabling a stage: also disables dependent stages.
        """
        if stage_id not in STAGES:
            return False

        with self.lock:
            # Set the primary stage
            if not self._set_stage_value(stage_id, enabled):
                return False

            # Handle cascading effects
            if enabled and stage_id == "monitor_only":
                # Monitor-only mode: disable all protection stages
                for dependent_stage in STAGE_DEPENDENCIES.get("monitor_only", []):
                    self._set_stage_value(dependent_stage, False)
            elif not enabled and stage_id in STAGE_DEPENDENCIES:
                # Disabling a stage: also disable its dependents
                for dependent_stage in STAGE_DEPENDENCIES[stage_id]:
                    self._set_stage_value(dependent_stage, False)

            # Save once after all changes
            self.save_config()

        if notify:
            self._notify_datapath(CMD_RELOAD_CONFIG)

        return True

    def get_stage_status(self, stage_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a specific stage."""
        if stage_id not in STAGES:
            return None

        stage_def = STAGES[stage_id]
        section = stage_def["config_section"]
        key = stage_def["enable_key"]

        with self.lock:
            if section is None:
                enabled = self.config.get(key, False)
            else:
                enabled = self.config.get(section, {}).get(key, False)

            return {
                "id": stage_id,
                "name": stage_def["name"],
                "description": stage_def["description"],
                "category": stage_def["category"],
                "enabled": enabled,
                "config_section": section,
                "enable_key": key
            }

    # ==================== Validation Helpers ====================

    def get_config_schema(self) -> Dict[str, Any]:
        """Get configuration schema with field descriptions."""
        return {
            "ip_lists": {
                "max_whitelist_entries": {"type": "int", "min": 100, "max": 1000000, "desc": "Maximum exact IP whitelist entries"},
                "max_blacklist_entries": {"type": "int", "min": 100, "max": 1000000, "desc": "Maximum blacklist entries"},
                "max_protected_entries": {"type": "int", "min": 10, "max": 100000, "desc": "Maximum protected server entries"},
                "max_whitelist_cidrs": {"type": "int", "min": 10, "max": 10000, "desc": "Maximum CIDR whitelist entries"},
                "enforce_protected_ips": {"type": "bool", "desc": "Only allow traffic to protected IPs"}
            },
            "flow_table": {
                "max_flows": {"type": "int", "min": 1000, "max": 100000000, "desc": "Maximum concurrent flows"},
                "idle_timeout_sec": {"type": "int", "min": 1, "max": 3600, "desc": "Timeout for established flows"},
                "syn_timeout_sec": {"type": "int", "min": 1, "max": 120, "desc": "Timeout for half-open connections"},
                "default_pps_limit": {"type": "int", "min": 0, "max": 10000000, "desc": "Default packets/sec per flow (0=unlimited)"},
                "default_bps_limit": {"type": "int", "min": 0, "max": 10000000000, "desc": "Default bytes/sec per flow (0=unlimited)"},
                "enable_syn_protection": {"type": "bool", "desc": "Enable aggressive SYN timeout"}
            },
            "syn_proxy": {
                "enabled": {"type": "bool", "desc": "Enable SYN proxy"},
                "max_connections": {"type": "int", "min": 1000, "max": 100000000, "desc": "Maximum tracked connections"},
                "connect_timeout_ms": {"type": "int", "min": 100, "max": 60000, "desc": "Timeout waiting for server (ms)"},
                "idle_timeout_sec": {"type": "int", "min": 1, "max": 3600, "desc": "Connection idle timeout"},
                "secret_rotation_sec": {"type": "int", "min": 1, "max": 3600, "desc": "Secret rotation interval"}
            },
            "syn_cookie": {
                "enabled": {"type": "bool", "desc": "Enable SYN cookies"},
                "challenge_threshold": {"type": "int", "min": 100, "max": 1000000, "desc": "PPS threshold to start challenging"}
            },
            "connection_limits": {
                "max_ips": {"type": "int", "min": 1000, "max": 10000000, "desc": "Maximum IPs to track"},
                "max_connections_per_ip": {"type": "int", "min": 1, "max": 100000, "desc": "Max connections per IP"},
                "time_window_sec": {"type": "int", "min": 1, "max": 3600, "desc": "Time window for limits"},
                "cleanup_interval_sec": {"type": "int", "min": 1, "max": 300, "desc": "Cleanup interval"}
            },
            "udp_gatekeeper": {
                "pps_threshold": {"type": "int", "min": 100, "max": 10000000, "desc": "UDP packets/sec per IP"},
                "bps_threshold": {"type": "int", "min": 1000, "max": 10000000000, "desc": "UDP bytes/sec per IP"},
                "cms_width": {"type": "int", "min": 256, "max": 1048576, "desc": "Count-Min Sketch width"},
                "cms_depth": {"type": "int", "min": 2, "max": 16, "desc": "Count-Min Sketch depth"},
                "window_sec": {"type": "int", "min": 1, "max": 60, "desc": "Time window in seconds"},
                "check_reputation": {"type": "bool", "desc": "Check reputation before rate check"},
                "reputation_threshold": {"type": "int", "min": 0, "max": 65535, "desc": "Block if reputation below this"},
                "check_blacklist": {"type": "bool", "desc": "Check blacklist for UDP"},
                "attack_pps_divisor": {"type": "int", "min": 1, "max": 100, "desc": "Threshold divisor during attack"},
                "attack_bps_divisor": {"type": "int", "min": 1, "max": 100, "desc": "Threshold divisor during attack"}
            },
            "telemetry": {
                "db_path": {"type": "str", "desc": "SQLite database path"},
                "export_interval_sec": {"type": "int", "min": 1, "max": 300, "desc": "Export interval"},
                "max_flow_records": {"type": "int", "min": 256, "max": 1048576, "desc": "Ring buffer size"},
                "flow_sample_rate": {"type": "int", "min": 1, "max": 10000, "desc": "1:N sampling rate"},
                "export_packet_samples": {"type": "bool", "desc": "Export individual packet samples"},
                "events_enabled": {"type": "bool", "desc": "Record attack events"}
            },
            "validation": {
                "validate_ip_checksum": {"type": "bool", "desc": "Validate IP header checksum"},
                "validate_udp_checksum": {"type": "bool", "desc": "Validate UDP checksum"},
                "validate_tcp_checksum": {"type": "bool", "desc": "Validate TCP checksum"},
                "validate_icmp_checksum": {"type": "bool", "desc": "Validate ICMP message checksum"},
                "drop_invalid_src_ip": {"type": "bool", "desc": "Drop packets from invalid source IPs"},
                "drop_land_attack": {"type": "bool", "desc": "Drop LAND attack packets"},
                "drop_tcp_null": {"type": "bool", "desc": "Drop TCP NULL flag packets"},
                "drop_tcp_xmas": {"type": "bool", "desc": "Drop XMAS tree packets"},
                "drop_zero_ttl": {"type": "bool", "desc": "Drop zero TTL packets"},
                "drop_port_zero": {"type": "bool", "desc": "Drop TCP/UDP with port 0"},
                "drop_syn_fragment": {"type": "bool", "desc": "Drop fragmented TCP SYN packets"},
                "drop_ip_reserved_flag": {"type": "bool", "desc": "Drop packets with IP reserved flag set"},
                "drop_teardrop": {"type": "bool", "desc": "Drop teardrop attack fragments"},
                "drop_tcp_data_offset": {"type": "bool", "desc": "Drop TCP with data offset < 5 (header < 20B)"},
                "drop_fragment_fin_rst": {"type": "bool", "desc": "Drop fragmented FIN/RST packets"},
                "drop_all_fragments": {"type": "bool", "desc": "Drop ALL IP fragments (aggressive, recommended for DDoS appliances)"},
                "drop_fragments": {"type": "bool", "desc": "Drop small/suspicious fragmented packets"},
                "decrement_ttl": {"type": "bool", "desc": "Decrement TTL on forwarding"}
            },
            "rate_limits": {
                "global_pps_limit": {"type": "int", "min": 0, "max": 1000000000, "desc": "Global packets/sec limit (0=unlimited)"},
                "global_bps_limit": {"type": "int", "min": 0, "max": 100000000000, "desc": "Global bytes/sec limit (0=unlimited)"},
                "normal_pps_per_ip": {"type": "int", "min": 100, "max": 10000000, "desc": "Normal mode packets/sec per source IP"},
                "normal_bps_per_ip": {"type": "int", "min": 1000, "max": 10000000000, "desc": "Normal mode bytes/sec per source IP"},
                "attack_pps_per_ip": {"type": "int", "min": 10, "max": 1000000, "desc": "Attack mode packets/sec per source IP"},
                "attack_bps_per_ip": {"type": "int", "min": 1000, "max": 1000000000, "desc": "Attack mode bytes/sec per source IP"},
                "dynamic_enabled": {"type": "bool", "desc": "Automatically switch between normal and attack limits based on anomaly level"},
                "anomaly_detection_window": {"type": "int", "min": 1, "max": 300, "desc": "Window for anomaly-based rate adjustment (seconds)"},
                "progressive_enabled": {"type": "bool", "desc": "Interpolate limits between normal and attack based on anomaly severity"},
                "level_low_percent": {"type": "int", "min": 1, "max": 100, "desc": "Percent of normal limit at LOW anomaly"},
                "level_medium_percent": {"type": "int", "min": 1, "max": 100, "desc": "Percent of normal limit at MEDIUM anomaly"},
                "level_high_percent": {"type": "int", "min": 1, "max": 100, "desc": "Percent of normal limit at HIGH anomaly"},
                "level_critical_percent": {"type": "int", "min": 1, "max": 100, "desc": "Percent of normal limit at CRITICAL anomaly"},
                "spoofed_aggregate_enabled": {"type": "bool", "desc": "Enable per-destination aggregate limiting during spoofed floods"},
                "spoofed_adaptive_limit_pct": {"type": "int", "min": 100, "max": 500, "desc": "Percent of learned baseline PPS as aggregate threshold"},
                "spoofed_min_dst_pps": {"type": "int", "min": 1000, "max": 10000000, "desc": "Minimum packets/sec floor per destination"},
                "spoofed_syn_per_dst_limit": {"type": "int", "min": 100, "max": 1000000, "desc": "Maximum SYN packets/sec per destination"},
                "spoofed_packet_multiplier": {"type": "int", "min": 1, "max": 16, "desc": "Unvalidated packet count multiplier toward aggregate threshold"},
                "legitimate_table_size": {"type": "int", "min": 1000, "max": 10000000, "desc": "Maximum entries in validated source IP table"},
                "legitimate_ttl_sec": {"type": "int", "min": 30, "max": 3600, "desc": "Time-to-live for validated source entries (seconds)"}
            },
            "ports": {
                "client_facing_port": {"type": "int", "min": 0, "max": 7, "desc": "Port facing clients"},
                "server_facing_port": {"type": "int", "min": 0, "max": 7, "desc": "Port facing servers"}
            },
            "maintenance": {
                "flow_age_interval_sec": {"type": "int", "min": 1, "max": 60, "desc": "Flow aging interval"},
                "secret_rotation_sec": {"type": "int", "min": 1, "max": 3600, "desc": "Secret rotation interval"},
                "stats_print_interval_sec": {"type": "int", "min": 0, "max": 300, "desc": "Stats print interval (0=disabled)"}
            },
            "geo_blocking": {
                "enabled": {"type": "bool", "desc": "Enable geo-blocking"},
                "mode": {"type": "str", "desc": "Mode: 'blacklist' (block selected) or 'whitelist' (allow only selected)"},
                "database_path": {"type": "str", "desc": "Path to GeoIP CSV database (ip2country.csv)"},
                "blocked_countries": {"type": "list", "desc": "List of country codes to block (ISO 3166-1 alpha-2)"},
                "allowed_countries": {"type": "list", "desc": "List of country codes to allow (whitelist mode)"},
                "log_blocked": {"type": "bool", "desc": "Log blocked packets"},
                "block_unknown": {"type": "bool", "desc": "Block IPs with unknown/unresolvable country"}
            },
            "other_protocols": {
                "enabled": {"type": "bool", "desc": "Enable other protocols handling"},
                "default_action": {"type": "str", "desc": "Default action: 'drop', 'accept', or 'rate_limit'"},
                "allowed_protocols": {"type": "list", "desc": "List of allowed IP protocol numbers (e.g., 47=GRE, 50=ESP)"},
                "rate_limit_pps": {"type": "int", "min": 0, "max": 1000000, "desc": "Rate limit for other protocols (PPS)"},
                "log_unknown": {"type": "bool", "desc": "Log unknown protocol packets"}
            },
            "signatures": {
                "enabled": {"type": "bool", "desc": "Enable L3/L4 signature detection"},
                "log_matches": {"type": "bool", "desc": "Log signature matches"},
                "block_amplification": {"type": "bool", "desc": "Block amplification attacks (DNS, NTP, SSDP)"},
                "block_scans": {"type": "bool", "desc": "Block port scan patterns"}
            },
            "tcp_flag_rate": {
                "enabled": {"type": "bool", "desc": "Enable per-TCP-flag rate limiting (Stage 9b)"},
                "max_entries": {"type": "int", "min": 1000, "max": 1000000, "desc": "Maximum IPs to track for flag rate limiting"},
                "cleanup_interval_sec": {"type": "int", "min": 10, "max": 600, "desc": "Cleanup interval for expired entries (seconds)"},
                "report_violations": {"type": "bool", "desc": "Report violations to Layer 4 for reputation updates"},
                "syn_pps": {"type": "int", "min": 0, "max": 1000000, "desc": "SYN packets/sec per source (connection initiation)"},
                "syn_ack_pps": {"type": "int", "min": 0, "max": 1000000, "desc": "SYN+ACK packets/sec per source"},
                "ack_pps": {"type": "int", "min": 0, "max": 1000000, "desc": "Pure ACK packets/sec per source (bulk transfers)"},
                "rst_pps": {"type": "int", "min": 0, "max": 1000000, "desc": "RST packets/sec per source"},
                "fin_pps": {"type": "int", "min": 0, "max": 1000000, "desc": "FIN packets/sec per source"},
                "psh_pps": {"type": "int", "min": 0, "max": 1000000, "desc": "PSH packets/sec per source (data push)"},
                "urg_pps": {"type": "int", "min": 0, "max": 1000000, "desc": "URG packets/sec per source (rare, usually attack)"},
                "other_pps": {"type": "int", "min": 0, "max": 1000000, "desc": "Other flag combinations packets/sec per source"}
            },
            "tcp_abuse": {
                "enabled": {"type": "bool", "desc": "Enable TCP protocol abuse detection"},
                "report_to_layer4": {"type": "bool", "desc": "Report abuse detections to Layer 4 for reputation updates"},
                "dup_seq_threshold": {"type": "int", "min": 10, "max": 10000, "desc": "Duplicate SEQ count per second to trigger detection"},
                "random_seq_threshold": {"type": "int", "min": 5, "max": 1000, "desc": "Random SEQ jumps in 10s window to trigger detection"},
                "random_ack_threshold": {"type": "int", "min": 5, "max": 1000, "desc": "Random ACK jumps in 10s window to trigger detection"},
                "zero_window_threshold": {"type": "int", "min": 1, "max": 100, "desc": "Zero window count in 10s to trigger detection"},
                "tiny_window_bytes": {"type": "int", "min": 1, "max": 1000, "desc": "Window size threshold for 'tiny window' detection (bytes)"},
                "small_window_bytes": {"type": "int", "min": 100, "max": 10000, "desc": "Window size threshold for 'small window' detection (bytes)"},
                "same_window_threshold": {"type": "int", "min": 10, "max": 10000, "desc": "Same window value repetitions per second to trigger"},
                "same_ack_threshold": {"type": "int", "min": 10, "max": 10000, "desc": "Same ACK value repetitions per second to trigger"},
                "action_dup_seq": {"type": "int", "min": 0, "max": 2, "desc": "Action for duplicate SEQ flood (0=log, 1=drop, 2=rate_limit)"},
                "action_random_seq": {"type": "int", "min": 0, "max": 2, "desc": "Action for random SEQ flood (0=log, 1=drop, 2=rate_limit)"},
                "action_random_ack": {"type": "int", "min": 0, "max": 2, "desc": "Action for random ACK flood (0=log, 1=drop, 2=rate_limit)"},
                "action_zero_window": {"type": "int", "min": 0, "max": 2, "desc": "Action for zero window attack (0=log, 1=drop, 2=rate_limit)"},
                "action_tiny_window": {"type": "int", "min": 0, "max": 2, "desc": "Action for tiny window attack (0=log, 1=drop, 2=rate_limit)"},
                "action_small_window": {"type": "int", "min": 0, "max": 2, "desc": "Action for small window (0=log, 1=drop, 2=rate_limit)"},
                "action_same_window": {"type": "int", "min": 0, "max": 2, "desc": "Action for same window flood (0=log, 1=drop, 2=rate_limit)"},
                "action_same_ack": {"type": "int", "min": 0, "max": 2, "desc": "Action for same ACK flood (0=log, 1=drop, 2=rate_limit)"}
            },
            "layer2_response": {
                "enabled": {"type": "bool", "desc": "Enable automatic attack response actions"},
                "auto_enable_syn_proxy_on_attack": {"type": "bool", "desc": "Automatically enable SYN proxy when attack detected"},
                "auto_reduce_rate_limits_on_attack": {"type": "bool", "desc": "Automatically tighten rate limits during attacks"},
                "attack_rate_limit_divisor": {"type": "int", "min": 1, "max": 100, "desc": "Divide normal rate limits by this factor during attack"},
                "min_anomaly_level_for_response": {"type": "int", "min": 1, "max": 4, "desc": "Minimum anomaly severity to trigger auto-response (1=Low, 4=Critical)"},
                "response_delay_sec": {"type": "int", "min": 0, "max": 60, "desc": "Seconds to wait before activating auto-response after detection"}
            },
            "l7_validation": {
                "dns_enabled": {"type": "bool", "desc": "Enable DNS protocol validation (UDP port 53)"},
                "dns_drop_invalid_opcode": {"type": "bool", "desc": "Drop DNS with invalid opcode (>5)"},
                "dns_drop_qr_mismatch": {"type": "bool", "desc": "Drop DNS with QR bit direction mismatch"},
                "dns_drop_qdcount_invalid": {"type": "bool", "desc": "Drop DNS queries with QDCOUNT != 1"},
                "dns_drop_both_port53": {"type": "bool", "desc": "Drop packets with both src and dst port 53"},
                "dns_drop_zone_transfer": {"type": "bool", "desc": "Drop AXFR zone transfer over UDP"},
                "dns_drop_label_too_long": {"type": "bool", "desc": "Drop DNS with label > 63 bytes"},
                "dns_drop_name_too_long": {"type": "bool", "desc": "Drop DNS with FQDN > 255 bytes"},
                "dns_drop_pointer_loop": {"type": "bool", "desc": "Drop DNS with compression pointer loops"},
                "dns_drop_too_short": {"type": "bool", "desc": "Drop DNS packets shorter than 12 bytes"},
                "dns_max_udp_size": {"type": "int", "min": 512, "max": 65535, "desc": "Maximum DNS UDP message size"},
                "ntp_enabled": {"type": "bool", "desc": "Enable NTP protocol validation (UDP port 123)"},
                "ntp_drop_invalid_version": {"type": "bool", "desc": "Drop NTP with version 0 or >4"},
                "ntp_drop_invalid_mode": {"type": "bool", "desc": "Drop NTP with mode > 7"},
                "ntp_drop_invalid_stratum": {"type": "bool", "desc": "Drop NTP with stratum > 15"},
                "ntp_drop_monlist": {"type": "bool", "desc": "Drop NTP Mode 7 private (monlist amplification)"},
                "ntp_drop_control": {"type": "bool", "desc": "Drop NTP Mode 6 control messages"},
                "ntp_drop_size_mismatch": {"type": "bool", "desc": "Drop NTP with incorrect packet size"},
                "ntp_drop_too_short": {"type": "bool", "desc": "Drop NTP packets shorter than minimum"},
                "http_enabled": {"type": "bool", "desc": "Enable HTTP first-packet validation (TCP 80/8080)"},
                "http_drop_invalid_method": {"type": "bool", "desc": "Drop HTTP with unknown request method"},
                "http_drop_invalid_version": {"type": "bool", "desc": "Drop HTTP with invalid version string"},
                "http_drop_line_too_long": {"type": "bool", "desc": "Drop HTTP with request line exceeding max"},
                "http_drop_non_ascii": {"type": "bool", "desc": "Drop HTTP with non-printable characters"},
                "http_max_request_line": {"type": "int", "min": 256, "max": 65535, "desc": "Maximum HTTP request line length"},
                "icmp_enabled": {"type": "bool", "desc": "Enable ICMP type/code filtering"},
                "icmp_drop_redirect": {"type": "bool", "desc": "Drop ICMP Redirect (type 5) - route injection"},
                "icmp_drop_router_advert": {"type": "bool", "desc": "Drop ICMP Router Advertisement (type 9)"},
                "icmp_drop_router_solicit": {"type": "bool", "desc": "Drop ICMP Router Solicitation (type 10)"},
                "icmp_drop_timestamp": {"type": "bool", "desc": "Drop ICMP Timestamp request/reply (type 13/14)"},
                "icmp_drop_address_mask": {"type": "bool", "desc": "Drop ICMP Address Mask request/reply (type 17/18)"},
                "icmp_drop_info": {"type": "bool", "desc": "Drop ICMP Information request/reply (type 15/16)"},
                "icmp_drop_source_quench": {"type": "bool", "desc": "Drop ICMP Source Quench (type 4) - obsolete per RFC 6633"},
                "icmp_rate_limit_pps": {"type": "int", "min": 0, "max": 1000000, "desc": "Global ICMP rate limit in PPS (0=unlimited)"}
            },
            "log_level": {"type": "int", "min": 0, "max": 8, "desc": "DPDK log level"},
            "stats_enabled": {"type": "bool", "desc": "Enable statistics collection"}
        }

    # ==================== Geo-Blocking Management ====================

    def get_geo_blocking(self) -> Dict[str, Any]:
        """Get geo-blocking configuration with countries list."""
        with self.lock:
            geo = deepcopy(self.config.get("geo_blocking", {}))
            # Provide the full list of countries for UI
            geo["all_countries"] = self._get_all_countries()
            return geo

    def set_geo_blocking_enabled(self, enabled: bool, notify: bool = True) -> bool:
        """Enable or disable geo-blocking."""
        result = self.update_value("geo_blocking", "enabled", enabled, notify)
        if result and notify:
            # Send enable/disable as numeric 1/0 (not ASCII)
            self._send_geo_command(CMD_GEO_SET_ENABLED, 1 if enabled else 0)
        return result

    def set_geo_block_unknown(self, block: bool, notify: bool = True) -> bool:
        """Set whether to block IPs with unknown/unresolvable country."""
        with self.lock:
            if "geo_blocking" not in self.config:
                self.config["geo_blocking"] = {}
            self.config["geo_blocking"]["block_unknown"] = block
            self.save_config()

        if notify:
            # Send as numeric 1/0 (not ASCII)
            self._send_geo_command(CMD_GEO_BLOCK_UNKNOWN, 1 if block else 0)
        return True

    def set_geo_blocking_mode(self, mode: str, notify: bool = True) -> bool:
        """Set geo-blocking mode: 'blacklist' or 'whitelist'."""
        if mode not in ("blacklist", "whitelist"):
            return False
        result = self.update_value("geo_blocking", "mode", mode, notify)
        if result and notify:
            # Send mode command: "BL" for blacklist, "WL" for whitelist
            mode_str = "BL" if mode == "blacklist" else "WL"
            self._send_geo_command(CMD_GEO_SET_MODE, mode_str)
        return result

    def add_geo_country(self, country_code: str, notify: bool = True) -> bool:
        """Add a country to the geo filter (blocked or allowed based on mode)."""
        if len(country_code) != 2:
            return False

        country_code = country_code.upper()

        with self.lock:
            geo = self.config.get("geo_blocking", {})
            mode = geo.get("mode", "blacklist")

            if mode == "blacklist":
                countries = geo.get("blocked_countries", [])
                if country_code not in countries:
                    countries.append(country_code)
                    self.config["geo_blocking"]["blocked_countries"] = countries
            else:
                countries = geo.get("allowed_countries", [])
                if country_code not in countries:
                    countries.append(country_code)
                    self.config["geo_blocking"]["allowed_countries"] = countries

            self.save_config()

        if notify:
            self._send_geo_command(CMD_GEO_ADD_COUNTRY, country_code)
            self._notify_datapath()

        return True

    def remove_geo_country(self, country_code: str, notify: bool = True) -> bool:
        """Remove a country from the geo filter."""
        if len(country_code) != 2:
            return False

        country_code = country_code.upper()

        with self.lock:
            geo = self.config.get("geo_blocking", {})
            mode = geo.get("mode", "blacklist")

            if mode == "blacklist":
                countries = geo.get("blocked_countries", [])
                if country_code in countries:
                    countries.remove(country_code)
                    self.config["geo_blocking"]["blocked_countries"] = countries
            else:
                countries = geo.get("allowed_countries", [])
                if country_code in countries:
                    countries.remove(country_code)
                    self.config["geo_blocking"]["allowed_countries"] = countries

            self.save_config()

        if notify:
            self._send_geo_command(CMD_GEO_DEL_COUNTRY, country_code)
            self._notify_datapath()

        return True

    def set_geo_countries(self, countries: List[str], notify: bool = True) -> bool:
        """Set the full list of countries for current mode."""
        # Validate all country codes
        validated = []
        for code in countries:
            if len(code) == 2:
                validated.append(code.upper())

        with self.lock:
            geo = self.config.get("geo_blocking", {})
            mode = geo.get("mode", "blacklist")

            if mode == "blacklist":
                self.config["geo_blocking"]["blocked_countries"] = validated
            else:
                self.config["geo_blocking"]["allowed_countries"] = validated

            self.save_config()

        if notify:
            # Batch all geo commands over a single socket connection
            # to avoid overwhelming the C socket backlog
            commands = [(CMD_GEO_CLEAR, "")]
            for code in validated:
                commands.append((CMD_GEO_ADD_COUNTRY, code))
            self._send_geo_commands_batch(commands)
            self._notify_datapath()

        return True

    def clear_geo_countries(self, notify: bool = True) -> bool:
        """Clear all countries from the geo filter."""
        with self.lock:
            self.config["geo_blocking"]["blocked_countries"] = []
            self.config["geo_blocking"]["allowed_countries"] = []
            self.save_config()

        if notify:
            self._send_geo_command(CMD_GEO_CLEAR, "")
            self._notify_datapath()

        return True

    def _send_geo_command(self, cmd: int, country_code) -> bool:
        """Send a single geo-blocking command to datapath."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(self.socket_path)

            # Pack: cmd (1 byte) + country code as 2-byte value + padding
            if isinstance(country_code, int):
                cc_val = country_code
            elif country_code and len(country_code) >= 2:
                cc_val = (ord(country_code[0]) << 8) | ord(country_code[1])
            else:
                cc_val = 0

            packet = struct.pack('<BIB', cmd, cc_val, 0)
            sock.sendall(packet)

            response = sock.recv(4)
            sock.close()

            return len(response) >= 1 and response[0] == 0
        except socket.error:
            return False
        except Exception as e:
            logger.error("Error sending geo command: %s", e)
            return False

    def _send_geo_commands_batch(self, commands: list) -> bool:
        """Send multiple geo commands over a single socket connection.

        Each command is a (cmd_byte, country_code) tuple.
        The C handle_client() loops on recv(), so multiple commands
        can be sent on one connection without reopening the socket.
        """
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(30.0)
            sock.connect(self.socket_path)

            for cmd, country_code in commands:
                if isinstance(country_code, int):
                    cc_val = country_code
                elif country_code and len(country_code) >= 2:
                    cc_val = (ord(country_code[0]) << 8) | ord(country_code[1])
                else:
                    cc_val = 0

                packet = struct.pack('<BIB', cmd, cc_val, 0)
                sock.sendall(packet)

                response = sock.recv(4)
                if len(response) < 1 or response[0] != 0:
                    logger.warning("Geo batch: command %s %s failed", hex(cmd), country_code)

            sock.close()
            return True
        except socket.error as e:
            logger.error("Geo batch socket error: %s", e)
            return False
        except Exception as e:
            logger.error("Geo batch error: %s", e)
            return False

    def sync_geo_to_datapath(self):
        """Sync geo-blocking settings from config to the C datapath.

        Called on startup to ensure C has the right state even if it
        was restarted independently. Sends: mode, block_unknown, countries.
        """
        try:
            geo = self.config.get("geo_blocking", {})
            if not geo:
                return

            commands = []

            # 1. Set mode
            mode = geo.get("mode", "blacklist")
            mode_str = "BL" if mode == "blacklist" else "WL"
            commands.append((CMD_GEO_SET_MODE, mode_str))

            # 2. Set block_unknown (numeric 1/0, not ASCII)
            block_unknown = geo.get("block_unknown", True)
            commands.append((CMD_GEO_BLOCK_UNKNOWN, 1 if block_unknown else 0))

            # 3. Set enabled (numeric 1/0, not ASCII)
            enabled = geo.get("enabled", False)
            commands.append((CMD_GEO_SET_ENABLED, 1 if enabled else 0))

            # 4. Clear and re-add countries
            commands.append((CMD_GEO_CLEAR, ""))
            if mode == "blacklist":
                countries = geo.get("blocked_countries", [])
            else:
                countries = geo.get("allowed_countries", [])

            for code in countries:
                if len(code) == 2:
                    commands.append((CMD_GEO_ADD_COUNTRY, code.upper()))

            if commands:
                self._send_geo_commands_batch(commands)
                logger.info("Geo sync: mode=%s, block_unknown=%s, enabled=%s, countries=%d",
                            mode, block_unknown, enabled, len(countries))
        except Exception as e:
            logger.warning("Geo sync failed (datapath may not be running): %s", e)

    def _get_all_countries(self) -> List[Dict[str, str]]:
        """Get list of all country codes with names."""
        return [
            {"code": "AF", "name": "Afghanistan"},
            {"code": "AL", "name": "Albania"},
            {"code": "DZ", "name": "Algeria"},
            {"code": "AR", "name": "Argentina"},
            {"code": "AM", "name": "Armenia"},
            {"code": "AU", "name": "Australia"},
            {"code": "AT", "name": "Austria"},
            {"code": "AZ", "name": "Azerbaijan"},
            {"code": "BD", "name": "Bangladesh"},
            {"code": "BY", "name": "Belarus"},
            {"code": "BE", "name": "Belgium"},
            {"code": "BR", "name": "Brazil"},
            {"code": "BG", "name": "Bulgaria"},
            {"code": "CA", "name": "Canada"},
            {"code": "CL", "name": "Chile"},
            {"code": "CN", "name": "China"},
            {"code": "CO", "name": "Colombia"},
            {"code": "HR", "name": "Croatia"},
            {"code": "CZ", "name": "Czech Republic"},
            {"code": "DK", "name": "Denmark"},
            {"code": "EG", "name": "Egypt"},
            {"code": "EE", "name": "Estonia"},
            {"code": "FI", "name": "Finland"},
            {"code": "FR", "name": "France"},
            {"code": "GE", "name": "Georgia"},
            {"code": "DE", "name": "Germany"},
            {"code": "GR", "name": "Greece"},
            {"code": "HK", "name": "Hong Kong"},
            {"code": "HU", "name": "Hungary"},
            {"code": "IN", "name": "India"},
            {"code": "ID", "name": "Indonesia"},
            {"code": "IR", "name": "Iran"},
            {"code": "IQ", "name": "Iraq"},
            {"code": "IE", "name": "Ireland"},
            {"code": "IL", "name": "Israel"},
            {"code": "IT", "name": "Italy"},
            {"code": "JP", "name": "Japan"},
            {"code": "KZ", "name": "Kazakhstan"},
            {"code": "KE", "name": "Kenya"},
            {"code": "KP", "name": "North Korea"},
            {"code": "KR", "name": "South Korea"},
            {"code": "KW", "name": "Kuwait"},
            {"code": "LV", "name": "Latvia"},
            {"code": "LT", "name": "Lithuania"},
            {"code": "MY", "name": "Malaysia"},
            {"code": "MX", "name": "Mexico"},
            {"code": "MD", "name": "Moldova"},
            {"code": "MA", "name": "Morocco"},
            {"code": "NL", "name": "Netherlands"},
            {"code": "NZ", "name": "New Zealand"},
            {"code": "NG", "name": "Nigeria"},
            {"code": "NO", "name": "Norway"},
            {"code": "PK", "name": "Pakistan"},
            {"code": "PE", "name": "Peru"},
            {"code": "PH", "name": "Philippines"},
            {"code": "PL", "name": "Poland"},
            {"code": "PT", "name": "Portugal"},
            {"code": "RO", "name": "Romania"},
            {"code": "RU", "name": "Russia"},
            {"code": "SA", "name": "Saudi Arabia"},
            {"code": "RS", "name": "Serbia"},
            {"code": "SG", "name": "Singapore"},
            {"code": "SK", "name": "Slovakia"},
            {"code": "SI", "name": "Slovenia"},
            {"code": "ZA", "name": "South Africa"},
            {"code": "ES", "name": "Spain"},
            {"code": "SE", "name": "Sweden"},
            {"code": "CH", "name": "Switzerland"},
            {"code": "TW", "name": "Taiwan"},
            {"code": "TH", "name": "Thailand"},
            {"code": "TR", "name": "Turkey"},
            {"code": "UA", "name": "Ukraine"},
            {"code": "AE", "name": "United Arab Emirates"},
            {"code": "GB", "name": "United Kingdom"},
            {"code": "US", "name": "United States"},
            {"code": "UZ", "name": "Uzbekistan"},
            {"code": "VE", "name": "Venezuela"},
            {"code": "VN", "name": "Vietnam"},
        ]

    def get_config_info(self) -> Dict[str, Any]:
        """Get configuration metadata."""
        with self.lock:
            return {
                "config_path": str(self.config_path),
                "last_modified": self.last_modified.isoformat() if self.last_modified else None,
                "file_exists": self.config_path.exists(),
                "sections": list(self.config.keys())
            }

    # ==================== Signature Management ====================

    def get_signatures(self) -> Dict[str, Any]:
        """Get all signatures with their current state."""
        with self.lock:
            sig_config = deepcopy(self.config.get("signatures", {}))

            # Define all built-in signatures with their metadata
            signatures = {
                "config": sig_config,
                "categories": self._get_signature_categories(),
                "amplification": self._get_amplification_signatures(),
                "scans": self._get_scan_signatures(),
                "anomalies": self._get_anomaly_signatures(),
                "attack_tools": self._get_attack_tool_signatures()
            }

            return signatures

    def _get_signature_categories(self) -> List[Dict[str, Any]]:
        """Get signature category definitions."""
        return [
            {
                "id": "amplification",
                "name": "Amplification Attacks",
                "description": "UDP reflection/amplification attacks (DNS, NTP, SSDP, etc.)",
                "config_key": "block_amplification",
                "id_range": "1000-1999"
            },
            {
                "id": "scans",
                "name": "Port Scans",
                "description": "TCP/UDP port scanning patterns",
                "config_key": "block_scans",
                "id_range": "2000-2999"
            },
            {
                "id": "anomalies",
                "name": "Protocol Anomalies",
                "description": "Invalid protocol combinations and suspicious patterns",
                "config_key": "block_anomalies",
                "id_range": "3000-3999"
            },
            {
                "id": "attack_tools",
                "name": "Attack Tools",
                "description": "Known DDoS tool signatures",
                "config_key": "block_attack_tools",
                "id_range": "4000-4999"
            }
        ]

    def _get_amplification_signatures(self) -> List[Dict[str, Any]]:
        """Get amplification attack signatures."""
        # Load enabled state from config if available
        sig_config = self.config.get("signatures", {})
        disabled_ports = sig_config.get("disabled_amplification_ports", [])

        return [
            {"id": 1000, "port": 19, "name": "Chargen", "amplification": 358, "enabled": 19 not in disabled_ports,
             "description": "Character Generator Protocol - very high amplification"},
            {"id": 1001, "port": 53, "name": "DNS", "amplification": 28, "enabled": 53 not in disabled_ports,
             "description": "DNS amplification via ANY queries"},
            {"id": 1002, "port": 111, "name": "RPC", "amplification": 6, "enabled": 111 not in disabled_ports,
             "description": "Sun RPC portmapper"},
            {"id": 1003, "port": 123, "name": "NTP", "amplification": 556, "enabled": 123 not in disabled_ports,
             "description": "NTP monlist amplification - very high"},
            {"id": 1004, "port": 137, "name": "NetBIOS", "amplification": 3, "enabled": 137 not in disabled_ports,
             "description": "NetBIOS Name Service"},
            {"id": 1005, "port": 161, "name": "SNMP", "amplification": 6, "enabled": 161 not in disabled_ports,
             "description": "SNMP GetBulk amplification"},
            {"id": 1006, "port": 389, "name": "CLDAP", "amplification": 56, "enabled": 389 not in disabled_ports,
             "description": "Connectionless LDAP - high amplification"},
            {"id": 1007, "port": 520, "name": "RIP", "amplification": 13, "enabled": 520 not in disabled_ports,
             "description": "Routing Information Protocol"},
            {"id": 1008, "port": 751, "name": "Kerberos", "amplification": 14, "enabled": 751 not in disabled_ports,
             "description": "Kerberos authentication"},
            {"id": 1009, "port": 1434, "name": "MSSQL", "amplification": 25, "enabled": 1434 not in disabled_ports,
             "description": "Microsoft SQL Server Browser"},
            {"id": 1010, "port": 1900, "name": "SSDP", "amplification": 30, "enabled": 1900 not in disabled_ports,
             "description": "Simple Service Discovery Protocol"},
            {"id": 1011, "port": 3283, "name": "Apple Remote", "amplification": 35, "enabled": 3283 not in disabled_ports,
             "description": "Apple Remote Desktop"},
            {"id": 1012, "port": 3389, "name": "RDP", "amplification": 85, "enabled": 3389 not in disabled_ports,
             "description": "Remote Desktop Protocol - high amplification"},
            {"id": 1013, "port": 3702, "name": "WS-Discovery", "amplification": 10, "enabled": 3702 not in disabled_ports,
             "description": "Web Services Discovery"},
            {"id": 1014, "port": 5093, "name": "Sentinel", "amplification": 50, "enabled": 5093 not in disabled_ports,
             "description": "Sentinel License Manager"},
            {"id": 1015, "port": 5353, "name": "mDNS", "amplification": 2, "enabled": 5353 not in disabled_ports,
             "description": "Multicast DNS"},
            {"id": 1016, "port": 5683, "name": "CoAP", "amplification": 34, "enabled": 5683 not in disabled_ports,
             "description": "Constrained Application Protocol"},
            {"id": 1017, "port": 6881, "name": "BitTorrent", "amplification": 3, "enabled": 6881 not in disabled_ports,
             "description": "BitTorrent DHT"},
            {"id": 1018, "port": 11211, "name": "Memcached", "amplification": 51000, "enabled": 11211 not in disabled_ports,
             "description": "Memcached - EXTREME amplification (51000x)"},
            {"id": 1019, "port": 17185, "name": "VxWorks", "amplification": 17, "enabled": 17185 not in disabled_ports,
             "description": "VxWorks Debug Service"},
            {"id": 1020, "port": 27015, "name": "Steam", "amplification": 5, "enabled": 27015 not in disabled_ports,
             "description": "Steam game server query"},
            {"id": 1021, "port": 33848, "name": "Jenkins", "amplification": 100, "enabled": 33848 not in disabled_ports,
             "description": "Jenkins UDP discovery - high amplification"}
        ]

    def _get_scan_signatures(self) -> List[Dict[str, Any]]:
        """Get scan detection signatures."""
        sig_config = self.config.get("signatures", {})
        disabled_scans = sig_config.get("disabled_scan_ids", [])

        return [
            {"id": 2001, "name": "TCP SYN Scan", "enabled": 2001 not in disabled_scans,
             "description": "TCP SYN-only packets (≤60 bytes) - classic port scan pattern",
             "severity": 5},
            {"id": 2002, "name": "TCP FIN Scan", "enabled": 2002 not in disabled_scans,
             "description": "TCP FIN-only packets - stealth scan technique",
             "severity": 6},
            {"id": 2003, "name": "UDP Scan", "enabled": 2003 not in disabled_scans,
             "description": "UDP packets with minimal payload (≤28 bytes)",
             "severity": 4}
        ]

    def _get_anomaly_signatures(self) -> List[Dict[str, Any]]:
        """Get protocol anomaly signatures."""
        sig_config = self.config.get("signatures", {})
        disabled_anomalies = sig_config.get("disabled_anomaly_ids", [])

        return [
            {"id": 3001, "name": "TCP NULL Scan", "enabled": 3001 not in disabled_anomalies,
             "description": "TCP packet with no flags set - invalid per RFC",
             "severity": 7},
            {"id": 3002, "name": "TCP XMAS Scan", "enabled": 3002 not in disabled_anomalies,
             "description": "TCP FIN+PSH+URG flags - 'Christmas tree' scan",
             "severity": 7},
            {"id": 3003, "name": "Invalid SYN+FIN", "enabled": 3003 not in disabled_anomalies,
             "description": "Invalid TCP flag combination SYN+FIN",
             "severity": 8},
            {"id": 3004, "name": "Invalid SYN+RST", "enabled": 3004 not in disabled_anomalies,
             "description": "Invalid TCP flag combination SYN+RST",
             "severity": 8},
            {"id": 3010, "name": "TTL=1 Anomaly", "enabled": 3010 not in disabled_anomalies,
             "description": "Packet with TTL=1 from internet (traceroute or attack)",
             "severity": 4},
            {"id": 3011, "name": "Low TTL Anomaly", "enabled": 3011 not in disabled_anomalies,
             "description": "Packet with TTL<10 (suspicious for DDoS)",
             "severity": 3}
        ]

    def _get_attack_tool_signatures(self) -> List[Dict[str, Any]]:
        """Get attack tool signatures."""
        sig_config = self.config.get("signatures", {})
        disabled_tools = sig_config.get("disabled_tool_ids", [])

        return [
            {"id": 4001, "name": "Generic UDP Flood", "enabled": 4001 not in disabled_tools,
             "description": "UDP flood pattern: high port, fixed 1024-byte size",
             "severity": 8},
            {"id": 4010, "name": "Mirai DNS", "enabled": 4010 not in disabled_tools,
             "description": "Potential Mirai botnet DNS amplification request",
             "severity": 9},
            {"id": 4020, "name": "GRE Flood", "enabled": 4020 not in disabled_tools,
             "description": "GRE encapsulation flood attack",
             "severity": 8}
        ]

    def set_signature_category_enabled(self, category: str, enabled: bool, notify: bool = True) -> bool:
        """Enable or disable an entire signature category."""
        category_keys = {
            "amplification": "block_amplification",
            "scans": "block_scans",
            "anomalies": "block_anomalies",
            "attack_tools": "block_attack_tools"
        }

        if category not in category_keys:
            return False

        return self.update_value("signatures", category_keys[category], enabled, notify)

    def set_amplification_signature_enabled(self, port: int, enabled: bool, notify: bool = True) -> bool:
        """Enable or disable a specific amplification signature by port."""
        with self.lock:
            sig_config = self.config.get("signatures", {})
            disabled_ports = sig_config.get("disabled_amplification_ports", [])

            if enabled and port in disabled_ports:
                disabled_ports.remove(port)
            elif not enabled and port not in disabled_ports:
                disabled_ports.append(port)

            if "signatures" not in self.config:
                self.config["signatures"] = {}
            self.config["signatures"]["disabled_amplification_ports"] = disabled_ports

            self.save_config()

        if notify:
            self._notify_datapath()

        return True

    def set_scan_signature_enabled(self, sig_id: int, enabled: bool, notify: bool = True) -> bool:
        """Enable or disable a specific scan signature."""
        with self.lock:
            sig_config = self.config.get("signatures", {})
            disabled_ids = sig_config.get("disabled_scan_ids", [])

            if enabled and sig_id in disabled_ids:
                disabled_ids.remove(sig_id)
            elif not enabled and sig_id not in disabled_ids:
                disabled_ids.append(sig_id)

            if "signatures" not in self.config:
                self.config["signatures"] = {}
            self.config["signatures"]["disabled_scan_ids"] = disabled_ids

            self.save_config()

        if notify:
            self._notify_datapath()

        return True

    def set_anomaly_signature_enabled(self, sig_id: int, enabled: bool, notify: bool = True) -> bool:
        """Enable or disable a specific anomaly signature."""
        with self.lock:
            sig_config = self.config.get("signatures", {})
            disabled_ids = sig_config.get("disabled_anomaly_ids", [])

            if enabled and sig_id in disabled_ids:
                disabled_ids.remove(sig_id)
            elif not enabled and sig_id not in disabled_ids:
                disabled_ids.append(sig_id)

            if "signatures" not in self.config:
                self.config["signatures"] = {}
            self.config["signatures"]["disabled_anomaly_ids"] = disabled_ids

            self.save_config()

        if notify:
            self._notify_datapath()

        return True

    def set_attack_tool_signature_enabled(self, sig_id: int, enabled: bool, notify: bool = True) -> bool:
        """Enable or disable a specific attack tool signature."""
        with self.lock:
            sig_config = self.config.get("signatures", {})
            disabled_ids = sig_config.get("disabled_tool_ids", [])

            if enabled and sig_id in disabled_ids:
                disabled_ids.remove(sig_id)
            elif not enabled and sig_id not in disabled_ids:
                disabled_ids.append(sig_id)

            if "signatures" not in self.config:
                self.config["signatures"] = {}
            self.config["signatures"]["disabled_tool_ids"] = disabled_ids

            self.save_config()

        if notify:
            self._notify_datapath()

        return True

    def set_signature_enabled(self, sig_id: int, enabled: bool, notify: bool = True) -> bool:
        """Enable or disable any signature by ID (auto-detects category)."""
        if 1000 <= sig_id < 2000:
            # Amplification - find port from ID
            amp_sigs = self._get_amplification_signatures()
            for sig in amp_sigs:
                if sig["id"] == sig_id:
                    return self.set_amplification_signature_enabled(sig["port"], enabled, notify)
            return False
        elif 2000 <= sig_id < 3000:
            return self.set_scan_signature_enabled(sig_id, enabled, notify)
        elif 3000 <= sig_id < 4000:
            return self.set_anomaly_signature_enabled(sig_id, enabled, notify)
        elif 4000 <= sig_id < 5000:
            return self.set_attack_tool_signature_enabled(sig_id, enabled, notify)
        else:
            return False

    def add_custom_amplification_signature(self, port: int, name: str, amplification: int = 1,
                                           description: str = "", notify: bool = True) -> bool:
        """Add a custom amplification signature (port-based)."""
        with self.lock:
            sig_config = self.config.get("signatures", {})
            custom_sigs = sig_config.get("custom_amplification", [])

            # Check if port already exists
            for sig in custom_sigs:
                if sig.get("port") == port:
                    return False  # Already exists

            custom_sigs.append({
                "port": port,
                "name": name,
                "amplification": amplification,
                "description": description,
                "enabled": True
            })

            if "signatures" not in self.config:
                self.config["signatures"] = {}
            self.config["signatures"]["custom_amplification"] = custom_sigs

            self.save_config()

        if notify:
            self._notify_datapath()

        return True

    def remove_custom_amplification_signature(self, port: int, notify: bool = True) -> bool:
        """Remove a custom amplification signature."""
        with self.lock:
            sig_config = self.config.get("signatures", {})
            custom_sigs = sig_config.get("custom_amplification", [])

            original_len = len(custom_sigs)
            custom_sigs = [s for s in custom_sigs if s.get("port") != port]

            if len(custom_sigs) == original_len:
                return False  # Not found

            self.config["signatures"]["custom_amplification"] = custom_sigs
            self.save_config()

        if notify:
            self._notify_datapath()

        return True

    def get_custom_amplification_signatures(self) -> List[Dict[str, Any]]:
        """Get custom amplification signatures."""
        with self.lock:
            sig_config = self.config.get("signatures", {})
            return deepcopy(sig_config.get("custom_amplification", []))


# ==================== Layer2 Configuration ====================

# Default Layer2 configuration values
# Updated defaults based on evaluation
DEFAULT_LAYER2_CONFIG_VALUES = {
    # Lowered from 6.0 to 4.0 - Z=6 was too conservative
    "z_score_threshold": 4.0,
    "min_tier_agreement": 2,
    "jsd_threshold": 0.15,
    "max_flow_fraction_threshold": 15.0,
    "topk_flow_share_threshold": 30.0,
    "alpha_immediate_1s": 0.8,
    "alpha_immediate_10s": 0.18,
    "alpha_immediate_60s": 0.033,
    "alpha_immediate": 0.18,
    "alpha_hourly": 0.1,
    "alpha_weekly": 0.05,
    "min_samples_immediate_1s": 10,
    "min_samples_immediate_10s": 10,
    "min_samples_immediate_60s": 30,
    "min_samples_immediate": 10,
    # Lowered from 60/180 to 20/40 for faster tier maturity
    "min_samples_hourly": 20,
    "min_samples_weekly": 40,
    "cool_down_seconds": 30.0,
    "baseline_freeze_enabled": True,
    "detection_interval_ms": 1000,
    # Add jitter to prevent timing attacks (+/-100ms)
    "jitter_ms": 100,
    "min_pps_for_detection": 100,
    "baseline_file": "data/layer2_baselines.json",
    "baseline_save_interval_sec": 300,
    # Baseline staleness brackets for warm start
    "baseline_fresh_sec": 3600,        # < 1h = full trust
    "baseline_moderate_sec": 21600,    # < 6h = 1.5x variance inflation
    "baseline_stale_sec": 86400,       # < 24h = 2.0x variance inflation
    "baseline_expired_sec": 604800,    # < 7d = 3.0x variance inflation, > 7d = discard
    # Progressive trust multipliers by learning phase
    "trust_multiplier_cold": 2.0,
    "trust_multiplier_warming": 1.5,
    "trust_multiplier_moderate": 1.2,
    "use_feature_weights": False,
    "feature_weights": [1.0] * 39,
    "log_detections": True,
    "log_baseline_updates": False,
    "log_interval_sec": 60,
    # Adaptive threshold tuning configuration
    "adaptive_enabled": True,
    "adaptive_min_threshold": 4.0,
    "adaptive_max_threshold": 10.0,
    "adaptive_step": 0.25,
    "adaptive_fp_threshold": 0.30,
    "adaptive_tp_min": 0.50,
    "adaptive_eval_interval_sec": 300,
    "adaptive_min_samples": 10,
    "fp_duration_threshold_sec": 10.0,
    "tp_duration_threshold_sec": 30.0,
    # Severity classification Z-scores
    "z_critical_3tier": 12.0,
    "z_high_3tier": 9.0,
    "z_medium_3tier": 6.0,
    "z_high_2tier": 15.0,
    "z_medium_2tier": 10.0,
    "z_medium_1tier": 15.0,
    # Warmup thresholds
    "warmup_pps_threshold": 50000,
    "warmup_syn_threshold": 5000,
    # Baseline poison protection
    "baseline_poison_protection_enabled": True,
    "baseline_change_rate_threshold": 2.0,
    "baseline_poison_window_sec": 300,
    "baseline_poison_count_threshold": 10,
    # Logging
    "log_level": 2,
    # Spoofed detection
    "spoofed_min_pps": 1000,
    "spoofed_randomness_threshold": 50,
    "spoofed_require_anomaly": True,
    # Feature config
    "min_features_per_tier": 2,
    "strong_z_multiplier": 2.0,
    # Fast detection
    "fast_detection_enabled": True,
    "fast_detection_interval_ms": 100,
    "fast_threshold_multiplier": 1.5,
    "fast_min_pps_spike": 10000,
    "fast_syn_spike_threshold": 5000,
    "fast_consecutive_required": 2,
    "fast_warmup_samples": 30,
    # Alert-Only Mode (industry-standard: start in alert-only)
    "learning_action": 1,             # 0=BLOCK (enforce), 1=ALERT_ONLY (detect only)
    "auto_promote_on_mature": True,   # Auto-switch to BLOCK when baselines mature
    "min_learning_duration_sec": 3600, # Min seconds before auto-promote (1 hour)
    "force_alert_early_phases": True,  # Always suppress COLD/WARMING phases
    # Feature selection (all enabled by default)
    "feature_enabled": [True] * 39,
    # Feature auto-selection (disabled by default -- opt-in)
    "feature_auto_select": False,
    "feature_auto_quality_min": 0.05,
    "feature_auto_min_samples": 300,
    # Adaptive daily max increase and FP guard
    "adaptive_daily_max_increase": 2.0,
    "adaptive_fp_z_multiplier": 1.5,
    # Baseline cumulative drift
    "baseline_cumulative_drift_threshold": 3.0,
    # CUSUM tuning
    "cusum_k_factor": 0.25,
    "cusum_h_factor": 5.0,
    "cusum_min_samples": 30,
    # Sensitivity preset
    "sensitivity_preset": 0,
    # JSD parameters
    "jsd_update_interval_ms": 5000,
    "jsd_max_updates_per_minute": 12,
    "jsd_contribution_multiplier": 3.0,
    "jsd_alpha": 0.1,
    "jsd_min_samples": 30,
    # Attack classification thresholds
    "attack_detection_threshold": 0.3,
    "attack_medium_conf_threshold": 0.4,
    "attack_high_conf_threshold": 0.6,
    "attack_multi_vector_ratio": 0.6,
    # Warmup severity thresholds
    "warmup_critical_pps": 500000,
    "warmup_high_pps": 200000,
    "warmup_medium_pps": 100000,
    # Warmup synthetic Z-score tuning
    "warmup_z_coefficient": 4.0,
    "warmup_z_max": 20.0,
    "warmup_high_src_boost": 1.2,
    # Flash crowd scoring weights
    "fc_weight_syn_completion": 0.4,
    "fc_weight_response_ratio": 0.3,
    "fc_weight_bpp_diversity": 0.15,
    "fc_weight_port_concentration": 0.15,
    "fc_bpp_low": 100.0,
    "fc_bpp_high": 1000.0,
    "fc_port_few": 50.0,
    "fc_port_moderate": 200.0,
    # Adaptive warmup
    "adaptive_warmup_enabled": True,
    "warmup_learning_window_sec": 30,
    "warmup_spike_factor": 3.0,
    "warmup_min_observations": 5,
    "warmup_percentile_threshold": 95,
}


class Layer2ConfigManager:
    """
    Manages Layer2 configuration for anomaly detection.

    Thread-safe operations for concurrent access from Flask routes.
    """

    def __init__(self, config_path: str = DEFAULT_LAYER2_CONFIG_PATH,
                 socket_path: str = DEFAULT_SOCKET_PATH):
        self.config_path = Path(config_path)
        self.socket_path = socket_path
        self.lock = threading.RLock()
        self.config: Dict[str, Any] = {}
        self.last_modified = None

        # Load initial config
        self.load_config()

    def load_config(self) -> bool:
        """Load Layer2 configuration from JSON file."""
        with self.lock:
            try:
                if self.config_path.exists():
                    with open(self.config_path, 'r') as f:
                        self.config = json.load(f)
                    self.last_modified = datetime.fromtimestamp(
                        os.path.getmtime(self.config_path)
                    )
                else:
                    # Use defaults if file doesn't exist
                    self.config = deepcopy(DEFAULT_LAYER2_CONFIG_VALUES)
                    self.save_config()
                return True
            except Exception as e:
                logger.error("Error loading config: %s", e)
                self.config = deepcopy(DEFAULT_LAYER2_CONFIG_VALUES)
                return False

    def save_config(self, description: str = None) -> bool:
        """Save Layer2 configuration to JSON file, DB, and notify C datapath to reload."""
        with self.lock:
            try:
                _atomic_json_write(self.config_path, self.config, indent=4)

                self.last_modified = datetime.now()

                # Save to DB for persistence
                self._save_to_db(description)

                # Notify running C process to reload Layer 2 config
                self._last_applied = self._notify_l2_reload()
                return True
            except Exception as e:
                logger.error("Error saving config: %s", e)
                return False

    def _save_to_db(self, description: str = None):
        """Save Layer2 config to SystemConfigDB and create a ConfigSnapshot."""
        try:
            from api.database.connection import db_session
            from api.database.models import ConfigSnapshot, SystemConfigDB
            from sqlalchemy import func as sa_func

            with db_session() as db:
                # Update live SystemConfigDB row
                sys_config = db.query(SystemConfigDB).filter(
                    SystemConfigDB.id == 1
                ).first()
                if sys_config is None:
                    sys_config = SystemConfigDB(id=1)
                    db.add(sys_config)
                sys_config.layer2 = deepcopy(self.config)
                sys_config.version = (sys_config.version or 0) + 1
                sys_config.updated_at = datetime.now()

                # Create versioned snapshot
                max_ver = db.query(sa_func.max(ConfigSnapshot.version)).scalar()
                version = (max_ver or 0) + 1

                snapshot = ConfigSnapshot(
                    version=version,
                    config_data=deepcopy(self.config),
                    description=description or "layer2 config update",
                )
                db.add(snapshot)

                # Keep max 50 snapshots, prune oldest
                count = db.query(ConfigSnapshot).count()
                if count > 50:
                    oldest = db.query(ConfigSnapshot).order_by(
                        ConfigSnapshot.id.asc()
                    ).limit(count - 50).all()
                    for old in oldest:
                        db.delete(old)
        except Exception as e:
            # DB failure must not break config save
            logger.warning("DB save failed (non-fatal): %s", e)

    def _notify_l2_reload(self) -> bool:
        """Notify C datapath to reload Layer 2 configuration via control socket."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(self.socket_path)
            # Must match control_cmd struct: cmd(B) + ip(I) + prefix_len(B) + mode(B)
            packet = struct.pack('<BIB', CMD_L2_RELOAD_CONFIG, 0, 0)
            sock.sendall(packet)
            response = sock.recv(4)
            sock.close()
            return len(response) >= 1 and response[0] == 0
        except socket.error:
            # Socket not available - datapath not running (expected during dev)
            return False
        except Exception as e:
            logger.error("Error notifying datapath: %s", e)
            return False

    def get_config(self) -> Dict[str, Any]:
        """Get full Layer2 configuration."""
        with self.lock:
            return deepcopy(self.config)

    def update_value(self, key: str, value: Any):
        """Update a single configuration value.

        Returns dict {'saved': True, 'applied': bool} on success, False on failure.
        Router-level VALID_L2_KEYS validation gates which keys are allowed.
        """
        with self.lock:
            try:
                if key not in DEFAULT_LAYER2_CONFIG_VALUES and key not in self.config:
                    return False
                self.config[key] = value
                saved = self.save_config()
                if not saved:
                    return False
                return {'saved': True, 'applied': getattr(self, '_last_applied', False)}
            except Exception as e:
                logger.error("Error updating value: %s", e)
                return False

    def update_config(self, values: Dict[str, Any]) -> bool:
        """Update multiple configuration values.

        Router-level VALID_L2_KEYS validation gates which keys are allowed.
        Here we accept any key in defaults or the currently loaded config.
        """
        with self.lock:
            try:
                for key, value in values.items():
                    if key in DEFAULT_LAYER2_CONFIG_VALUES or key in self.config:
                        self.config[key] = value
                return self.save_config()
            except Exception as e:
                logger.error("Error updating config: %s", e)
                return False

    def reset_to_defaults(self) -> bool:
        """Reset Layer2 configuration to defaults."""
        with self.lock:
            self.config = deepcopy(DEFAULT_LAYER2_CONFIG_VALUES)
            return self.save_config()

    def get_config_info(self) -> Dict[str, Any]:
        """Get Layer2 configuration metadata."""
        with self.lock:
            return {
                "config_path": str(self.config_path),
                "last_modified": self.last_modified.isoformat() if self.last_modified else None,
                "file_exists": self.config_path.exists()
            }

    def get_config_schema(self) -> Dict[str, Any]:
        """Get Layer2 configuration schema with field descriptions."""
        return {
            "z_score_threshold": {"type": "float", "min": 3.0, "max": 12.0, "desc": "Z-score threshold for anomaly detection"},
            "min_tier_agreement": {"type": "int", "min": 1, "max": 3, "desc": "Minimum tiers that must agree (1-3)"},
            "jsd_threshold": {"type": "float", "min": 0.05, "max": 0.5, "desc": "Jensen-Shannon divergence threshold for protocol mix"},
            "max_flow_fraction_threshold": {"type": "float", "min": 5.0, "max": 50.0, "desc": "Single flow fraction threshold (%)"},
            "topk_flow_share_threshold": {"type": "float", "min": 10.0, "max": 80.0, "desc": "Top-K flow share threshold (%)"},
            "alpha_immediate_1s": {"type": "float", "min": 0.01, "max": 1.0, "desc": "EWMA alpha for Tier 1 sub-tier 1s (flash spike)"},
            "alpha_immediate_10s": {"type": "float", "min": 0.01, "max": 1.0, "desc": "EWMA alpha for Tier 1 sub-tier 10s (short attack)"},
            "alpha_immediate_60s": {"type": "float", "min": 0.01, "max": 1.0, "desc": "EWMA alpha for Tier 1 sub-tier 60s (slow ramp)"},
            "alpha_immediate": {"type": "float", "min": 0.01, "max": 1.0, "desc": "EWMA alpha for Tier 1 (backward compat, maps to 10s)"},
            "alpha_hourly": {"type": "float", "min": 0.01, "max": 1.0, "desc": "EWMA alpha for Tier 2 (medium)"},
            "alpha_weekly": {"type": "float", "min": 0.01, "max": 1.0, "desc": "EWMA alpha for Tier 3 (slow)"},
            "min_samples_immediate_1s": {"type": "int", "min": 1, "max": 100, "desc": "Min samples for Tier 1 sub-tier 1s ready"},
            "min_samples_immediate_10s": {"type": "int", "min": 1, "max": 100, "desc": "Min samples for Tier 1 sub-tier 10s ready"},
            "min_samples_immediate_60s": {"type": "int", "min": 1, "max": 100, "desc": "Min samples for Tier 1 sub-tier 60s ready"},
            "min_samples_immediate": {"type": "int", "min": 1, "max": 100, "desc": "Min samples for Tier 1 ready (backward compat)"},
            "min_samples_hourly": {"type": "int", "min": 1, "max": 1000, "desc": "Min samples for Tier 2 ready"},
            "min_samples_weekly": {"type": "int", "min": 1, "max": 10000, "desc": "Min samples for Tier 3 ready"},
            "cool_down_seconds": {"type": "float", "min": 0, "max": 300, "desc": "Seconds after anomaly before clearing"},
            "baseline_freeze_enabled": {"type": "bool", "desc": "Freeze baselines during attacks"},
            "detection_interval_ms": {"type": "int", "min": 100, "max": 10000, "desc": "Detection loop interval (ms)"},
            # Add jitter to prevent timing attacks
            "jitter_ms": {"type": "int", "min": 0, "max": 500, "desc": "Random jitter ±N ms to prevent timing attacks"},
            "min_pps_for_detection": {"type": "int", "min": 0, "max": 100000, "desc": "Minimum PPS for detection (0=always detect)"},
            "baseline_file": {"type": "str", "desc": "Path to save/load baselines"},
            "baseline_save_interval_sec": {"type": "int", "min": 0, "max": 3600, "desc": "Auto-save interval (0=disabled)"},
            "use_feature_weights": {"type": "bool", "desc": "Enable feature weights"},
            "feature_weights": {"type": "list", "desc": "Per-feature weights (39 values, 0.0-1.0)"},
            "log_detections": {"type": "bool", "desc": "Log detection events"},
            "log_baseline_updates": {"type": "bool", "desc": "Log baseline updates (verbose)"},
            "log_interval_sec": {"type": "int", "min": 0, "max": 3600, "desc": "Status log interval"},
            # Adaptive threshold tuning
            "adaptive_enabled": {"type": "bool", "desc": "Enable adaptive threshold tuning"},
            "adaptive_min_threshold": {"type": "float", "min": 3.0, "max": 8.0, "desc": "Minimum Z-score threshold"},
            "adaptive_max_threshold": {"type": "float", "min": 6.0, "max": 15.0, "desc": "Maximum Z-score threshold"},
            "adaptive_step": {"type": "float", "min": 0.1, "max": 1.0, "desc": "Threshold adjustment step size"},
            "adaptive_fp_threshold": {"type": "float", "min": 0.1, "max": 0.8, "desc": "FP rate threshold to increase sensitivity (0.0-1.0)"},
            "adaptive_tp_min": {"type": "float", "min": 0.2, "max": 0.9, "desc": "Minimum TP rate threshold (0.0-1.0)"},
            "adaptive_eval_interval_sec": {"type": "int", "min": 60, "max": 3600, "desc": "Evaluation interval in seconds"},
            "adaptive_min_samples": {"type": "int", "min": 5, "max": 100, "desc": "Minimum events for evaluation"},
            "fp_duration_threshold_sec": {"type": "float", "min": 1.0, "max": 60.0, "desc": "Detection duration below which is FP"},
            "tp_duration_threshold_sec": {"type": "float", "min": 10.0, "max": 300.0, "desc": "Detection duration above which is TP"}
        }


# Global instances for Flask routes
_rules_engine: Optional[RulesEngine] = None
_config_manager: Optional[ConfigManager] = None
_layer2_config_manager: Optional[Layer2ConfigManager] = None


def get_rules_engine() -> RulesEngine:
    """Get or create the global rules engine instance."""
    global _rules_engine
    if _rules_engine is None:
        _rules_engine = RulesEngine()
    return _rules_engine


def init_rules_engine(rules_file: str = DEFAULT_RULES_FILE,
                      socket_path: str = DEFAULT_SOCKET_PATH) -> RulesEngine:
    """Initialize the global rules engine with custom paths."""
    global _rules_engine
    _rules_engine = RulesEngine(rules_file, socket_path)
    return _rules_engine


def get_config_manager() -> ConfigManager:
    """Get or create the global config manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager


def init_config_manager(config_path: str = DEFAULT_LAYER1_CONFIG,
                        socket_path: str = DEFAULT_SOCKET_PATH) -> ConfigManager:
    """Initialize the global config manager with custom paths."""
    global _config_manager
    _config_manager = ConfigManager(config_path, socket_path)
    return _config_manager


def get_layer2_config_manager() -> Layer2ConfigManager:
    """Get or create the global Layer2 config manager instance."""
    global _layer2_config_manager
    if _layer2_config_manager is None:
        _layer2_config_manager = Layer2ConfigManager()
    return _layer2_config_manager


def init_layer2_config_manager(config_path: str = DEFAULT_LAYER2_CONFIG_PATH,
                               socket_path: str = DEFAULT_SOCKET_PATH) -> Layer2ConfigManager:
    """Initialize the global Layer2 config manager with custom paths."""
    global _layer2_config_manager
    _layer2_config_manager = Layer2ConfigManager(config_path, socket_path)
    return _layer2_config_manager
