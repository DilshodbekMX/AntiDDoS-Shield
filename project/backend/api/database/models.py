"""
SQLAlchemy ORM Models for Anti-DDoS Platform.

This module defines all database tables using SQLAlchemy ORM.
Models include proper relationships, indexes, and constraints.
"""

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Integer,
    BigInteger,
    String,
    Text,
    Float,
    Boolean,
    DateTime,
    Index,
    UniqueConstraint,
    CheckConstraint,
    JSON,
    Enum as SQLEnum,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.sql import func
import enum


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


# ==================== Enums ====================

class IPListType(str, enum.Enum):
    """IP list type."""
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    GREYLIST = "greylist"


class PolicyAction(str, enum.Enum):
    """Policy action type."""
    ALLOW = "allow"
    BLOCK = "block"
    RATE_LIMIT = "rate_limit"
    CHALLENGE = "challenge"
    LOG = "log"
    REDIRECT = "redirect"


class PolicySource(str, enum.Enum):
    """Policy creation source."""
    MANUAL = "manual"
    ML = "ml"
    THREAT_INTEL = "threat_intel"
    AUTO = "auto"
    IMPORT = "import"


class AttackType(str, enum.Enum):
    """DDoS attack type classification."""
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    ICMP_FLOOD = "icmp_flood"
    DNS_AMPLIFICATION = "dns_amplification"
    NTP_AMPLIFICATION = "ntp_amplification"
    MEMCACHED_AMPLIFICATION = "memcached_amplification"
    HTTP_FLOOD = "http_flood"
    SLOWLORIS = "slowloris"
    ACK_FLOOD = "ack_flood"
    RST_FLOOD = "rst_flood"
    FRAGMENT_FLOOD = "fragment_flood"
    CARPET_BOMB = "carpet_bomb"
    VOLUMETRIC = "volumetric"
    APPLICATION = "application"
    UNKNOWN = "unknown"


class AttackSeverity(str, enum.Enum):
    """Attack severity level."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ReportType(str, enum.Enum):
    """Report type."""
    INCIDENT = "incident"
    TRAFFIC = "traffic"
    SECURITY = "security"
    SLA = "sla"
    EXECUTIVE = "executive"
    CUSTOM = "custom"


class ReportFormat(str, enum.Enum):
    """Report output format."""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"


class ReportStatus(str, enum.Enum):
    """Report generation status."""
    PENDING = "pending"
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class WebhookEvent(str, enum.Enum):
    """Webhook event types."""
    ATTACK_STARTED = "attack_started"
    ATTACK_ENDED = "attack_ended"
    ATTACK_MITIGATED = "attack_mitigated"
    THRESHOLD_EXCEEDED = "threshold_exceeded"
    CONFIG_CHANGED = "config_changed"
    SLA_BREACH = "sla_breach"
    POLICY_TRIGGERED = "policy_triggered"
    IP_BLOCKED = "ip_blocked"
    IP_WHITELISTED = "ip_whitelisted"




# ==================== Core Tables ====================

class ProtectedIP(Base):
    """Protected IP addresses."""
    __tablename__ = "protected_ips"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)  # Supports IPv6
    prefix_len: Mapped[Optional[int]] = mapped_column(Integer)  # NULL for single IP
    description: Mapped[Optional[str]] = mapped_column(String(256))
    priority: Mapped[int] = mapped_column(Integer, default=100)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    __table_args__ = (
        UniqueConstraint("ip_address", "prefix_len", name="uq_protected_ip"),
        Index("ix_protected_ips_ip", "ip_address"),
    )


# ==================== Security Tables ====================

class IPListEntry(Base):
    """IP whitelist, blacklist, and greylist entries."""
    __tablename__ = "ip_lists"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    list_type: Mapped[IPListType] = mapped_column(
        SQLEnum(IPListType), nullable=False, index=True
    )
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    prefix_len: Mapped[int] = mapped_column(Integer, default=32)
    description: Mapped[Optional[str]] = mapped_column(String(256))
    reason: Mapped[Optional[str]] = mapped_column(String(256))

    # Expiration
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, index=True)
    is_permanent: Mapped[bool] = mapped_column(Boolean, default=False)

    # Tracking
    hit_count: Mapped[int] = mapped_column(BigInteger, default=0)
    last_hit_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Audit
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    created_by: Mapped[Optional[str]] = mapped_column(String(64))
    source: Mapped[Optional[str]] = mapped_column(String(32))  # manual, threat_intel, ml, api

    __table_args__ = (
        UniqueConstraint("list_type", "ip_address", "prefix_len", name="uq_ip_list_entry"),
        Index("ix_ip_lists_lookup", "list_type", "ip_address"),
        Index("ix_ip_lists_expires", "expires_at"),
    )


class Policy(Base):
    """DDoS mitigation policies."""
    __tablename__ = "policies"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    description: Mapped[Optional[str]] = mapped_column(String(256))

    # Policy definition
    priority: Mapped[int] = mapped_column(Integer, default=100, index=True)
    action: Mapped[PolicyAction] = mapped_column(
        SQLEnum(PolicyAction), nullable=False, default=PolicyAction.BLOCK
    )
    conditions: Mapped[Optional[dict]] = mapped_column(JSON)  # Flexible condition matching
    rate_limit_pps: Mapped[Optional[int]] = mapped_column(Integer)
    rate_limit_bps: Mapped[Optional[int]] = mapped_column(BigInteger)

    # State
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, index=True)

    # Source tracking
    source: Mapped[PolicySource] = mapped_column(
        SQLEnum(PolicySource), default=PolicySource.MANUAL, nullable=False
    )
    confidence: Mapped[Optional[float]] = mapped_column(Float)  # For ML-generated policies

    # Stats
    hit_count: Mapped[int] = mapped_column(BigInteger, default=0)
    last_hit_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Audit
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )
    created_by: Mapped[Optional[str]] = mapped_column(String(64))

    __table_args__ = (
        Index("ix_policies_active", "enabled", "priority"),
        CheckConstraint("priority >= 1 AND priority <= 1000", name="valid_priority"),
    )


class Attack(Base):
    """Attack detection and mitigation records."""
    __tablename__ = "attacks"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )


    # Attack classification
    attack_type: Mapped[AttackType] = mapped_column(
        SQLEnum(AttackType), nullable=False, index=True
    )
    severity: Mapped[AttackSeverity] = mapped_column(
        SQLEnum(AttackSeverity), nullable=False, index=True
    )

    # Target information
    target_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    target_port: Mapped[Optional[int]] = mapped_column(Integer)
    target_protocol: Mapped[Optional[str]] = mapped_column(String(10))

    # Attack metrics
    peak_pps: Mapped[int] = mapped_column(BigInteger, default=0)
    peak_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    source_ips_count: Mapped[int] = mapped_column(Integer, default=0)
    total_packets: Mapped[int] = mapped_column(BigInteger, default=0)
    total_bytes: Mapped[int] = mapped_column(BigInteger, default=0)
    packets_dropped: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_dropped: Mapped[int] = mapped_column(BigInteger, default=0)

    # Timeline
    started_at: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    mitigated_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    ended_at: Mapped[Optional[datetime]] = mapped_column(DateTime, index=True)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    is_mitigated: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mitigation_time_ms: Mapped[Optional[float]] = mapped_column(Float)

    # Detection details
    ml_confidence: Mapped[Optional[float]] = mapped_column(Float)
    signatures_matched: Mapped[Optional[list]] = mapped_column(JSON)
    top_source_ips: Mapped[Optional[list]] = mapped_column(JSON)
    top_source_countries: Mapped[Optional[list]] = mapped_column(JSON)
    top_source_asns: Mapped[Optional[list]] = mapped_column(JSON)

    # Additional details
    notes: Mapped[Optional[str]] = mapped_column(Text)
    extra_data: Mapped[Optional[dict]] = mapped_column(JSON)

    __table_args__ = (
        Index("ix_attacks_active", "is_active"),
        Index("ix_attacks_timeline", "started_at", "ended_at"),
    )



# ==================== Reporting Tables ====================

class Report(Base):
    """Generated and scheduled reports."""
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )


    # Report definition
    report_type: Mapped[ReportType] = mapped_column(
        SQLEnum(ReportType), nullable=False
    )
    report_format: Mapped[ReportFormat] = mapped_column(
        SQLEnum(ReportFormat), default=ReportFormat.PDF, nullable=False
    )
    title: Mapped[Optional[str]] = mapped_column(String(128))

    # Time range
    start_date: Mapped[Optional[datetime]] = mapped_column(DateTime)
    end_date: Mapped[Optional[datetime]] = mapped_column(DateTime)

    # Generation status
    status: Mapped[ReportStatus] = mapped_column(
        SQLEnum(ReportStatus), default=ReportStatus.PENDING, nullable=False, index=True
    )
    file_path: Mapped[Optional[str]] = mapped_column(String(512))
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer)
    error_message: Mapped[Optional[str]] = mapped_column(Text)

    # Scheduling (for recurring reports)
    schedule_cron: Mapped[Optional[str]] = mapped_column(String(64))
    is_scheduled: Mapped[bool] = mapped_column(Boolean, default=False)
    next_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, index=True)
    recipients: Mapped[Optional[list]] = mapped_column(JSON)

    # Audit
    generated_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    generated_by: Mapped[Optional[str]] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())

    __table_args__ = (
        Index("ix_reports_scheduled", "is_scheduled", "next_run_at"),
    )


# ==================== Integration Tables ====================

class Webhook(Base):
    """Webhook configurations for event notifications."""
    __tablename__ = "webhooks"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )


    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    url: Mapped[str] = mapped_column(String(512), nullable=False)
    events: Mapped[list] = mapped_column(JSON, nullable=False)  # List of WebhookEvent values
    secret: Mapped[Optional[str]] = mapped_column(String(128))  # For HMAC signing
    headers: Mapped[Optional[dict]] = mapped_column(JSON)  # Custom headers

    # State
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    failure_count: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_success_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_failure_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_error: Mapped[Optional[str]] = mapped_column(String(512))

    # Audit
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )


class APIToken(Base):
    """API tokens for programmatic access."""
    __tablename__ = "api_tokens"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )


    name: Mapped[str] = mapped_column(String(64), nullable=False)
    token_prefix: Mapped[str] = mapped_column(String(8), nullable=False)  # For identification
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)  # SHA256
    permissions: Mapped[list] = mapped_column(JSON, default=list)

    # State
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False, index=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, index=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    last_used_ip: Mapped[Optional[str]] = mapped_column(String(45))
    use_count: Mapped[int] = mapped_column(Integer, default=0)

    # Audit
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    created_by: Mapped[Optional[str]] = mapped_column(String(64))
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime)
    revoked_by: Mapped[Optional[str]] = mapped_column(String(64))


class SystemConfigDB(Base):
    """System configuration stored in database."""
    __tablename__ = "system_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # Layer configurations (JSON blobs)
    layer1: Mapped[Optional[dict]] = mapped_column(JSON)
    layer2: Mapped[Optional[dict]] = mapped_column(JSON)

    # Versioning
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)

    # Audit
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )
    updated_by: Mapped[Optional[str]] = mapped_column(String(64))


class ConfigSnapshot(Base):
    """Versioned config snapshots for rollback and audit."""
    __tablename__ = "config_snapshots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    config_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )


class PerIPL2Config(Base):
    """Per-IP Layer 2 detection configuration overrides.

    Each protected IP can have custom detection parameters that override
    the global Layer 2 config. NULL fields = use global default.
    """
    __tablename__ = "per_ip_l2_config"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True, index=True)

    # Detection thresholds (nullable = use global)
    z_score_threshold: Mapped[Optional[float]] = mapped_column(Float)
    min_tier_agreement: Mapped[Optional[int]] = mapped_column(Integer)
    min_features_per_tier: Mapped[Optional[int]] = mapped_column(Integer)
    cool_down_seconds: Mapped[Optional[float]] = mapped_column(Float)
    baseline_freeze_enabled: Mapped[Optional[bool]] = mapped_column(Boolean)

    # EWMA sub-tiers
    alpha_immediate_1s: Mapped[Optional[float]] = mapped_column(Float)
    alpha_immediate_10s: Mapped[Optional[float]] = mapped_column(Float)
    alpha_immediate_60s: Mapped[Optional[float]] = mapped_column(Float)
    min_samples_immediate_1s: Mapped[Optional[int]] = mapped_column(Integer)
    min_samples_immediate_10s: Mapped[Optional[int]] = mapped_column(Integer)
    min_samples_immediate_60s: Mapped[Optional[int]] = mapped_column(Integer)

    # Warmup thresholds
    warmup_pps_threshold: Mapped[Optional[int]] = mapped_column(Integer)
    warmup_syn_threshold: Mapped[Optional[int]] = mapped_column(Integer)

    # Per-IP feature selection (JSON array of 39 floats, NULL = use global weights)
    feature_weights: Mapped[Optional[str]] = mapped_column(Text)

    # State & audit
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )
    updated_by: Mapped[Optional[str]] = mapped_column(String(64))


class AuditLog(Base):
    """Security audit trail."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)


    # Actor
    user_id: Mapped[Optional[str]] = mapped_column(String(64), index=True)
    user_name: Mapped[Optional[str]] = mapped_column(String(64))
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    user_agent: Mapped[Optional[str]] = mapped_column(String(256))

    # Action
    action: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(64))
    resource_name: Mapped[Optional[str]] = mapped_column(String(128))

    # Details
    details: Mapped[Optional[dict]] = mapped_column(JSON)
    old_value: Mapped[Optional[dict]] = mapped_column(JSON)
    new_value: Mapped[Optional[dict]] = mapped_column(JSON)

    # Result
    success: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    error_message: Mapped[Optional[str]] = mapped_column(String(512))

    # Timestamp
    timestamp: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )

    __table_args__ = (
        Index("ix_audit_logs_search", "action", "timestamp"),
        Index("ix_audit_logs_user", "user_id", "timestamp"),
    )


# ==================== Traffic Rollup Table ====================

class TrafficRollup(Base):
    """1-minute traffic rollups for historical queries."""
    __tablename__ = "traffic_rollups"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)

    # Aggregate metrics (1-minute snapshot)
    rx_pps: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_pps: Mapped[int] = mapped_column(BigInteger, default=0)
    rx_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    tx_bps: Mapped[int] = mapped_column(BigInteger, default=0)
    dropped_pps: Mapped[int] = mapped_column(BigInteger, default=0)

    # Drop breakdown
    drops_validation: Mapped[int] = mapped_column(BigInteger, default=0)
    drops_blacklist: Mapped[int] = mapped_column(BigInteger, default=0)
    drops_rate_limit: Mapped[int] = mapped_column(BigInteger, default=0)
    drops_syn_flood: Mapped[int] = mapped_column(BigInteger, default=0)
    drops_reputation: Mapped[int] = mapped_column(BigInteger, default=0)
    drops_signature: Mapped[int] = mapped_column(BigInteger, default=0)
    drops_proto_blocked: Mapped[int] = mapped_column(BigInteger, default=0)
    drops_proto_rate_limit: Mapped[int] = mapped_column(BigInteger, default=0)

    # Anomaly state snapshot
    anomaly_active: Mapped[bool] = mapped_column(Boolean, default=False)
    anomaly_level: Mapped[int] = mapped_column(Integer, default=0)
    active_attacks: Mapped[int] = mapped_column(Integer, default=0)

    # Protected IP count
    protected_ip_count: Mapped[int] = mapped_column(Integer, default=0)


