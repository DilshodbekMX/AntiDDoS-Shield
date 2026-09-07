"""
Pydantic Models for API

Data validation and serialization models for all API endpoints.
"""

from enum import Enum
from typing import Optional, List, Any, Dict
from datetime import datetime
from pydantic import BaseModel, Field, validator
import ipaddress


# ==================== Enums ====================

class AttackType(str, Enum):
    """Attack classification types."""
    UNKNOWN = "unknown"
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


class AttackSeverity(str, Enum):
    """Attack severity level."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IPListType(str, Enum):
    """IP list type."""
    WHITELIST = "whitelist"
    BLACKLIST = "blacklist"
    GREYLIST = "greylist"


class PolicyAction(str, Enum):
    """Policy action type."""
    ALLOW = "allow"
    BLOCK = "block"
    RATE_LIMIT = "rate_limit"
    CHALLENGE = "challenge"
    LOG = "log"


class StatsPeriod(str, Enum):
    """Statistics time period."""
    REALTIME = "realtime"
    HOUR_1 = "1h"
    HOUR_24 = "24h"
    DAY_7 = "7d"
    DAY_30 = "30d"


# ==================== Base Models ====================

class APIResponse(BaseModel):
    """Standard API response wrapper."""
    success: bool = True
    data: Optional[Any] = None
    message: Optional[str] = None
    error: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class PaginationParams(BaseModel):
    """Pagination parameters."""
    page: int = Field(default=1, ge=1)
    per_page: int = Field(default=20, ge=1, le=100)
    sort_by: Optional[str] = None
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$")


class PaginatedResponse(BaseModel):
    """Paginated response with metadata."""
    items: List[Any]
    total: int
    page: int
    per_page: int
    pages: int


# ==================== Configuration Models ====================

class Layer1Config(BaseModel):
    """Layer 1 configuration."""
    enabled: bool = True
    rate_limit_pps: int = Field(default=100000, ge=0)
    rate_limit_bps: int = Field(default=1000000000, ge=0)
    syn_rate_limit: int = Field(default=10000, ge=0)
    udp_rate_limit: int = Field(default=50000, ge=0)
    icmp_rate_limit: int = Field(default=1000, ge=0)
    syn_proxy_enabled: bool = True
    syn_proxy_mode: str = Field(default="auto", pattern="^(off|auto|always)$")
    tcp_fingerprint_enabled: bool = True
    geo_blocking_enabled: bool = False
    blocked_countries: List[str] = Field(default_factory=list)
    monitor_only: bool = False
    tap_mode: bool = False


class Layer2Config(BaseModel):
    """Layer 2 configuration."""
    enabled: bool = True
    detection_sensitivity: str = Field(default="medium", pattern="^(low|medium|high)$")
    z_score_threshold: float = Field(default=3.0, ge=1.0, le=10.0)
    baseline_learning_hours: int = Field(default=24, ge=1, le=168)
    anomaly_cooldown_seconds: int = Field(default=300, ge=60)


class SystemConfig(BaseModel):
    """Complete system configuration."""
    layer1: Layer1Config = Field(default_factory=Layer1Config)
    layer2: Layer2Config = Field(default_factory=Layer2Config)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ConfigUpdate(BaseModel):
    """Model for partial configuration update."""
    layer1: Optional[Layer1Config] = None
    layer2: Optional[Layer2Config] = None


# ==================== Statistics Models ====================

class TrafficStats(BaseModel):
    """Traffic statistics."""
    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    packets_dropped: int = 0
    bytes_dropped: int = 0
    drop_rate_pct: float = 0.0
    current_pps: int = 0
    current_bps: int = 0
    peak_pps_24h: int = 0
    peak_bps_24h: int = 0


class SecurityStats(BaseModel):
    """Security statistics."""
    attacks_detected: int = 0
    attacks_mitigated: int = 0
    attacks_active: int = 0
    avg_mitigation_time_ms: float = 0.0
    false_positives: int = 0
    blacklist_hits: int = 0
    whitelist_hits: int = 0
    rate_limit_drops: int = 0
    syn_proxy_challenges: int = 0
    syn_proxy_passes: int = 0
    geo_blocks: int = 0


class LayerStats(BaseModel):
    """Per-layer statistics."""
    packets_processed: int = 0
    packets_dropped: int = 0
    decisions_made: int = 0
    avg_latency_ns: int = 0
    errors: int = 0


class SLAStats(BaseModel):
    """SLA compliance statistics."""
    availability_pct: float = 100.0
    mttd_ms: float = 0.0  # Mean time to detect
    mttr_ms: float = 0.0  # Mean time to respond
    mitigation_effectiveness_pct: float = 100.0
    false_positive_rate_pct: float = 0.0
    sla_breaches: int = 0


class SystemStats(BaseModel):
    """Complete system statistics."""
    timestamp: datetime
    period: StatsPeriod
    traffic: TrafficStats
    security: SecurityStats
    layer1: LayerStats
    layer2: LayerStats
    sla: SLAStats


class StatsHistoryPoint(BaseModel):
    """Single point in stats history."""
    timestamp: datetime
    pps: int
    bps: int
    drops: int
    attacks: int


# ==================== Attack Models ====================

class AttackBase(BaseModel):
    """Base attack model."""
    attack_type: AttackType
    severity: AttackSeverity
    target_ip: str
    target_port: Optional[int] = None
    source_ips_count: int = 0
    peak_pps: int = 0
    peak_bps: int = 0


class Attack(AttackBase):
    """Full attack model."""
    id: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    is_active: bool = True
    mitigated: bool = False
    mitigation_time_ms: Optional[float] = None
    total_packets_dropped: int = 0
    total_bytes_dropped: int = 0
    top_source_ips: List[str] = Field(default_factory=list)
    signatures_matched: List[str] = Field(default_factory=list)
    ml_confidence: Optional[float] = None


class AttackSummary(BaseModel):
    """Summarized attack for listing."""
    id: str
    attack_type: AttackType
    severity: AttackSeverity
    target_ip: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    is_active: bool
    mitigated: bool
    peak_pps: int
    peak_bps: int


# ==================== IP List Models ====================

class IPListEntryBase(BaseModel):
    """Base IP list entry."""
    ip: str
    description: Optional[str] = Field(default=None, max_length=256)
    expires_at: Optional[datetime] = None

    @validator('ip')
    def validate_ip_or_cidr(cls, v):
        try:
            if '/' in v:
                network = ipaddress.ip_network(v, strict=False)
                if network.prefixlen < 8:
                    raise ValueError("Prefix too broad (minimum /8)")
            else:
                ipaddress.ip_address(v)
            return v
        except ValueError as e:
            raise ValueError(f"Invalid IP/CIDR: {v} - {e}")


class IPListEntryCreate(IPListEntryBase):
    """Create IP list entry."""
    duration_seconds: Optional[int] = Field(default=None, ge=0, description="0 for permanent")


class IPListEntry(IPListEntryBase):
    """Full IP list entry."""
    id: int
    list_type: IPListType
    created_at: datetime
    created_by: str
    hit_count: int = 0
    last_hit_at: Optional[datetime] = None
    is_expired: bool = False


class IPListBulkAdd(BaseModel):
    """Bulk add IPs to list."""
    ips: List[str] = Field(min_items=1, max_items=1000)
    description: Optional[str] = None
    duration_seconds: Optional[int] = None

    @validator('ips', each_item=True)
    def validate_ips(cls, v):
        try:
            if '/' in v:
                ipaddress.ip_network(v, strict=False)
            else:
                ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f"Invalid IP/CIDR: {v}")


# ==================== Policy Models ====================

class PolicyCondition(BaseModel):
    """Policy matching condition."""
    field: str = Field(description="Field to match (src_ip, dst_port, protocol, etc.)")
    operator: str = Field(pattern="^(eq|ne|gt|lt|ge|le|in|not_in|contains|matches)$")
    value: Any


class PolicyBase(BaseModel):
    """Base policy model."""
    name: str = Field(min_length=1, max_length=64)
    description: Optional[str] = Field(default=None, max_length=256)
    priority: int = Field(default=100, ge=1, le=1000)
    action: PolicyAction
    conditions: List[PolicyCondition] = Field(min_items=1)
    enabled: bool = True


class PolicyCreate(PolicyBase):
    """Create policy."""
    expires_at: Optional[datetime] = None


class Policy(PolicyBase):
    """Full policy model."""
    id: int
    created_at: datetime
    updated_at: datetime
    created_by: str
    expires_at: Optional[datetime] = None
    is_expired: bool = False
    hit_count: int = 0
    last_hit_at: Optional[datetime] = None
    source: str = Field(default="manual", description="manual, ml, threat_intel")


# ==================== Report Models ====================

class ReportType(str, Enum):
    """Report types."""
    INCIDENT = "incident"
    TRAFFIC = "traffic"
    SECURITY = "security"
    SLA = "sla"
    EXECUTIVE = "executive"
    CUSTOM = "custom"


class ReportFormat(str, Enum):
    """Report output formats."""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"


class ReportRequest(BaseModel):
    """Report generation request."""
    report_type: ReportType
    format: ReportFormat = ReportFormat.PDF
    start_date: datetime
    end_date: datetime
    include_charts: bool = True
    include_details: bool = True
    custom_sections: Optional[List[str]] = None


class Report(BaseModel):
    """Generated report."""
    id: str
    report_type: ReportType
    format: ReportFormat
    start_date: datetime
    end_date: datetime
    generated_at: datetime
    generated_by: str
    file_path: Optional[str] = None
    file_size_bytes: Optional[int] = None
    status: str = "completed"


# ==================== Authentication Models ====================

class TokenCreate(BaseModel):
    """Create API token request."""
    name: str = Field(min_length=1, max_length=64, description="Token name for identification")
    permissions: List[str] = Field(default=["read"], description="Token permissions")
    expires_in_hours: int = Field(default=24, ge=1, le=8760)


class Token(BaseModel):
    """API token response."""
    id: str
    name: str
    token: str = Field(description="Only shown once on creation")
    permissions: List[str]
    created_at: datetime
    expires_at: datetime


class TokenInfo(BaseModel):
    """Token information (without actual token)."""
    id: str
    name: str
    permissions: List[str]
    created_at: datetime
    expires_at: datetime
    last_used_at: Optional[datetime] = None


class UserLogin(BaseModel):
    """User login request."""
    username: str
    password: str


class LoginResponse(BaseModel):
    """Login response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: str
    permissions: List[str]


# ==================== Webhook Models ====================

class WebhookEvent(str, Enum):
    """Webhook event types."""
    ATTACK_STARTED = "attack.started"
    ATTACK_ENDED = "attack.ended"
    ATTACK_MITIGATED = "attack.mitigated"
    THRESHOLD_EXCEEDED = "threshold.exceeded"
    CONFIG_CHANGED = "config.changed"
    SLA_BREACH = "sla.breach"


class WebhookCreate(BaseModel):
    """Create webhook."""
    url: str = Field(description="Webhook endpoint URL")
    events: List[WebhookEvent] = Field(min_items=1)
    secret: Optional[str] = Field(default=None, description="HMAC secret for signature")
    enabled: bool = True


class Webhook(WebhookCreate):
    """Full webhook model."""
    id: str
    created_at: datetime
    last_triggered_at: Optional[datetime] = None
    failure_count: int = 0


# ==================== Multi-Tenant Models ====================

class TenantStatus(str, Enum):
    """Tenant operational status."""
    ACTIVE = "active"
    ATTACK_MODE = "attack_mode"
    PROVISIONING = "provisioning"
    SUSPENDED = "suspended"
    MAINTENANCE = "maintenance"
    MIGRATING = "migrating"
    DISABLED = "disabled"


class TenantTier(str, Enum):
    """Tenant service tier."""
    FREE = "free"
    BASIC = "basic"
    STANDARD = "standard"
    PREMIUM = "premium"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


class TenantType(str, Enum):
    """Tenant business classification."""
    DIRECT = "direct"
    RESELLER = "reseller"
    MANAGED = "managed"
    TRIAL = "trial"
    INTERNAL = "internal"


class TenantQuotas(BaseModel):
    """Per-tenant resource quotas and limits."""
    max_clean_bps: int = Field(default=1_000_000_000, description="Max clean bits per second")
    max_attack_bps: int = Field(default=10_000_000_000, description="Max attack bits per second")
    max_clean_pps: int = Field(default=1_000_000, description="Max clean packets per second")
    max_attack_pps: int = Field(default=10_000_000, description="Max attack packets per second")
    max_flows: int = Field(default=100_000, description="Max concurrent flows")
    max_connections: int = Field(default=50_000, description="Max concurrent connections")
    max_policies: int = Field(default=100, description="Max custom policies")
    max_blacklist: int = Field(default=10_000, description="Max blacklist entries")
    max_whitelist: int = Field(default=1_000, description="Max whitelist entries")
    max_custom_signatures: int = Field(default=50, description="Max custom signatures")
    api_requests_per_minute: int = Field(default=60, description="API rate limit per minute")
    api_requests_per_hour: int = Field(default=1_000, description="API rate limit per hour")


class TenantFeatures(BaseModel):
    """Per-tenant feature flags."""
    l1_basic: bool = True
    l1_advanced: bool = False
    l2_anomaly: bool = True
    l3_ml: bool = False
    l4_reputation: bool = False
    l4_challenges: bool = False
    l4_bot_mgmt: bool = False
    l5_intel: bool = False
    realtime_dashboard: bool = True
    api_access: bool = True
    custom_reports: bool = False
    managed_rules: bool = False
    carpet_bomb_detection: bool = Field(
        default=False,
        description="Carpet Bomb Attack Detection (Subnet /24 Aggregation at Gateway)"
    )


class TenantContact(BaseModel):
    """Tenant contact details."""
    primary_email: str = Field(..., description="Primary contact email")
    phone: Optional[str] = None
    technical_contact: Optional[str] = None
    billing_email: Optional[str] = None


class TenantCreate(BaseModel):
    """Create tenant request."""
    name: str = Field(min_length=1, max_length=64)
    description: Optional[str] = None
    tier: TenantTier = TenantTier.STANDARD
    tenant_type: TenantType = TenantType.DIRECT
    protected_ips: List[str] = Field(default_factory=list)
    protected_prefixes: List[str] = Field(default_factory=list)
    contact: TenantContact
    quotas: Optional[TenantQuotas] = None
    features: Optional[TenantFeatures] = None


class TenantUpdate(BaseModel):
    """Update tenant request."""
    name: Optional[str] = None
    description: Optional[str] = None
    status: Optional[TenantStatus] = None
    tier: Optional[TenantTier] = None
    protected_ips: Optional[List[str]] = None
    protected_prefixes: Optional[List[str]] = None
    contact: Optional[TenantContact] = None
    quotas: Optional[TenantQuotas] = None
    features: Optional[TenantFeatures] = None


class Tenant(BaseModel):
    """Full tenant response model."""
    id: int
    name: str
    description: Optional[str] = None
    status: TenantStatus = TenantStatus.ACTIVE
    tier: TenantTier = TenantTier.STANDARD
    tenant_type: TenantType = TenantType.DIRECT
    protected_ips: List[str] = Field(default_factory=list)
    protected_prefixes: List[str] = Field(default_factory=list)
    contact: TenantContact
    quotas: TenantQuotas = Field(default_factory=TenantQuotas)
    features: TenantFeatures = Field(default_factory=TenantFeatures)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: Optional[datetime] = None


class TenantConfig(BaseModel):
    """Tenant layer configuration."""
    tenant_id: int
    l1: Optional[Dict[str, Any]] = None
    l2: Optional[Dict[str, Any]] = None
    l3: Optional[Dict[str, Any]] = None
    l4: Optional[Dict[str, Any]] = None
    l5: Optional[Dict[str, Any]] = None
    version: int = 1


class ConfigUpdate(BaseModel):
    """Config update request."""
    layer: str = Field(..., pattern="^(l1|l2|l3|l4|l5)$")
    config: Dict[str, Any]

