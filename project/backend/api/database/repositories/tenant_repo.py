"""
Tenant repository for multi-tenant data access.

Provides CRUD operations and specialized queries for tenant management,
including hierarchy support, protected IP management, and tenant search.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from sqlalchemy import select, func, and_, or_
from sqlalchemy.orm import Session, joinedload

from ..models import (
    Tenant,
    TenantStatus,
    TenantTier,
    TenantType,
    ProtectedIP,
    TenantConfig,
)
from .base import BaseRepository, NotFoundError, DuplicateError


class TenantRepository(BaseRepository[Tenant]):
    """
    Repository for tenant management operations.

    Provides multi-tenant CRUD, hierarchy support, and specialized queries.
    """

    def __init__(self, db: Session):
        super().__init__(Tenant, db)

    # ==================== Basic CRUD ====================

    def get_with_relations(self, tenant_id: int) -> Optional[Tenant]:
        """
        Get tenant with all related data loaded.

        Args:
            tenant_id: Tenant ID

        Returns:
            Tenant with protected_ips, config loaded
        """
        return (
            self.db.query(Tenant)
            .options(
                joinedload(Tenant.protected_ips),
                joinedload(Tenant.config),
            )
            .filter(Tenant.id == tenant_id)
            .first()
        )

    def get_by_name(self, name: str) -> Optional[Tenant]:
        """
        Get tenant by name.

        Args:
            name: Tenant name

        Returns:
            Tenant or None
        """
        return self.db.query(Tenant).filter(Tenant.name == name).first()

    def get_by_external_id(self, external_id: str) -> Optional[Tenant]:
        """
        Get tenant by external ID (billing/CRM reference).

        Args:
            external_id: External system ID

        Returns:
            Tenant or None
        """
        return self.db.query(Tenant).filter(Tenant.external_id == external_id).first()

    def name_exists(self, name: str, exclude_id: Optional[int] = None) -> bool:
        """
        Check if tenant name already exists.

        Args:
            name: Tenant name to check
            exclude_id: Tenant ID to exclude (for updates)

        Returns:
            True if name exists
        """
        query = self.db.query(Tenant).filter(Tenant.name == name)
        if exclude_id:
            query = query.filter(Tenant.id != exclude_id)
        return query.first() is not None

    # ==================== Listing ====================

    def list_tenants(
        self,
        status: Optional[TenantStatus] = None,
        tier: Optional[TenantTier] = None,
        tenant_type: Optional[TenantType] = None,
        parent_id: Optional[int] = None,
        search: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
        order_by: str = "id",
        order_desc: bool = False,
    ) -> List[Tenant]:
        """
        List tenants with filtering and pagination.

        Args:
            status: Filter by status
            tier: Filter by tier
            tenant_type: Filter by type
            parent_id: Filter by parent tenant
            search: Search in name/description
            skip: Offset for pagination
            limit: Max results
            order_by: Column to sort by
            order_desc: Sort descending

        Returns:
            List of tenants
        """
        query = self.db.query(Tenant)

        # Apply filters
        if status:
            query = query.filter(Tenant.status == status)
        if tier:
            query = query.filter(Tenant.tier == tier)
        if tenant_type:
            query = query.filter(Tenant.tenant_type == tenant_type)
        if parent_id is not None:
            query = query.filter(Tenant.parent_tenant_id == parent_id)
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Tenant.name.ilike(search_term),
                    Tenant.description.ilike(search_term),
                    Tenant.external_id.ilike(search_term),
                )
            )

        # Ordering
        if hasattr(Tenant, order_by):
            col = getattr(Tenant, order_by)
            query = query.order_by(col.desc() if order_desc else col)

        return query.offset(skip).limit(limit).all()

    def count_tenants(
        self,
        status: Optional[TenantStatus] = None,
        tier: Optional[TenantTier] = None,
        search: Optional[str] = None,
    ) -> int:
        """
        Count tenants matching filters.

        Args:
            status: Filter by status
            tier: Filter by tier
            search: Search in name/description

        Returns:
            Count of matching tenants
        """
        query = self.db.query(func.count(Tenant.id))

        if status:
            query = query.filter(Tenant.status == status)
        if tier:
            query = query.filter(Tenant.tier == tier)
        if search:
            search_term = f"%{search}%"
            query = query.filter(
                or_(
                    Tenant.name.ilike(search_term),
                    Tenant.description.ilike(search_term),
                )
            )

        return query.scalar() or 0

    def list_active(self) -> List[Tenant]:
        """
        Get all active tenants.

        Returns:
            List of active tenants
        """
        return (
            self.db.query(Tenant)
            .filter(Tenant.status == TenantStatus.ACTIVE)
            .order_by(Tenant.id)
            .all()
        )

    def list_by_tier(self, tier: TenantTier) -> List[Tenant]:
        """
        Get all tenants of a specific tier.

        Args:
            tier: Service tier

        Returns:
            List of tenants
        """
        return (
            self.db.query(Tenant)
            .filter(Tenant.tier == tier)
            .order_by(Tenant.id)
            .all()
        )

    # ==================== Hierarchy ====================

    def get_children(self, tenant_id: int) -> List[Tenant]:
        """
        Get child tenants (sub-accounts).

        Args:
            tenant_id: Parent tenant ID

        Returns:
            List of child tenants
        """
        return (
            self.db.query(Tenant)
            .filter(Tenant.parent_tenant_id == tenant_id)
            .order_by(Tenant.id)
            .all()
        )

    def get_parent(self, tenant_id: int) -> Optional[Tenant]:
        """
        Get parent tenant (for reseller model).

        Args:
            tenant_id: Child tenant ID

        Returns:
            Parent tenant or None
        """
        tenant = self.get(tenant_id)
        if tenant and tenant.parent_tenant_id:
            return self.get(tenant.parent_tenant_id)
        return None

    def get_hierarchy(self, tenant_id: int) -> List[Tenant]:
        """
        Get tenant hierarchy from root to this tenant.

        Args:
            tenant_id: Tenant ID

        Returns:
            List of tenants from root to current
        """
        hierarchy = []
        current = self.get(tenant_id)

        while current:
            hierarchy.insert(0, current)
            if current.parent_tenant_id:
                current = self.get(current.parent_tenant_id)
            else:
                break

        return hierarchy

    # ==================== Status Management ====================

    def set_status(
        self,
        tenant_id: int,
        status: TenantStatus,
        updated_by: Optional[str] = None,
    ) -> Optional[Tenant]:
        """
        Update tenant status.

        Args:
            tenant_id: Tenant ID
            status: New status
            updated_by: Who made the change

        Returns:
            Updated tenant or None
        """
        tenant = self.get(tenant_id)
        if not tenant:
            return None

        tenant.status = status
        tenant.updated_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(tenant)
        return tenant

    def suspend(self, tenant_id: int, reason: Optional[str] = None) -> Optional[Tenant]:
        """
        Suspend a tenant.

        Args:
            tenant_id: Tenant ID
            reason: Suspension reason

        Returns:
            Updated tenant
        """
        return self.set_status(tenant_id, TenantStatus.SUSPENDED)

    def activate(self, tenant_id: int) -> Optional[Tenant]:
        """
        Activate a tenant.

        Args:
            tenant_id: Tenant ID

        Returns:
            Updated tenant
        """
        return self.set_status(tenant_id, TenantStatus.ACTIVE)

    def set_attack_mode(self, tenant_id: int) -> Optional[Tenant]:
        """
        Set tenant to attack mode (elevated priority).

        Args:
            tenant_id: Tenant ID

        Returns:
            Updated tenant
        """
        return self.set_status(tenant_id, TenantStatus.ATTACK_MODE)

    # ==================== Protected IPs ====================

    def get_protected_ips(self, tenant_id: int) -> List[ProtectedIP]:
        """
        Get all protected IPs for a tenant.

        Args:
            tenant_id: Tenant ID

        Returns:
            List of protected IPs
        """
        return (
            self.db.query(ProtectedIP)
            .filter(ProtectedIP.tenant_id == tenant_id)
            .order_by(ProtectedIP.priority)
            .all()
        )

    def add_protected_ip(
        self,
        tenant_id: int,
        ip_address: str,
        prefix_len: Optional[int] = None,
        description: Optional[str] = None,
        priority: int = 100,
    ) -> ProtectedIP:
        """
        Add a protected IP to tenant.

        Args:
            tenant_id: Tenant ID
            ip_address: IP address
            prefix_len: CIDR prefix (None for single IP)
            description: Description
            priority: Routing priority

        Returns:
            Created ProtectedIP

        Raises:
            DuplicateError: If IP already protected
        """
        # Check if exists
        existing = (
            self.db.query(ProtectedIP)
            .filter(
                ProtectedIP.tenant_id == tenant_id,
                ProtectedIP.ip_address == ip_address,
                ProtectedIP.prefix_len == prefix_len,
            )
            .first()
        )
        if existing:
            raise DuplicateError(f"IP {ip_address} already protected for tenant {tenant_id}")

        protected_ip = ProtectedIP(
            tenant_id=tenant_id,
            ip_address=ip_address,
            prefix_len=prefix_len,
            description=description,
            priority=priority,
        )
        self.db.add(protected_ip)
        self.db.commit()
        self.db.refresh(protected_ip)
        return protected_ip

    def remove_protected_ip(
        self,
        tenant_id: int,
        ip_address: str,
        prefix_len: Optional[int] = None,
    ) -> bool:
        """
        Remove a protected IP from tenant.

        Args:
            tenant_id: Tenant ID
            ip_address: IP address
            prefix_len: CIDR prefix

        Returns:
            True if removed, False if not found
        """
        result = (
            self.db.query(ProtectedIP)
            .filter(
                ProtectedIP.tenant_id == tenant_id,
                ProtectedIP.ip_address == ip_address,
                ProtectedIP.prefix_len == prefix_len,
            )
            .delete()
        )
        self.db.commit()
        return result > 0

    def count_protected_ips(self, tenant_id: int) -> int:
        """
        Count protected IPs for tenant.

        Args:
            tenant_id: Tenant ID

        Returns:
            Count of protected IPs
        """
        return (
            self.db.query(func.count(ProtectedIP.id))
            .filter(ProtectedIP.tenant_id == tenant_id)
            .scalar()
            or 0
        )

    def find_tenant_by_protected_ip(self, ip_address: str) -> Optional[Tenant]:
        """
        Find tenant that owns a protected IP.

        Args:
            ip_address: IP address to look up

        Returns:
            Tenant or None
        """
        protected_ip = (
            self.db.query(ProtectedIP)
            .filter(ProtectedIP.ip_address == ip_address)
            .first()
        )
        if protected_ip:
            return self.get(protected_ip.tenant_id)
        return None

    # ==================== Configuration ====================

    def get_config(self, tenant_id: int) -> Optional[TenantConfig]:
        """
        Get tenant configuration.

        Args:
            tenant_id: Tenant ID

        Returns:
            TenantConfig or None
        """
        return (
            self.db.query(TenantConfig)
            .filter(TenantConfig.tenant_id == tenant_id)
            .first()
        )

    def set_config(
        self,
        tenant_id: int,
        layer1: Optional[dict] = None,
        layer2: Optional[dict] = None,
        layer3: Optional[dict] = None,
        layer4: Optional[dict] = None,
        layer5: Optional[dict] = None,
        updated_by: Optional[str] = None,
    ) -> TenantConfig:
        """
        Set or update tenant configuration.

        Args:
            tenant_id: Tenant ID
            layer1-5: Layer configurations
            updated_by: Who made the change

        Returns:
            TenantConfig
        """
        config = self.get_config(tenant_id)

        if config:
            # Update existing
            if layer1 is not None:
                config.layer1 = layer1
            if layer2 is not None:
                config.layer2 = layer2
            if layer3 is not None:
                config.layer3 = layer3
            if layer4 is not None:
                config.layer4 = layer4
            if layer5 is not None:
                config.layer5 = layer5
            config.version += 1
            config.updated_at = datetime.utcnow()
            config.updated_by = updated_by
        else:
            # Create new
            config = TenantConfig(
                tenant_id=tenant_id,
                layer1=layer1 or {},
                layer2=layer2 or {},
                layer3=layer3 or {},
                layer4=layer4 or {},
                layer5=layer5 or {},
                updated_by=updated_by,
            )
            self.db.add(config)

        self.db.commit()
        self.db.refresh(config)
        return config

    # ==================== Quotas ====================

    def get_quotas(self, tenant_id: int) -> Optional[dict]:
        """
        Get tenant quotas.

        Args:
            tenant_id: Tenant ID

        Returns:
            Quotas dict or None
        """
        tenant = self.get(tenant_id)
        return tenant.quotas if tenant else None

    def set_quotas(self, tenant_id: int, quotas: dict) -> Optional[Tenant]:
        """
        Update tenant quotas.

        Args:
            tenant_id: Tenant ID
            quotas: New quotas

        Returns:
            Updated tenant
        """
        tenant = self.get(tenant_id)
        if not tenant:
            return None

        tenant.quotas = quotas
        tenant.updated_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(tenant)
        return tenant

    # ==================== Features ====================

    def get_features(self, tenant_id: int) -> Optional[dict]:
        """
        Get tenant enabled features.

        Args:
            tenant_id: Tenant ID

        Returns:
            Features dict or None
        """
        tenant = self.get(tenant_id)
        return tenant.features if tenant else None

    def set_features(self, tenant_id: int, features: dict) -> Optional[Tenant]:
        """
        Update tenant features.

        Args:
            tenant_id: Tenant ID
            features: New features

        Returns:
            Updated tenant
        """
        tenant = self.get(tenant_id)
        if not tenant:
            return None

        tenant.features = features
        tenant.updated_at = datetime.utcnow()

        self.db.commit()
        self.db.refresh(tenant)
        return tenant

    def has_feature(self, tenant_id: int, feature: str) -> bool:
        """
        Check if tenant has a specific feature enabled.

        Args:
            tenant_id: Tenant ID
            feature: Feature name

        Returns:
            True if feature enabled
        """
        features = self.get_features(tenant_id)
        if not features:
            return False
        return features.get(feature, False)

    # ==================== Statistics ====================

    def get_stats(self) -> Dict[str, Any]:
        """
        Get aggregate tenant statistics.

        Returns:
            Dict with counts by status, tier, etc.
        """
        total = self.count()
        by_status = {}
        by_tier = {}

        for status in TenantStatus:
            count = self.count({"status": status})
            if count > 0:
                by_status[status.value] = count

        for tier in TenantTier:
            count = self.count({"tier": tier})
            if count > 0:
                by_tier[tier.value] = count

        protected_ips = (
            self.db.query(func.count(ProtectedIP.id)).scalar() or 0
        )

        return {
            "total": total,
            "by_status": by_status,
            "by_tier": by_tier,
            "protected_ips_total": protected_ips,
        }
