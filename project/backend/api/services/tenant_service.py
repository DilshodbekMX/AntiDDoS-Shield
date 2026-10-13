"""
Tenant Service (Database Integration)

Business logic for tenant management with persistent database storage.
"""

import logging
from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any
import ipaddress

from sqlalchemy.orm import Session

from ..models import (
    Tenant as TenantSchema,
    TenantCreate,
    TenantUpdate,
    TenantStatus,
    TenantTier,
    TenantQuotas,
    TenantFeatures,
    TenantContact
)
from ..database import get_db, init_db
from ..database.models import (
    Tenant as TenantModel,
    ProtectedIP,
    TenantStatus as DBTenantStatus,
    TenantTier as DBTenantTier,
    TenantType as DBTenantType,
)
from ..database.repositories.tenant_repo import TenantRepository
from ..database.repositories.base import NotFoundError, DuplicateError
from .dataplane_service import get_dataplane_service

logger = logging.getLogger(__name__)


class TenantService:
    """
    Service layer for tenant management.

    Uses database for persistent storage and integrates with:
    - TenantRepository for CRUD operations
    - C data plane via shared memory/socket for live config
    - Redis for caching (TODO)
    """

    def __init__(self, db: Optional[Session] = None):
        """
        Initialize tenant service.

        Args:
            db: Optional database session. If not provided, creates new session per operation.
        """
        self._db = db
        self._db_initialized = False

    def _get_db(self) -> Session:
        """Get database session, initializing if needed."""
        if not self._db_initialized:
            try:
                init_db()
                self._db_initialized = True
            except Exception as e:
                logger.warning(f"Database init warning (may already be initialized): {e}")
                self._db_initialized = True

        if self._db:
            return self._db
        return next(get_db())

    def _get_repo(self, db: Session) -> TenantRepository:
        """Get tenant repository for given session."""
        return TenantRepository(db)

    def _db_tenant_to_schema(self, db_tenant: TenantModel) -> TenantSchema:
        """Convert SQLAlchemy Tenant to Pydantic Tenant schema."""
        # Extract protected IPs from relationship
        protected_ips = []
        protected_prefixes = []

        for pip in db_tenant.protected_ips:
            if pip.prefix_len and pip.prefix_len < 32:
                protected_prefixes.append(f"{pip.ip_address}/{pip.prefix_len}")
            else:
                protected_ips.append(pip.ip_address)

        # Parse JSON fields with defaults
        quotas = TenantQuotas(**(db_tenant.quotas or {}))
        features = TenantFeatures(**(db_tenant.features or {}))
        contact_data = db_tenant.contact or {"primary_email": "unknown@example.com"}
        contact = TenantContact(**contact_data)

        return TenantSchema(
            id=db_tenant.id,
            name=db_tenant.name,
            description=db_tenant.description,
            tier=TenantTier(db_tenant.tier.value) if db_tenant.tier else TenantTier.BASIC,
            tenant_type=db_tenant.tenant_type.value if db_tenant.tenant_type else "direct",
            parent_tenant_id=db_tenant.parent_tenant_id,
            status=TenantStatus(db_tenant.status.value) if db_tenant.status else TenantStatus.ACTIVE,
            protected_ips=protected_ips,
            protected_prefixes=protected_prefixes,
            quotas=quotas,
            features=features,
            contact=contact,
            created_at=db_tenant.created_at,
            updated_at=db_tenant.updated_at,
        )

    async def list_tenants(
        self,
        status: Optional[TenantStatus] = None,
        tier: Optional[TenantTier] = None,
        search: Optional[str] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Tuple[List[TenantSchema], int]:
        """List tenants with filtering and pagination."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)

            # Convert Pydantic enums to DB enums
            db_status = DBTenantStatus(status.value) if status else None
            db_tier = DBTenantTier(tier.value) if tier else None

            # Get tenants from database
            skip = (page - 1) * per_page
            db_tenants = repo.list_tenants(
                status=db_status,
                tier=db_tier,
                search=search,
                skip=skip,
                limit=per_page
            )

            # Get total count
            total = repo.count_tenants(status=db_status, tier=db_tier, search=search)

            # Convert to schema
            tenants = [self._db_tenant_to_schema(t) for t in db_tenants]

            return tenants, total
        finally:
            if not self._db:
                db.close()

    async def get_tenant(self, tenant_id: int) -> Optional[TenantSchema]:
        """Get a tenant by ID."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)
            db_tenant = repo.get_with_relations(tenant_id)
            if db_tenant:
                return self._db_tenant_to_schema(db_tenant)
            return None
        finally:
            if not self._db:
                db.close()

    async def get_tenant_by_name(self, name: str) -> Optional[TenantSchema]:
        """Get a tenant by name."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)
            db_tenant = repo.get_by_name(name)
            if db_tenant:
                return self._db_tenant_to_schema(db_tenant)
            return None
        finally:
            if not self._db:
                db.close()

    async def create_tenant(self, data: TenantCreate, created_by: str) -> TenantSchema:
        """Create a new tenant."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)

            # Check for duplicate name
            if repo.name_exists(data.name):
                raise DuplicateError(f"Tenant name '{data.name}' already exists")

            # Helper to convert Pydantic model or dict to dict
            def to_dict(obj):
                if obj is None:
                    return {}
                if isinstance(obj, dict):
                    return obj
                if hasattr(obj, 'model_dump'):
                    return obj.model_dump()
                if hasattr(obj, 'dict'):
                    return obj.dict()
                return dict(obj)

            # Create tenant model
            db_tenant = TenantModel(
                name=data.name,
                description=data.description,
                tier=DBTenantTier(data.tier.value) if data.tier else DBTenantTier.BASIC,
                tenant_type=DBTenantType(data.tenant_type.value) if data.tenant_type else DBTenantType.DIRECT,
                parent_tenant_id=data.parent_tenant_id,
                status=DBTenantStatus.PROVISIONING,
                quotas=to_dict(data.quotas),
                features=to_dict(data.features),
                contact=to_dict(data.contact),
                created_by=created_by,
            )

            # Save to database
            db.add(db_tenant)
            db.commit()
            db.refresh(db_tenant)

            # Add protected IPs
            for ip in data.protected_ips:
                protected_ip = ProtectedIP(
                    tenant_id=db_tenant.id,
                    ip_address=ip,
                    prefix_len=32,
                    description="Initial protected IP",
                )
                db.add(protected_ip)

            for prefix in data.protected_prefixes:
                ip_addr, prefix_len = prefix.rsplit('/', 1)
                protected_ip = ProtectedIP(
                    tenant_id=db_tenant.id,
                    ip_address=ip_addr,
                    prefix_len=int(prefix_len),
                    description="Initial protected prefix",
                )
                db.add(protected_ip)

            db.commit()
            db.refresh(db_tenant)

            # Push configuration to C data plane
            tenant_schema = self._db_tenant_to_schema(db_tenant)
            self._push_tenant_to_dataplane(tenant_schema)

            # Set status to active after provisioning
            db_tenant.status = DBTenantStatus.ACTIVE
            db.commit()
            db.refresh(db_tenant)

            logger.info(f"Created tenant {db_tenant.id}: {data.name} by {created_by}")
            return self._db_tenant_to_schema(db_tenant)
        except DuplicateError:
            raise
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to create tenant: {e}")
            raise
        finally:
            if not self._db:
                db.close()

    async def update_tenant(
        self,
        tenant_id: int,
        data: TenantUpdate,
        updated_by: str
    ) -> TenantSchema:
        """Update a tenant."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)
            db_tenant = repo.get(tenant_id)

            if not db_tenant:
                raise NotFoundError(f"Tenant {tenant_id} not found")

            update_dict = data.dict(exclude_unset=True)

            # Handle enum conversions
            if 'tier' in update_dict and update_dict['tier']:
                update_dict['tier'] = DBTenantTier(update_dict['tier'].value)
            if 'status' in update_dict and update_dict['status']:
                update_dict['status'] = DBTenantStatus(update_dict['status'].value)

            # Handle nested objects - convert Pydantic models to dicts if needed
            if 'quotas' in update_dict and update_dict['quotas']:
                if hasattr(update_dict['quotas'], 'dict'):
                    update_dict['quotas'] = update_dict['quotas'].dict()
                elif hasattr(update_dict['quotas'], 'model_dump'):
                    update_dict['quotas'] = update_dict['quotas'].model_dump()
                # else: already a dict, keep as is
            if 'features' in update_dict and update_dict['features']:
                if hasattr(update_dict['features'], 'dict'):
                    update_dict['features'] = update_dict['features'].dict()
                elif hasattr(update_dict['features'], 'model_dump'):
                    update_dict['features'] = update_dict['features'].model_dump()
                # else: already a dict, keep as is
            if 'contact' in update_dict and update_dict['contact']:
                if hasattr(update_dict['contact'], 'dict'):
                    update_dict['contact'] = update_dict['contact'].dict()
                elif hasattr(update_dict['contact'], 'model_dump'):
                    update_dict['contact'] = update_dict['contact'].model_dump()
                # else: already a dict, keep as is

            # Check for name conflict
            if 'name' in update_dict and update_dict['name']:
                if repo.name_exists(update_dict['name'], exclude_id=tenant_id):
                    raise DuplicateError(f"Tenant name '{update_dict['name']}' already exists")

            # Handle protected_ips and protected_prefixes separately (stored in ProtectedIP table)
            new_protected_ips = update_dict.pop('protected_ips', None)
            new_protected_prefixes = update_dict.pop('protected_prefixes', None)

            # Apply updates to tenant model (excluding protected_ips/prefixes)
            for field, value in update_dict.items():
                if value is not None and hasattr(db_tenant, field):
                    setattr(db_tenant, field, value)

            # Update protected IPs if provided
            if new_protected_ips is not None or new_protected_prefixes is not None:
                # Delete existing protected IPs for this tenant
                db.query(ProtectedIP).filter(ProtectedIP.tenant_id == tenant_id).delete()

                # Add new protected IPs
                if new_protected_ips:
                    for ip in new_protected_ips:
                        protected_ip = ProtectedIP(
                            tenant_id=tenant_id,
                            ip_address=ip,
                            prefix_len=32,
                            description="Updated protected IP",
                        )
                        db.add(protected_ip)

                # Add new protected prefixes
                if new_protected_prefixes:
                    for prefix in new_protected_prefixes:
                        ip_addr, prefix_len = prefix.rsplit('/', 1)
                        protected_ip = ProtectedIP(
                            tenant_id=tenant_id,
                            ip_address=ip_addr,
                            prefix_len=int(prefix_len),
                            description="Updated protected prefix",
                        )
                        db.add(protected_ip)

            db_tenant.updated_at = datetime.utcnow()
            db.commit()
            db.refresh(db_tenant)

            # Push updated config to data plane
            tenant_schema = self._db_tenant_to_schema(db_tenant)
            self._push_tenant_to_dataplane(tenant_schema)

            logger.info(f"Updated tenant {tenant_id} by {updated_by}")
            return tenant_schema
        except (NotFoundError, DuplicateError):
            raise
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to update tenant: {e}")
            raise
        finally:
            if not self._db:
                db.close()

    async def delete_tenant(self, tenant_id: int, deleted_by: str) -> None:
        """Soft-delete a tenant by setting status to DISABLED."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)
            db_tenant = repo.get(tenant_id)

            if not db_tenant:
                raise NotFoundError(f"Tenant {tenant_id} not found")

            db_tenant.status = DBTenantStatus.DISABLED
            db_tenant.updated_at = datetime.utcnow()
            db.commit()

            # Disable in data plane
            self._disable_tenant_in_dataplane(tenant_id)

            logger.info(f"Deleted tenant {tenant_id} by {deleted_by}")
        except NotFoundError:
            raise
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to delete tenant: {e}")
            raise
        finally:
            if not self._db:
                db.close()

    async def set_tenant_status(
        self,
        tenant_id: int,
        status: TenantStatus,
        reason: str = None,
        updated_by: str = None
    ) -> None:
        """Set tenant status."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)
            db_status = DBTenantStatus(status.value)

            updated = repo.set_status(tenant_id, db_status, updated_by)
            if not updated:
                raise NotFoundError(f"Tenant {tenant_id} not found")

            # Update status in data plane
            self._update_tenant_status_dataplane(tenant_id, status)

            logger.info(
                f"Tenant {tenant_id} status changed to {status} "
                f"by {updated_by}. Reason: {reason}"
            )
        except NotFoundError:
            raise
        finally:
            if not self._db:
                db.close()

    async def add_protected_ip(
        self,
        tenant_id: int,
        ip: str,
        added_by: str
    ) -> None:
        """Add an IP to protection."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)

            # Validate tenant exists
            db_tenant = repo.get(tenant_id)
            if not db_tenant:
                raise NotFoundError(f"Tenant {tenant_id} not found")

            # Validate and parse IP
            if '/' in ip:
                network = ipaddress.ip_network(ip, strict=False)
                ip_addr = str(network.network_address)
                prefix_len = network.prefixlen
            else:
                ipaddress.ip_address(ip)
                ip_addr = ip
                prefix_len = 32

            # Add to database
            try:
                repo.add_protected_ip(tenant_id, ip_addr, prefix_len, f"Added by {added_by}")
            except DuplicateError:
                logger.warning(f"IP {ip} already protected for tenant {tenant_id}")
                return

            # Push to DPDK data plane via control socket
            dp = get_dataplane_service()
            if not dp.add_to_protected(ip_addr, prefix_len):
                logger.error(f"Failed to push protected IP {ip} to dataplane (control socket error)")
                raise RuntimeError(f"IP {ip} saved to DB but failed to push to dataplane - check control socket")

            logger.info(f"Added protected IP {ip} to tenant {tenant_id} by {added_by}")
        except (NotFoundError, DuplicateError):
            raise
        finally:
            if not self._db:
                db.close()

    async def remove_protected_ip(
        self,
        tenant_id: int,
        ip: str,
        removed_by: str
    ) -> None:
        """Remove an IP from protection."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)

            # Validate tenant exists
            db_tenant = repo.get(tenant_id)
            if not db_tenant:
                raise NotFoundError(f"Tenant {tenant_id} not found")

            # Parse IP
            if '/' in ip:
                network = ipaddress.ip_network(ip, strict=False)
                ip_addr = str(network.network_address)
                prefix_len = network.prefixlen
            else:
                ip_addr = ip
                prefix_len = 32

            # Remove from database
            removed = repo.remove_protected_ip(tenant_id, ip_addr, prefix_len)
            if not removed:
                logger.warning(f"IP {ip} not found for tenant {tenant_id}")

            # Remove from DPDK data plane via control socket
            dp = get_dataplane_service()
            if not dp.remove_from_protected(ip_addr, prefix_len):
                logger.error(f"Failed to remove protected IP {ip} from dataplane (control socket error)")

            logger.info(f"Removed protected IP {ip} from tenant {tenant_id} by {removed_by}")
        except NotFoundError:
            raise
        finally:
            if not self._db:
                db.close()

    async def get_quota_usage(self, tenant_id: int) -> Dict[str, Any]:
        """Get current quota usage for a tenant."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)
            db_tenant = repo.get(tenant_id)

            if not db_tenant:
                raise NotFoundError(f"Tenant {tenant_id} not found")

            # Count protected IPs
            protected_count = repo.count_protected_ips(tenant_id)

            # TODO: Get actual usage from data plane stats
            return {
                "current_bps": 0,
                "current_pps": 0,
                "flows_used": 0,
                "connections_used": 0,
                "policies_used": 0,
                "blacklist_used": 0,
                "whitelist_used": 0,
                "protected_ips": protected_count,
            }
        except NotFoundError:
            raise
        finally:
            if not self._db:
                db.close()

    async def update_quotas(
        self,
        tenant_id: int,
        quotas: TenantQuotas,
        updated_by: str
    ) -> None:
        """Update tenant quotas."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)
            # Convert Pydantic model or dict to dict
            quotas_dict = quotas if isinstance(quotas, dict) else (
                quotas.model_dump() if hasattr(quotas, 'model_dump') else quotas.dict()
            )
            updated = repo.set_quotas(tenant_id, quotas_dict)

            if not updated:
                raise NotFoundError(f"Tenant {tenant_id} not found")

            # Push to data plane
            tenant = await self.get_tenant(tenant_id)
            if tenant:
                self._push_tenant_to_dataplane(tenant)

            logger.info(f"Updated quotas for tenant {tenant_id} by {updated_by}")
        except NotFoundError:
            raise
        finally:
            if not self._db:
                db.close()

    async def update_features(
        self,
        tenant_id: int,
        features: TenantFeatures,
        updated_by: str
    ) -> None:
        """Update tenant features."""
        db = self._get_db()
        try:
            repo = self._get_repo(db)
            # Convert Pydantic model or dict to dict
            features_dict = features if isinstance(features, dict) else (
                features.model_dump() if hasattr(features, 'model_dump') else features.dict()
            )
            updated = repo.set_features(tenant_id, features_dict)

            if not updated:
                raise NotFoundError(f"Tenant {tenant_id} not found")

            # Push to data plane
            tenant = await self.get_tenant(tenant_id)
            if tenant:
                self._push_tenant_to_dataplane(tenant)

            logger.info(f"Updated features for tenant {tenant_id} by {updated_by}")
        except NotFoundError:
            raise
        finally:
            if not self._db:
                db.close()

    # ==================== Data Plane Integration ====================

    def _push_tenant_to_dataplane(self, tenant: TenantSchema) -> None:
        """Push tenant configuration to the data plane."""
        try:
            dp = get_dataplane_service()

            # Push protected IPs/prefixes
            failed = 0
            for ip in tenant.protected_ips:
                if not dp.add_to_protected(ip, 32):
                    logger.error(f"Failed to push protected IP {ip} to dataplane")
                    failed += 1

            for prefix in tenant.protected_prefixes:
                if '/' in prefix:
                    ip_addr, prefix_len = prefix.rsplit('/', 1)
                    if not dp.add_to_protected(ip_addr, int(prefix_len)):
                        logger.error(f"Failed to push protected prefix {prefix} to dataplane")
                        failed += 1

            # Request config reload to pick up any other changes
            dp.reload_config()

            if failed > 0:
                logger.warning(f"Tenant {tenant.id}: {failed} protected IPs failed to push to dataplane")
            else:
                logger.info(f"Pushed tenant {tenant.id} config to data plane ({len(tenant.protected_ips)} IPs)")
        except Exception as e:
            logger.warning(f"Failed to push tenant config to data plane: {e}")

    def _disable_tenant_in_dataplane(self, tenant_id: int) -> None:
        """Disable a tenant in the data plane."""
        try:
            db = self._get_db()
            repo = self._get_repo(db)
            db_tenant = repo.get_with_relations(tenant_id)

            if not db_tenant:
                return

            tenant = self._db_tenant_to_schema(db_tenant)
            dp = get_dataplane_service()

            # Remove protected IPs/prefixes
            for ip in tenant.protected_ips:
                dp.remove_from_protected(ip, 32)

            for prefix in tenant.protected_prefixes:
                if '/' in prefix:
                    ip_addr, prefix_len = prefix.rsplit('/', 1)
                    dp.remove_from_protected(ip_addr, int(prefix_len))

            logger.debug(f"Disabled tenant {tenant_id} in data plane")
        except Exception as e:
            logger.warning(f"Failed to disable tenant in data plane: {e}")

    def _update_tenant_status_dataplane(self, tenant_id: int, status: TenantStatus) -> None:
        """Update tenant status in the data plane."""
        try:
            if status == TenantStatus.SUSPENDED or status == TenantStatus.DISABLED:
                self._disable_tenant_in_dataplane(tenant_id)
            elif status == TenantStatus.ACTIVE:
                db = self._get_db()
                repo = self._get_repo(db)
                db_tenant = repo.get_with_relations(tenant_id)
                if db_tenant:
                    tenant = self._db_tenant_to_schema(db_tenant)
                    self._push_tenant_to_dataplane(tenant)

            logger.debug(f"Updated tenant {tenant_id} status to {status} in data plane")
        except Exception as e:
            logger.warning(f"Failed to update tenant status in data plane: {e}")


# Singleton instance
_tenant_service = None


def get_tenant_service() -> TenantService:
    """Get or create the tenant service singleton."""
    global _tenant_service
    if _tenant_service is None:
        _tenant_service = TenantService()
    return _tenant_service
