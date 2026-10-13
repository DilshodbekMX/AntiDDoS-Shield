"""
Policy Service (Database Persistence)

Business logic for policy management.
Uses SQLAlchemy repository for persistent storage.
"""

import logging
import re
from datetime import datetime
from typing import Optional, List, Tuple, Dict, Any

from sqlalchemy.orm import Session

from ..models import (
    Policy as PolicySchema,
    PolicyCreate,
    PolicyAction,
    PolicyCondition
)
from ..database import get_db, init_db
from ..database.models import (
    Policy as PolicyModel,
    PolicyAction as DBPolicyAction,
    PolicySource as DBPolicySource
)
from ..database.repositories.policy_repo import PolicyRepository
from .dataplane_service import get_dataplane_service

logger = logging.getLogger(__name__)


class PolicyService:
    """
    Service layer for policy management.

    Uses SQLAlchemy repositories for persistent storage with
    real-time sync to C data plane policy matching engine.
    """

    def __init__(self, db: Optional[Session] = None):
        self._db = db
        self._db_initialized = False

    def _get_db(self) -> Session:
        """Get database session, initializing if needed."""
        if not self._db_initialized:
            try:
                init_db()
                self._db_initialized = True
            except Exception as e:
                logger.warning(f"Database init warning: {e}")
        if self._db:
            return self._db
        return next(get_db())

    def _get_policy_repo(self) -> PolicyRepository:
        """Get policy repository."""
        return PolicyRepository(self._get_db())

    # ==================== Model Conversion ====================

    def _schema_to_db_action(self, action: PolicyAction) -> DBPolicyAction:
        """Convert Pydantic PolicyAction to SQLAlchemy enum."""
        return DBPolicyAction(action.value)

    def _db_to_schema_action(self, action: DBPolicyAction) -> PolicyAction:
        """Convert SQLAlchemy PolicyAction to Pydantic enum."""
        return PolicyAction(action.value)

    def _conditions_to_dict(self, conditions: List[PolicyCondition]) -> dict:
        """Convert list of PolicyCondition to dict for DB storage."""
        return {
            "conditions": [
                {
                    "field": c.field,
                    "operator": c.operator,
                    "value": c.value
                }
                for c in conditions
            ]
        }

    def _dict_to_conditions(self, conditions_dict: Optional[dict]) -> List[PolicyCondition]:
        """Convert dict from DB to list of PolicyCondition."""
        if not conditions_dict or "conditions" not in conditions_dict:
            return []
        return [
            PolicyCondition(
                field=c.get("field", ""),
                operator=c.get("operator", "eq"),
                value=c.get("value")
            )
            for c in conditions_dict.get("conditions", [])
        ]

    def _source_to_string(self, source: Optional[DBPolicySource]) -> str:
        """Convert SQLAlchemy PolicySource to string."""
        if source:
            return source.value
        return "manual"

    def _db_policy_to_schema(self, db_policy: PolicyModel) -> PolicySchema:
        """Convert SQLAlchemy Policy to Pydantic schema."""
        now = datetime.utcnow()
        is_expired = db_policy.expires_at is not None and db_policy.expires_at <= now

        return PolicySchema(
            id=db_policy.id,
            name=db_policy.name,
            description=db_policy.description,
            priority=db_policy.priority,
            action=self._db_to_schema_action(db_policy.action),
            conditions=self._dict_to_conditions(db_policy.conditions),
            enabled=db_policy.enabled,
            expires_at=db_policy.expires_at,
            created_at=db_policy.created_at,
            updated_at=db_policy.updated_at,
            created_by=db_policy.created_by or "system",
            is_expired=is_expired,
            hit_count=db_policy.hit_count or 0,
            last_hit_at=db_policy.last_hit_at,
            source=self._source_to_string(db_policy.source)
        )

    # ==================== Policy CRUD ====================

    async def list_policies(
        self,
        enabled: Optional[bool] = None,
        action: Optional[PolicyAction] = None,
        source: Optional[str] = None,
        include_expired: bool = False,
        page: int = 1,
        per_page: int = 20
    ) -> Tuple[List[PolicySchema], int]:
        """List policies with filtering and pagination."""
        repo = self._get_policy_repo()

        # Convert action if provided
        db_action = self._schema_to_db_action(action) if action else None

        # Convert source string to enum if provided
        db_source = None
        if source:
            try:
                db_source = DBPolicySource(source)
            except ValueError:
                pass

        # Get total count
        total = repo.count_policies(enabled_only=(enabled is True))

        # Get paginated list
        skip = (page - 1) * per_page
        db_policies = repo.list_policies(
            enabled_only=(enabled is True),
            action=db_action,
            source=db_source,
            skip=skip,
            limit=per_page
        )

        # Convert and filter
        policies = []
        now = datetime.utcnow()
        for db_policy in db_policies:
            # Filter expired if needed
            if not include_expired:
                if db_policy.expires_at is not None and db_policy.expires_at <= now:
                    continue

            # Filter by enabled if False specifically requested
            if enabled is False and db_policy.enabled:
                continue

            policies.append(self._db_policy_to_schema(db_policy))

        return policies, total

    async def get_policy(
        self,
        policy_id: int
    ) -> Optional[PolicySchema]:
        """Get a specific policy."""
        repo = self._get_policy_repo()
        db_policy = repo.get(policy_id)

        if db_policy:
            return self._db_policy_to_schema(db_policy)
        return None

    async def create_policy(
        self,
        policy_data: PolicyCreate,
        created_by: str
    ) -> PolicySchema:
        """Create a new policy."""
        repo = self._get_policy_repo()

        # Check for duplicate name
        existing = repo.get_by_name(policy_data.name)
        if existing:
            raise ValueError(f"Policy with name '{policy_data.name}' already exists")

        # Convert conditions to dict
        conditions_dict = self._conditions_to_dict(policy_data.conditions)

        # Create policy
        try:
            db_policy = repo.create_policy(
                name=policy_data.name,
                action=self._schema_to_db_action(policy_data.action),
                conditions=conditions_dict,
                priority=policy_data.priority,
                description=policy_data.description,
                expires_at=policy_data.expires_at,
                source=DBPolicySource.MANUAL,
                created_by=created_by
            )
        except Exception as e:
            if "already exists" in str(e).lower() or "duplicate" in str(e).lower():
                raise ValueError(f"Policy with name '{policy_data.name}' already exists")
            raise

        try:
            dp = get_dataplane_service()
            dp.add_policy(db_policy.id, b"")
        except Exception as e:
            logger.warning(f"Failed to push policy {db_policy.id} to data plane: {e}")

        logger.info(f"Created policy {db_policy.id} by {created_by}")
        return self._db_policy_to_schema(db_policy)

    async def update_policy(
        self,
        policy_id: int,
        policy_data: PolicyCreate,
        updated_by: str
    ) -> PolicySchema:
        """Update an existing policy."""
        repo = self._get_policy_repo()
        db_policy = repo.get(policy_id)

        if not db_policy:
            raise ValueError(f"Policy {policy_id} not found")

        # Check name uniqueness if name changed
        if db_policy.name != policy_data.name:
            existing = repo.get_by_name(policy_data.name)
            if existing:
                raise ValueError(f"Policy with name '{policy_data.name}' already exists")

        # Update fields
        db_policy.name = policy_data.name
        db_policy.description = policy_data.description
        db_policy.priority = policy_data.priority
        db_policy.action = self._schema_to_db_action(policy_data.action)
        db_policy.conditions = self._conditions_to_dict(policy_data.conditions)
        db_policy.enabled = policy_data.enabled
        db_policy.expires_at = policy_data.expires_at
        db_policy.updated_at = datetime.utcnow()

        # Commit changes
        db = self._get_db()
        db.commit()
        db.refresh(db_policy)

        try:
            dp = get_dataplane_service()
            dp.update_policy(policy_id, b"")
        except Exception as e:
            logger.warning(f"Failed to push policy {policy_id} update to data plane: {e}")

        logger.info(f"Updated policy {policy_id} by {updated_by}")
        return self._db_policy_to_schema(db_policy)

    async def delete_policy(
        self,
        policy_id: int,
        deleted_by: str
    ) -> None:
        """Delete a policy."""
        repo = self._get_policy_repo()
        db_policy = repo.get(policy_id)

        if not db_policy:
            raise ValueError(f"Policy {policy_id} not found")

        repo.delete(policy_id)

        try:
            dp = get_dataplane_service()
            dp.delete_policy(policy_id)
        except Exception as e:
            logger.warning(f"Failed to remove policy {policy_id} from data plane: {e}")

        logger.info(f"Deleted policy {policy_id} by {deleted_by}")

    async def set_policy_enabled(
        self,
        policy_id: int,
        enabled: bool,
        updated_by: str
    ) -> None:
        """Enable or disable a policy."""
        repo = self._get_policy_repo()
        db_policy = repo.get(policy_id)

        if not db_policy:
            raise ValueError(f"Policy {policy_id} not found")

        db_policy.enabled = enabled
        db_policy.updated_at = datetime.utcnow()

        db = self._get_db()
        db.commit()

        try:
            dp = get_dataplane_service()
            if enabled:
                dp.enable_policy(policy_id)
            else:
                dp.disable_policy(policy_id)
        except Exception as e:
            logger.warning(f"Failed to sync policy {policy_id} enabled={enabled} to data plane: {e}")

        logger.info(f"Policy {policy_id} {'enabled' if enabled else 'disabled'} by {updated_by}")

    async def check_policy_quota(self) -> bool:
        """Check if there is quota for more policies."""
        repo = self._get_policy_repo()
        count = repo.count_policies()
        return count < 100

    # ==================== Policy Validation ====================

    async def validate_conditions(
        self,
        conditions: List[PolicyCondition]
    ) -> List[str]:
        """Validate policy conditions."""
        errors = []

        valid_fields = [
            "src_ip", "dst_ip", "src_port", "dst_port",
            "protocol", "packet_size", "rate", "country",
            "tcp_flags", "http_method", "http_path", "user_agent"
        ]

        valid_operators = [
            "eq", "ne", "gt", "lt", "ge", "le",
            "in", "not_in", "contains", "matches"
        ]

        for i, cond in enumerate(conditions):
            if cond.field not in valid_fields:
                errors.append(f"Condition {i}: Invalid field '{cond.field}'. Valid: {valid_fields}")

            if cond.operator not in valid_operators:
                errors.append(f"Condition {i}: Invalid operator '{cond.operator}'. Valid: {valid_operators}")

            # Field-specific validation
            if cond.field in ["src_ip", "dst_ip"]:
                if cond.operator in ["eq", "ne"]:
                    # Validate IP format
                    import ipaddress
                    try:
                        if '/' in str(cond.value):
                            ipaddress.ip_network(cond.value, strict=False)
                        else:
                            ipaddress.ip_address(cond.value)
                    except ValueError:
                        errors.append(f"Condition {i}: Invalid IP address/CIDR '{cond.value}'")

            if cond.field in ["src_port", "dst_port"]:
                if cond.operator in ["eq", "ne", "gt", "lt", "ge", "le"]:
                    try:
                        port = int(cond.value)
                        if port < 0 or port > 65535:
                            errors.append(f"Condition {i}: Port must be 0-65535")
                    except (ValueError, TypeError):
                        errors.append(f"Condition {i}: Port must be an integer")

            if cond.field == "protocol":
                valid_protocols = ["tcp", "udp", "icmp", "any"]
                if str(cond.value).lower() not in valid_protocols:
                    errors.append(f"Condition {i}: Invalid protocol. Valid: {valid_protocols}")

            if cond.field == "country":
                if len(str(cond.value)) != 2:
                    errors.append(f"Condition {i}: Country must be 2-letter ISO code")

            if cond.operator == "matches":
                # Validate regex
                try:
                    re.compile(str(cond.value))
                except re.error as e:
                    errors.append(f"Condition {i}: Invalid regex pattern: {e}")

        return errors

    async def test_policy_match(
        self,
        policy: PolicyCreate,
        test_packet: dict
    ) -> Dict[str, Any]:
        """Test if a policy matches a test packet."""
        matches = []
        mismatches = []

        for cond in policy.conditions:
            packet_value = test_packet.get(cond.field)

            if packet_value is None:
                mismatches.append({
                    "field": cond.field,
                    "reason": "Field not in test packet"
                })
                continue

            matched = self._evaluate_condition(cond, packet_value)

            if matched:
                matches.append({
                    "field": cond.field,
                    "operator": cond.operator,
                    "expected": cond.value,
                    "actual": packet_value
                })
            else:
                mismatches.append({
                    "field": cond.field,
                    "operator": cond.operator,
                    "expected": cond.value,
                    "actual": packet_value
                })

        all_matched = len(mismatches) == 0 and len(matches) > 0

        return {
            "matches": all_matched,
            "action": policy.action if all_matched else None,
            "matched_conditions": matches,
            "unmatched_conditions": mismatches,
        }

    def _evaluate_condition(self, cond: PolicyCondition, value: Any) -> bool:
        """Evaluate a single condition."""
        expected = cond.value
        op = cond.operator

        if op == "eq":
            return str(value) == str(expected)
        elif op == "ne":
            return str(value) != str(expected)
        elif op == "gt":
            return float(value) > float(expected)
        elif op == "lt":
            return float(value) < float(expected)
        elif op == "ge":
            return float(value) >= float(expected)
        elif op == "le":
            return float(value) <= float(expected)
        elif op == "in":
            return value in expected
        elif op == "not_in":
            return value not in expected
        elif op == "contains":
            return str(expected) in str(value)
        elif op == "matches":
            return bool(re.match(str(expected), str(value)))

        return False

    # ==================== Policy Stats ====================

    async def get_policy_stats(
        self,
        policy_id: int
    ) -> Dict[str, Any]:
        """Get policy hit statistics."""
        policy = await self.get_policy(policy_id)
        if not policy:
            raise ValueError(f"Policy {policy_id} not found")

        # The persisted counters (hit_count, last_hit_at) are real. The aggregate
        # time-series come from the data plane, which is not wired into this build, so
        # they are reported as unavailable rather than fabricated. `stats_source` lets
        # clients distinguish "no data plane" from a genuine zero.
        return {
            "policy_id": policy_id,
            "hit_count": policy.hit_count,
            "last_hit_at": policy.last_hit_at,
            "hits_24h": None,
            "hits_by_hour": None,
            "unique_ips_matched": None,
            "bytes_affected": None,
            "stats_source": "unavailable",
        }

    async def reject_ml_policy(
        self,
        policy_id: int,
        feedback: str,
        rejected_by: str
    ) -> None:
        """Reject an ML-generated policy with feedback."""
        policy = await self.get_policy(policy_id)

        if not policy:
            raise ValueError(f"Policy {policy_id} not found")

        # Delete the policy
        await self.delete_policy(policy_id, rejected_by)

        try:
            import sys
            from pathlib import Path
            sys.path.insert(0, str(Path(__file__).parent.parent.parent))
            from parsers.layer3 import get_writer as get_layer3_writer
            writer = get_layer3_writer()
            if writer:
                writer.send_policy_feedback(policy_id=policy_id, accepted=False, feedback=feedback)
        except Exception as e:
            logger.warning(f"Failed to send ML feedback for policy {policy_id}: {e}")

        logger.info(
            f"ML policy {policy_id} rejected by {rejected_by}. Feedback: {feedback}"
        )


# Singleton instance
_policy_service = None

def get_policy_service() -> PolicyService:
    """Get or create the policy service singleton."""
    global _policy_service
    if _policy_service is None:
        _policy_service = PolicyService()
    return _policy_service
