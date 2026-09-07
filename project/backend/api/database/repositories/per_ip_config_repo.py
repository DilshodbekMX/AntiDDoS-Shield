"""
Per-IP Layer 2 Configuration Repository.

Manages per-IP detection config overrides stored in the database.
NULL fields inherit from global config.
"""

import json
from typing import Optional, List, Dict, Any
from datetime import datetime

from sqlalchemy.orm import Session

from ..models import PerIPL2Config
from .base import BaseRepository


# Fields that can be overridden per-IP
OVERRIDE_FIELDS = [
    'z_score_threshold', 'min_tier_agreement', 'min_features_per_tier',
    'cool_down_seconds', 'baseline_freeze_enabled',
    'alpha_immediate_1s', 'alpha_immediate_10s', 'alpha_immediate_60s',
    'min_samples_immediate_1s', 'min_samples_immediate_10s', 'min_samples_immediate_60s',
    'warmup_pps_threshold', 'warmup_syn_threshold',
]


class PerIPL2ConfigRepository(BaseRepository[PerIPL2Config]):
    """Repository for per-IP Layer 2 configuration overrides."""

    def __init__(self, db: Session):
        super().__init__(PerIPL2Config, db)

    def get_by_ip(self, ip_address: str) -> Optional[PerIPL2Config]:
        """Get config override for a specific IP."""
        return (
            self.db.query(PerIPL2Config)
            .filter(PerIPL2Config.ip_address == ip_address)
            .first()
        )

    def get_all_active(self) -> List[PerIPL2Config]:
        """Get all active per-IP config overrides."""
        return (
            self.db.query(PerIPL2Config)
            .filter(PerIPL2Config.is_active == True)
            .all()
        )

    def upsert(
        self,
        ip_address: str,
        data: Dict[str, Any],
        updated_by: Optional[str] = None,
    ) -> PerIPL2Config:
        """Create or update per-IP config override.

        Only OVERRIDE_FIELDS are accepted. Other keys are ignored.
        Setting a field to None reverts it to global default.
        """
        existing = self.get_by_ip(ip_address)

        if existing:
            # Update existing
            for field in OVERRIDE_FIELDS:
                if field in data:
                    setattr(existing, field, data[field])

            existing.version += 1
            existing.updated_at = datetime.utcnow()
            existing.updated_by = updated_by
            existing.is_active = True

            self.db.commit()
            self.db.refresh(existing)
            return existing
        else:
            # Create new
            config = PerIPL2Config(ip_address=ip_address, updated_by=updated_by)
            for field in OVERRIDE_FIELDS:
                if field in data:
                    setattr(config, field, data[field])

            self.db.add(config)
            self.db.commit()
            self.db.refresh(config)
            return config

    def delete_by_ip(self, ip_address: str) -> bool:
        """Delete per-IP config override (revert to global)."""
        config = self.get_by_ip(ip_address)
        if config:
            self.db.delete(config)
            self.db.commit()
            return True
        return False

    def get_overrides_dict(self, config: PerIPL2Config) -> Dict[str, Any]:
        """Get non-null override fields as a dict."""
        overrides = {}
        for field in OVERRIDE_FIELDS:
            value = getattr(config, field, None)
            if value is not None:
                overrides[field] = value
        # feature_weights is stored as JSON text -- decode for callers
        if config.feature_weights is not None:
            try:
                overrides['feature_weights'] = json.loads(config.feature_weights)
            except (ValueError, TypeError):
                pass
        return overrides

    def set_feature_weights(self, ip_address: str, weights: List[float],
                            updated_by: Optional[str] = None) -> 'PerIPL2Config':
        """Persist per-IP feature weights (JSON-encoded in TEXT column).

        Creates the row if it doesn't exist yet.
        """
        existing = self.get_by_ip(ip_address)
        if existing:
            existing.feature_weights = json.dumps(weights)
            existing.version += 1
            existing.updated_at = datetime.utcnow()
            existing.updated_by = updated_by
            existing.is_active = True
            self.db.commit()
            self.db.refresh(existing)
            return existing
        else:
            cfg = PerIPL2Config(
                ip_address=ip_address,
                feature_weights=json.dumps(weights),
                updated_by=updated_by,
            )
            self.db.add(cfg)
            self.db.commit()
            self.db.refresh(cfg)
            return cfg

    def get_feature_weights(self, ip_address: str) -> Optional[List[float]]:
        """Return per-IP feature weights list, or None if not set."""
        cfg = self.get_by_ip(ip_address)
        if cfg and cfg.feature_weights is not None:
            try:
                return json.loads(cfg.feature_weights)
            except (ValueError, TypeError):
                return None
        return None

    def clear_feature_weights(self, ip_address: str,
                              updated_by: Optional[str] = None) -> bool:
        """Clear per-IP feature weights (revert to global). Returns False if not found."""
        cfg = self.get_by_ip(ip_address)
        if cfg is None or cfg.feature_weights is None:
            return False
        cfg.feature_weights = None
        cfg.version += 1
        cfg.updated_at = datetime.utcnow()
        cfg.updated_by = updated_by
        self.db.commit()
        return True

    def get_merged(
        self,
        ip_address: str,
        global_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Get effective config for an IP (per-IP overrides on top of global).

        Returns a copy of global_config with per-IP overrides applied.
        """
        effective = dict(global_config)
        config = self.get_by_ip(ip_address)
        if config and config.is_active:
            for field in OVERRIDE_FIELDS:
                value = getattr(config, field, None)
                if value is not None:
                    effective[field] = value
        return effective
