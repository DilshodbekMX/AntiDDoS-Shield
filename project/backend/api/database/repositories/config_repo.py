"""
Configuration repository for system configuration management.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from sqlalchemy.orm import Session

from ..models import SystemConfigDB
from .base import BaseRepository


class ConfigRepository(BaseRepository[SystemConfigDB]):
    """Repository for system configuration management."""

    def __init__(self, db: Session):
        super().__init__(SystemConfigDB, db)

    def get_config(self) -> Optional[SystemConfigDB]:
        """Get configuration."""
        return (
            self.db.query(SystemConfigDB)
            .filter(SystemConfigDB.id == 1)
            .first()
        )

    def get_or_create(self) -> SystemConfigDB:
        """Get or create default configuration."""
        config = self.get_config()
        if config is None:
            config = SystemConfigDB(
                id=1,
                layer1=self._default_layer1(),
                layer2=self._default_layer2(),
                version=1,
            )
            self.db.add(config)
            self.db.commit()
            self.db.refresh(config)
        return config

    def update_config(
        self,
        layer1: Optional[dict] = None,
        layer2: Optional[dict] = None,
        updated_by: Optional[str] = None,
    ) -> SystemConfigDB:
        """Update configuration."""
        config = self.get_or_create()

        if layer1 is not None:
            config.layer1 = layer1
        if layer2 is not None:
            config.layer2 = layer2

        config.version += 1
        config.updated_at = datetime.utcnow()
        config.updated_by = updated_by

        self.db.commit()
        self.db.refresh(config)
        return config

    def update_layer(
        self,
        layer: int,
        layer_config: dict,
        updated_by: Optional[str] = None,
    ) -> SystemConfigDB:
        """Update a specific layer configuration."""
        config = self.get_or_create()

        layer_attr = f"layer{layer}"
        if hasattr(config, layer_attr):
            setattr(config, layer_attr, layer_config)
            config.version += 1
            config.updated_at = datetime.utcnow()
            config.updated_by = updated_by

            self.db.commit()
            self.db.refresh(config)

        return config

    def reset_config(
        self,
        updated_by: Optional[str] = None,
    ) -> SystemConfigDB:
        """Reset configuration to defaults."""
        config = self.get_or_create()

        config.layer1 = self._default_layer1()
        config.layer2 = self._default_layer2()
        config.version += 1
        config.updated_at = datetime.utcnow()
        config.updated_by = updated_by

        self.db.commit()
        self.db.refresh(config)
        return config

    def delete_config(self) -> bool:
        """Delete configuration."""
        config = self.get_config()
        if config:
            self.db.delete(config)
            self.db.commit()
            return True
        return False

    def get_version(self) -> int:
        """Get current config version for cache invalidation."""
        config = self.get_config()
        return config.version if config else 0

    @staticmethod
    def _default_layer1() -> dict:
        """Default Layer 1 configuration."""
        return {
            "enabled": True,
            "rate_limit_pps": 1000000,
            "rate_limit_bps": 10000000000,
            "syn_rate_limit": 100000,
            "syn_proxy_enabled": True,
            "syn_proxy_threshold": 50000,
            "blocked_countries": [],
            "geo_blocking_enabled": False,
            "tcp_fingerprint_enabled": True,
            "signature_matching_enabled": True,
            "monitor_only": False,
            "tap_mode": False,
        }

    @staticmethod
    def _default_layer2() -> dict:
        """Default Layer 2 configuration."""
        return {
            "enabled": True,
            "baseline_learning_hours": 24,
            "anomaly_detection_enabled": True,
            "anomaly_sensitivity": 0.7,
            "anomaly_cooldown_seconds": 300,
            "pps_threshold_multiplier": 3.0,
            "bps_threshold_multiplier": 3.0,
            "entropy_threshold": 0.3,
            "adaptive_thresholds_enabled": True,
        }

