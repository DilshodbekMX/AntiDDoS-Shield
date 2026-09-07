"""
Configuration Service (Database Persistence)

Business logic for configuration management.
Uses SQLAlchemy repository for persistent storage.
"""

import logging
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

from sqlalchemy.orm import Session

from ..models import (
    SystemConfig, ConfigUpdate,
    Layer1Config, Layer2Config,
)
from ..database import get_db, init_db
from ..database.models import SystemConfigDB
from ..database.repositories.config_repo import ConfigRepository
from .dataplane_service import get_dataplane_service

logger = logging.getLogger(__name__)


class ConfigHistoryEntry(BaseModel):
    """Configuration change history entry."""
    timestamp: datetime
    user: str
    section: str
    changes: Dict[str, Any]


class ConfigService:
    """
    Service layer for configuration management.

    Uses SQLAlchemy repository for persistent storage with
    real-time sync to C data plane.
    """

    def __init__(self, db: Optional[Session] = None):
        self._db = db
        self._db_initialized = False
        # In-memory history cache (persisted history would need separate table)
        self._history: List[ConfigHistoryEntry] = []

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

    def _get_repo(self) -> ConfigRepository:
        """Get config repository."""
        return ConfigRepository(self._get_db())

    # ==================== Model Conversion ====================

    def _db_to_schema(self, db_config: SystemConfigDB) -> SystemConfig:
        """Convert database model to Pydantic schema."""
        return SystemConfig(
            layer1=Layer1Config(**(db_config.layer1 or {})),
            layer2=Layer2Config(**(db_config.layer2 or {})),
            updated_at=db_config.updated_at,
        )

    def _layer_schema_to_dict(self, layer: BaseModel) -> dict:
        """Convert layer schema to dict for DB storage."""
        return layer.dict()

    # ==================== Public API ====================

    async def get_config(self) -> Optional[SystemConfig]:
        """Get complete configuration."""
        repo = self._get_repo()
        db_config = repo.get_or_create()
        return self._db_to_schema(db_config)

    async def get_layer_config(self, layer: int) -> Optional[BaseModel]:
        """Get configuration for a specific layer."""
        config = await self.get_config()
        if config is None:
            return None

        layer_map = {
            1: config.layer1,
            2: config.layer2,
        }
        return layer_map.get(layer)

    async def update_config(
        self,
        update: ConfigUpdate,
        updated_by: str
    ) -> SystemConfig:
        """Update configuration."""
        repo = self._get_repo()

        # Build update kwargs
        kwargs: Dict[str, Any] = {"updated_by": updated_by}
        changes = {}

        if update.layer1:
            kwargs["layer1"] = self._layer_schema_to_dict(update.layer1)
            changes["layer1"] = kwargs["layer1"]
        if update.layer2:
            kwargs["layer2"] = self._layer_schema_to_dict(update.layer2)
            changes["layer2"] = kwargs["layer2"]

        db_config = repo.update_config(**kwargs)

        # Record history
        await self._record_history(updated_by, "full_config", changes)

        # Push to data plane
        await self._push_config_to_dataplane(db_config)

        logger.info(f"Updated config by {updated_by}")
        return self._db_to_schema(db_config)

    async def update_layer_config(
        self,
        layer: int,
        layer_config: BaseModel,
        updated_by: str
    ) -> BaseModel:
        """Update configuration for a specific layer."""
        repo = self._get_repo()

        # Get old config for history
        old_db_config = repo.get_or_create()
        old_layer_dict = getattr(old_db_config, f"layer{layer}", {}) or {}

        layer_dict = self._layer_schema_to_dict(layer_config)
        db_config = repo.update_layer(layer, layer_dict, updated_by)

        # Record history
        await self._record_history(
            updated_by,
            f"layer{layer}",
            {"old": old_layer_dict, "new": layer_dict}
        )

        # Push to data plane
        await self._push_layer_to_dataplane(layer, layer_dict)

        logger.info(f"Updated layer{layer} config by {updated_by}")
        return layer_config

    async def validate_config(
        self,
        update: ConfigUpdate
    ) -> List[str]:
        """Validate configuration before applying."""
        errors = []

        if update.layer1:
            errors.extend(await self._validate_layer1(update.layer1))
        if update.layer2:
            errors.extend(await self._validate_layer2(update.layer2))

        return errors

    async def validate_layer_config(
        self,
        layer: int,
        config: BaseModel
    ) -> List[str]:
        """Validate layer-specific configuration."""
        validators = {
            1: self._validate_layer1,
            2: self._validate_layer2,
        }
        validator = validators.get(layer)
        if validator:
            return await validator(config)
        return []

    async def _validate_layer1(self, config: Layer1Config) -> List[str]:
        """Validate Layer 1 configuration."""
        errors = []

        if config.rate_limit_pps > 10_000_000:
            errors.append("rate_limit_pps exceeds maximum (10M)")
        if config.rate_limit_bps > 100_000_000_000:
            errors.append("rate_limit_bps exceeds maximum (100G)")
        if config.syn_rate_limit > config.rate_limit_pps:
            errors.append("syn_rate_limit cannot exceed rate_limit_pps")

        # Validate country codes
        for cc in config.blocked_countries:
            if len(cc) != 2 or not cc.isalpha():
                errors.append(f"Invalid country code: {cc}")

        return errors

    async def _validate_layer2(self, config: Layer2Config) -> List[str]:
        """Validate Layer 2 configuration."""
        errors = []

        if config.baseline_learning_hours < 1:
            errors.append("baseline_learning_hours must be at least 1")
        if config.anomaly_cooldown_seconds < 60:
            errors.append("anomaly_cooldown_seconds must be at least 60")

        return errors

    async def reload_config(self) -> bool:
        """Force reload configuration in data plane."""
        repo = self._get_repo()
        db_config = repo.get_config()

        if db_config is None:
            return False

        try:
            await self._push_config_to_dataplane(db_config)
            logger.info(f"Config reload completed")
            return True
        except Exception as e:
            logger.error(f"Failed to reload config: {e}")
            return False

    async def reset_config(self, reset_by: str) -> SystemConfig:
        """Reset configuration to defaults."""
        repo = self._get_repo()

        # Get old config for history
        old_config = repo.get_config()
        if old_config:
            await self._record_history(
                reset_by,
                "reset",
                {"previous": {
                    "layer1": old_config.layer1,
                    "layer2": old_config.layer2,
                }}
            )

        # Reset to defaults
        db_config = repo.reset_config(reset_by)

        # Push to data plane
        await self._push_config_to_dataplane(db_config)

        logger.info(f"Reset config by {reset_by}")
        return self._db_to_schema(db_config)

    async def get_config_history(
        self,
        limit: int = 20
    ) -> List[ConfigHistoryEntry]:
        """Get configuration change history."""
        return self._history[-limit:]

    async def get_config_version(self) -> int:
        """Get current config version for cache invalidation."""
        repo = self._get_repo()
        return repo.get_version()

    # ==================== Data Plane Integration ====================

    async def _push_config_to_dataplane(
        self,
        db_config: SystemConfigDB
    ) -> None:
        """Push full configuration to data plane."""
        try:
            dataplane = get_dataplane_service()
            dataplane.push_full_config(
                1,
                layer1=db_config.layer1,
                layer2=db_config.layer2,
            )
            logger.debug(f"Pushed full config to dataplane")
        except Exception as e:
            logger.warning(f"Failed to push config to dataplane: {e}")
            # Don't raise - DB update succeeded

    async def _push_layer_to_dataplane(
        self,
        layer: int,
        config: dict
    ) -> None:
        """Push layer-specific configuration to data plane."""
        try:
            dataplane = get_dataplane_service()
            if layer == 1:
                dataplane.push_layer1_config(1, config)
            elif layer == 2:
                dataplane.push_layer2_config(1, config)
            logger.debug(f"Pushed layer{layer} config to dataplane")
        except Exception as e:
            logger.warning(f"Failed to push layer{layer} config to dataplane: {e}")
            # Don't raise - DB update succeeded

    # ==================== History ====================

    async def _record_history(
        self,
        user: str,
        section: str,
        changes: Dict[str, Any]
    ) -> None:
        """Record configuration change in history."""
        entry = ConfigHistoryEntry(
            timestamp=datetime.utcnow(),
            user=user,
            section=section,
            changes=changes
        )

        self._history.append(entry)

        # Keep last 100 entries
        if len(self._history) > 100:
            self._history = self._history[-100:]


# Singleton instance
_config_service = None

def get_config_service() -> ConfigService:
    """Get or create the config service singleton."""
    global _config_service
    if _config_service is None:
        _config_service = ConfigService()
    return _config_service
