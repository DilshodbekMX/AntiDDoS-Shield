"""
Attack lifecycle manager.

Bridges real-time anomaly detection to persistent attack records.
Polls per-IP anomaly state every 5 seconds, detects state transitions
(start/update/end), and persists to database + WebSocket + webhooks.
"""

import logging
from datetime import datetime
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

# In-memory tracking of currently active attacks
# Maps IP string -> { attack_id, started_at, peak_pps, peak_bps, peak_src_ips }
_active_attacks: Dict[str, Dict[str, Any]] = {}
_initialized: bool = False


# C attack_type enum -> DB AttackType enum value mapping
_ATTACK_TYPE_MAP = {
    0: 'unknown',
    1: 'syn_flood',
    2: 'udp_flood',
    3: 'icmp_flood',
    4: 'dns_amplification',
    5: 'ntp_amplification',
    6: 'memcached_amplification',
    7: 'http_flood',
    8: 'slowloris',
    9: 'ack_flood',
    10: 'rst_flood',
    11: 'fragment_flood',
    12: 'volumetric',
}

# C anomaly_protocol -> fallback attack type
_PROTO_ATTACK_FALLBACK = {
    0: 'syn_flood',     # TCP
    1: 'udp_flood',     # UDP
    2: 'icmp_flood',    # ICMP
    3: 'volumetric',    # OTHER
}

# C anomaly level -> DB severity
_SEVERITY_MAP = {
    1: 'low',
    2: 'medium',
    3: 'high',
    4: 'critical',
}


def _map_attack_type(anomaly: dict) -> str:
    """Map C anomaly data to AttackType enum value."""
    c_type = anomaly.get('attack_type', 0)
    if c_type in _ATTACK_TYPE_MAP and c_type != 0:
        return _ATTACK_TYPE_MAP[c_type]

    # Fall back to protocol-based inference
    proto = anomaly.get('anomaly_protocol', 255)
    return _PROTO_ATTACK_FALLBACK.get(proto, 'unknown')


def _map_severity(anomaly: dict) -> str:
    """Map C anomaly level to AttackSeverity enum value."""
    level = anomaly.get('level', 0)
    return _SEVERITY_MAP.get(level, 'medium')


async def _reconcile_on_startup():
    """Load active attacks from DB into _active_attacks on startup.

    Handles crash recovery:
    - Active attacks still under anomaly -> resume tracking
    - Active attacks with no anomaly -> end cleanly (no orphans)
    """
    try:
        from ...services.dpdk_service import get_dpdk_service
        from ...database.connection import get_db
        from ...database.repositories.attack_repo import AttackRepository

        db = next(get_db())
        try:
            repo = AttackRepository(db)
            active = repo.get_active_attacks()
            if not active:
                return

            dpdk = get_dpdk_service()
            anomaly_data = dpdk.get_per_ip_anomaly() or {}

            resumed = 0
            ended = 0
            for attack in active:
                ip = attack.target_ip
                if ip in anomaly_data and anomaly_data[ip].get('anomaly_active', False):
                    # Attack still ongoing -- resume tracking
                    _active_attacks[ip] = {
                        'attack_id': attack.id,
                        'started_at': attack.started_at,
                        'peak_pps': attack.peak_pps or 0,
                        'peak_bps': attack.peak_bps or 0,
                        'peak_src_ips': attack.source_ips_count or 0,
                        'attack_type': attack.attack_type.value,
                        'severity': attack.severity.value,
                    }
                    resumed += 1
                else:
                    # Attack no longer active -- end it cleanly
                    repo.end_attack(
                        attack.id,
                        peak_pps=attack.peak_pps or 0,
                        peak_bps=attack.peak_bps or 0,
                        packets_dropped=attack.packets_dropped or 0,
                        source_ips_count=attack.source_ips_count or 0,
                    )
                    ended += 1

            if resumed or ended:
                logger.info(
                    f"Startup reconciliation: resumed={resumed} ended={ended} orphaned attacks"
                )
        finally:
            db.close()
    except Exception as e:
        logger.error(f"Startup reconciliation failed: {e}")


async def monitor_attack_lifecycle():
    """
    Monitor per-IP anomaly state and manage attack lifecycle.

    Runs every 5 seconds via scheduler. Detects:
    - NEW attacks (anomaly_active transitions to True)
    - ONGOING attacks (update peak metrics)
    - ENDED attacks (anomaly_active transitions to False)
    """
    global _initialized
    try:
        from ...services.dpdk_service import get_dpdk_service
        from ...database.connection import get_db
        from ...database.repositories.attack_repo import AttackRepository
        from ...database.models import AttackType, AttackSeverity

        # On first run, reconcile DB state with in-memory tracking
        if not _initialized:
            await _reconcile_on_startup()
            _initialized = True

        dpdk = get_dpdk_service()
        anomaly_data = dpdk.get_per_ip_anomaly()
        features_data = dpdk.get_per_ip_features()

        if not anomaly_data:
            # If no data, check for stale attacks to end
            _check_stale_attacks()
            return

        now_active_ips = set()

        for ip_str, anomaly in anomaly_data.items():
            if not anomaly.get('anomaly_active', False):
                continue
            if anomaly.get('level', 0) < 1:
                continue

            now_active_ips.add(ip_str)
            features = features_data.get(ip_str, {}) if features_data else {}

            if ip_str not in _active_attacks:
                # NEW ATTACK
                await _start_attack(ip_str, anomaly, features)
            else:
                # ONGOING ATTACK -- update peaks
                _update_attack_peaks(ip_str, anomaly, features)

        # Check for ended attacks
        for ip_str in list(_active_attacks.keys()):
            if ip_str not in now_active_ips:
                await _end_attack(ip_str)

    except Exception as e:
        logger.error(f"Attack lifecycle monitor error: {e}")


async def _start_attack(ip_str: str, anomaly: dict, features: dict):
    """Record start of a new attack."""
    try:
        from ...database.connection import get_db
        from ...database.repositories.attack_repo import AttackRepository
        from ...database.models import AttackType, AttackSeverity

        attack_type_str = _map_attack_type(anomaly)
        severity_str = _map_severity(anomaly)

        try:
            attack_type = AttackType(attack_type_str)
        except ValueError:
            attack_type = AttackType.UNKNOWN

        try:
            severity = AttackSeverity(severity_str)
        except ValueError:
            severity = AttackSeverity.MEDIUM

        target_port = anomaly.get('anomaly_dst_port')
        if target_port == 0:
            target_port = None

        pps = features.get('packets_per_sec', 0)
        bps = features.get('bytes_per_sec', 0)
        src_ips = features.get('unique_src_ips', 0)

        db = next(get_db())
        try:
            repo = AttackRepository(db)
            attack = repo.start_attack(
                attack_type=attack_type,
                severity=severity,
                target_ip=ip_str,
                target_port=target_port,
            )

            # Update initial metrics
            if pps or bps or src_ips:
                repo.update_metrics(
                    attack.id,
                    peak_pps=pps,
                    peak_bps=bps,
                    source_ips_count=src_ips,
                )

            _active_attacks[ip_str] = {
                'attack_id': attack.id,
                'started_at': datetime.utcnow(),
                'peak_pps': pps,
                'peak_bps': bps,
                'peak_src_ips': src_ips,
                'attack_type': attack_type_str,
                'severity': severity_str,
            }

            logger.warning(
                f"Attack STARTED: {ip_str} type={attack_type_str} "
                f"severity={severity_str} id={attack.id}"
            )

        finally:
            db.close()

        # Broadcast via WebSocket (fire-and-forget)
        try:
            from ...websocket.handlers import broadcast_attack_started
            await broadcast_attack_started(
                attack_id=attack.id,
                attack_type=attack_type_str,
                severity=severity_str,
                target_ip=ip_str,
                peak_pps=pps,
                peak_bps=bps,
                source_ips_count=src_ips,
            )
        except Exception as e:
            logger.debug(f"WebSocket broadcast failed: {e}")

        # Dispatch webhooks
        try:
            from .webhook_dispatcher import dispatch_event
            await dispatch_event('attack_started', {
                'attack_id': attack.id,
                'attack_type': attack_type_str,
                'severity': severity_str,
                'target_ip': ip_str,
                'target_port': target_port,
                'peak_pps': pps,
                'peak_bps': bps,
                'source_ips_count': src_ips,
                'timestamp': datetime.utcnow().isoformat(),
            })
        except Exception as e:
            logger.debug(f"Webhook dispatch failed: {e}")

    except Exception as e:
        logger.error(f"Failed to start attack record for {ip_str}: {e}")


def _update_attack_peaks(ip_str: str, anomaly: dict, features: dict):
    """Update peak metrics for an ongoing attack."""
    try:
        tracked = _active_attacks[ip_str]
        pps = features.get('packets_per_sec', 0)
        bps = features.get('bytes_per_sec', 0)
        src_ips = features.get('unique_src_ips', 0)

        new_peak = False
        if pps > tracked['peak_pps']:
            tracked['peak_pps'] = pps
            new_peak = True
        if bps > tracked['peak_bps']:
            tracked['peak_bps'] = bps
            new_peak = True
        if src_ips > tracked['peak_src_ips']:
            tracked['peak_src_ips'] = src_ips
            new_peak = True

        # Update severity if it escalated
        new_severity = _map_severity(anomaly)
        severity_order = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        if severity_order.get(new_severity, 0) > severity_order.get(tracked['severity'], 0):
            tracked['severity'] = new_severity

        # Persist to DB periodically (only when peaks change)
        if new_peak:
            from ...database.connection import get_db
            from ...database.repositories.attack_repo import AttackRepository

            db = next(get_db())
            try:
                repo = AttackRepository(db)
                repo.update_metrics(
                    tracked['attack_id'],
                    peak_pps=tracked['peak_pps'],
                    peak_bps=tracked['peak_bps'],
                    source_ips_count=tracked['peak_src_ips'],
                )
            finally:
                db.close()

    except Exception as e:
        logger.debug(f"Failed to update attack peaks for {ip_str}: {e}")


async def _end_attack(ip_str: str):
    """Record end of an attack."""
    try:
        tracked = _active_attacks.pop(ip_str, None)
        if not tracked:
            return

        from ...database.connection import get_db
        from ...database.repositories.attack_repo import AttackRepository

        attack_id = tracked['attack_id']
        duration = (datetime.utcnow() - tracked['started_at']).total_seconds()
        # Mitigation time = time from detection to when attack stopped
        mitigation_time_ms = duration * 1000

        db = next(get_db())
        try:
            repo = AttackRepository(db)
            repo.end_attack(
                attack_id,
                peak_pps=tracked['peak_pps'],
                peak_bps=tracked['peak_bps'],
                source_ips_count=tracked['peak_src_ips'],
            )
            repo.mark_mitigated(attack_id, mitigation_time_ms=mitigation_time_ms)
        finally:
            db.close()

        logger.warning(
            f"Attack ENDED: {ip_str} id={attack_id} "
            f"duration={duration:.0f}s peak_pps={tracked['peak_pps']}"
        )

        # Broadcast via WebSocket
        try:
            from ...websocket.handlers import broadcast_attack_ended
            await broadcast_attack_ended(
                attack_id=attack_id,
                duration_seconds=duration,
                packets_dropped=0,  # Not tracked per-attack yet
            )
        except Exception as e:
            logger.debug(f"WebSocket broadcast failed: {e}")

        # Dispatch webhooks
        try:
            from .webhook_dispatcher import dispatch_event
            await dispatch_event('attack_ended', {
                'attack_id': attack_id,
                'target_ip': ip_str,
                'attack_type': tracked['attack_type'],
                'severity': tracked['severity'],
                'duration_seconds': duration,
                'peak_pps': tracked['peak_pps'],
                'peak_bps': tracked['peak_bps'],
                'source_ips_count': tracked['peak_src_ips'],
                'timestamp': datetime.utcnow().isoformat(),
            })
        except Exception as e:
            logger.debug(f"Webhook dispatch failed: {e}")

    except Exception as e:
        logger.error(f"Failed to end attack for {ip_str}: {e}")


def _check_stale_attacks():
    """End attacks that have been tracked >10 minutes with no anomaly data."""
    now = datetime.utcnow()
    stale_threshold = 600  # 10 minutes

    for ip_str in list(_active_attacks.keys()):
        tracked = _active_attacks[ip_str]
        age = (now - tracked['started_at']).total_seconds()
        if age > stale_threshold:
            logger.warning(f"Ending stale attack for {ip_str} (no anomaly data)")
            # Can't await in sync context, just clean up DB directly
            try:
                from ...database.connection import get_db
                from ...database.repositories.attack_repo import AttackRepository

                db = next(get_db())
                try:
                    repo = AttackRepository(db)
                    repo.end_attack(
                        tracked['attack_id'],
                        peak_pps=tracked['peak_pps'],
                        peak_bps=tracked['peak_bps'],
                        source_ips_count=tracked['peak_src_ips'],
                    )
                finally:
                    db.close()
            except Exception as e:
                logger.error(f"Failed to end stale attack: {e}")

            del _active_attacks[ip_str]
