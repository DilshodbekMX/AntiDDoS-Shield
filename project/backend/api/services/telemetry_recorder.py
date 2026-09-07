"""
Telemetry Recorder Service

Persists per-IP feature vectors and attack events to SQLite for:
1. ML training datasets (labeled normal/attack samples)
2. Attack forensics (feature timeline reconstruction)
3. FP/TP review (operator can correct adaptive threshold labels)
4. Baseline validation (compare historical vs current baselines)

Sampling strategy:
- Normal traffic:  1 sample per IP per 60 seconds
- Anomaly active:  1 sample per IP per second (full rate)
- Post-attack:     full rate continues for 60s after anomaly clears

Storage: ~250 MB/day typical (64 IPs, hybrid sampling, 5 baseline tiers)
"""

import logging
import sqlite3
import time
import threading
from pathlib import Path
from typing import Dict, Any, Optional, List

logger = logging.getLogger(__name__)

# Database path
DB_PATH = Path(__file__).resolve().parents[3] / "data" / "antiddos.db"

# Sampling intervals (seconds)
NORMAL_SAMPLE_INTERVAL = 60      # 1 sample/min during normal
ATTACK_SAMPLE_INTERVAL = 1       # 1 sample/s during attack
POST_ATTACK_TAIL_SEC = 60        # Continue full rate for 60s after attack clears
FLUSH_INTERVAL = 10              # Batch flush every 10s

# Retention
MAX_FEATURE_ROWS = 5_000_000     # ~1 GB at ~200 bytes/row
PRUNE_INTERVAL = 3600            # Check retention every hour
PRUNE_BATCH = 100_000            # Delete in batches to avoid long locks

# All 39 L2 feature names matching baselines.h enum order
L2_FEATURE_NAMES = [
    'packets_per_sec', 'bytes_per_sec', 'flows_per_sec',
    'syn_per_sec', 'syn_ack_per_sec', 'ack_per_sec', 'rst_per_sec', 'fin_per_sec',
    'tcp_ratio', 'udp_ratio', 'icmp_ratio', 'other_ratio',
    'syn_ack_ratio', 'rst_syn_ratio', 'bytes_per_packet',
    'unique_src_ips', 'unique_dst_ports', 'unique_flows',
    'new_srcip_rate',
    'max_flow_fraction', 'topk_flow_share', 'heavy_hitter_count',
    'avg_packets_per_flow', 'flow_duration_avg',
    'syn_tcp_ratio', 'synack_tcp_ratio', 'ack_tcp_ratio', 'rst_tcp_ratio', 'fin_tcp_ratio',
    'burst_factor',
    'udp_flow_ratio',
    'icmp_echo_ratio',
    'dst_port_density',
    'src_ip_entropy',
    'small_pkt_ratio', 'fragment_ratio', 'ttl_mean',
    'tcp_completion_rate',
    'src_port_entropy',
]

# Map from per_ip_features_data dict keys -> L2 feature index
# Features available from the per-IP features packet (Layer 1 export)
_FEAT_FROM_IP_FEATURES = {
    'packets_per_sec': 0, 'bytes_per_sec': 1, 'flows_per_sec': 2,
    'syn_per_sec': 3, 'syn_ack_per_sec': 4, 'ack_per_sec': 5,
    'rst_per_sec': 6, 'fin_per_sec': 7,
    'tcp_ratio': 8, 'udp_ratio': 9, 'icmp_ratio': 10, 'other_ratio': 11,
    'rst_syn_ratio': 13,
    'unique_src_ips': 15, 'unique_dst_ports': 16, 'unique_flows': 17,
    'new_srcip_rate': 18,
    'max_flow_fraction': 19, 'topk_flow_share': 20, 'heavy_hitter_count': 21,
    'avg_packets_per_flow': 22, 'flow_duration_avg_ms': 23,
    'src_ip_entropy': 33,
}

# Baseline tier names (matches BASELINE_TIER_NAMES in dpdk_service.py)
BASELINE_TIER_NAMES = ['1s', '10s', '60s', 'hourly', 'weekly']

# C-exported baseline features (18 of 25 -- indices that BASELINE_FEATURE_KEYS maps)
# These are the features that C Layer 2 exports baselines for
BASELINE_FEATURE_INDICES = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 17, 19, 20, 21, 22, 23]


SCHEMA_SQL = """
-- Per-IP feature snapshots (ML training dataset)
CREATE TABLE IF NOT EXISTS ip_feature_samples (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       REAL    NOT NULL,
    dst_ip          TEXT    NOT NULL,

    -- Raw feature values (39 features matching L2 baselines.h enum)
    feat_values     TEXT    NOT NULL,       -- JSON array of 39 doubles

    -- Baseline means for computing z-scores offline (tier1_10s, legacy)
    baseline_means  TEXT,                   -- JSON array of 39 doubles (NULL if no baseline)
    baseline_stds   TEXT,                   -- JSON array of 39 doubles

    -- All 5 EWMA tiers: {"1s":{"means":[...],"stds":[...]},"10s":{...},...}
    baselines_all   TEXT,                   -- JSON object, all tiers × 39 features

    -- Detection state (from per_ip_anomaly_entry)
    anomaly_active      INTEGER NOT NULL DEFAULT 0,
    anomaly_level       INTEGER NOT NULL DEFAULT 0,
    max_z_score         REAL    NOT NULL DEFAULT 0,
    attack_type         INTEGER NOT NULL DEFAULT 0,
    confidence          INTEGER NOT NULL DEFAULT 0,
    detection_method    INTEGER NOT NULL DEFAULT 0,
    rate_limit_pct      INTEGER NOT NULL DEFAULT 100,

    -- Label (from adaptive threshold TP/FP classification)
    label               TEXT    NOT NULL DEFAULT 'normal'
);

CREATE INDEX IF NOT EXISTS idx_samples_ts ON ip_feature_samples(timestamp);
CREATE INDEX IF NOT EXISTS idx_samples_ip ON ip_feature_samples(dst_ip, timestamp);
CREATE INDEX IF NOT EXISTS idx_samples_label ON ip_feature_samples(label);
CREATE INDEX IF NOT EXISTS idx_samples_anomaly ON ip_feature_samples(anomaly_active, timestamp);

-- Attack events (one row per detection lifecycle)
CREATE TABLE IF NOT EXISTS attack_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    dst_ip              TEXT    NOT NULL,
    started_at          REAL    NOT NULL,
    ended_at            REAL,
    duration_sec        REAL,
    peak_z_score        REAL,
    attack_type         INTEGER,
    attack_type_name    TEXT,
    severity            INTEGER,
    detection_method    INTEGER,
    label               TEXT    DEFAULT 'unknown',
    operator_feedback   TEXT,
    threshold_at_start  REAL,
    rate_limit_pct      INTEGER,
    peak_pps            INTEGER,
    peak_bps            INTEGER,
    unique_src_ips      INTEGER,
    confidence          INTEGER,
    protocol_name       TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON attack_events(started_at);
CREATE INDEX IF NOT EXISTS idx_events_ip ON attack_events(dst_ip, started_at);
CREATE INDEX IF NOT EXISTS idx_events_label ON attack_events(label);
"""


class TelemetryRecorder:
    """Records per-IP feature telemetry and attack events to SQLite."""

    _instance: Optional['TelemetryRecorder'] = None

    @classmethod
    def get_instance(cls) -> 'TelemetryRecorder':
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def __init__(self):
        self._db: Optional[sqlite3.Connection] = None
        self._buffer: List[tuple] = []
        self._event_buffer: List[Dict] = []
        self._lock = threading.Lock()
        self._thread: Optional[threading.Thread] = None
        self._running = False

        # Per-IP sampling state
        self._last_sample_time: Dict[str, float] = {}
        # Track active attacks for event lifecycle
        self._active_attacks: Dict[str, Dict] = {}
        # Post-attack tail tracking
        self._attack_ended_time: Dict[str, float] = {}
        # Last prune check
        self._last_prune = 0.0

    def start(self):
        """Initialize DB and start background recorder thread."""
        if self._running:
            return

        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript(SCHEMA_SQL)
        # Migrate: add baselines_all column if missing (existing DBs)
        try:
            self._db.execute("SELECT baselines_all FROM ip_feature_samples LIMIT 0")
        except sqlite3.OperationalError:
            self._db.execute("ALTER TABLE ip_feature_samples ADD COLUMN baselines_all TEXT")
            logger.info("Migrated ip_feature_samples: added baselines_all column")
        self._db.commit()
        logger.info("Telemetry recorder initialized: %s", DB_PATH)

        self._running = True
        self._thread = threading.Thread(
            target=self._recorder_loop, daemon=True, name="telemetry-recorder")
        self._thread.start()

    def stop(self):
        """Stop recorder and flush remaining data."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        self._flush()
        if self._db:
            self._db.close()
            self._db = None

    def _recorder_loop(self):
        """Background loop: read from DPDKService, sample, buffer, flush."""
        from .dpdk_service import get_dpdk_service

        while self._running:
            try:
                service = get_dpdk_service()
                now = time.time()

                # Get current data snapshots
                features_data = service.get_per_ip_features()
                anomaly_data = service.get_per_ip_anomaly()
                baseline_data = service.get_per_ip_baselines()
                global_anomaly = service.get_anomaly()

                current_threshold = 0.0
                if global_anomaly:
                    current_threshold = global_anomaly.get('current_threshold', 0.0)

                per_ip_anomalies = anomaly_data.get('per_ip_anomalies', []) \
                    if isinstance(anomaly_data, dict) else []

                # Build anomaly lookup by IP
                anomaly_by_ip: Dict[str, Dict] = {}
                for a in per_ip_anomalies:
                    if isinstance(a, dict) and a.get('dst_ip_str'):
                        anomaly_by_ip[a['dst_ip_str']] = a

                # Sample each IP
                for ip_str, feat in features_data.items():
                    anom = anomaly_by_ip.get(ip_str, {})
                    is_anomalous = bool(anom.get('anomaly_active', False))

                    # Determine sampling interval
                    interval = ATTACK_SAMPLE_INTERVAL if is_anomalous else NORMAL_SAMPLE_INTERVAL

                    # Post-attack tail: keep full rate for 60s
                    if not is_anomalous and ip_str in self._attack_ended_time:
                        if now - self._attack_ended_time[ip_str] < POST_ATTACK_TAIL_SEC:
                            interval = ATTACK_SAMPLE_INTERVAL
                        else:
                            del self._attack_ended_time[ip_str]

                    # Check if enough time has passed since last sample
                    last = self._last_sample_time.get(ip_str, 0)
                    if now - last < interval:
                        continue
                    self._last_sample_time[ip_str] = now

                    # Build 39-element feature vector
                    feat_values = self._build_feature_vector(feat)

                    # Get baselines for this IP
                    bl = baseline_data.get(ip_str, {})
                    baseline_means = self._extract_baseline_means(bl)
                    baseline_stds = self._extract_baseline_stds(bl)
                    baselines_all = self._extract_all_baselines(bl)

                    # Determine label
                    label = 'normal'
                    if is_anomalous:
                        label = 'attack'

                    row = (
                        now, ip_str,
                        _json_array(feat_values),
                        _json_array(baseline_means) if baseline_means else None,
                        _json_array(baseline_stds) if baseline_stds else None,
                        baselines_all,
                        1 if is_anomalous else 0,
                        anom.get('level', 0),
                        anom.get('max_z_score', 0.0),
                        anom.get('attack_type', 0),
                        anom.get('confidence', 0),
                        anom.get('detection_method', 0),
                        anom.get('rate_limit_pct', 100),
                        label,
                    )

                    with self._lock:
                        self._buffer.append(row)

                    # Track attack event lifecycle
                    self._track_attack_event(ip_str, anom, now, current_threshold, feat)

                # Periodic flush
                if len(self._buffer) >= 100 or now - getattr(self, '_last_flush', 0) > FLUSH_INTERVAL:
                    self._flush()
                    self._last_flush = now

                # Periodic prune
                if now - self._last_prune > PRUNE_INTERVAL:
                    self._prune_old_data()
                    self._last_prune = now

            except Exception as e:
                logger.error("Telemetry recorder error: %s", e, exc_info=True)

            time.sleep(1)

    def _build_feature_vector(self, feat: Dict) -> List[float]:
        """Build 39-element feature vector from per-IP features data."""
        values = [0.0] * 39

        # Direct mappings from per-IP features packet
        values[0] = feat.get('packets_per_sec', 0)
        values[1] = feat.get('bytes_per_sec', 0)
        values[2] = feat.get('flows_per_sec', 0)
        values[3] = feat.get('syn_per_sec', 0)
        values[4] = feat.get('syn_ack_per_sec', 0)
        values[5] = feat.get('ack_per_sec', 0)
        values[6] = feat.get('rst_per_sec', 0)
        values[7] = feat.get('fin_per_sec', 0)
        values[8] = feat.get('tcp_ratio', 0)
        values[9] = feat.get('udp_ratio', 0)
        values[10] = feat.get('icmp_ratio', 0)
        values[11] = feat.get('other_ratio', 0)

        # Ratio features -- compute from raw values where needed
        pps = max(1, values[0])
        syn = max(1, values[3])
        values[12] = (values[4] / syn * 100) if syn > 0 else 0       # syn_ack_ratio
        values[13] = feat.get('rst_syn_ratio', 0) * 100              # rst_syn_ratio (already 0-1 in parser)
        values[14] = values[1] / pps if pps > 0 else 0               # bytes_per_packet

        values[15] = feat.get('unique_src_ips', 0)
        values[16] = feat.get('unique_dst_ports', 0)
        values[17] = feat.get('unique_flows', 0)
        values[18] = feat.get('new_srcip_rate', 0)

        values[19] = feat.get('max_flow_fraction', 0)
        values[20] = feat.get('topk_flow_share', 0)
        values[21] = feat.get('heavy_hitter_count', 0)
        values[22] = feat.get('avg_packets_per_flow', 0)
        values[23] = feat.get('flow_duration_avg_ms', 0)

        # TCP flag ratios (% of TCP) -- compute from raw counts
        tcp_total = values[3] + values[4] + values[5] + values[6] + values[7]
        if tcp_total > 0:
            values[24] = values[3] / tcp_total * 100    # syn_tcp_ratio
            values[25] = values[4] / tcp_total * 100    # synack_tcp_ratio
            values[26] = values[5] / tcp_total * 100    # ack_tcp_ratio
            values[27] = values[6] / tcp_total * 100    # rst_tcp_ratio
            values[28] = values[7] / tcp_total * 100    # fin_tcp_ratio

        # L2 detection features (now exported from shared memory via stats socket)
        values[29] = feat.get('burst_factor', 0)
        values[30] = feat.get('udp_flow_ratio', 0)
        values[31] = feat.get('icmp_echo_ratio', 0)
        values[32] = feat.get('dst_port_density', 0)
        values[33] = feat.get('src_ip_entropy', 0)
        values[34] = feat.get('small_pkt_ratio', 0)
        values[35] = feat.get('fragment_ratio', 0)
        values[36] = feat.get('ttl_mean', 0)
        values[37] = feat.get('tcp_completion_rate', 0)
        values[38] = feat.get('src_port_entropy', 0)

        return values

    def _extract_baseline_means(self, bl: Dict) -> Optional[List[float]]:
        """Extract tier1_10s baseline means (39 features)."""
        if not bl:
            return None
        means = []
        for name in L2_FEATURE_NAMES:
            means.append(bl.get(f'bl_10s_{name}', 0.0))
        return means

    def _extract_baseline_stds(self, bl: Dict) -> Optional[List[float]]:
        """Extract tier1_10s baseline stddevs (39 features)."""
        if not bl:
            return None
        stds = []
        for name in L2_FEATURE_NAMES:
            stds.append(bl.get(f'bl_10s_{name}_stddev', 0.0))
        return stds

    def _extract_all_baselines(self, bl: Dict) -> Optional[str]:
        """Extract all 5 EWMA tiers of baselines as a JSON string.

        Output format: {"1s":{"means":[39 floats],"stds":[39 floats]},"10s":{...},...}
        Feature order matches L2_FEATURE_NAMES (39 features).
        """
        if not bl:
            return None
        tiers_data = {}
        for tier_name in BASELINE_TIER_NAMES:
            means = []
            stds = []
            for name in L2_FEATURE_NAMES:
                means.append(bl.get(f'bl_{tier_name}_{name}', 0.0))
                stds.append(bl.get(f'bl_{tier_name}_{name}_stddev', 0.0))
            tiers_data[tier_name] = {
                'means': means,
                'stds': stds,
                'ready': bl.get(f'bl_{tier_name}_ready', False),
                'samples': bl.get(f'bl_{tier_name}_samples', 0),
            }
        return _json_baselines(tiers_data)

    def _track_attack_event(self, ip_str: str, anom: Dict, now: float,
                            threshold: float, feat: Dict):
        """Track attack start/end for attack_events table."""
        is_active = bool(anom.get('anomaly_active', False))

        if is_active and ip_str not in self._active_attacks:
            # Attack started
            self._active_attacks[ip_str] = {
                'dst_ip': ip_str,
                'started_at': now,
                'peak_z_score': anom.get('max_z_score', 0),
                'attack_type': anom.get('attack_type', 0),
                'attack_type_name': anom.get('attack_type_name', ''),
                'severity': anom.get('severity', 0),
                'detection_method': anom.get('detection_method', 0),
                'threshold_at_start': threshold,
                'rate_limit_pct': anom.get('rate_limit_pct', 100),
                'peak_pps': feat.get('packets_per_sec', 0),
                'peak_bps': feat.get('bytes_per_sec', 0),
                'unique_src_ips': feat.get('unique_src_ips', 0),
                'confidence': anom.get('confidence', 0),
                'protocol_name': anom.get('anomaly_protocol_name', ''),
            }

        elif is_active and ip_str in self._active_attacks:
            # Attack ongoing -- update peaks
            ev = self._active_attacks[ip_str]
            z = anom.get('max_z_score', 0)
            if z > ev['peak_z_score']:
                ev['peak_z_score'] = z
            pps = feat.get('packets_per_sec', 0)
            if pps > ev['peak_pps']:
                ev['peak_pps'] = pps
            bps = feat.get('bytes_per_sec', 0)
            if bps > ev['peak_bps']:
                ev['peak_bps'] = bps
            srcs = feat.get('unique_src_ips', 0)
            if srcs > ev['unique_src_ips']:
                ev['unique_src_ips'] = srcs

        elif not is_active and ip_str in self._active_attacks:
            # Attack ended
            ev = self._active_attacks.pop(ip_str)
            ev['ended_at'] = now
            ev['duration_sec'] = now - ev['started_at']

            # Label based on duration (matches adaptive threshold logic)
            duration = ev['duration_sec']
            if duration < 10 and ev['peak_z_score'] < threshold * 1.5:
                ev['label'] = 'fp'
            elif duration >= 30:
                ev['label'] = 'tp'
            else:
                ev['label'] = 'ambiguous'

            with self._lock:
                self._event_buffer.append(ev)

            # Start post-attack tail sampling
            self._attack_ended_time[ip_str] = now

    def _flush(self):
        """Flush buffered samples and events to SQLite."""
        with self._lock:
            samples = self._buffer[:]
            self._buffer.clear()
            events = self._event_buffer[:]
            self._event_buffer.clear()

        if not samples and not events:
            return
        if not self._db:
            return

        try:
            if samples:
                self._db.executemany(
                    "INSERT INTO ip_feature_samples "
                    "(timestamp, dst_ip, feat_values, baseline_means, baseline_stds, "
                    "baselines_all, "
                    "anomaly_active, anomaly_level, max_z_score, attack_type, "
                    "confidence, detection_method, rate_limit_pct, label) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    samples
                )

            for ev in events:
                self._db.execute(
                    "INSERT INTO attack_events "
                    "(dst_ip, started_at, ended_at, duration_sec, peak_z_score, "
                    "attack_type, attack_type_name, severity, detection_method, "
                    "label, threshold_at_start, rate_limit_pct, peak_pps, "
                    "peak_bps, unique_src_ips, confidence, protocol_name) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ev['dst_ip'], ev['started_at'], ev.get('ended_at'),
                     ev.get('duration_sec'), ev['peak_z_score'],
                     ev['attack_type'], ev.get('attack_type_name'),
                     ev.get('severity'), ev['detection_method'],
                     ev.get('label', 'unknown'), ev.get('threshold_at_start'),
                     ev.get('rate_limit_pct'), ev.get('peak_pps'),
                     ev.get('peak_bps'), ev.get('unique_src_ips'),
                     ev.get('confidence'), ev.get('protocol_name'))
                )

            self._db.commit()
            if samples:
                logger.debug("Flushed %d feature samples, %d events", len(samples), len(events))

        except Exception as e:
            logger.error("Telemetry flush error: %s", e)

    def _prune_old_data(self):
        """Remove oldest rows when exceeding retention limit."""
        if not self._db:
            return
        try:
            count = self._db.execute(
                "SELECT COUNT(*) FROM ip_feature_samples").fetchone()[0]
            if count > MAX_FEATURE_ROWS:
                excess = count - MAX_FEATURE_ROWS
                self._db.execute(
                    "DELETE FROM ip_feature_samples WHERE id IN "
                    "(SELECT id FROM ip_feature_samples ORDER BY id ASC LIMIT ?)",
                    (min(excess, PRUNE_BATCH),)
                )
                self._db.commit()
                logger.info("Pruned %d old telemetry rows (total was %d)",
                            min(excess, PRUNE_BATCH), count)
        except Exception as e:
            logger.error("Telemetry prune error: %s", e)

    # ==================== Query API ====================

    def get_feature_samples(self, dst_ip: Optional[str] = None,
                            label: Optional[str] = None,
                            since: Optional[float] = None,
                            limit: int = 1000) -> List[Dict]:
        """Query recorded feature samples."""
        if not self._db:
            return []

        query = "SELECT * FROM ip_feature_samples WHERE 1=1"
        params: list = []
        if dst_ip:
            query += " AND dst_ip = ?"
            params.append(dst_ip)
        if label:
            query += " AND label = ?"
            params.append(label)
        if since:
            query += " AND timestamp >= ?"
            params.append(since)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        try:
            self._db.row_factory = sqlite3.Row
            rows = self._db.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Query error: %s", e)
            return []

    def get_attack_events(self, dst_ip: Optional[str] = None,
                          label: Optional[str] = None,
                          since: Optional[float] = None,
                          limit: int = 100) -> List[Dict]:
        """Query recorded attack events."""
        if not self._db:
            return []

        query = "SELECT * FROM attack_events WHERE 1=1"
        params: list = []
        if dst_ip:
            query += " AND dst_ip = ?"
            params.append(dst_ip)
        if label:
            query += " AND label = ?"
            params.append(label)
        if since:
            query += " AND started_at >= ?"
            params.append(since)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        try:
            self._db.row_factory = sqlite3.Row
            rows = self._db.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        except Exception as e:
            logger.error("Query error: %s", e)
            return []

    def update_event_feedback(self, event_id: int, feedback: str) -> bool:
        """Update operator feedback on an attack event."""
        if not self._db:
            return False
        if feedback not in ('tp', 'fp', 'flash_crowd'):
            return False
        try:
            self._db.execute(
                "UPDATE attack_events SET operator_feedback = ?, label = ? WHERE id = ?",
                (feedback, feedback, event_id)
            )
            self._db.commit()
            return True
        except Exception as e:
            logger.error("Feedback update error: %s", e)
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get telemetry recorder statistics."""
        if not self._db:
            return {}
        try:
            samples = self._db.execute(
                "SELECT COUNT(*) FROM ip_feature_samples").fetchone()[0]
            events = self._db.execute(
                "SELECT COUNT(*) FROM attack_events").fetchone()[0]
            tp = self._db.execute(
                "SELECT COUNT(*) FROM attack_events WHERE label = 'tp'").fetchone()[0]
            fp = self._db.execute(
                "SELECT COUNT(*) FROM attack_events WHERE label = 'fp'").fetchone()[0]
            attack_samples = self._db.execute(
                "SELECT COUNT(*) FROM ip_feature_samples WHERE anomaly_active = 1"
            ).fetchone()[0]
            return {
                'total_feature_samples': samples,
                'total_attack_events': events,
                'tp_events': tp,
                'fp_events': fp,
                'attack_samples': attack_samples,
                'normal_samples': samples - attack_samples,
                'buffer_size': len(self._buffer),
                'active_attacks_tracked': len(self._active_attacks),
                'db_path': str(DB_PATH),
            }
        except Exception as e:
            logger.error("Stats error: %s", e)
            return {}


    def clear_all_data(self) -> Dict[str, int]:
        """Delete all recorded feature samples and attack events."""
        if not self._db:
            return {'error': 'DB not initialized'}
        try:
            samples = self._db.execute(
                "SELECT COUNT(*) FROM ip_feature_samples").fetchone()[0]
            events = self._db.execute(
                "SELECT COUNT(*) FROM attack_events").fetchone()[0]
            self._db.execute("DELETE FROM ip_feature_samples")
            self._db.execute("DELETE FROM attack_events")
            self._db.commit()
            self._buffer.clear()
            self._event_buffer.clear()
            self._active_attacks.clear()
            self._last_sample_time.clear()
            self._attack_ended_time.clear()
            self._last_prune = 0.0
            logger.info("Cleared all telemetry data: %d samples, %d events",
                        samples, events)
            return {'samples_deleted': samples, 'events_deleted': events}
        except Exception as e:
            logger.error("Clear data error: %s", e)
            return {'error': str(e)}


def _json_array(values: List[float]) -> str:
    """Compact JSON array encoding for feature vectors."""
    return '[' + ','.join(f'{v:.6g}' for v in values) + ']'


def _json_baselines(tiers: Dict[str, Any]) -> str:
    """Compact JSON encoding for all baseline tiers."""
    import json
    # Use compact separators to save space
    return json.dumps(tiers, separators=(',', ':'))


def get_telemetry_recorder() -> TelemetryRecorder:
    """Get or create the singleton telemetry recorder."""
    return TelemetryRecorder.get_instance()
