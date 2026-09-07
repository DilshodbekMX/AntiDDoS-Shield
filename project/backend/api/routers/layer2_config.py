"""
Layer 2 Configuration Router

FastAPI router for Layer 2 (anomaly detection) configuration management:
- Full configuration CRUD
- Adaptive threshold tuning
- Detection parameters
"""

from typing import Optional, Dict, Any, List
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, Field

import json
import logging
import re
import shutil
import socket
import struct
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

logger = logging.getLogger(__name__)

from rules import get_layer2_config_manager, init_layer2_config_manager, CMD_L2_LOAD_PROFILE, CMD_L2_SAVE_BASELINES, CMD_L2_RESET_BASELINES, CMD_L2_FORCE_MATURE, CMD_L2_FEEDBACK, CMD_L2_UNFREEZE_BASELINES
from ..services.dpdk_service import get_dpdk_service

# Control socket path (must match C CONTROL_SOCKET_PATH)
CONTROL_SOCKET_PATH = "/var/run/antiddos/control.sock"

# Staging path for profile files (C reads from this fixed path)
PROFILE_STAGING_PATH = Path("/var/run/antiddos/pending_profile.json")

# Project root for data directory
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
PROFILES_DIR = PROJECT_ROOT / "data" / "profiles"
def _get_baselines_path() -> Path:
    """Resolve baseline file path from Layer 2 config (stays in sync with C engine)."""
    try:
        config = layer2_config_manager.get_config()
        rel_path = config.get("baseline_file", "data/layer2_baselines.json")
        return PROJECT_ROOT / rel_path
    except Exception:
        return PROJECT_ROOT / "data" / "layer2_baselines.json"

router = APIRouter(prefix="/layer2", tags=["Layer 2 Config"])

# Initialize Layer 2 config manager
layer2_config_manager = init_layer2_config_manager()


# Request models
class ValueUpdateRequest(BaseModel):
    value: Any


class AdaptiveConfigUpdate(BaseModel):
    enabled: Optional[bool] = None
    min_threshold: Optional[float] = Field(None, ge=3.0, le=8.0)
    max_threshold: Optional[float] = Field(None, ge=6.0, le=15.0)
    step: Optional[float] = Field(None, ge=0.1, le=1.0)
    fp_threshold: Optional[float] = Field(None, ge=0.1, le=0.8)
    tp_min: Optional[float] = Field(None, ge=0.2, le=0.9)
    eval_interval_sec: Optional[int] = Field(None, ge=60, le=3600)
    min_samples: Optional[int] = Field(None, ge=5, le=100)
    fp_duration_threshold_sec: Optional[float] = Field(None, ge=1.0, le=60.0)
    tp_duration_threshold_sec: Optional[float] = Field(None, ge=10.0, le=300.0)
    daily_max_increase: Optional[float] = Field(None, ge=0.5, le=5.0)
    fp_z_multiplier: Optional[float] = Field(None, ge=1.0, le=3.0)


class ThresholdsUpdate(BaseModel):
    min_threshold: Optional[float] = Field(None, ge=3.0, le=8.0)
    max_threshold: Optional[float] = Field(None, ge=6.0, le=15.0)


class ClassificationUpdate(BaseModel):
    fp_duration_sec: Optional[float] = Field(None, ge=1.0, le=60.0)
    tp_duration_sec: Optional[float] = Field(None, ge=10.0, le=300.0)


class TuningUpdate(BaseModel):
    step: Optional[float] = Field(None, ge=0.1, le=1.0)
    fp_threshold: Optional[float] = Field(None, ge=0.1, le=0.8)
    tp_min: Optional[float] = Field(None, ge=0.2, le=0.9)
    eval_interval_sec: Optional[int] = Field(None, ge=60, le=3600)
    min_samples: Optional[int] = Field(None, ge=5, le=100)


class EnabledRequest(BaseModel):
    enabled: bool


# Configuration endpoints
@router.get("/config")
async def get_layer2_config():
    """Get full Layer2 configuration."""
    return layer2_config_manager.get_config()


@router.get("/config/info")
async def get_layer2_config_info():
    """Get Layer2 configuration metadata."""
    return layer2_config_manager.get_config_info()


@router.get("/config/schema")
async def get_layer2_config_schema():
    """Get Layer2 configuration schema with field descriptions."""
    return layer2_config_manager.get_config_schema()


# Valid configuration keys for Layer2
# Must match keys in DEFAULT_LAYER2_CONFIG_VALUES (rules.py)
VALID_L2_KEYS = {
    # Detection thresholds
    'z_score_threshold', 'min_tier_agreement', 'min_features_per_tier', 'strong_z_multiplier',
    'jsd_threshold', 'max_flow_fraction_threshold', 'topk_flow_share_threshold',
    # EWMA smoothing -- Tier 1 sub-tiers
    'alpha_immediate_1s', 'alpha_immediate_10s', 'alpha_immediate_60s',
    'alpha_immediate', 'alpha_hourly', 'alpha_weekly',
    'min_samples_immediate_1s', 'min_samples_immediate_10s', 'min_samples_immediate_60s',
    'min_samples_immediate', 'min_samples_hourly', 'min_samples_weekly',
    # Attack handling
    'cool_down_seconds', 'baseline_freeze_enabled',
    # Timing
    'detection_interval_ms', 'jitter_ms', 'min_pps_for_detection',
    # Fast detection
    'fast_detection_enabled', 'fast_detection_interval_ms', 'fast_threshold_multiplier',
    'fast_min_pps_spike', 'fast_syn_spike_threshold', 'fast_consecutive_required', 'fast_warmup_samples',
    # Warmup thresholds
    'warmup_pps_threshold', 'warmup_syn_threshold',
    'warmup_critical_pps', 'warmup_high_pps', 'warmup_medium_pps',
    # Severity classification Z-scores
    'z_critical_3tier', 'z_high_3tier', 'z_medium_3tier',
    'z_high_2tier', 'z_medium_2tier', 'z_medium_1tier',
    # Baseline poison protection
    'baseline_poison_protection_enabled', 'baseline_change_rate_threshold',
    'baseline_poison_window_sec', 'baseline_poison_count_threshold',
    'baseline_cumulative_drift_threshold',
    # Adaptive warmup
    'adaptive_warmup_enabled', 'warmup_learning_window_sec',
    'warmup_spike_factor', 'warmup_min_observations', 'warmup_percentile_threshold',
    # Baseline persistence
    'baseline_save_interval_sec',
    # Logging
    'log_level', 'log_detections', 'log_baseline_updates', 'log_interval_sec',
    # Spoofed detection
    'spoofed_min_pps', 'spoofed_randomness_threshold', 'spoofed_require_anomaly',
    # Adaptive threshold tuning
    'adaptive_enabled', 'adaptive_min_threshold', 'adaptive_max_threshold',
    'adaptive_step', 'adaptive_fp_threshold', 'adaptive_tp_min',
    'adaptive_eval_interval_sec', 'adaptive_min_samples',
    'fp_duration_threshold_sec', 'tp_duration_threshold_sec',
    'adaptive_daily_max_increase', 'adaptive_fp_z_multiplier',
    # Alert-Only Mode
    'learning_action', 'auto_promote_on_mature',
    'min_learning_duration_sec', 'force_alert_early_phases',
    # Baseline staleness brackets
    'baseline_fresh_sec', 'baseline_moderate_sec', 'baseline_stale_sec', 'baseline_expired_sec',
    # Progressive trust multipliers
    'trust_multiplier_cold', 'trust_multiplier_warming', 'trust_multiplier_moderate',
    # Feature selection
    'feature_enabled',
    # Feature weights
    'use_feature_weights', 'feature_weights',
    # Feature auto-selection
    'feature_auto_select', 'feature_auto_quality_min', 'feature_auto_min_samples',
    # Warmup advanced
    'warmup_z_coefficient', 'warmup_z_max', 'warmup_high_src_boost',
    # Flow characterization
    'fc_weight_syn_completion', 'fc_weight_response_ratio',
    'fc_weight_bpp_diversity', 'fc_weight_port_concentration',
    'fc_bpp_low', 'fc_bpp_high', 'fc_port_few', 'fc_port_moderate',
    # CUSUM tuning (P1a)
    'cusum_k_factor', 'cusum_h_factor', 'cusum_min_samples',
    # Sensitivity preset (P1b)
    'sensitivity_preset',
    # JSD parameters (P3a)
    'jsd_update_interval_ms', 'jsd_max_updates_per_minute',
    'jsd_contribution_multiplier', 'jsd_alpha', 'jsd_min_samples',
    # Attack classification thresholds (P3b)
    'attack_detection_threshold', 'attack_medium_conf_threshold',
    'attack_high_conf_threshold', 'attack_multi_vector_ratio',
}


@router.put("/config")
async def update_layer2_config(data: Dict[str, Any] = Body(...)):
    """Update Layer2 configuration values."""
    # Validate data is not empty
    if not data:
        raise HTTPException(status_code=400, detail='Configuration data cannot be empty')

    # Validate keys
    unknown_keys = set(data.keys()) - VALID_L2_KEYS
    if unknown_keys:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown configuration keys: {sorted(unknown_keys)}"
        )

    if layer2_config_manager.update_config(data):
        return {'status': 'updated'}
    else:
        raise HTTPException(status_code=400, detail='Failed to update Layer2 configuration')


@router.put("/config/value/{key}")
async def update_layer2_value(key: str, req: ValueUpdateRequest):
    """Update a single Layer2 configuration value."""
    if key not in VALID_L2_KEYS:
        raise HTTPException(status_code=400, detail=f'Unknown configuration key: {key}')
    result = layer2_config_manager.update_value(key, req.value)
    if result:
        applied = result.get('applied', False) if isinstance(result, dict) else False
        return {'status': 'updated', 'key': key, 'applied': applied}
    else:
        raise HTTPException(status_code=400, detail=f'Failed to update {key}')


@router.post("/config/reset")
async def reset_layer2_config():
    """Reset Layer2 configuration to defaults."""
    if layer2_config_manager.reset_to_defaults():
        return {'status': 'reset'}
    else:
        raise HTTPException(status_code=500, detail='Failed to reset Layer2 configuration')


@router.post("/config/reload")
async def reload_layer2_config():
    """Reload Layer2 configuration from file."""
    if layer2_config_manager.load_config():
        return {'status': 'reloaded'}
    else:
        raise HTTPException(status_code=500, detail='Failed to reload Layer2 configuration')


# Adaptive threshold endpoints
@router.get("/adaptive")
async def get_adaptive_config():
    """Get adaptive threshold configuration and current runtime threshold."""
    config = layer2_config_manager.get_config()

    # Get current_threshold from realtime anomaly data (C runtime state)
    current_threshold = config.get('z_score_threshold', 4.0)  # fallback to configured
    try:
        service = get_dpdk_service()
        anomaly = service.get_anomaly()
        if anomaly and 'current_threshold' in anomaly:
            current_threshold = anomaly['current_threshold']
    except Exception:
        pass  # Use config fallback if service unavailable

    return {
        'enabled': config.get('adaptive_enabled', True),
        'current_threshold': current_threshold,
        'min_threshold': config.get('adaptive_min_threshold', 4.0),
        'max_threshold': config.get('adaptive_max_threshold', 10.0),
        'step': config.get('adaptive_step', 0.25),
        'fp_threshold': config.get('adaptive_fp_threshold', 0.30),
        'tp_min': config.get('adaptive_tp_min', 0.50),
        'eval_interval_sec': config.get('adaptive_eval_interval_sec', 300),
        'min_samples': config.get('adaptive_min_samples', 10),
        'fp_duration_threshold_sec': config.get('fp_duration_threshold_sec', 10.0),
        'tp_duration_threshold_sec': config.get('tp_duration_threshold_sec', 30.0),
        'daily_max_increase': config.get('adaptive_daily_max_increase', 2.0),
        'fp_z_multiplier': config.get('adaptive_fp_z_multiplier', 1.5),
    }


@router.put("/adaptive")
async def update_adaptive_config(req: AdaptiveConfigUpdate):
    """Update adaptive threshold configuration."""
    field_map = {
        'enabled': 'adaptive_enabled',
        'min_threshold': 'adaptive_min_threshold',
        'max_threshold': 'adaptive_max_threshold',
        'step': 'adaptive_step',
        'fp_threshold': 'adaptive_fp_threshold',
        'tp_min': 'adaptive_tp_min',
        'eval_interval_sec': 'adaptive_eval_interval_sec',
        'min_samples': 'adaptive_min_samples',
        'fp_duration_threshold_sec': 'fp_duration_threshold_sec',
        'tp_duration_threshold_sec': 'tp_duration_threshold_sec',
        'daily_max_increase': 'adaptive_daily_max_increase',
        'fp_z_multiplier': 'adaptive_fp_z_multiplier',
    }

    updates = {}
    req_dict = req.model_dump(exclude_none=True)
    for api_key, config_key in field_map.items():
        if api_key in req_dict:
            updates[config_key] = req_dict[api_key]

    if updates:
        if layer2_config_manager.update_config(updates):
            return {'status': 'updated', 'fields': list(updates.keys())}
        else:
            raise HTTPException(status_code=400, detail='Failed to update adaptive configuration')

    raise HTTPException(status_code=400, detail='No valid fields provided')


@router.post("/adaptive/enabled")
async def set_adaptive_enabled(req: EnabledRequest):
    """Enable or disable adaptive threshold tuning."""
    if layer2_config_manager.update_value('adaptive_enabled', req.enabled):
        return {'status': 'updated', 'enabled': req.enabled}
    else:
        raise HTTPException(status_code=400, detail='Failed to update adaptive enabled state')


@router.post("/adaptive/thresholds")
async def set_adaptive_thresholds(req: ThresholdsUpdate):
    """Set min/max threshold bounds for adaptive tuning."""
    updates = {}
    if req.min_threshold is not None:
        updates['adaptive_min_threshold'] = req.min_threshold
    if req.max_threshold is not None:
        updates['adaptive_max_threshold'] = req.max_threshold

    if not updates:
        raise HTTPException(status_code=400, detail='No valid fields provided')

    # Validate min < max
    config = layer2_config_manager.get_config()
    min_t = updates.get('adaptive_min_threshold', config.get('adaptive_min_threshold', 4.0))
    max_t = updates.get('adaptive_max_threshold', config.get('adaptive_max_threshold', 10.0))
    if min_t >= max_t:
        raise HTTPException(status_code=400, detail='min_threshold must be less than max_threshold')

    if layer2_config_manager.update_config(updates):
        return {'status': 'updated', 'min_threshold': min_t, 'max_threshold': max_t}
    else:
        raise HTTPException(status_code=400, detail='Failed to update thresholds')


@router.post("/adaptive/classification")
async def set_adaptive_classification(req: ClassificationUpdate):
    """Set FP/TP classification duration thresholds."""
    updates = {}
    if req.fp_duration_sec is not None:
        updates['fp_duration_threshold_sec'] = req.fp_duration_sec
    if req.tp_duration_sec is not None:
        updates['tp_duration_threshold_sec'] = req.tp_duration_sec

    if not updates:
        raise HTTPException(status_code=400, detail='No valid fields provided')

    # Validate fp < tp
    config = layer2_config_manager.get_config()
    fp_t = updates.get('fp_duration_threshold_sec', config.get('fp_duration_threshold_sec', 10.0))
    tp_t = updates.get('tp_duration_threshold_sec', config.get('tp_duration_threshold_sec', 30.0))
    if fp_t >= tp_t:
        raise HTTPException(status_code=400, detail='fp_duration_sec must be less than tp_duration_sec')

    if layer2_config_manager.update_config(updates):
        return {'status': 'updated', 'fp_duration_sec': fp_t, 'tp_duration_sec': tp_t}
    else:
        raise HTTPException(status_code=400, detail='Failed to update classification thresholds')


@router.post("/adaptive/tuning")
async def set_adaptive_tuning(req: TuningUpdate):
    """Set adaptive tuning parameters (step, fp_threshold, tp_min, interval, samples)."""
    updates = {}

    if req.step is not None:
        updates['adaptive_step'] = req.step
    if req.fp_threshold is not None:
        updates['adaptive_fp_threshold'] = req.fp_threshold
    if req.tp_min is not None:
        updates['adaptive_tp_min'] = req.tp_min
    if req.eval_interval_sec is not None:
        updates['adaptive_eval_interval_sec'] = req.eval_interval_sec
    if req.min_samples is not None:
        updates['adaptive_min_samples'] = req.min_samples

    if not updates:
        raise HTTPException(status_code=400, detail='No valid fields provided')

    if layer2_config_manager.update_config(updates):
        return {'status': 'updated', 'fields': list(req.model_dump(exclude_none=True).keys())}
    else:
        raise HTTPException(status_code=400, detail='Failed to update tuning parameters')


# ==================== Operator Feedback ====================


class FeedbackRequest(BaseModel):
    feedback: str = Field(..., description="false_positive, true_positive, or flash_crowd")


@router.post("/feedback")
async def submit_detection_feedback(req: FeedbackRequest):
    """Submit operator ground truth for the most recent detection event.

    Replaces duration-based FP/TP heuristic with real operator classification.
    This directly affects adaptive threshold tuning.
    """
    feedback_map = {
        "false_positive": 0,
        "true_positive": 1,
        "flash_crowd": 2,
    }
    if req.feedback not in feedback_map:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid feedback type. Must be one of: {list(feedback_map.keys())}",
        )
    mode = feedback_map[req.feedback]
    ok = _send_control_command_with_mode(CMD_L2_FEEDBACK, mode)
    if not ok:
        raise HTTPException(status_code=500, detail="Failed to send feedback to datapath")
    return {"status": "ok", "feedback": req.feedback}


# ==================== Profile Endpoints ====================

def _send_control_command_with_mode(cmd: int, mode: int) -> bool:
    """Send a command with mode field to the C datapath via Unix control socket."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(CONTROL_SOCKET_PATH)
        packet = struct.pack('<BIB', cmd, 0, mode)
        sock.sendall(packet)
        response = sock.recv(4)
        sock.close()
        return len(response) >= 1 and response[0] == 0
    except socket.error:
        return False
    except Exception as e:
        print(f"[Layer2Config] Error sending command: {e}")
        return False


def _send_control_command(cmd: int) -> bool:
    """Send a command to the C datapath via Unix control socket."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(CONTROL_SOCKET_PATH)
        # Must match control_cmd struct: cmd(B) + ip(I) + prefix_len(B) = 6 bytes
        packet = struct.pack('<BIB', cmd, 0, 0)
        sock.sendall(packet)
        response = sock.recv(4)
        sock.close()
        return len(response) >= 1 and response[0] == 0
    except socket.error:
        return False
    except Exception as e:
        print(f"[Layer2Profiles] Error sending command: {e}")
        return False


class ProfileApplyRequest(BaseModel):
    name: str


class ProfileExportRequest(BaseModel):
    name: str
    description: str = ""


# Feature names matching L2 C code (l2_feature_names[])
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
    'src_port_entropy',
    'small_pkt_ratio', 'fragment_ratio', 'ttl_mean',
    'tcp_completion_rate',
]

# Feature group mapping (matches C l2_feature_to_group[] in baselines.c)
L2_FEATURE_GROUPS = [
    'Volume', 'Volume', 'Volume',                                        # PPS, BPS, FPS
    'TCP Flags', 'TCP Flags', 'TCP Flags', 'TCP Flags', 'TCP Flags',    # SYN..FIN/s
    'Protocol Mix', 'Protocol Mix', 'Protocol Mix', 'Protocol Mix',      # TCP/UDP/ICMP/Other ratio
    'Ratios', 'Ratios', 'Ratios',                                        # SYN-ACK/SYN, RST/SYN, BPP
    'Cardinality', 'Cardinality', 'Cardinality',                         # Unique IPs/ports/flows
    'Churn',                                                              # New src IP rate
    'Concentration', 'Concentration', 'Concentration',                    # Max flow %, top-K, heavy hitters
    'Flow Behavior', 'Flow Behavior',                                     # Avg pkts/flow, flow duration
    'TCP Flag Ratios', 'TCP Flag Ratios', 'TCP Flag Ratios', 'TCP Flag Ratios', 'TCP Flag Ratios',  # SYN/SYNACK/ACK/RST/FIN % of TCP
    'Volume',                                                             # burst_factor
    'Flow Behavior',                                                      # udp_flow_ratio
    'Protocol Mix',                                                       # icmp_echo_ratio
    'Cardinality',                                                        # dst_port_density
    'Entropy', 'Entropy',                                                 # src_ip_entropy, src_port_entropy
    'Packet Characteristics', 'Packet Characteristics', 'Packet Characteristics',  # small_pkt_ratio, fragment_ratio, ttl_mean
    'Ratios',                                                             # tcp_completion_rate
]

# Cardinality features that use log-transform in baselines
LOG_TRANSFORM_FEATURES = {'unique_src_ips', 'unique_dst_ports', 'unique_flows'}

import math


def _compute_feature_quality(quality_min: float = 0.05, min_samples: int = 300) -> list:
    """Compute feature quality scores from saved baselines (mirrors C l2_compute_feature_quality)."""
    quality = []
    baselines_data = None
    baselines_path = _get_baselines_path()
    if baselines_path.exists():
        try:
            baselines_data = json.loads(baselines_path.read_text())
        except Exception:
            pass

    for i, name in enumerate(L2_FEATURE_NAMES):
        q = {'cv': 0.0, 'range_ratio': 0.0, 'zero_dominant': False, 'score': None, 'auto_disabled': False}
        if baselines_data:
            # Use immediate tier (60s sub-tier = index 2) for quality assessment
            immediate = baselines_data.get('immediate', [])
            tier_data = immediate[2] if isinstance(immediate, list) and len(immediate) > 2 else {}
            feat = tier_data.get('features', {}).get(name, {})
            mean = feat.get('mean', 0.0)
            variance = feat.get('variance', 0.0)
            min_obs = feat.get('min', 0.0)
            max_obs = feat.get('max', 0.0)
            samples = feat.get('samples', 0)

            # Reverse log-transform for cardinality features
            if name in LOG_TRANSFORM_FEATURES:
                raw_mean = max(math.exp(mean) - 1.0, 0.0)
                variance = variance * (raw_mean + 1.0) ** 2
                mean = raw_mean
                min_obs = max(math.exp(min_obs) - 1.0, 0.0) if min_obs > 0 else 0.0
                max_obs = max(math.exp(max_obs) - 1.0, 0.0) if max_obs > 0 else 0.0

            if samples >= min_samples:
                abs_mean = abs(mean)
                stddev = math.sqrt(max(variance, 0.0))
                dyn_range = max_obs - min_obs

                q['cv'] = round(stddev / abs_mean if abs_mean > 1.0 else stddev, 4)
                q['range_ratio'] = round(dyn_range / abs_mean if abs_mean > 1.0 else dyn_range, 4)
                q['zero_dominant'] = abs_mean < 1e-6 and stddev < 1e-6

                if q['zero_dominant']:
                    q['score'] = 0.0
                else:
                    cv_signal = min(q['cv'] * 10.0, 1.0)
                    range_signal = min(q['range_ratio'] * 5.0, 1.0)
                    q['score'] = round(cv_signal * range_signal, 4)

                # Volume group (indices 0,1,2 and burst_factor=29) never auto-disabled
                is_volume = L2_FEATURE_GROUPS[i] == 'Volume'
                q['auto_disabled'] = not is_volume and q['score'] < quality_min
        quality.append(q)
    return quality


@router.get("/features")
async def get_feature_config():
    """Get feature names, groups, enabled states, and quality scores for the dashboard."""
    config = layer2_config_manager.get_config()
    enabled = config.get('feature_enabled', [True] * len(L2_FEATURE_NAMES))
    # Pad if config has fewer entries than current feature count (migration)
    while len(enabled) < len(L2_FEATURE_NAMES):
        enabled.append(True)

    quality_min = config.get('feature_auto_quality_min', 0.05)
    min_samples = config.get('feature_auto_min_samples', 300)
    quality = _compute_feature_quality(quality_min, min_samples)

    return {
        'features': [
            {
                'index': i,
                'name': name,
                'group': L2_FEATURE_GROUPS[i],
                'enabled': enabled[i],
                'quality': quality[i],
            }
            for i, name in enumerate(L2_FEATURE_NAMES)
        ],
        'auto_select': {
            'enabled': config.get('feature_auto_select', False),
            'min_quality': quality_min,
            'min_samples': min_samples,
        },
    }


@router.put("/features/enabled")
async def set_feature_enabled(data: Dict[str, Any] = Body(...)):
    """Update feature enabled states. Body: { feature_enabled: [bool, ...] }"""
    enabled = data.get('feature_enabled')
    if not isinstance(enabled, list) or len(enabled) != len(L2_FEATURE_NAMES):
        raise HTTPException(
            status_code=400,
            detail=f'feature_enabled must be an array of {len(L2_FEATURE_NAMES)} booleans'
        )
    # Validate all entries are booleans
    if not all(isinstance(v, bool) for v in enabled):
        raise HTTPException(status_code=400, detail='All entries must be booleans')

    # Bridge feature_enabled -> feature_weights so C detection engine actually respects toggles.
    # C reads only feature_weights (not feature_enabled); a weight of 0.0 with
    # use_feature_weights=true is the only way to suppress a feature in the C engine.
    config = layer2_config_manager.get_config()
    current_weights = config.get('feature_weights', [1.0] * len(L2_FEATURE_NAMES))
    # Pad/trim to current feature count in case config is stale
    if len(current_weights) < len(L2_FEATURE_NAMES):
        current_weights = current_weights + [1.0] * (len(L2_FEATURE_NAMES) - len(current_weights))
    effective_weights = [
        # Disabled -> zero weight; enabled -> preserve existing weight if non-zero, else restore to 1.0
        0.0 if not enabled[i] else (current_weights[i] if current_weights[i] > 0.0 else 1.0)
        for i in range(len(L2_FEATURE_NAMES))
    ]
    any_disabled = not all(enabled)

    if layer2_config_manager.update_config({
        'feature_enabled': enabled,
        'feature_weights': effective_weights,
        'use_feature_weights': any_disabled,
    }):
        return {'status': 'updated'}
    raise HTTPException(status_code=400, detail='Failed to update feature config')


@router.put("/features/auto-select")
async def set_auto_select(data: Dict[str, Any] = Body(...)):
    """Enable/disable automatic feature selection and configure thresholds.

    When enabled, this also applies quality-driven weights immediately:
      - score >= 0.5 (green):  weight = 1.0  (fully retained)
      - 0.05 <= score < 0.5 (amber): weight = score / 0.5  (linearly reduced)
      - score < 0.05 (red):   weight = 0.0  (auto-disabled, unless volume)
    Volume features (pps, bps, flows_per_sec, burst_factor) are never touched.
    """
    updates = {}
    if 'enabled' in data:
        updates['feature_auto_select'] = bool(data['enabled'])
    if 'min_quality' in data:
        val = float(data['min_quality'])
        if not (0.0 <= val <= 1.0):
            raise HTTPException(status_code=400, detail='min_quality must be between 0.0 and 1.0')
        updates['feature_auto_quality_min'] = val
    if 'min_samples' in data:
        val = int(data['min_samples'])
        if not (10 <= val <= 10000):
            raise HTTPException(status_code=400, detail='min_samples must be between 10 and 10000')
        updates['feature_auto_min_samples'] = val
    if not updates:
        raise HTTPException(status_code=400, detail='No valid fields provided')
    if not layer2_config_manager.update_config(updates):
        raise HTTPException(status_code=400, detail='Failed to update auto-select config')

    # If auto-select is being enabled (or is already enabled and thresholds changed),
    # compute quality-driven weights and persist them.
    config = layer2_config_manager.get_config()
    if config.get('feature_auto_select', False):
        quality_min = config.get('feature_auto_quality_min', 0.05)
        min_samples = config.get('feature_auto_min_samples', 300)
        quality = _compute_feature_quality(quality_min, min_samples)

        current_weights = config.get('feature_weights', [1.0] * len(L2_FEATURE_NAMES))
        if len(current_weights) < len(L2_FEATURE_NAMES):
            current_weights += [1.0] * (len(L2_FEATURE_NAMES) - len(current_weights))

        new_weights = list(current_weights)
        any_changed = False
        for i, q in enumerate(quality):
            is_volume = L2_FEATURE_GROUPS[i] == 'Volume'
            if is_volume:
                continue  # Never auto-adjust volume features
            score = q.get('score')
            if score is None:
                continue  # Not enough samples -- leave weight unchanged
            if score >= 0.5:
                w = 1.0
            elif score >= quality_min:
                # Amber band: linearly reduce weight from 1.0 at s=0.5 down to 0.2 at s=quality_min
                w = round(0.2 + 0.8 * (score - quality_min) / (0.5 - quality_min), 4)
            else:
                w = 0.0  # Red: auto-disabled
            if new_weights[i] != w:
                new_weights[i] = w
                any_changed = True

        if any_changed:
            has_disabled = any(w == 0.0 for w in new_weights)
            layer2_config_manager.update_config({
                'feature_weights': new_weights,
                'use_feature_weights': has_disabled or any(w < 1.0 for w in new_weights),
            })

    return {'status': 'updated', 'fields': list(updates.keys())}


@router.get("/profiles")
async def list_profiles():
    """List available baseline profiles (templates + exported)."""
    profiles = []
    if PROFILES_DIR.exists():
        for f in sorted(PROFILES_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text())
                profiles.append({
                    "id": f.stem,
                    "name": data.get("name", f.stem),
                    "description": data.get("description", ""),
                    "source": data.get("source", "unknown"),
                })
            except Exception:
                continue
    return {"profiles": profiles}


@router.post("/profiles/apply")
async def apply_profile(req: ProfileApplyRequest):
    """Apply a baseline profile to skip learning period."""
    source = PROFILES_DIR / f"{req.name}.json"
    if not source.exists():
        raise HTTPException(status_code=404, detail=f"Profile not found: {req.name}")

    # Stage profile to fixed path for C to read
    PROFILE_STAGING_PATH.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(str(source), str(PROFILE_STAGING_PATH))

    # Send CMD_L2_LOAD_PROFILE via control socket
    success = _send_control_command(CMD_L2_LOAD_PROFILE)
    if success:
        return {"status": "applied", "profile": req.name}
    else:
        PROFILE_STAGING_PATH.unlink(missing_ok=True)
        raise HTTPException(
            status_code=500,
            detail="Failed to apply profile (datapath not running?)"
        )


@router.post("/profiles/export")
async def export_profile(req: ProfileExportRequest):
    """Export current baselines as a reusable profile."""
    baselines_path = _get_baselines_path()
    if not baselines_path.exists():
        raise HTTPException(status_code=404, detail="No baselines saved yet")

    try:
        baselines = json.loads(baselines_path.read_text())
    except Exception as e:
        logger.exception("Failed to read baselines for export")
        raise HTTPException(status_code=500, detail="Internal server error")

    # Extract immediate tier features into compact profile format
    # v3: "immediate" is an array of 3 sub-tiers; v2: single object
    immediate_raw = baselines.get("immediate", {})
    if isinstance(immediate_raw, list):
        immediate = immediate_raw[1] if len(immediate_raw) > 1 else (immediate_raw[0] if immediate_raw else {})
    else:
        immediate = immediate_raw
    features = immediate.get("features", {})

    feature_means = {}
    feature_variances = {}
    sample_count = 100

    for feat_name in L2_FEATURE_NAMES:
        feat_data = features.get(feat_name, {})
        mean_val = feat_data.get("mean", 0.0)
        var_val = feat_data.get("variance", 0.0)

        # Reverse log-transform for cardinality features
        if feat_name in LOG_TRANSFORM_FEATURES:
            raw_mean = math.exp(mean_val) - 1.0
            if raw_mean < 0.0:
                raw_mean = 0.0
            raw_var = var_val * (raw_mean + 1.0) ** 2
            mean_val = raw_mean
            var_val = raw_var

        feature_means[feat_name] = round(mean_val, 4)
        feature_variances[feat_name] = round(var_val, 4)

        # Use actual sample count from first feature
        if feat_name == L2_FEATURE_NAMES[0]:
            sample_count = int(feat_data.get("samples", 100))

    # Build profile JSON
    from datetime import datetime, timezone
    profile = {
        "schema_version": 1,
        "name": req.name,
        "description": req.description,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source": "exported",
        "baseline_snapshot": {
            "feature_means": feature_means,
            "feature_variances": feature_variances,
            "initial_sample_count": min(sample_count, 1000),
        },
        "recommended_config": {},
    }

    # Sanitize filename
    safe_name = re.sub(r'[^a-z0-9_-]', '_', req.name.lower().strip())
    if not safe_name:
        safe_name = "exported_profile"

    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    output_path = PROFILES_DIR / f"{safe_name}.json"
    output_path.write_text(json.dumps(profile, indent=2))

    return {"status": "exported", "id": safe_name, "name": req.name}


# ==================== Baseline Management Endpoints ====================

@router.post("/baselines/save")
async def save_baselines():
    """Save current baselines to disk."""
    success = _send_control_command(CMD_L2_SAVE_BASELINES)
    if success:
        return {"status": "saved"}
    raise HTTPException(status_code=500, detail="Failed to save baselines (datapath not running?)")


@router.post("/baselines/reset")
async def reset_baselines():
    """Reset all baselines. Returns to COLD phase."""
    success = _send_control_command(CMD_L2_RESET_BASELINES)
    if success:
        return {"status": "reset", "phase": "COLD"}
    raise HTTPException(status_code=500, detail="Failed to reset baselines (datapath not running?)")


@router.post("/baselines/force-mature")
async def force_mature():
    """Force learning phase to MATURE."""
    success = _send_control_command(CMD_L2_FORCE_MATURE)
    if success:
        return {"status": "forced", "phase": "MATURE"}
    raise HTTPException(status_code=500, detail="Failed to force mature (datapath not running?)")


@router.post("/baselines/unfreeze")
async def unfreeze_baselines():
    """Operator override -- reset baseline poison tracker and unfreeze baselines.

    Use when baselines are stuck frozen after a false positive or after an attack
    clears but the 300s poisoning window has not yet expired.
    """
    success = _send_control_command(CMD_L2_UNFREEZE_BASELINES)
    if success:
        return {"status": "unfrozen"}
    raise HTTPException(status_code=500, detail="Failed to unfreeze baselines (datapath not running?)")


@router.get("/baselines/summary")
async def get_baselines_summary():
    """Get time-appropriate baseline means and stddevs for ALL features.

    Picks the most specific ready tier for the current time:
      weekly[day_hour] -> hourly[hour] -> immediate[60s]
    This matches how C Layer 2 detection selects baselines.
    Used by the Feature Monitor page for baseline overlays.
    """
    from datetime import datetime

    baselines_path = _get_baselines_path()
    if not baselines_path.exists():
        return {"features": {}, "total_updates": 0, "save_timestamp": 0, "tier_used": "none"}

    try:
        baselines = json.loads(baselines_path.read_text())
    except Exception:
        return {"features": {}, "total_updates": 0, "save_timestamp": 0, "tier_used": "none"}

    now = datetime.now()
    current_hour = now.hour                           # 0-23
    current_day_hour = now.weekday() * 24 + now.hour  # 0-167 (Mon=0)

    # Try tiers in specificity order: weekly -> hourly -> immediate
    tier_data = None
    tier_used = "immediate"

    # Weekly (Tier 3) -- most specific
    weekly_raw = baselines.get("weekly", [])
    if isinstance(weekly_raw, list) and current_day_hour < len(weekly_raw):
        slot = weekly_raw[current_day_hour]
        if isinstance(slot, dict) and slot.get("ready", False):
            tier_data = slot
            tier_used = f"weekly (day {now.weekday()} hour {current_hour})"

    # Hourly (Tier 2) -- fallback
    if tier_data is None:
        hourly_raw = baselines.get("hourly", [])
        if isinstance(hourly_raw, list) and current_hour < len(hourly_raw):
            slot = hourly_raw[current_hour]
            if isinstance(slot, dict) and slot.get("ready", False):
                tier_data = slot
                tier_used = f"hourly (hour {current_hour})"

    # Immediate (Tier 1) -- final fallback, use 60s sub-tier
    if tier_data is None:
        immediate_raw = baselines.get("immediate", {})
        if isinstance(immediate_raw, list) and len(immediate_raw) > 2:
            tier_data = immediate_raw[2]
        elif isinstance(immediate_raw, list) and len(immediate_raw) > 0:
            tier_data = immediate_raw[-1]
        else:
            tier_data = immediate_raw if isinstance(immediate_raw, dict) else {}
        tier_used = "immediate (60s)"

    features_map = tier_data.get("features", {}) if tier_data else {}
    ready = tier_data.get("ready", False) if tier_data else False
    result = {}

    for feat_name in L2_FEATURE_NAMES:
        feat = features_map.get(feat_name, {})
        mean = feat.get("mean", 0.0)
        variance = feat.get("variance", 0.0)
        samples = feat.get("samples", 0)

        if feat_name in LOG_TRANSFORM_FEATURES:
            raw_mean = max(math.exp(mean) - 1.0, 0.0)
            variance = variance * (raw_mean + 1.0) ** 2
            mean = raw_mean

        stddev = math.sqrt(max(variance, 0.0))
        result[feat_name] = {
            "mean": round(mean, 2),
            "stddev": round(stddev, 2),
            "samples": samples,
            "ready": ready,
        }

    return {
        "features": result,
        "total_updates": baselines.get("total_updates", 0),
        "save_timestamp": baselines.get("save_timestamp_unix", 0),
        "tier_used": tier_used,
    }


@router.get("/baselines/data")
async def get_baselines_data(feature: str = "packets_per_sec", ip: Optional[str] = None):
    """Get full baseline tier data for visualization.

    Returns immediate, hourly (24 slots), and weekly (168 slots) baseline
    values for the requested feature.  When *ip* is provided, returns live
    per-IP baseline means from the DPDK stats stream instead of the global
    saved baselines.
    """
    if feature not in L2_FEATURE_NAMES:
        raise HTTPException(status_code=400, detail=f"Unknown feature: {feature}")

    # ---- Per-IP baselines: saved file (all slots) + live overlay (current slot) ----
    if ip:
        import ipaddress as _ipaddress
        from datetime import datetime

        is_log = feature in LOG_TRANSFORM_FEATURES

        def _extract_pip_feature(tier_data: dict) -> dict:
            feat = tier_data.get("features", {}).get(feature, {})
            mean = feat.get("mean", 0.0)
            variance = feat.get("variance", 0.0)
            samples = feat.get("samples", 0)
            if is_log:
                raw_mean = max(math.exp(mean) - 1.0, 0.0)
                variance = variance * (raw_mean + 1.0) ** 2
                mean = raw_mean
            stddev = math.sqrt(max(variance, 0.0))
            return {"mean": round(mean, 2), "stddev": round(stddev, 2), "samples": samples,
                    "ready": tier_data.get("ready", False)}

        # Try to read saved per-IP baselines from disk (has all 24+168 slots)
        baselines_path = _get_baselines_path()
        per_ip_file = baselines_path.parent / (baselines_path.name + ".per_ip")
        saved_ip_baselines = None
        if per_ip_file.exists():
            try:
                saved_data = json.loads(per_ip_file.read_text())
                # Find matching IP entry by converting dst_ip integer to string
                target_ip = int(_ipaddress.ip_address(ip))
                for entry in saved_data.get("entries", []):
                    dst_ip_int = entry.get("dst_ip", 0)
                    # dst_ip is in network byte order (big-endian) -- convert
                    import socket as _socket
                    dst_ip_host = _socket.ntohl(dst_ip_int & 0xFFFFFFFF)
                    if dst_ip_host == target_ip:
                        saved_ip_baselines = entry.get("baselines", {})
                        break
            except Exception:
                pass

        if saved_ip_baselines:
            # Extract all slots from saved file
            imm_raw = saved_ip_baselines.get("immediate", [])
            immediate = [_extract_pip_feature(s) for s in imm_raw] if imm_raw else \
                        [{"mean": 0, "stddev": 0, "samples": 0, "ready": False}] * 3

            hourly_raw = saved_ip_baselines.get("hourly", [])
            hourly = []
            for i in range(24):
                if i < len(hourly_raw):
                    hourly.append(_extract_pip_feature(hourly_raw[i]))
                else:
                    hourly.append({"mean": 0, "stddev": 0, "samples": 0, "ready": False})

            weekly_raw = saved_ip_baselines.get("weekly", [])
            weekly = []
            for i in range(168):
                if i < len(weekly_raw):
                    weekly.append(_extract_pip_feature(weekly_raw[i]))
                else:
                    weekly.append({"mean": 0, "stddev": 0, "samples": 0, "ready": False})

            # Overlay live data for current slots (more up-to-date than saved)
            service = get_dpdk_service()
            per_ip_data = service.get_per_ip_baselines() if service else {}
            ip_bl = per_ip_data.get(ip, {})
            if not ip_bl:
                for key, val in per_ip_data.items():
                    try:
                        if _ipaddress.ip_address(key) == _ipaddress.ip_address(ip):
                            ip_bl = val
                            break
                    except ValueError:
                        pass

            if ip_bl:
                now = datetime.now()
                # Overlay immediate tiers from live stream
                for idx, tn in enumerate(['1s', '10s', '60s']):
                    live_mean = ip_bl.get(f'bl_{tn}_{feature}', 0.0)
                    live_stddev = ip_bl.get(f'bl_{tn}_{feature}_stddev', 0.0)
                    live_ready = ip_bl.get(f'bl_{tn}_ready', False)
                    live_samples = ip_bl.get(f'bl_{tn}_samples', 0)
                    if idx < len(immediate):
                        immediate[idx] = {"mean": round(live_mean, 2), "stddev": round(live_stddev, 2),
                                           "samples": live_samples, "ready": live_ready}
                # Overlay current hourly slot
                h = now.hour
                live_hmean = ip_bl.get(f'bl_hourly_{feature}', 0.0)
                live_hstd = ip_bl.get(f'bl_hourly_{feature}_stddev', 0.0)
                live_hready = ip_bl.get('bl_hourly_ready', False)
                live_hsamples = ip_bl.get('bl_hourly_samples', 0)
                hourly[h] = {"mean": round(live_hmean, 2), "stddev": round(live_hstd, 2),
                              "samples": live_hsamples, "ready": live_hready}
                # Overlay current weekly slot
                w = now.weekday() * 24 + now.hour
                live_wmean = ip_bl.get(f'bl_weekly_{feature}', 0.0)
                live_wstd = ip_bl.get(f'bl_weekly_{feature}_stddev', 0.0)
                live_wready = ip_bl.get('bl_weekly_ready', False)
                live_wsamples = ip_bl.get('bl_weekly_samples', 0)
                weekly[w] = {"mean": round(live_wmean, 2), "stddev": round(live_wstd, 2),
                              "samples": live_wsamples, "ready": live_wready}

            total_updates = saved_ip_baselines.get("total_updates", 0)
        else:
            # No saved file -- use live-only data (current slot only)
            service = get_dpdk_service()
            per_ip_data = service.get_per_ip_baselines() if service else {}
            ip_bl = per_ip_data.get(ip, {})
            if not ip_bl:
                for key, val in per_ip_data.items():
                    try:
                        if _ipaddress.ip_address(key) == _ipaddress.ip_address(ip):
                            ip_bl = val
                            break
                    except ValueError:
                        pass

            if not ip_bl:
                # No data at all -- return empty with fallback flag
                empty_tier = {"mean": 0, "stddev": 0, "samples": 0, "ready": False}
                return {
                    "feature": feature,
                    "features_available": L2_FEATURE_NAMES,
                    "total_updates": 0,
                    "save_timestamp": 0,
                    "per_ip": ip,
                    "fallback": "no_data",
                    "immediate": [empty_tier.copy() for _ in range(3)],
                    "hourly": [empty_tier.copy() for _ in range(24)],
                    "weekly": [empty_tier.copy() for _ in range(168)],
                }

            now = datetime.now()
            immediate = []
            for tn in ['1s', '10s', '60s']:
                mean = ip_bl.get(f'bl_{tn}_{feature}', 0.0)
                stddev = ip_bl.get(f'bl_{tn}_{feature}_stddev', 0.0)
                ready = ip_bl.get(f'bl_{tn}_ready', False)
                samples = ip_bl.get(f'bl_{tn}_samples', 0)
                immediate.append({"mean": round(mean, 2), "stddev": round(stddev, 2),
                                   "samples": samples, "ready": ready})

            empty_slot = {"mean": 0, "stddev": 0, "samples": 0, "ready": False}
            hourly = [empty_slot.copy() for _ in range(24)]
            h_mean = ip_bl.get(f'bl_hourly_{feature}', 0.0)
            h_std = ip_bl.get(f'bl_hourly_{feature}_stddev', 0.0)
            hourly[now.hour] = {"mean": round(h_mean, 2), "stddev": round(h_std, 2),
                                 "samples": ip_bl.get('bl_hourly_samples', 0),
                                 "ready": ip_bl.get('bl_hourly_ready', False)}

            weekly = [empty_slot.copy() for _ in range(168)]
            w_idx = now.weekday() * 24 + now.hour
            w_mean = ip_bl.get(f'bl_weekly_{feature}', 0.0)
            w_std = ip_bl.get(f'bl_weekly_{feature}_stddev', 0.0)
            weekly[w_idx] = {"mean": round(w_mean, 2), "stddev": round(w_std, 2),
                              "samples": ip_bl.get('bl_weekly_samples', 0),
                              "ready": ip_bl.get('bl_weekly_ready', False)}

            total_updates = 0

        # Compute learning progress
        imm_ready = sum(1 for t in immediate if t["ready"])
        hourly_ready_count = sum(1 for t in hourly if t["ready"])
        weekly_ready_count = sum(1 for t in weekly if t["ready"])

        if imm_ready == 3 and hourly_ready_count == 24 and weekly_ready_count == 168:
            phase = "mature"
            phase_label = "Mature"
            eta_text = None
        elif imm_ready == 3 and hourly_ready_count == 24:
            phase = "weekly"
            phase_label = "Learning weekly patterns"
            remaining_weekly = 168 - weekly_ready_count
            eta_hours = remaining_weekly
            eta_text = f"~{eta_hours // 24}d {eta_hours % 24}h remaining" if eta_hours >= 24 else f"~{eta_hours}h remaining"
        elif imm_ready == 3:
            phase = "hourly"
            phase_label = "Learning daily patterns"
            remaining_hourly = 24 - hourly_ready_count
            eta_text = f"~{remaining_hourly}h remaining"
        else:
            phase = "immediate"
            phase_label = "Warming up"
            eta_text = "~30 min remaining"

        learning_status = {
            "phase": phase,
            "phase_label": phase_label,
            "eta": eta_text,
            "tier1_progress": f"{imm_ready}/3",
            "tier2_progress": f"{hourly_ready_count}/24",
            "tier3_progress": f"{weekly_ready_count}/168",
        }

        return {
            "feature": feature,
            "features_available": L2_FEATURE_NAMES,
            "total_updates": total_updates,
            "save_timestamp": 0,
            "per_ip": ip,
            "learning_status": learning_status,
            "immediate": immediate,
            "hourly": hourly,
            "weekly": weekly,
        }

    # ---- Global saved baselines (no IP filter) ----
    baselines_path = _get_baselines_path()
    if not baselines_path.exists():
        raise HTTPException(status_code=404, detail="No baselines saved yet. Save baselines first.")

    try:
        baselines = json.loads(baselines_path.read_text())
    except Exception as e:
        logger.exception("Failed to read baselines for visualization")
        raise HTTPException(status_code=500, detail="Internal server error")

    is_log = feature in LOG_TRANSFORM_FEATURES

    def extract_feature(tier_data: dict) -> dict:
        feat = tier_data.get("features", {}).get(feature, {})
        mean = feat.get("mean", 0.0)
        variance = feat.get("variance", 0.0)
        samples = feat.get("samples", 0)
        if is_log:
            raw_mean = max(math.exp(mean) - 1.0, 0.0)
            variance = variance * (raw_mean + 1.0) ** 2
            mean = raw_mean
        stddev = math.sqrt(max(variance, 0.0))
        return {"mean": round(mean, 2), "stddev": round(stddev, 2), "samples": samples,
                "ready": tier_data.get("ready", False)}

    # Immediate (Tier 1) -- v3: array of 3 sub-tiers, v2: single object
    immediate_raw = baselines.get("immediate", {})
    if isinstance(immediate_raw, list):
        immediate = [extract_feature(s) for s in immediate_raw]
    else:
        single = extract_feature(immediate_raw)
        immediate = [single, single, single]

    # Hourly (Tier 2) - 24 slots
    hourly_raw = baselines.get("hourly", [])
    hourly = []
    for i in range(24):
        if i < len(hourly_raw):
            hourly.append(extract_feature(hourly_raw[i]))
        else:
            hourly.append({"mean": 0, "stddev": 0, "samples": 0, "ready": False})

    # Weekly (Tier 3) - 168 slots
    weekly_raw = baselines.get("weekly", [])
    weekly = []
    for i in range(168):
        if i < len(weekly_raw):
            weekly.append(extract_feature(weekly_raw[i]))
        else:
            weekly.append({"mean": 0, "stddev": 0, "samples": 0, "ready": False})

    return {
        "feature": feature,
        "features_available": L2_FEATURE_NAMES,
        "total_updates": baselines.get("total_updates", 0),
        "save_timestamp": baselines.get("save_timestamp_unix", 0),
        "immediate": immediate,
        "hourly": hourly,
        "weekly": weekly,
    }


# ============================================================================
# Learning Status Endpoint
# ============================================================================

from pydantic import BaseModel as _BaseModel


class LearningStatusResponse(_BaseModel):
    """Learning state machine status for Layer 2 anomaly detection."""
    state: str                   # 'cold_start' | 'warmup' | 'moderate' | 'mature'
    phase: int                   # numeric phase: 0=cold, 1=warmup, 2=moderate, 3=mature
    progress_pct: int            # overall 0-100 progress toward mature
    tier1_ready: bool
    tier2_ready: bool            # current hourly slot ready
    tier3_ready: bool            # current weekly slot ready
    tier1_progress: int          # 0-100
    tier2_progress: int          # 0-100 (current slot)
    tier3_progress: int          # 0-100 (current slot)
    tier1_eta_sec: int
    tier2_eta_sec: int
    tier3_eta_sec: int
    tier2_slots_ready: int       # how many of 24 hourly slots are ready
    tier3_slots_ready: int       # how many of 168 weekly slots are ready
    baseline_age_sec: int        # 0 = cold start (no saved baselines)
    eta_mature_seconds: int      # estimated seconds to full maturity
    total_updates: int
    mitigation_active: bool
    learning_action: int         # 0=BLOCK, 1=ALERT_ONLY
    suppressed_count: int
    trust_multiplier: float


_PHASE_NAMES = {0: 'cold_start', 1: 'warmup', 2: 'moderate', 3: 'mature'}


@router.get("/learning-status", response_model=LearningStatusResponse)
async def get_learning_status():
    """Get Layer 2 learning phase state and tier-by-tier progress.

    Returns the current learning state machine status including per-tier
    progress percentages, ETAs, and estimated time to full maturity.
    Reads live data from the DPDK stats stream if available, falls back
    to saved baselines for static progress.
    """
    dpdk = get_dpdk_service()
    anomaly = dpdk.get_anomaly()

    phase = int(anomaly.get('learning_phase', 0))
    tier1_progress = int(anomaly.get('tier1_progress', 0))
    tier2_progress = int(anomaly.get('tier2_progress', 0))
    tier3_progress = int(anomaly.get('tier3_progress', 0))
    tier1_eta_sec = int(anomaly.get('tier1_eta_sec', 0))
    tier2_eta_sec = int(anomaly.get('tier2_eta_sec', 0))
    tier3_eta_sec = int(anomaly.get('tier3_eta_sec', 0))
    baseline_age_sec = int(anomaly.get('baseline_age_sec', 0))
    tier1_ready = bool(anomaly.get('tier1_ready', False))
    tier2_ready_count = int(anomaly.get('tier2_ready_count', 0))
    tier3_ready_count = int(anomaly.get('tier3_ready_count', 0))
    total_updates = int(anomaly.get('baseline_updates', 0))
    mitigation_active = bool(anomaly.get('mitigation_active', True))
    learning_action = int(anomaly.get('learning_action', 0))
    suppressed_count = int(anomaly.get('suppressed_count', 0))
    trust_multiplier = float(anomaly.get('trust_multiplier', 1.0))

    tier2_ready = tier2_progress >= 100
    tier3_ready = tier3_progress >= 100

    # Overall progress: weighted average of tier progress
    # Tier 1 contributes 20%, Tier 2 contributes 30%, Tier 3 contributes 50%
    # (matching the real-world time-to-maturity weights: 10s, 24h, 7d)
    progress_pct = int(tier1_progress * 0.20 + tier2_progress * 0.30 + tier3_progress * 0.50)

    # ETA to full maturity: worst-case tier that isn't ready yet
    if phase >= 3:
        eta_mature_seconds = 0
    else:
        eta_mature_seconds = max(tier1_eta_sec, tier2_eta_sec, tier3_eta_sec)

    return LearningStatusResponse(
        state=_PHASE_NAMES.get(phase, 'cold_start'),
        phase=phase,
        progress_pct=progress_pct,
        tier1_ready=tier1_ready,
        tier2_ready=tier2_ready,
        tier3_ready=tier3_ready,
        tier1_progress=tier1_progress,
        tier2_progress=tier2_progress,
        tier3_progress=tier3_progress,
        tier1_eta_sec=tier1_eta_sec,
        tier2_eta_sec=tier2_eta_sec,
        tier3_eta_sec=tier3_eta_sec,
        tier2_slots_ready=tier2_ready_count,
        tier3_slots_ready=tier3_ready_count,
        baseline_age_sec=baseline_age_sec,
        eta_mature_seconds=eta_mature_seconds,
        total_updates=total_updates,
        mitigation_active=mitigation_active,
        learning_action=learning_action,
        suppressed_count=suppressed_count,
        trust_multiplier=trust_multiplier,
    )
