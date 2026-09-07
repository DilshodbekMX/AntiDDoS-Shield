"""
System Operations Router

FastAPI router for system-wide operations:
- Hot reload configuration (SIGHUP equivalent)
- System health checks
- Service status
- Kill switch for emergency traffic stop
"""

import os
import socket
import struct
import signal
import logging
from typing import Optional, Dict, Any, List
from datetime import datetime
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from ..auth import UserContext, get_current_user

# Import config managers
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from rules import (
    get_config_manager,
    get_layer2_config_manager,
    get_rules_engine,
    CMD_RELOAD_CONFIG,
    DEFAULT_SOCKET_PATH,
    CMD_CLEAR_PER_IP_ANOMALY,
    CMD_CLEAR_ALL_ANOMALY,
    CMD_L2_RESET_BASELINES,
    CMD_L2_SAVE_BASELINES,
    CMD_L1_FACTORY_RESET,
)
import ipaddress

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/system", tags=["System"])

# ============================================================================
# Constants
# ============================================================================

CONTROL_SOCKET_PATH = os.environ.get("ANTIDDOS_SOCKET_PATH", DEFAULT_SOCKET_PATH)

# Control commands (must match core/control_socket.h)
CMD_UPDATE_STAGE = 0x31
CMD_GET_STATS = 0x32

# Response codes
RESP_OK = 0x00
RESP_ERROR = 0x01
RESP_INVALID_CMD = 0x02
RESP_RATE_LIMITED = 0x03


# ============================================================================
# Request Models
# ============================================================================

class ReloadRequest(BaseModel):
    layer1: bool = True
    layer2: bool = True
    notify_datapath: bool = True


class KillSwitchRequest(BaseModel):
    enabled: bool
    reason: Optional[str] = None


class ResetDataRequest(BaseModel):
    """Request model for data reset operations."""
    clear_per_ip_data: bool = True
    clear_attacks: bool = True
    clear_traffic: bool = True
    reset_configs: bool = True  # Reset JSON configs + DB to defaults
    specific_ips: Optional[List[str]] = None  # If provided, only clear these IPs
    reason: Optional[str] = None


# ============================================================================
# Helper Functions
# ============================================================================

def send_control_command(cmd: int, ip: int = 0, prefix_len: int = 0) -> tuple[bool, str]:
    """Send a command to the DPDK control socket."""
    sock = None
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(CONTROL_SOCKET_PATH)

        # Pack command (must match control_cmd struct: cmd + ip + prefix_len = 6 bytes)
        packet = struct.pack('<BIB', cmd, ip, prefix_len)
        sock.sendall(packet)

        # Wait for response
        response = sock.recv(4)

        if len(response) >= 1:
            status = response[0]
            if status == RESP_OK:
                return True, "Command executed successfully"
            elif status == RESP_INVALID_CMD:
                return False, "Invalid command"
            elif status == RESP_RATE_LIMITED:
                return False, "Rate limited - try again later"
            else:
                return False, f"Command failed with status {status}"

        return False, "No response from datapath"

    except FileNotFoundError:
        return False, "Datapath not running (control socket not found)"
    except ConnectionRefusedError:
        return False, "Datapath not accepting connections"
    except PermissionError:
        return False, (
            "Permission denied on control socket. "
            "Backend process may need restart (missing 'antiddos' group). "
            "Run: systemctl restart antiddos-backend"
        )
    except socket.timeout:
        return False, "Timeout waiting for datapath response"
    except Exception as e:
        logger.error(f"Control socket error: {e}")
        return False, f"Socket error: {str(e)}"
    finally:
        if sock:
            sock.close()


def get_datapath_pid() -> Optional[int]:
    """Get the PID of the DPDK datapath process."""
    try:
        # Try to find the process by looking at socket owner
        import subprocess
        result = subprocess.run(
            ['lsof', '-t', CONTROL_SOCKET_PATH],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip().split()[0])
    except Exception:
        pass

    # Fallback: look for process by name
    try:
        import subprocess
        result = subprocess.run(
            ['pgrep', '-f', 'antiddos'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip().split()[0])
    except Exception:
        pass

    return None


# ============================================================================
# Endpoints
# ============================================================================

@router.post("/reload")
async def hot_reload_config(request: ReloadRequest = ReloadRequest(),
                            user: UserContext = Depends(get_current_user)):
    """
    Hot reload all configurations.

    This triggers a configuration reload across:
    - Layer 1 (DPDK datapath)
    - Layer 2 (Anomaly detection)

    Equivalent to sending SIGHUP to the datapath process.

    **Parameters:**
    - layer1: Reload Layer 1 config (default: true)
    - layer2: Reload Layer 2 config (default: true)
    - notify_datapath: Send CMD_RELOAD_CONFIG to control socket (default: true)

    **Returns:**
    - Status of each reload operation
    """
    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "layer1": {"status": "skipped"},
        "layer2": {"status": "skipped"},
        "datapath": {"status": "skipped"},
    }

    # Reload Layer 1 config (JSON file)
    if request.layer1:
        try:
            config_manager = get_config_manager()
            if config_manager and config_manager.load_config():
                results["layer1"] = {"status": "success", "message": "Config reloaded from file"}
            else:
                results["layer1"] = {"status": "error", "message": "Failed to reload config"}
        except Exception as e:
            results["layer1"] = {"status": "error", "message": str(e)}

    # Reload Layer 2 config (JSON file)
    if request.layer2:
        try:
            l2_config_manager = get_layer2_config_manager()
            if l2_config_manager and l2_config_manager.load_config():
                results["layer2"] = {"status": "success", "message": "Config reloaded from file"}
            else:
                results["layer2"] = {"status": "error", "message": "Failed to reload config"}
        except Exception as e:
            results["layer2"] = {"status": "error", "message": str(e)}

    # Notify datapath via control socket
    if request.notify_datapath:
        success, message = send_control_command(CMD_RELOAD_CONFIG)
        results["datapath"] = {
            "status": "success" if success else "error",
            "message": message
        }

    # Determine overall status
    statuses = [v["status"] for v in results.values() if isinstance(v, dict) and v.get("status") not in ("skipped",)]
    if not statuses:
        overall = "skipped"
    elif all(s == "success" for s in statuses):
        overall = "success"
    elif any(s == "success" for s in statuses):
        overall = "partial"
    else:
        overall = "error"

    results["overall_status"] = overall

    if overall == "error":
        raise HTTPException(status_code=500, detail=results)

    return results


@router.post("/reload/sighup")
async def send_sighup(user: UserContext = Depends(get_current_user)):
    """
    Send SIGHUP signal to the datapath process.

    This is a direct signal to the DPDK process to reload its configuration.
    Requires the backend to have permission to signal the datapath process.

    **Returns:**
    - Status of the signal operation
    """
    pid = get_datapath_pid()

    if pid is None:
        raise HTTPException(
            status_code=503,
            detail="Datapath process not found - is it running?"
        )

    try:
        os.kill(pid, signal.SIGHUP)
        return {
            "status": "success",
            "pid": pid,
            "message": f"SIGHUP sent to datapath process (PID {pid})"
        }
    except PermissionError:
        raise HTTPException(
            status_code=403,
            detail=f"Permission denied to signal process {pid}"
        )
    except ProcessLookupError:
        raise HTTPException(
            status_code=503,
            detail=f"Process {pid} no longer exists"
        )
    except Exception as e:
        logger.exception("Failed to send signal to process")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )


@router.get("/health")
async def health_check():
    """
    System health check.

    Returns the health status of all system components:
    - API backend
    - Datapath (DPDK)
    - Control socket
    - Configuration files
    """
    health = {
        "timestamp": datetime.utcnow().isoformat(),
        "api": {"status": "healthy"},
        "datapath": {"status": "unknown"},
        "config": {"status": "unknown"},
    }

    # Check datapath
    pid = get_datapath_pid()
    if pid:
        health["datapath"] = {
            "status": "healthy",
            "pid": pid,
            "socket": CONTROL_SOCKET_PATH
        }
    else:
        # Check if socket exists
        if os.path.exists(CONTROL_SOCKET_PATH):
            health["datapath"] = {
                "status": "degraded",
                "message": "Socket exists but process not found"
            }
        else:
            health["datapath"] = {
                "status": "unavailable",
                "message": "Datapath not running"
            }

    # Check config files
    config_manager = get_config_manager()
    if config_manager:
        config_info = config_manager.get_config_info()
        health["config"] = {
            "status": "healthy",
            "layer1_path": str(config_info.get("path", "unknown")),
            "layer1_modified": config_info.get("last_modified"),
        }
    else:
        health["config"] = {
            "status": "error",
            "message": "Config manager not initialized"
        }

    # Overall health
    statuses = [v.get("status") for v in health.values() if isinstance(v, dict)]
    if all(s == "healthy" for s in statuses):
        health["overall"] = "healthy"
    elif "unavailable" in statuses or "error" in statuses:
        health["overall"] = "degraded"
    else:
        health["overall"] = "healthy"

    return health


@router.get("/status")
async def system_status(user: UserContext = Depends(get_current_user)):
    """
    Get detailed system status.

    Returns:
    - Component versions
    - Uptime information
    - Current configuration summary
    - Active features
    """
    config_manager = get_config_manager()
    l2_config_manager = get_layer2_config_manager()

    status = {
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",  # TODO: Get from package
        "components": {
            "layer1": "enabled",
            "layer2": "enabled",
        },
        "features": {},
        "datapath": {},
    }

    # Get Layer 1 feature status
    if config_manager:
        config = config_manager.get_config()
        status["features"]["syn_proxy"] = config.get("syn_proxy", {}).get("enabled", False)
        status["features"]["rate_limiting"] = config.get("rate_limit", {}).get("enabled", False)
        status["features"]["geo_blocking"] = config.get("geo_blocking", {}).get("enabled", False)
        status["features"]["signatures"] = config.get("signatures", {}).get("enabled", False)
        status["features"]["ip_reputation"] = config.get("reputation", {}).get("enabled", False)

    # Get Layer 2 feature status
    if l2_config_manager:
        l2_config = l2_config_manager.get_config()
        status["features"]["anomaly_detection"] = l2_config.get("detection_enabled", True)
        status["features"]["adaptive_thresholds"] = l2_config.get("adaptive_enabled", True)

    # Get datapath status
    pid = get_datapath_pid()
    if pid:
        status["datapath"]["running"] = True
        status["datapath"]["pid"] = pid

        # Try to get stats via control socket
        try:
            # Send stats request (if implemented)
            pass
        except Exception:
            pass
    else:
        status["datapath"]["running"] = False

    return status


@router.post("/killswitch")
async def kill_switch(request: KillSwitchRequest,
                      user: UserContext = Depends(get_current_user)):
    """
    Emergency kill switch - stop all traffic processing.

    **WARNING**: This will cause ALL traffic to be dropped.
    Use only in emergency situations.

    When enabled:
    - All incoming traffic is dropped
    - No packets are forwarded
    - Statistics continue to be collected

    **Parameters:**
    - enabled: True to enable kill switch, False to disable
    - reason: Optional reason for audit log

    **Returns:**
    - Status of the operation
    """
    config_manager = get_config_manager()

    if not config_manager:
        raise HTTPException(status_code=503, detail="Config manager not available")

    # Update the monitor_only mode which effectively becomes a kill switch
    # when combined with dropping unknown traffic
    try:
        # Log the action
        logger.warning(
            f"Kill switch {'ENABLED' if request.enabled else 'DISABLED'}"
            f"{f' - Reason: {request.reason}' if request.reason else ''}"
        )

        # Update config to drop all traffic
        if request.enabled:
            # Enable monitor_only mode (no forwarding)
            config_manager.update_top_level("monitor_only", True)
        else:
            # Disable monitor_only mode (resume forwarding)
            config_manager.update_top_level("monitor_only", False)

        # Notify datapath
        success, message = send_control_command(CMD_RELOAD_CONFIG)

        return {
            "status": "success",
            "kill_switch": request.enabled,
            "reason": request.reason,
            "datapath_notified": success,
            "datapath_message": message,
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.exception("Kill switch error")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/socket/status")
async def control_socket_status(user: UserContext = Depends(get_current_user)):
    """
    Get control socket status and statistics.

    Returns information about the Unix domain socket used
    for communication with the DPDK datapath.
    """
    status = {
        "path": CONTROL_SOCKET_PATH,
        "exists": os.path.exists(CONTROL_SOCKET_PATH),
        "connectable": False,
        "pid": None,
    }

    if status["exists"]:
        # Try to get socket stats
        try:
            stat_info = os.stat(CONTROL_SOCKET_PATH)
            status["permissions"] = oct(stat_info.st_mode)[-3:]
            status["owner_uid"] = stat_info.st_uid
            status["group_gid"] = stat_info.st_gid
        except Exception:
            pass

        # Try to connect
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect(CONTROL_SOCKET_PATH)
            sock.close()
            status["connectable"] = True
        except Exception as e:
            status["connection_error"] = str(e)

    # Get PID
    status["pid"] = get_datapath_pid()

    return status


@router.post("/reset")
async def reset_data(request: ResetDataRequest = ResetDataRequest(),
                     user: UserContext = Depends(get_current_user)):
    """
    Reset in-memory data and optionally database records.

    This clears:
    - Per-IP anomaly detection data (DPDK service in-memory)
    - Per-IP traffic features data (DPDK service in-memory)
    - Traffic samples (DPDK service in-memory)
    - Attack records (database, if requested)

    **WARNING**: This operation is irreversible. Data will be permanently deleted.

    **Parameters:**
    - clear_per_ip_data: Clear per-IP anomaly and features data (default: true)
    - clear_attacks: Clear attack history from database (default: true)
    - clear_traffic: Clear traffic samples (default: true)
    - specific_ips: If provided, only clear data for these IPs
    - reason: Optional reason for audit log

    **Returns:**
    - Status of each reset operation
    """
    from ..services.dpdk_service import get_dpdk_service
    from ..services.telemetry_recorder import get_telemetry_recorder

    results = {
        "timestamp": datetime.utcnow().isoformat(),
        "per_ip_data": {"status": "skipped"},
        "attacks": {"status": "skipped"},
        "traffic": {"status": "skipped"},
        "telemetry_db": {"status": "skipped"},
        "reason": request.reason,
    }

    # Clear per-IP data from DPDK service and datapath
    if request.clear_per_ip_data:
        try:
            dpdk_service = get_dpdk_service()
            datapath_cleared = False
            datapath_msg = ""

            if request.specific_ips:
                cleared_ips = []
                for ip_str in request.specific_ips:
                    # Clear from backend in-memory cache
                    dpdk_service.clear_per_ip_data(ip_str)
                    cleared_ips.append(ip_str)

                    # Also send command to DPDK datapath to clear anomaly state
                    try:
                        ip_int = int(ipaddress.ip_address(ip_str))
                        success, msg = send_control_command(CMD_CLEAR_PER_IP_ANOMALY, ip_int, 32)
                        if success:
                            datapath_cleared = True
                            datapath_msg = "Datapath anomaly cleared"
                        else:
                            datapath_msg = f"Datapath: {msg}"
                    except Exception as e:
                        datapath_msg = f"Datapath error: {e}"

                results["per_ip_data"] = {
                    "status": "success",
                    "message": f"Cleared data for {len(cleared_ips)} IPs. {datapath_msg}",
                    "cleared_ips": cleared_ips,
                    "datapath_cleared": datapath_cleared
                }
            else:
                # Clear ALL backend in-memory data (stats, traffic, anomaly, per-IP, sysmon)
                dpdk_service.clear_all_data()

                # Clear all anomaly state from DPDK datapath
                success, msg = send_control_command(CMD_CLEAR_ALL_ANOMALY, 0, 0)
                datapath_cleared = success
                datapath_msg = msg if not success else "Datapath anomalies cleared"

                # Reset baselines in DPDK (back to COLD phase -- re-learn from scratch)
                bl_success, bl_msg = send_control_command(CMD_L2_RESET_BASELINES, 0, 0)
                baselines_cleared = bl_success
                if bl_success:
                    # Force-save zeroed baselines to disk (overwrites root-owned files)
                    save_ok, save_msg = send_control_command(CMD_L2_SAVE_BASELINES, 0, 0)
                    datapath_msg += ". Baselines reset to COLD"
                    if save_ok:
                        datapath_msg += " and saved to disk"
                    else:
                        datapath_msg += f" (disk save: {save_msg})"
                else:
                    datapath_msg += f". Baselines: {bl_msg}"

                # Reset Layer 1 runtime state (flow tables, reputation, signatures, etc.)
                l1_ok, l1_msg = send_control_command(CMD_L1_FACTORY_RESET, 0, 0)
                if l1_ok:
                    datapath_msg += ". Layer 1 runtime state cleared"
                else:
                    datapath_msg += f". Layer 1 reset: {l1_msg}"

                # Report actual status -- if critical datapath commands failed, flag it
                all_ok = datapath_cleared and baselines_cleared and l1_ok
                results["per_ip_data"] = {
                    "status": "success" if all_ok else "partial",
                    "message": f"Cleared all in-memory data. {datapath_msg}",
                    "datapath_cleared": datapath_cleared,
                    "baselines_cleared": baselines_cleared,
                    "layer1_cleared": l1_ok
                }
        except Exception as e:
            logger.error(f"Failed to clear per-IP data: {e}")
            results["per_ip_data"] = {"status": "error", "message": str(e)}

    # Clear traffic samples + rollup history
    if request.clear_traffic:
        try:
            dpdk_service = get_dpdk_service()
            dpdk_service.clear_traffic()

            # Also clear traffic rollup table in DB
            from ..database.connection import get_db
            from ..database.models import TrafficRollup
            from sqlalchemy import delete as sa_delete
            db = next(get_db())
            try:
                count = db.query(TrafficRollup).count()
                db.execute(sa_delete(TrafficRollup))
                db.commit()
                results["traffic"] = {
                    "status": "success",
                    "message": f"Cleared traffic samples and {count} rollup records"
                }
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to clear traffic: {e}")
            results["traffic"] = {"status": "error", "message": str(e)}

    # Clear attacks from database
    if request.clear_attacks:
        try:
            from ..database.connection import get_db
            from ..database.models import Attack
            from sqlalchemy import delete

            db = next(get_db())
            try:
                if request.specific_ips:
                    # Delete attacks for specific IPs
                    stmt = delete(Attack).where(Attack.target_ip.in_(request.specific_ips))
                else:
                    # Delete all attacks
                    stmt = delete(Attack)

                result = db.execute(stmt)
                db.commit()
                deleted_count = result.rowcount

                results["attacks"] = {
                    "status": "success",
                    "message": f"Deleted {deleted_count} attack records"
                }
            finally:
                db.close()
        except Exception as e:
            logger.error(f"Failed to clear attacks: {e}")
            results["attacks"] = {"status": "error", "message": str(e)}

    # Clear telemetry recorder DB (feature samples + attack events)
    if request.clear_per_ip_data or request.clear_attacks:
        try:
            recorder = get_telemetry_recorder()
            clear_result = recorder.clear_all_data()
            if 'error' in clear_result:
                results["telemetry_db"] = {"status": "error", "message": clear_result['error']}
            else:
                results["telemetry_db"] = {
                    "status": "success",
                    "message": f"Deleted {clear_result['samples_deleted']} feature samples, "
                               f"{clear_result['events_deleted']} attack events"
                }
        except Exception as e:
            logger.error(f"Failed to clear telemetry DB: {e}")
            results["telemetry_db"] = {"status": "error", "message": str(e)}

    # Reset configs to defaults (JSON files + DB)
    if request.reset_configs:
        try:
            config_results = {}

            # Reset Layer 1 config
            l1_mgr = get_config_manager()
            l1_ok = l1_mgr.reset_to_defaults(notify=True)
            config_results["layer1"] = "reset" if l1_ok else "failed"

            # Reset Layer 2 config
            l2_mgr = get_layer2_config_manager()
            l2_ok = l2_mgr.reset_to_defaults()
            config_results["layer2"] = "reset" if l2_ok else "failed"

            # Clear ALL DB tables for true factory reset
            from ..database.connection import get_db
            from ..database.models import (
                ConfigSnapshot, SystemConfigDB, PerIPL2Config,
                IPListEntry, Policy, ProtectedIP, Report, Webhook
            )
            from sqlalchemy import delete as sa_delete

            db = next(get_db())
            try:
                db.execute(sa_delete(ConfigSnapshot))
                db.execute(sa_delete(PerIPL2Config))
                db.execute(sa_delete(IPListEntry))
                db.execute(sa_delete(Policy))
                db.execute(sa_delete(ProtectedIP))
                db.execute(sa_delete(Report))
                db.execute(sa_delete(Webhook))
                sys_cfg = db.query(SystemConfigDB).filter(SystemConfigDB.id == 1).first()
                if sys_cfg:
                    db.delete(sys_cfg)
                db.commit()
                config_results["db"] = "cleared (configs, per-ip-config, ip-lists, policies, protected-ips, reports, webhooks)"
            finally:
                db.close()

            # Reset rules.json (whitelist/blacklist/protected IP mappings)
            try:
                rules_engine = get_rules_engine()
                rules_engine.clear_whitelist()
                rules_engine.clear_blacklist()
                rules_engine.clear_protected()
                config_results["rules"] = "cleared"
            except Exception as e:
                config_results["rules"] = f"failed: {e}"

            # Delete baseline data files (absolute path, include all patterns)
            import glob
            project_root = Path(__file__).parent.parent.parent.parent
            data_dir = project_root / "data"
            baseline_patterns = ["baselines*", "layer2_baselines*"]
            failed_files = []
            for pattern in baseline_patterns:
                for f in glob.glob(str(data_dir / pattern)):
                    try:
                        os.remove(f)
                        config_results.setdefault("files_removed", []).append(f)
                    except PermissionError:
                        failed_files.append(f"{f} (permission denied — owned by root?)")
                    except OSError as e:
                        failed_files.append(f"{f} ({e})")
            if failed_files:
                config_results["files_failed"] = failed_files
                logger.warning(f"Could not delete baseline files: {failed_files}")

            # Clean up generated report files
            import shutil
            reports_dir = Path("/tmp/antiddos_reports")
            if reports_dir.exists():
                report_count = sum(1 for _ in reports_dir.iterdir())
                shutil.rmtree(reports_dir, ignore_errors=True)
                reports_dir.mkdir(parents=True, exist_ok=True)
                config_results["reports_cleaned"] = report_count

            results["configs"] = {
                "status": "success",
                "message": f"Configs reset to defaults: {config_results}",
            }
        except Exception as e:
            logger.error(f"Failed to reset configs: {e}")
            results["configs"] = {"status": "error", "message": str(e)}

    # Log the action
    logger.warning(
        f"Data reset performed: per_ip={request.clear_per_ip_data}, "
        f"attacks={request.clear_attacks}, traffic={request.clear_traffic}, "
        f"configs={request.reset_configs}"
        f"{f' - Reason: {request.reason}' if request.reason else ''}"
    )

    # Determine overall status
    statuses = [v["status"] for v in results.values() if isinstance(v, dict) and "status" in v]
    if all(s in ("success", "skipped") for s in statuses):
        results["overall_status"] = "success"
    elif any(s == "success" for s in statuses):
        results["overall_status"] = "partial"
    else:
        results["overall_status"] = "error"

    return results


@router.delete("/reset/ip/{ip_address}")
async def reset_ip_data(ip_address: str,
                        user: UserContext = Depends(get_current_user)):
    """
    Reset all data for a specific IP address.

    Clears per-IP anomaly data, features data, and attack records
    for the specified IP address.

    **Parameters:**
    - ip_address: The IP address to clear data for

    **Returns:**
    - Status of the reset operation
    """
    request = ResetDataRequest(
        clear_per_ip_data=True,
        clear_attacks=True,
        clear_traffic=False,
        specific_ips=[ip_address],
        reason=f"Manual reset for IP {ip_address}"
    )
    return await reset_data(request)
