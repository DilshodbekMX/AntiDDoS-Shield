"""
Task scheduler using APScheduler.

Manages scheduled background tasks including:
- Stats broadcasting (1s)
- Attack lifecycle monitoring (5s)
- Traffic rollup (1m)
- Cleanup (1h)
- Report generation (1m check)
- Health checks (30s)

NOTE: sync_threat_intel and decay_reputation removed -- no infrastructure exists.
"""

import logging
import asyncio
from typing import Optional, Dict, Callable, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum

try:
    from apscheduler.schedulers.asyncio import AsyncIOScheduler
    from apscheduler.triggers.interval import IntervalTrigger
    from apscheduler.triggers.cron import CronTrigger
    HAS_APSCHEDULER = True
except ImportError:
    HAS_APSCHEDULER = False
    AsyncIOScheduler = None
    IntervalTrigger = None
    CronTrigger = None

logger = logging.getLogger(__name__)


class TaskStatus(str, Enum):
    """Task execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class TaskResult:
    """Result of a task execution."""
    task_id: str
    status: TaskStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: Optional[float] = None
    error: Optional[str] = None
    result: Any = None


class TaskScheduler:
    """
    Manages background task scheduling and execution.

    Uses APScheduler for production or a simple asyncio-based
    scheduler as fallback.
    """

    def __init__(self):
        self._scheduler: Optional[AsyncIOScheduler] = None
        self._tasks: Dict[str, dict] = {}
        self._running = False
        self._fallback_tasks: Dict[str, asyncio.Task] = {}
        self._task_history: list = []

    async def start(self):
        """Start the scheduler."""
        if self._running:
            return

        self._running = True

        if HAS_APSCHEDULER:
            self._scheduler = AsyncIOScheduler()
            self._scheduler.start()
            logger.info("APScheduler started")
        else:
            logger.warning("APScheduler not available, using fallback scheduler")

        # Register default tasks
        await self._register_default_tasks()

        logger.info("Task scheduler started")

    async def stop(self):
        """Stop the scheduler."""
        self._running = False

        if self._scheduler:
            self._scheduler.shutdown(wait=False)
            self._scheduler = None

        # Cancel fallback tasks
        for task in self._fallback_tasks.values():
            task.cancel()
        self._fallback_tasks.clear()

        logger.info("Task scheduler stopped")

    def add_task(
        self,
        task_id: str,
        func: Callable,
        trigger: str = "interval",
        seconds: int = None,
        minutes: int = None,
        hours: int = None,
        cron: str = None,
        args: tuple = None,
        kwargs: dict = None,
    ):
        """
        Add a scheduled task.

        Args:
            task_id: Unique task identifier
            func: Async function to execute
            trigger: 'interval' or 'cron'
            seconds: Interval in seconds (for interval trigger)
            minutes: Interval in minutes (for interval trigger)
            hours: Interval in hours (for interval trigger)
            cron: Cron expression (for cron trigger)
            args: Positional arguments for func
            kwargs: Keyword arguments for func
        """
        self._tasks[task_id] = {
            "func": func,
            "trigger": trigger,
            "seconds": seconds,
            "minutes": minutes,
            "hours": hours,
            "cron": cron,
            "args": args or (),
            "kwargs": kwargs or {},
            "last_run": None,
            "run_count": 0,
            "error_count": 0,
        }

        if self._scheduler and HAS_APSCHEDULER:
            if trigger == "interval":
                interval_kwargs = {}
                if seconds:
                    interval_kwargs["seconds"] = seconds
                if minutes:
                    interval_kwargs["minutes"] = minutes
                if hours:
                    interval_kwargs["hours"] = hours

                self._scheduler.add_job(
                    self._run_task,
                    IntervalTrigger(**interval_kwargs),
                    id=task_id,
                    args=(task_id,),
                    replace_existing=True,
                )
            elif trigger == "cron" and cron:
                self._scheduler.add_job(
                    self._run_task,
                    CronTrigger.from_crontab(cron),
                    id=task_id,
                    args=(task_id,),
                    replace_existing=True,
                )
        else:
            # Fallback: use asyncio tasks
            self._start_fallback_task(task_id)

        logger.info(f"Task registered: {task_id}")

    def remove_task(self, task_id: str):
        """Remove a scheduled task."""
        if task_id in self._tasks:
            del self._tasks[task_id]

        if self._scheduler:
            try:
                self._scheduler.remove_job(task_id)
            except Exception:
                pass

        if task_id in self._fallback_tasks:
            self._fallback_tasks[task_id].cancel()
            del self._fallback_tasks[task_id]

        logger.info(f"Task removed: {task_id}")

    def _start_fallback_task(self, task_id: str):
        """Start a fallback asyncio task."""
        task_config = self._tasks.get(task_id)
        if not task_config:
            return

        # Calculate interval in seconds
        interval = 0
        if task_config.get("seconds"):
            interval = task_config["seconds"]
        elif task_config.get("minutes"):
            interval = task_config["minutes"] * 60
        elif task_config.get("hours"):
            interval = task_config["hours"] * 3600

        if interval <= 0:
            interval = 60  # Default 1 minute

        async def run_loop():
            while self._running:
                try:
                    await self._run_task(task_id)
                except Exception as e:
                    logger.error(f"Fallback task error {task_id}: {e}")
                await asyncio.sleep(interval)

        self._fallback_tasks[task_id] = asyncio.create_task(run_loop())

    async def _run_task(self, task_id: str):
        """Execute a task and track results."""
        task_config = self._tasks.get(task_id)
        if not task_config:
            return

        started_at = datetime.utcnow()
        result = TaskResult(
            task_id=task_id,
            status=TaskStatus.RUNNING,
            started_at=started_at,
        )

        try:
            func = task_config["func"]
            args = task_config["args"]
            kwargs = task_config["kwargs"]

            if asyncio.iscoroutinefunction(func):
                result.result = await func(*args, **kwargs)
            else:
                result.result = func(*args, **kwargs)

            result.status = TaskStatus.COMPLETED
            task_config["run_count"] += 1
            task_config["consecutive_failures"] = 0

        except Exception as e:
            result.status = TaskStatus.FAILED
            result.error = str(e)
            task_config["error_count"] += 1
            task_config.setdefault("consecutive_failures", 0)
            task_config["consecutive_failures"] += 1
            logger.error(f"Task failed {task_id}: {e}", exc_info=True)

            # Alert on repeated consecutive failures (possible systemic issue)
            if task_config["consecutive_failures"] >= 3:
                logger.critical(
                    f"Task {task_id} has failed {task_config['consecutive_failures']} "
                    f"consecutive times. Total failures: {task_config['error_count']}. "
                    f"Last error: {e}"
                )

        finally:
            result.completed_at = datetime.utcnow()
            result.duration_ms = (result.completed_at - started_at).total_seconds() * 1000
            task_config["last_run"] = result.completed_at

            # Keep history (last 100 entries)
            self._task_history.append(result)
            if len(self._task_history) > 100:
                self._task_history = self._task_history[-100:]

    async def _register_default_tasks(self):
        """Register default scheduled tasks."""
        from .workers import (
            broadcast_stats,
            cleanup_expired,
            process_scheduled_reports,
            check_system_health,
            retry_failed_webhooks,
            monitor_attack_lifecycle,
            collect_traffic_rollup,
        )

        # Stats broadcast - every 1 second
        self.add_task(
            task_id="broadcast_stats",
            func=broadcast_stats,
            trigger="interval",
            seconds=1,
        )

        # NOTE: sync_threat_intel and decay_reputation removed.
        # sync_threat_intel: no threat intel feed infrastructure exists.
        # decay_reputation: no ReputationEntry DB model exists.

        # Cleanup expired entries - every 1 hour
        self.add_task(
            task_id="cleanup_expired",
            func=cleanup_expired,
            trigger="interval",
            hours=1,
        )

        # Check scheduled reports - every 1 minute
        self.add_task(
            task_id="process_reports",
            func=process_scheduled_reports,
            trigger="interval",
            minutes=1,
        )

        # Health check - every 30 seconds
        self.add_task(
            task_id="health_check",
            func=check_system_health,
            trigger="interval",
            seconds=30,
        )

        # Retry webhooks - every 1 minute
        self.add_task(
            task_id="retry_webhooks",
            func=retry_failed_webhooks,
            trigger="interval",
            minutes=1,
        )

        # Attack lifecycle monitor - every 5 seconds
        self.add_task(
            task_id="attack_lifecycle",
            func=monitor_attack_lifecycle,
            trigger="interval",
            seconds=5,
        )

        # Traffic rollup - every 60 seconds
        self.add_task(
            task_id="traffic_rollup",
            func=collect_traffic_rollup,
            trigger="interval",
            seconds=60,
        )

    def get_task_status(self, task_id: str) -> Optional[dict]:
        """Get status of a specific task."""
        task = self._tasks.get(task_id)
        if not task:
            return None

        return {
            "task_id": task_id,
            "trigger": task["trigger"],
            "last_run": task["last_run"].isoformat() if task["last_run"] else None,
            "run_count": task["run_count"],
            "error_count": task["error_count"],
        }

    def get_all_tasks(self) -> list:
        """Get status of all tasks."""
        return [self.get_task_status(tid) for tid in self._tasks.keys()]

    def get_task_history(self, limit: int = 50) -> list:
        """Get recent task execution history."""
        return [
            {
                "task_id": r.task_id,
                "status": r.status.value,
                "started_at": r.started_at.isoformat(),
                "completed_at": r.completed_at.isoformat() if r.completed_at else None,
                "duration_ms": r.duration_ms,
                "error": r.error,
            }
            for r in self._task_history[-limit:]
        ]

    async def run_task_now(self, task_id: str) -> TaskResult:
        """Manually trigger a task execution."""
        await self._run_task(task_id)
        return self._task_history[-1] if self._task_history else None


# Global scheduler instance
_scheduler: Optional[TaskScheduler] = None


def get_scheduler() -> TaskScheduler:
    """Get or create the global scheduler instance."""
    global _scheduler
    if _scheduler is None:
        _scheduler = TaskScheduler()
    return _scheduler


async def start_scheduler():
    """Start the global scheduler."""
    scheduler = get_scheduler()
    await scheduler.start()


async def stop_scheduler():
    """Stop the global scheduler."""
    global _scheduler
    if _scheduler:
        await _scheduler.stop()
        _scheduler = None
