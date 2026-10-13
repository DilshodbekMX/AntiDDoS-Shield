"""
Webhook dispatcher worker.

Handles webhook delivery with HMAC signing and retry logic.
"""

import hmac
import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

# In-memory webhook queue
_failed_webhooks: List[Dict[str, Any]] = []


def _sign_payload(payload: dict, secret: str) -> str:
    """Generate HMAC-SHA256 signature for a webhook payload."""
    body = json.dumps(payload, sort_keys=True, default=str)
    return hmac.new(
        secret.encode(), body.encode(), hashlib.sha256
    ).hexdigest()


def queue_webhook(
    webhook_id: str,
    url: str,
    payload: dict,
    event_type: str,
    secret: str = "",
):
    """Queue a webhook for delivery."""
    _failed_webhooks.append({
        "webhook_id": webhook_id,
        "url": url,
        "payload": payload,
        "event_type": event_type,
        "secret": secret,
        "attempts": 0,
        "max_attempts": 5,
        "created_at": datetime.utcnow(),
        "next_retry_at": datetime.utcnow(),
    })


async def dispatch_event(event_type: str, payload: dict):
    """
    Dispatch an event to all subscribed webhooks.

    Queries enabled webhooks from the database and queues delivery
    for each one that subscribes to this event type.
    """
    try:
        from ...database import get_db
        from ...database.models import Webhook

        db = next(get_db())
        try:
            webhooks = db.query(Webhook).filter(
                Webhook.enabled == True
            ).all()

            queued = 0
            for wh in webhooks:
                events = wh.events or []
                if event_type in events or "*" in events:
                    queue_webhook(
                        webhook_id=str(wh.id),
                        url=wh.url,
                        payload=payload,
                        event_type=event_type,
                        secret=wh.secret or "",
                    )
                    queued += 1

            if queued > 0:
                logger.debug(f"Queued {queued} webhooks for event: {event_type}")
        finally:
            db.close()
    except Exception as e:
        logger.debug(f"Webhook dispatch skipped: {e}")


async def retry_failed_webhooks():
    """
    Retry failed webhook deliveries.

    Runs every minute to retry failed webhooks with
    exponential backoff.
    """
    try:
        now = datetime.utcnow()
        retried = 0
        removed = 0

        # Process webhooks due for retry
        to_process = [w for w in _failed_webhooks if w["next_retry_at"] <= now]

        for webhook in to_process:
            if webhook["attempts"] >= webhook["max_attempts"]:
                _failed_webhooks.remove(webhook)
                removed += 1
                logger.warning(
                    f"Webhook {webhook['webhook_id']} failed after {webhook['attempts']} attempts"
                )
                continue

            success = await _deliver_webhook(webhook)

            if success:
                _failed_webhooks.remove(webhook)
                retried += 1
            else:
                webhook["attempts"] += 1
                backoff = min(3600, 60 * (2 ** webhook["attempts"]))
                webhook["next_retry_at"] = now + timedelta(seconds=backoff)

        if retried > 0 or removed > 0:
            logger.info(f"Webhook retry: delivered={retried}, removed={removed}")

    except Exception as e:
        logger.error(f"Webhook retry failed: {e}")


async def _deliver_webhook(webhook: dict) -> bool:
    """Attempt to deliver a webhook with HMAC signature."""
    try:
        import aiohttp

        now_iso = datetime.utcnow().isoformat()
        secret = webhook.get("secret", "")
        signature = _sign_payload(webhook["payload"], secret) if secret else ""

        headers = {
            "Content-Type": "application/json",
            "X-Webhook-Event": webhook["event_type"],
            "X-Webhook-Timestamp": now_iso,
        }
        if signature:
            headers["X-Webhook-Signature"] = f"sha256={signature}"

        async with aiohttp.ClientSession() as session:
            async with session.post(
                webhook["url"],
                json=webhook["payload"],
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as response:
                return response.status < 400

    except ImportError:
        logger.debug("aiohttp not available for webhook delivery")
        return False
    except Exception as e:
        logger.debug(f"Webhook delivery failed: {e}")
        return False
