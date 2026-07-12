"""Escalation on checkout timeout.

When a time-scoped checkout expires without a check-in, the KMS records it in
the audit log and (optionally) POSTs an escalation event to a configured
webhook so a hierarchically senior party / SIEM is notified. The webhook call
is best-effort and never blocks or crashes the KMS.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .logging_setup import get_logger
from .storage import Storage

logger = get_logger("escalation")


def fire_webhook(url: str, payload: dict, timeout: float = 5.0) -> bool:
    """POST a JSON payload. Returns True on 2xx, False otherwise (never raises)."""
    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json", "User-Agent": "qcg-kms"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, OSError, ValueError) as exc:
        logger.warning("escalation_webhook_failed", error=str(exc))
        return False


def process_expired_leases(storage: Storage, webhook_url: str | None) -> int:
    """Expire overdue checkouts, audit each, and fire escalations. Returns count."""
    due = storage.expire_due_leases()
    for lease in due:
        detail = (f"checkout expired without check-in "
                  f"(opened {lease['created_at']:.0f}, due {lease['expires_at']:.0f})")
        storage.audit_append(
            lease["username"], "checkout_timeout", "escalated",
            key_name=lease["key_name"], detail=detail,
        )
        logger.warning("checkout_timeout", lease_id=lease["id"],
                       user=lease["username"], key=lease["key_name"])
        if webhook_url:
            fire_webhook(webhook_url, {
                "event": "checkout_timeout",
                "lease_id": lease["id"],
                "username": lease["username"],
                "key": lease["key_name"],
                "label": lease.get("label"),
                "checked_out_at": lease["created_at"],
                "expired_at": lease["expires_at"],
            })
    return len(due)
