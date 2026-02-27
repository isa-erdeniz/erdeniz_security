"""
erdeniz_security/audit.py — SecurityAuditLog modeli ve log_event/get_alerts/get_stats.
"""
from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)


def _get_request_meta(request: Any | None) -> tuple[str | None, str]:
    if request is None:
        return None, ""
    ip = (request.META.get("HTTP_X_FORWARDED_FOR") or "").split(",")[0].strip() or request.META.get("REMOTE_ADDR")
    ua = request.META.get("HTTP_USER_AGENT", "")
    return ip, ua


def log_event(
    event_type: str,
    resource: str,
    project: str,
    user: Any = None,
    request: Any = None,
    success: bool = True,
    details: dict | None = None,
    duration_ms: int | None = None,
) -> None:
    """Audit kaydı oluştur."""
    ip, user_agent = _get_request_meta(request)
    details = details or {}
    try:
        from .models import SecurityAuditLog
        SecurityAuditLog.objects.create(
            event_type=event_type,
            user_id=user.pk if user and getattr(user, "pk", None) else None,
            ip_address=ip,
            user_agent=user_agent or "",
            resource=resource[:255],
            project=project[:50],
            success=success,
            details=details,
            duration_ms=duration_ms,
        )
    except Exception as e:
        logger.warning("Audit log: %s — %s", event_type, e)


def get_alerts(project: str | None = None, hours: int = 24) -> list[Any]:
    """Son X saatteki SECURITY_ALERT kayıtları."""
    try:
        from django.utils import timezone
        from datetime import timedelta
        from .models import SecurityAuditLog
        since = timezone.now() - timedelta(hours=hours)
        qs = SecurityAuditLog.objects.filter(event_type="SECURITY_ALERT", timestamp__gte=since)
        if project:
            qs = qs.filter(project=project)
        return list(qs.order_by("-timestamp")[:100])
    except Exception:
        return []


def get_stats(project: str | None = None, days: int = 7) -> dict[str, Any]:
    """İstatistik özeti."""
    try:
        from django.utils import timezone
        from datetime import timedelta
        from .models import SecurityAuditLog
        since = timezone.now() - timedelta(days=days)
        qs = SecurityAuditLog.objects.filter(timestamp__gte=since)
        if project:
            qs = qs.filter(project=project)
        return {"total": qs.count(), "failed": qs.filter(success=False).count(), "auth_fail": qs.filter(event_type="AUTH_FAIL").count(), "days": days}
    except Exception:
        return {"total": 0, "failed": 0, "auth_fail": 0, "days": days}
