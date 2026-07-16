"""
Audit Events Adapter

HTTP endpoints for audit event management.
"""

from __future__ import annotations

import logging
from csv import DictWriter
from datetime import datetime, timedelta, timezone
from io import StringIO
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Query

from ...application.ports import AuditEventQuery, AuditEventRepositoryPort

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1/organizations/audit", tags=["audit"])
_audit_repo: AuditEventRepositoryPort | None = None


def configure_audit_router(audit_repo: AuditEventRepositoryPort | None) -> None:
    """Configure audit event storage for this router."""
    global _audit_repo
    _audit_repo = audit_repo


def _require_audit_repo() -> AuditEventRepositoryPort:
    if _audit_repo is None:
        raise HTTPException(
            status_code=501,
            detail={
                "error": "audit_log_unavailable",
                "message": "Organization audit log storage is not configured for this deployment.",
                "message_id": f"audit-{uuid4()}",
            },
        )
    return _audit_repo


def _validate_organization_id(organization_id: str) -> str:
    normalized = str(organization_id or "").strip()
    if not normalized or normalized.lower() in {"null", "undefined"}:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "organization_required",
                "message": "organization_id is required for audit operations.",
                "message_id": f"audit-{uuid4()}",
            },
        )
    return normalized


def _validate_iso_datetime(name: str, value: str | None) -> None:
    if not value:
        return
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_audit_filter",
                "message": f"{name} must be an ISO 8601 datetime.",
                "message_id": f"audit-{uuid4()}",
            },
        ) from None


def _start_date_from_time_range(time_range: str | None) -> str | None:
    if not time_range:
        return None

    normalized = time_range.strip().lower()
    if normalized in {"all", "all_time", "all-time"}:
        return None

    units = {
        "h": "hours",
        "d": "days",
        "w": "weeks",
    }
    unit = normalized[-1:]
    if unit not in units:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_audit_filter",
                "message": "time_range must use h, d, or w units.",
                "message_id": f"audit-{uuid4()}",
            },
        )

    try:
        amount = int(normalized[:-1])
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_audit_filter",
                "message": "time_range must start with a positive integer.",
                "message_id": f"audit-{uuid4()}",
            },
        ) from None

    if amount <= 0:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_audit_filter",
                "message": "time_range must be positive.",
                "message_id": f"audit-{uuid4()}",
            },
        )

    return (datetime.now(timezone.utc) - timedelta(**{units[unit]: amount})).isoformat()


def _query(
    *,
    organization_id: str,
    page: int,
    per_page: int,
    limit: int | None,
    offset: int,
    category: str | None,
    resource_type: str | None,
    resource_id: str | None,
    action: str | None,
    actor: str | None,
    severity: str | None,
    search: str | None,
    ip_address: str | None,
    time_range: str | None,
    start_date: str | None,
    end_date: str | None,
) -> AuditEventQuery:
    if limit is not None:
        per_page = limit
        page = (offset // limit) + 1 if limit else 1

    if start_date is None:
        start_date = _start_date_from_time_range(time_range)

    _validate_iso_datetime("start_date", start_date)
    _validate_iso_datetime("end_date", end_date)

    return AuditEventQuery(
        organization_id=_validate_organization_id(organization_id),
        page=max(1, page),
        per_page=min(max(1, per_page), 1000),
        category=category,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        actor=actor,
        severity=severity,
        search=search,
        ip_address=ip_address,
        start_date=start_date,
        end_date=end_date,
    )


@router.get("/events")
async def list_audit_events(
    organization_id: str = Query(...),
    page: int = Query(1),
    per_page: int = Query(50),
    limit: int | None = Query(None),
    offset: int = Query(0),
    time_range: str | None = Query(None),
    category: str | None = Query(None),
    resource_type: str | None = Query(None),
    resource_id: str | None = Query(None),
    action: str | None = Query(None),
    actor: str | None = Query(None),
    severity: str | None = Query(None),
    search: str | None = Query(None),
    ip_address: str | None = Query(None),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
) -> dict:
    """List audit events for an organization."""
    logger.info("List audit events for org: %s, time_range: %s", organization_id, time_range)
    repo = _require_audit_repo()
    query = _query(
        organization_id=organization_id,
        page=page,
        per_page=per_page,
        limit=limit,
        offset=offset,
        category=category,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        actor=actor,
        severity=severity,
        search=search,
        ip_address=ip_address,
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
    )
    events, total = await repo.list(query)
    return {
        "events": [event.to_dict() for event in events],
        "total": total,
        "page": query.page,
        "per_page": query.per_page,
    }


@router.get("/events/export")
async def export_audit_events(
    organization_id: str = Query(...),
    format: str = Query("csv"),
    time_range: str | None = Query(None),
    category: str | None = Query(None),
    resource_type: str | None = Query(None),
    resource_id: str | None = Query(None),
    action: str | None = Query(None),
    actor: str | None = Query(None),
    severity: str | None = Query(None),
    search: str | None = Query(None),
    ip_address: str | None = Query(None),
    start_date: str | None = Query(None),
    end_date: str | None = Query(None),
) -> dict:
    """Export audit events for an organization."""
    logger.info("Export audit events for org: %s, format: %s", organization_id, format)
    repo = _require_audit_repo()
    query = _query(
        organization_id=organization_id,
        page=1,
        per_page=1000,
        limit=None,
        offset=0,
        category=category,
        resource_type=resource_type,
        resource_id=resource_id,
        action=action,
        actor=actor,
        severity=severity,
        search=search,
        ip_address=ip_address,
        time_range=time_range,
        start_date=start_date,
        end_date=end_date,
    )
    events, total = await repo.list(query)
    rows = [event.to_dict() for event in events]

    normalized_format = format.lower().strip()
    if normalized_format == "json":
        return {
            "format": "json",
            "filename": f"audit-events-{query.organization_id}.json",
            "events": rows,
            "total": total,
        }

    if normalized_format != "csv":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "unsupported_export_format",
                "message": "Audit export format must be csv or json.",
                "message_id": f"audit-{uuid4()}",
            },
        )

    output = StringIO()
    fieldnames = [
        "id",
        "timestamp",
        "actor_id",
        "actor_type",
        "action",
        "category",
        "resource_type",
        "resource_id",
        "resource_name",
        "severity",
        "message",
    ]
    writer = DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return {
        "format": "csv",
        "filename": f"audit-events-{query.organization_id}.csv",
        "content_type": "text/csv",
        "content": output.getvalue(),
        "total": total,
    }


@router.get("/events/{event_id}")
async def get_audit_event(
    event_id: str,
    organization_id: str = Query(...),
) -> dict:
    """Get a single audit event for an organization."""
    logger.info("Get audit event %s for org: %s", event_id, organization_id)
    repo = _require_audit_repo()
    event = await repo.get(_validate_organization_id(organization_id), event_id)
    if event is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "audit_event_not_found",
                "message": "Audit event was not found for this organization.",
                "message_id": f"audit-{uuid4()}",
            },
        )
    return event.to_dict()
