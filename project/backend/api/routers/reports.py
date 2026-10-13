"""
Reports Router

Report generation and management.
"""

import logging
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse

from ..auth import UserContext, get_current_user, get_audit_logger
from ..models import (
    Report, ReportRequest, ReportType, ReportFormat,
    APIResponse, PaginatedResponse
)
from ..services.report_service import get_report_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/reports", tags=["Reports"])


# ==================== Report Management ====================

@router.get("", response_model=APIResponse)
async def list_reports(
    request: Request,
    report_type: Optional[ReportType] = Query(default=None),
    start_date: Optional[datetime] = Query(default=None),
    end_date: Optional[datetime] = Query(default=None),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    user: UserContext = Depends(get_current_user),
):
    """
    List generated reports.
    """
    service = get_report_service()
    reports, total = await service.list_reports(
        report_type=report_type,
        start_date=start_date,
        end_date=end_date,
        page=page,
        per_page=per_page
    )

    pages = (total + per_page - 1) // per_page if per_page > 0 else 0

    return APIResponse(
        success=True,
        data=PaginatedResponse(
            items=reports,
            total=total,
            page=page,
            per_page=per_page,
            pages=pages
        )
    )


@router.post("", response_model=APIResponse)
async def generate_report(
    request: Request,
    report_request: ReportRequest,
    user: UserContext = Depends(get_current_user),
):
    """
    Generate a new report.

    **Report Types:**
    - `incident`: Detailed incident/attack report
    - `traffic`: Traffic analysis report
    - `security`: Security events summary
    - `sla`: SLA compliance report
    - `executive`: High-level executive summary
    - `custom`: Custom report with selected sections
    """
    if not user.is_admin and "reports:generate" not in user.permissions:
        raise HTTPException(status_code=403, detail="Report generation permission required")

    # Validate date range
    if report_request.end_date <= report_request.start_date:
        raise HTTPException(status_code=400, detail="End date must be after start date")

    max_range = timedelta(days=90)
    if report_request.end_date - report_request.start_date > max_range:
        raise HTTPException(
            status_code=400,
            detail=f"Report range too large. Maximum: {max_range.days} days"
        )

    service = get_report_service()

    # Generate report (may be async for large reports)
    report = await service.generate_report(
        report_request,
        generated_by=user.user_id
    )

    get_audit_logger().log_api_action(
        user, "generate_report", f"type:{report_request.report_type}", request
    )

    return APIResponse(
        success=True,
        data=report,
        message=f"Report generation started. ID: {report.id}"
    )


@router.get("/{report_id}", response_model=APIResponse)
async def get_report(
    request: Request,
    report_id: str,
    user: UserContext = Depends(get_current_user),
):
    """
    Get report details and status.
    """
    service = get_report_service()
    report = await service.get_report(report_id)

    if report is None:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    return APIResponse(success=True, data=report)


@router.get("/{report_id}/download")
async def download_report(
    request: Request,
    report_id: str,
    user: UserContext = Depends(get_current_user),
):
    """
    Download a generated report file.
    """
    service = get_report_service()
    report = await service.get_report(report_id)

    if report is None:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    if report.status != "completed":
        raise HTTPException(status_code=400, detail=f"Report not ready. Status: {report.status}")

    if not report.file_path:
        raise HTTPException(status_code=404, detail="Report file not available")

    # Determine media type
    media_types = {
        ReportFormat.PDF: "application/pdf",
        ReportFormat.HTML: "text/html",
        ReportFormat.JSON: "application/json",
        ReportFormat.CSV: "text/csv",
    }
    media_type = media_types.get(report.format, "application/octet-stream")

    # Generate filename
    filename = f"report_{report.report_type}_{report.id}.{report.format}"

    get_audit_logger().log_api_action(
        user, "download_report", f"report:{report_id}", request
    )

    # Validate file_path is within allowed reports directory
    import os
    from ..services.report_service import REPORTS_DIR
    reports_dir = os.path.abspath(str(REPORTS_DIR))
    resolved_path = os.path.abspath(report.file_path)
    if not resolved_path.startswith(reports_dir + os.sep):
        raise HTTPException(status_code=403, detail="Invalid report path")

    # Enforce file size limit (100MB) to prevent memory exhaustion
    MAX_REPORT_SIZE = 100 * 1024 * 1024
    try:
        file_size = os.path.getsize(resolved_path)
        if file_size > MAX_REPORT_SIZE:
            raise HTTPException(
                status_code=413,
                detail=f"Report file too large ({file_size // (1024*1024)}MB). Max: {MAX_REPORT_SIZE // (1024*1024)}MB"
            )
    except OSError:
        raise HTTPException(status_code=404, detail="Report file not found on disk")

    return FileResponse(
        path=resolved_path,
        media_type=media_type,
        filename=filename
    )


@router.delete("/{report_id}", response_model=APIResponse)
async def delete_report(
    request: Request,
    report_id: str,
    user: UserContext = Depends(get_current_user),
):
    """
    Delete a report.
    """
    service = get_report_service()

    report = await service.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Report {report_id} not found")

    await service.delete_report(report_id)

    get_audit_logger().log_api_action(
        user, "delete_report", f"report:{report_id}", request
    )

    return APIResponse(success=True, message=f"Report {report_id} deleted")


# ==================== Quick Reports ====================

@router.get("/quick/daily-summary", response_model=APIResponse)
async def get_daily_summary(
    request: Request,
    date: Optional[datetime] = Query(default=None, description="Date for summary (default: yesterday)"),
    user: UserContext = Depends(get_current_user),
):
    """
    Get a quick daily summary report (JSON).
    """
    if date is None:
        date = datetime.utcnow() - timedelta(days=1)

    service = get_report_service()
    summary = await service.generate_daily_summary(date)

    return APIResponse(success=True, data=summary)


@router.get("/quick/attack-summary", response_model=APIResponse)
async def get_attack_summary(
    request: Request,
    attack_id: str = Query(description="Attack ID to summarize"),
    user: UserContext = Depends(get_current_user),
):
    """
    Get a quick attack summary report (JSON).
    """
    service = get_report_service()
    summary = await service.generate_attack_summary(attack_id)

    if summary is None:
        raise HTTPException(status_code=404, detail=f"Attack {attack_id} not found")

    return APIResponse(success=True, data=summary)


@router.get("/quick/sla-status", response_model=APIResponse)
async def get_sla_status(
    request: Request,
    period: str = Query(default="30d", pattern="^(7d|30d|90d)$"),
    user: UserContext = Depends(get_current_user),
):
    """
    Get quick SLA compliance status (JSON).
    """
    service = get_report_service()
    sla_status = await service.get_sla_status(period)

    return APIResponse(success=True, data=sla_status)


# ==================== Scheduled Reports ====================

@router.get("/scheduled", response_model=APIResponse)
async def list_scheduled_reports(
    request: Request,
    user: UserContext = Depends(get_current_user),
):
    """
    List scheduled report configurations.
    """
    service = get_report_service()
    scheduled = await service.list_scheduled_reports()

    return APIResponse(success=True, data=scheduled)


@router.post("/scheduled", response_model=APIResponse)
async def create_scheduled_report(
    request: Request,
    schedule: dict,
    user: UserContext = Depends(get_current_user),
):
    """
    Create a scheduled report.

    **Schedule options:**
    - `frequency`: daily, weekly, monthly
    - `time`: Time of day to generate (UTC)
    - `report_type`: Type of report to generate
    - `format`: Output format
    - `recipients`: Email addresses to send to
    """
    if not user.is_admin and "reports:schedule" not in user.permissions:
        raise HTTPException(status_code=403, detail="Report scheduling permission required")

    service = get_report_service()
    created = await service.create_scheduled_report(schedule, created_by=user.user_id)

    get_audit_logger().log_api_action(
        user, "schedule_report", f"scheduled", request
    )

    return APIResponse(success=True, data=created, message="Scheduled report created")


@router.delete("/scheduled/{schedule_id}", response_model=APIResponse)
async def delete_scheduled_report(
    request: Request,
    schedule_id: str,
    user: UserContext = Depends(get_current_user),
):
    """
    Delete a scheduled report configuration.
    """
    service = get_report_service()
    await service.delete_scheduled_report(schedule_id)

    get_audit_logger().log_api_action(
        user, "delete_schedule", f"schedule:{schedule_id}", request
    )

    return APIResponse(success=True, message="Scheduled report deleted")
