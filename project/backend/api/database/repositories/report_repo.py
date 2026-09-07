"""
Report repository for report management.
"""

from typing import Optional, List
from datetime import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models import Report, ReportType, ReportFormat, ReportStatus
from .base import BaseRepository


class ReportRepository(BaseRepository[Report]):
    """Repository for report management."""

    def __init__(self, db: Session):
        super().__init__(Report, db)

    def list_reports(
        self,
        report_type: Optional[ReportType] = None,
        status: Optional[ReportStatus] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[Report]:
        """List reports."""
        query = self.db.query(Report)

        if report_type:
            query = query.filter(Report.report_type == report_type)
        if status:
            query = query.filter(Report.status == status)

        return query.order_by(Report.created_at.desc()).offset(skip).limit(limit).all()

    def count_reports(self) -> int:
        """Count reports."""
        return (
            self.db.query(func.count(Report.id))
            .scalar()
            or 0
        )

    def create_report(
        self,
        report_type: ReportType,
        report_format: ReportFormat = ReportFormat.PDF,
        title: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        generated_by: Optional[str] = None,
    ) -> Report:
        """Create a new report request."""
        report = Report(
            report_type=report_type,
            report_format=report_format,
            title=title,
            start_date=start_date,
            end_date=end_date,
            status=ReportStatus.PENDING,
            generated_by=generated_by,
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        return report

    def set_generating(self, report_id: str) -> Optional[Report]:
        """Mark report as generating."""
        report = self.get(report_id)
        if report:
            report.status = ReportStatus.GENERATING
            self.db.commit()
            self.db.refresh(report)
        return report

    def set_completed(
        self,
        report_id: str,
        file_path: str,
        file_size_bytes: int,
    ) -> Optional[Report]:
        """Mark report as completed."""
        report = self.get(report_id)
        if report:
            report.status = ReportStatus.COMPLETED
            report.file_path = file_path
            report.file_size_bytes = file_size_bytes
            report.generated_at = datetime.utcnow()
            self.db.commit()
            self.db.refresh(report)
        return report

    def set_failed(
        self,
        report_id: str,
        error_message: str,
    ) -> Optional[Report]:
        """Mark report as failed."""
        report = self.get(report_id)
        if report:
            report.status = ReportStatus.FAILED
            report.error_message = error_message
            self.db.commit()
            self.db.refresh(report)
        return report

    def get_pending(self, limit: int = 10) -> List[Report]:
        """Get pending reports for processing."""
        return (
            self.db.query(Report)
            .filter(Report.status == ReportStatus.PENDING)
            .order_by(Report.created_at)
            .limit(limit)
            .all()
        )

    def get_scheduled(self) -> List[Report]:
        """Get scheduled recurring reports."""
        now = datetime.utcnow()
        return (
            self.db.query(Report)
            .filter(
                Report.is_scheduled == True,
                Report.next_run_at <= now,
            )
            .all()
        )

    def schedule_report(
        self,
        report_type: ReportType,
        report_format: ReportFormat,
        schedule_cron: str,
        recipients: List[str],
        title: Optional[str] = None,
    ) -> Report:
        """Create a scheduled recurring report."""
        report = Report(
            report_type=report_type,
            report_format=report_format,
            title=title,
            is_scheduled=True,
            schedule_cron=schedule_cron,
            recipients=recipients,
            status=ReportStatus.PENDING,
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        return report

    def delete_old_reports(self, days: int = 90) -> int:
        """Delete reports older than N days."""
        from datetime import timedelta
        cutoff = datetime.utcnow() - timedelta(days=days)
        result = (
            self.db.query(Report)
            .filter(Report.created_at < cutoff)
            .delete()
        )
        self.db.commit()
        return result
