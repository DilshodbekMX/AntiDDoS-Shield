"""
Report generator worker.

Processes scheduled reports and generates output files.
"""

import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

_FREQUENCY_DELTAS = {
    "daily": timedelta(days=1),
    "weekly": timedelta(weeks=1),
    "monthly": timedelta(days=30),
    "quarterly": timedelta(days=90),
}


async def process_scheduled_reports():
    """
    Process scheduled reports.

    Runs every minute to check for due reports.
    Iterates over the ReportService's in-memory scheduled list,
    generates reports for any that are past their next_run time,
    and updates next_run.
    """
    try:
        from ...services.report_service import get_report_service
        from ...models import ReportRequest, ReportType, ReportFormat

        now = datetime.utcnow()
        report_service = get_report_service()

        reports_processed = 0

        for sr in report_service._scheduled:
            if not sr.get("enabled", True):
                continue

            next_run_str = sr.get("next_run")
            if not next_run_str:
                continue

            # Parse next_run (stored as ISO string)
            if isinstance(next_run_str, str):
                try:
                    next_run = datetime.fromisoformat(next_run_str)
                except ValueError:
                    continue
            else:
                next_run = next_run_str

            if next_run > now:
                continue

            # This report is due
            try:
                frequency = sr.get("frequency", "daily")
                delta = _FREQUENCY_DELTAS.get(frequency, timedelta(days=1))

                # Determine report period
                end_date = now
                start_date = now - delta

                # Get report type/format
                report_type_val = sr.get("report_type", "traffic")
                if isinstance(report_type_val, str):
                    report_type = ReportType(report_type_val)
                else:
                    report_type = report_type_val

                format_val = sr.get("format", "pdf")
                if isinstance(format_val, str):
                    report_format = ReportFormat(format_val)
                else:
                    report_format = format_val

                request = ReportRequest(
                    report_type=report_type,
                    format=report_format,
                    start_date=start_date,
                    end_date=end_date,
                )

                report = await report_service.generate_report(
                    request=request,
                    generated_by="scheduler",
                )

                # Update schedule
                sr["last_run"] = now.isoformat()
                new_next = report_service._calculate_next_run(
                    frequency, sr.get("time", "00:00")
                )
                sr["next_run"] = new_next.isoformat()

                reports_processed += 1
                logger.info(
                    f"Scheduled report generated: {report.id} "
                    f"(type={report_type_val}, schedule={sr['id']})"
                )

            except Exception as e:
                logger.error(f"Failed to process scheduled report {sr.get('id')}: {e}")

        if reports_processed > 0:
            logger.info(f"Processed {reports_processed} scheduled reports")

    except Exception as e:
        logger.error(f"Report processing failed: {e}")
