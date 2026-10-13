"""
Report Service

Business logic for report generation.
"""

import logging
import uuid
import os
import json
from datetime import datetime, timedelta
from typing import Optional, List, Tuple, Dict, Any
from pathlib import Path
from io import BytesIO

# PDF generation with reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

from ..models import (
    Report, ReportRequest, ReportType, ReportFormat
)
from ..database import get_db
from ..database.repositories.attack_repo import AttackRepository
from ..database.repositories.traffic_repo import TrafficRepository

logger = logging.getLogger(__name__)

# Report storage directory
REPORTS_DIR = Path("/tmp/antiddos_reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


class ReportService:
    """
    Service layer for report generation.

    In production, this would:
    - Generate actual PDF/HTML reports using templates
    - Store reports in object storage
    - Handle async report generation for large reports
    - Integrate with email system for scheduled reports
    """

    def __init__(self):
        # In-memory store for demo
        self._reports: Dict[str, Report] = {}
        self._scheduled: List[Dict] = []

    def _get_reports_dict(self) -> Dict[str, Report]:
        """Get or create reports dict."""
        return self._reports

    async def list_reports(
        self,
        report_type: Optional[ReportType] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        page: int = 1,
        per_page: int = 20
    ) -> Tuple[List[Report], int]:
        """List generated reports."""
        reports = list(self._get_reports_dict().values())

        # Filter
        if report_type:
            reports = [r for r in reports if r.report_type == report_type]
        if start_date:
            reports = [r for r in reports if r.generated_at >= start_date]
        if end_date:
            reports = [r for r in reports if r.generated_at <= end_date]

        # Sort by generated_at desc
        reports.sort(key=lambda r: r.generated_at, reverse=True)

        total = len(reports)

        # Paginate
        start = (page - 1) * per_page
        end = start + per_page
        paginated = reports[start:end]

        return paginated, total

    async def get_report(
        self,
        report_id: str
    ) -> Optional[Report]:
        """Get a specific report."""
        reports = self._get_reports_dict()
        return reports.get(report_id)

    async def generate_report(
        self,
        request: ReportRequest,
        generated_by: str
    ) -> Report:
        """Generate a new report."""
        report_id = str(uuid.uuid4())[:8]
        reports = self._get_reports_dict()

        # Create reports directory
        reports_dir = REPORTS_DIR
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Generate report content based on type
        report_data = self._generate_report_content(
            request.report_type, request.start_date, request.end_date
        )

        # Determine file extension
        format_ext = request.format.value if hasattr(request.format, 'value') else str(request.format)
        file_path = reports_dir / f"{report_id}.{format_ext}"

        # Write report file based on format
        if format_ext == "json":
            content = json.dumps(report_data, indent=2, default=str)
            file_path.write_text(content)
        elif format_ext == "csv":
            content = self._generate_csv_report(report_data)
            file_path.write_text(content)
        elif format_ext == "html":
            content = self._generate_html_report(report_data, request.report_type)
            file_path.write_text(content)
        elif format_ext == "pdf":
            # Generate actual PDF using reportlab
            self._generate_pdf_report(report_data, request.report_type, str(file_path))
        else:
            content = json.dumps(report_data, indent=2, default=str)
            file_path.write_text(content)

        file_size = file_path.stat().st_size

        report = Report(
            id=report_id,
            report_type=request.report_type,
            format=request.format,
            start_date=request.start_date,
            end_date=request.end_date,
            generated_at=datetime.utcnow(),
            generated_by=generated_by,
            file_path=str(file_path),
            file_size_bytes=file_size,
            status="completed",
        )

        reports[report_id] = report

        logger.info(f"Generated report {report_id} by {generated_by}")
        return report

    def _generate_report_content(
        self,
        report_type: ReportType,
        start_date: datetime,
        end_date: datetime
    ) -> Dict[str, Any]:
        """Generate report content from real database data.

        Each report type includes different sections:
        - executive: summary + traffic overview + attack count (brief)
        - incident: attack details + security events timeline + top sources
        - traffic: traffic analysis + drop reasons + bandwidth
        - security: security stats + drop reasons + events + top sources
        - sla: SLA metrics + availability + mitigation effectiveness
        - custom: all sections
        """
        # Extend end_date to end-of-day if it's at midnight (date-only input)
        if end_date.hour == 0 and end_date.minute == 0 and end_date.second == 0:
            end_date = end_date.replace(hour=23, minute=59, second=59)

        db = next(get_db())
        try:
            attack_repo = AttackRepository(db)
            traffic_repo = TrafficRepository(db)

            days = max(1, (end_date - start_date).days)
            attack_stats = attack_repo.get_attack_stats(days=days)
            attacks = attack_repo.list_attacks(
                start_date=start_date, end_date=end_date, limit=100
            )
            traffic_summary = traffic_repo.get_summary(start_date, end_date)

            # Common metadata
            total_min = max(traffic_summary.get('total_minutes', 1), 1)
            report = {
                "report_metadata": {
                    "report_type": report_type.value,
                    "report_title": self._report_title(report_type),
                    "start_date": start_date.isoformat(),
                    "end_date": end_date.isoformat(),
                    "generated_at": datetime.utcnow().isoformat(),
                    "period_days": days,
                },
                "summary": {
                    "total_traffic_packets": traffic_summary.get('total_rx_packets', 0),
                    "total_traffic_bytes": int(traffic_summary.get('avg_rx_bps', 0) * total_min * 60),
                    "attacks_detected": attack_stats.get('total', 0),
                    "attacks_mitigated": attack_stats.get('mitigated', 0),
                    "attacks_active": attack_stats.get('active', 0),
                    "availability_pct": traffic_summary.get('availability_pct', 100.0),
                    "total_dropped": traffic_summary.get('total_dropped', 0),
                },
            }

            # --- Type-specific sections ---

            # Traffic analysis (executive, traffic, custom)
            if report_type in (ReportType.EXECUTIVE, ReportType.TRAFFIC, ReportType.CUSTOM):
                drops = traffic_summary.get('drops_by_reason', {})
                report["traffic_analysis"] = {
                    "peak_pps": traffic_summary.get('peak_rx_pps', 0),
                    "peak_bps": traffic_summary.get('peak_rx_bps', 0),
                    "avg_pps": traffic_summary.get('avg_rx_pps', 0),
                    "avg_bps": traffic_summary.get('avg_rx_bps', 0),
                    "peak_tx_pps": traffic_summary.get('peak_tx_pps', 0),
                    "peak_tx_bps": traffic_summary.get('peak_tx_bps', 0),
                    "avg_tx_pps": traffic_summary.get('avg_tx_pps', 0),
                    "avg_tx_bps": traffic_summary.get('avg_tx_bps', 0),
                    "total_minutes": total_min,
                }
                report["drops_by_reason"] = {k: v for k, v in drops.items() if v > 0}

            # Attack details (incident, custom)
            if report_type in (ReportType.INCIDENT, ReportType.CUSTOM):
                attack_details = []
                for a in attacks[:20]:
                    duration_sec = 0
                    if a.ended_at and a.started_at:
                        duration_sec = int((a.ended_at - a.started_at).total_seconds())
                    attack_details.append({
                        "id": a.id,
                        "target_ip": a.target_ip,
                        "attack_type": a.attack_type.value,
                        "severity": a.severity.value,
                        "started_at": a.started_at.isoformat(),
                        "ended_at": a.ended_at.isoformat() if a.ended_at else "ongoing",
                        "duration_sec": duration_sec,
                        "peak_pps": a.peak_pps or 0,
                        "peak_bps": a.peak_bps or 0,
                        "packets_dropped": a.packets_dropped or 0,
                        "source_ips_count": a.source_ips_count or 0,
                        "is_mitigated": a.is_mitigated,
                        "mitigation_time_ms": a.mitigation_time_ms or 0,
                    })
                report["attack_details"] = attack_details

            # Security events (incident, security, custom)
            if report_type in (ReportType.INCIDENT, ReportType.SECURITY, ReportType.CUSTOM):
                security_events = []
                for a in attacks[:20]:
                    security_events.append({
                        "timestamp": a.started_at.isoformat(),
                        "event_type": "attack_detected",
                        "severity": a.severity.value,
                        "source_ip": a.target_ip,
                        "details": f"{a.attack_type.value} attack targeting {a.target_ip}",
                    })
                    if a.ended_at:
                        security_events.append({
                            "timestamp": a.ended_at.isoformat(),
                            "event_type": "attack_mitigated",
                            "severity": a.severity.value,
                            "source_ip": a.target_ip,
                            "details": f"Mitigated after {int((a.ended_at - a.started_at).total_seconds())}s",
                        })
                security_events.sort(key=lambda e: e["timestamp"], reverse=True)
                report["security_events"] = security_events

            # Top sources (incident, security, custom)
            if report_type in (ReportType.INCIDENT, ReportType.SECURITY, ReportType.CUSTOM):
                top_sources = []
                seen_ips = set()
                for a in attacks:
                    for ip in (a.top_source_ips or []):
                        if ip not in seen_ips and len(top_sources) < 10:
                            seen_ips.add(ip)
                            top_sources.append({
                                "ip": ip,
                                "country": "Unknown",
                                "packets": a.packets_dropped or 0,
                                "bytes": a.bytes_dropped or 0,
                            })
                report["top_sources"] = top_sources

            # Security stats (security, custom)
            if report_type in (ReportType.SECURITY, ReportType.CUSTOM):
                drops = traffic_summary.get('drops_by_reason', {})
                report["security_stats"] = {
                    "blacklist_hits": drops.get('Blacklist', 0),
                    "rate_limit_drops": drops.get('Rate Limit', 0),
                    "geo_blocks": drops.get('Geo Blocked', 0),
                    "syn_proxy_challenges": drops.get('SYN Flood', 0),
                    "signature_matches": drops.get('Signature Match', 0),
                    "reputation_drops": drops.get('Reputation', 0),
                    "validation_errors": drops.get('Validation Error', 0),
                }
                report["drops_by_reason"] = {k: v for k, v in drops.items() if v > 0}

            # SLA metrics (sla, executive, custom)
            if report_type in (ReportType.SLA, ReportType.EXECUTIVE, ReportType.CUSTOM):
                total_attacks = attack_stats.get('total', 0)
                mitigated = attack_stats.get('mitigated', 0)
                effectiveness = (mitigated / max(total_attacks, 1)) * 100
                anomaly_min = traffic_summary.get('anomaly_minutes', 0)
                report["sla_metrics"] = {
                    "availability_pct": round(traffic_summary.get('availability_pct', 100.0), 3),
                    "uptime_minutes": total_min - anomaly_min,
                    "downtime_minutes": anomaly_min,
                    "total_minutes": total_min,
                    "avg_mitigation_time_ms": round(attack_stats.get('avg_mitigation_time_ms', 0), 2),
                    "mitigation_effectiveness_pct": round(effectiveness, 2),
                    "sla_target_pct": 99.9,
                    "sla_compliant": traffic_summary.get('availability_pct', 100.0) >= 99.9,
                    "sla_breaches": 1 if traffic_summary.get('availability_pct', 100.0) < 99.9 else 0,
                }

            # Attack type breakdown (executive, security, custom)
            if report_type in (ReportType.EXECUTIVE, ReportType.SECURITY, ReportType.CUSTOM):
                report["attack_breakdown"] = attack_stats.get('by_type', {})
                report["severity_breakdown"] = attack_stats.get('by_severity', {})

            return report
        finally:
            db.close()

    @staticmethod
    def _report_title(report_type: ReportType) -> str:
        """Map report type to human-readable title."""
        return {
            ReportType.EXECUTIVE: "Executive Summary",
            ReportType.INCIDENT: "Incident Report",
            ReportType.TRAFFIC: "Traffic Analysis Report",
            ReportType.SECURITY: "Security Audit Report",
            ReportType.SLA: "SLA Compliance Report",
            ReportType.CUSTOM: "Custom Report",
        }.get(report_type, "Security Report")

    def _generate_csv_report(self, data: Dict[str, Any]) -> str:
        """Generate CSV formatted report."""
        meta = data['report_metadata']
        lines = [
            meta.get('report_title', 'Anti-DDoS Report'),
            f"Generated: {meta['generated_at']}",
            f"Period: {meta['start_date'][:10]} to {meta['end_date'][:10]}",
            "",
            "SUMMARY",
            "Metric,Value",
        ]
        for key, value in data['summary'].items():
            lines.append(f"{key},{value}")

        if 'traffic_analysis' in data:
            lines += ["", "TRAFFIC ANALYSIS", "Metric,Value"]
            for key, value in data['traffic_analysis'].items():
                lines.append(f"{key},{value}")

        if 'drops_by_reason' in data:
            lines += ["", "DROP REASONS", "Reason,Count"]
            for reason, count in data['drops_by_reason'].items():
                lines.append(f"{reason},{count}")

        if 'security_stats' in data:
            lines += ["", "SECURITY STATS", "Metric,Value"]
            for key, value in data['security_stats'].items():
                lines.append(f"{key},{value}")

        if 'sla_metrics' in data:
            lines += ["", "SLA METRICS", "Metric,Value"]
            for key, value in data['sla_metrics'].items():
                lines.append(f"{key},{value}")

        if 'attack_details' in data:
            lines += ["", "ATTACK DETAILS", "ID,Target,Type,Severity,Started,Duration(s),Peak PPS,Dropped"]
            for a in data['attack_details']:
                lines.append(f"{a['id']},{a['target_ip']},{a['attack_type']},{a['severity']},{a['started_at'][:19]},{a['duration_sec']},{a['peak_pps']},{a['packets_dropped']}")

        if 'top_sources' in data:
            lines += ["", "TOP ATTACK SOURCES", "IP,Country,Packets,Bytes"]
            for src in data['top_sources']:
                lines.append(f"{src['ip']},{src['country']},{src['packets']},{src['bytes']}")

        if 'security_events' in data:
            lines += ["", "SECURITY EVENTS", "Timestamp,Type,Severity,Source IP"]
            for evt in data['security_events']:
                lines.append(f"{evt['timestamp'][:19]},{evt['event_type']},{evt['severity']},{evt['source_ip']}")

        return "\n".join(lines)

    def _generate_html_report(self, data: Dict[str, Any], report_type: ReportType) -> str:
        """Generate HTML formatted report with type-specific sections."""
        meta = data['report_metadata']
        title = meta.get('report_title', 'Security Report')
        period = f"{meta['start_date'][:10]} to {meta['end_date'][:10]}"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #0f172a; color: #e2e8f0; }}
        .header {{ background: linear-gradient(135deg, #6366f1 0%, #8b5cf6 100%); padding: 30px; border-radius: 12px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; color: white; font-size: 28px; }}
        .header p {{ margin: 10px 0 0; color: rgba(255,255,255,0.8); }}
        .card {{ background: #1e293b; border-radius: 12px; padding: 24px; margin-bottom: 20px; border: 1px solid #334155; }}
        .card h2 {{ margin: 0 0 20px; color: #f8fafc; font-size: 18px; border-bottom: 1px solid #334155; padding-bottom: 10px; }}
        .metrics {{ display: flex; flex-wrap: wrap; gap: 8px; }}
        .metric {{ background: #0f172a; padding: 16px 24px; border-radius: 8px; min-width: 150px; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: #6366f1; }}
        .metric-value.green {{ color: #22c55e; }}
        .metric-value.red {{ color: #ef4444; }}
        .metric-value.amber {{ color: #f59e0b; }}
        .metric-label {{ font-size: 12px; color: #94a3b8; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; font-weight: 500; font-size: 12px; text-transform: uppercase; }}
        tr:hover {{ background: #334155; }}
        .severity-critical {{ color: #ef4444; }}
        .severity-high {{ color: #f97316; }}
        .severity-medium {{ color: #eab308; }}
        .severity-low {{ color: #22c55e; }}
        .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }}
        .badge-ok {{ background: #052e16; color: #22c55e; }}
        .badge-fail {{ background: #450a0a; color: #ef4444; }}
        .empty {{ color: #64748b; font-style: italic; padding: 20px; text-align: center; }}
        .footer {{ text-align: center; color: #64748b; font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>{title}</h1>
        <p>Period: {period}</p>
    </div>
"""
        s = data['summary']

        # --- Summary card (all types) ---
        html += f"""    <div class="card">
        <h2>Summary</h2>
        <div class="metrics">
            <div class="metric"><div class="metric-value">{s['total_traffic_packets']:,}</div><div class="metric-label">Total Packets</div></div>
            <div class="metric"><div class="metric-value">{s['attacks_detected']}</div><div class="metric-label">Attacks Detected</div></div>
            <div class="metric"><div class="metric-value">{s['attacks_mitigated']}</div><div class="metric-label">Attacks Mitigated</div></div>
            <div class="metric"><div class="metric-value">{s['availability_pct']}%</div><div class="metric-label">Availability</div></div>
            <div class="metric"><div class="metric-value">{s['total_dropped']:,}</div><div class="metric-label">Packets Dropped</div></div>
        </div>
    </div>
"""

        # --- Traffic Analysis (executive, traffic, custom) ---
        if 'traffic_analysis' in data:
            t = data['traffic_analysis']
            html += f"""    <div class="card">
        <h2>Traffic Analysis</h2>
        <div class="metrics">
            <div class="metric"><div class="metric-value">{t['peak_pps']:,}</div><div class="metric-label">Peak RX PPS</div></div>
            <div class="metric"><div class="metric-value">{t['avg_pps']:,}</div><div class="metric-label">Avg RX PPS</div></div>
            <div class="metric"><div class="metric-value">{t['peak_bps']:,}</div><div class="metric-label">Peak RX BPS</div></div>
            <div class="metric"><div class="metric-value">{t['avg_bps']:,}</div><div class="metric-label">Avg RX BPS</div></div>
            <div class="metric"><div class="metric-value">{t['peak_tx_pps']:,}</div><div class="metric-label">Peak TX PPS</div></div>
            <div class="metric"><div class="metric-value">{t['avg_tx_pps']:,}</div><div class="metric-label">Avg TX PPS</div></div>
        </div>
    </div>
"""

        # --- Drop Reasons (traffic, security, custom) ---
        if 'drops_by_reason' in data and data['drops_by_reason']:
            html += """    <div class="card">
        <h2>Drop Reasons</h2>
        <table><thead><tr><th>Reason</th><th>Count</th></tr></thead><tbody>
"""
            for reason, count in sorted(data['drops_by_reason'].items(), key=lambda x: -x[1]):
                html += f"            <tr><td>{reason}</td><td>{count:,}</td></tr>\n"
            html += """        </tbody></table>
    </div>
"""

        # --- SLA Metrics (sla, executive, custom) ---
        if 'sla_metrics' in data:
            sla = data['sla_metrics']
            badge = 'badge-ok' if sla['sla_compliant'] else 'badge-fail'
            badge_text = 'COMPLIANT' if sla['sla_compliant'] else 'BREACH'
            avail_class = 'green' if sla['availability_pct'] >= 99.9 else 'red'
            html += f"""    <div class="card">
        <h2>SLA Compliance <span class="badge {badge}">{badge_text}</span></h2>
        <div class="metrics">
            <div class="metric"><div class="metric-value {avail_class}">{sla['availability_pct']}%</div><div class="metric-label">Availability (target: {sla['sla_target_pct']}%)</div></div>
            <div class="metric"><div class="metric-value">{sla['uptime_minutes']:,}</div><div class="metric-label">Uptime (minutes)</div></div>
            <div class="metric"><div class="metric-value">{sla['downtime_minutes']:,}</div><div class="metric-label">Downtime (minutes)</div></div>
            <div class="metric"><div class="metric-value">{sla['avg_mitigation_time_ms']:,.0f}</div><div class="metric-label">Avg Mitigation (ms)</div></div>
            <div class="metric"><div class="metric-value">{sla['mitigation_effectiveness_pct']}%</div><div class="metric-label">Mitigation Effectiveness</div></div>
        </div>
    </div>
"""

        # --- Security Stats (security, custom) ---
        if 'security_stats' in data:
            ss = data['security_stats']
            html += f"""    <div class="card">
        <h2>Security Statistics</h2>
        <div class="metrics">
            <div class="metric"><div class="metric-value">{ss['blacklist_hits']:,}</div><div class="metric-label">Blacklist Hits</div></div>
            <div class="metric"><div class="metric-value">{ss['rate_limit_drops']:,}</div><div class="metric-label">Rate Limit Drops</div></div>
            <div class="metric"><div class="metric-value">{ss['geo_blocks']:,}</div><div class="metric-label">Geo Blocks</div></div>
            <div class="metric"><div class="metric-value">{ss['syn_proxy_challenges']:,}</div><div class="metric-label">SYN Proxy Challenges</div></div>
            <div class="metric"><div class="metric-value">{ss['signature_matches']:,}</div><div class="metric-label">Signature Matches</div></div>
            <div class="metric"><div class="metric-value">{ss['reputation_drops']:,}</div><div class="metric-label">Reputation Drops</div></div>
        </div>
    </div>
"""

        # --- Attack type/severity breakdown (executive, security, custom) ---
        if 'attack_breakdown' in data and data['attack_breakdown']:
            html += """    <div class="card">
        <h2>Attack Breakdown</h2>
        <table><thead><tr><th>Attack Type</th><th>Count</th></tr></thead><tbody>
"""
            for atype, cnt in sorted(data['attack_breakdown'].items(), key=lambda x: -x[1]):
                html += f"            <tr><td>{atype.replace('_', ' ').title()}</td><td>{cnt}</td></tr>\n"
            html += """        </tbody></table>
    </div>
"""

        # --- Attack Details (incident, custom) ---
        if 'attack_details' in data:
            attacks_list = data['attack_details']
            if attacks_list:
                html += """    <div class="card">
        <h2>Attack Details</h2>
        <table><thead><tr><th>Target</th><th>Type</th><th>Severity</th><th>Started</th><th>Duration</th><th>Peak PPS</th><th>Dropped</th><th>Status</th></tr></thead><tbody>
"""
                for a in attacks_list:
                    sev_class = f"severity-{a['severity']}"
                    dur = f"{a['duration_sec']}s" if a['duration_sec'] else "ongoing"
                    status = "Mitigated" if a['is_mitigated'] else "Active"
                    html += f"""            <tr><td><code>{a['target_ip']}</code></td><td>{a['attack_type'].replace('_',' ').title()}</td><td class="{sev_class}">{a['severity'].upper()}</td><td>{a['started_at'][:19]}</td><td>{dur}</td><td>{a['peak_pps']:,}</td><td>{a['packets_dropped']:,}</td><td>{status}</td></tr>\n"""
                html += """        </tbody></table>
    </div>
"""
            else:
                html += '    <div class="card"><h2>Attack Details</h2><div class="empty">No attacks recorded in this period.</div></div>\n'

        # --- Top Sources (incident, security, custom) ---
        if 'top_sources' in data:
            sources = data['top_sources']
            html += """    <div class="card">
        <h2>Top Attack Sources</h2>
"""
            if sources:
                html += """        <table><thead><tr><th>IP Address</th><th>Country</th><th>Packets</th><th>Bytes</th></tr></thead><tbody>
"""
                for src in sources:
                    html += f"""            <tr><td><code>{src['ip']}</code></td><td>{src['country']}</td><td>{src['packets']:,}</td><td>{src['bytes']:,}</td></tr>\n"""
                html += """        </tbody></table>
"""
            else:
                html += '        <div class="empty">No attack sources recorded in this period.</div>\n'
            html += "    </div>\n"

        # --- Security Events (incident, security, custom) ---
        if 'security_events' in data:
            events = data['security_events'][:15]
            html += """    <div class="card">
        <h2>Security Events</h2>
"""
            if events:
                html += """        <table><thead><tr><th>Timestamp</th><th>Event Type</th><th>Severity</th><th>Details</th></tr></thead><tbody>
"""
                for evt in events:
                    sev_class = f"severity-{evt['severity']}"
                    html += f"""            <tr><td>{evt['timestamp'][:19]}</td><td>{evt['event_type'].replace('_',' ').title()}</td><td class="{sev_class}">{evt['severity'].upper()}</td><td>{evt['details']}</td></tr>\n"""
                html += """        </tbody></table>
"""
            else:
                html += '        <div class="empty">No security events in this period.</div>\n'
            html += "    </div>\n"

        # --- Footer ---
        html += f"""
    <div class="footer">
        <p>Generated by Anti-DDoS Platform</p>
        <p>{meta['generated_at']}</p>
    </div>
</body>
</html>"""
        return html

    @staticmethod
    def _pdf_table(rows, col_widths, header_color='#6366f1', body_color='#f8fafc', grid_color='#e2e8f0'):
        """Create a styled reportlab Table."""
        t = Table(rows, colWidths=col_widths)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor(header_color)),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor(body_color)),
            ('TEXTCOLOR', (0, 1), (-1, -1), colors.HexColor('#1e293b')),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor(grid_color)),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
        ]))
        return t

    def _generate_pdf_report(self, data: Dict[str, Any], report_type: ReportType, file_path: str) -> None:
        """Generate PDF report with type-specific sections using reportlab."""
        doc = SimpleDocTemplate(file_path, pagesize=A4,
                                rightMargin=50, leftMargin=50, topMargin=50, bottomMargin=50)
        styles = getSampleStyleSheet()
        meta = data['report_metadata']
        title = meta.get('report_title', 'Security Report')

        title_style = ParagraphStyle('T', parent=styles['Heading1'], fontSize=24,
                                     textColor=colors.HexColor('#6366f1'), spaceAfter=20, alignment=TA_CENTER)
        sub_style = ParagraphStyle('S', parent=styles['Normal'], fontSize=12,
                                   textColor=colors.HexColor('#64748b'), spaceAfter=30, alignment=TA_CENTER)
        sec_style = ParagraphStyle('H', parent=styles['Heading2'], fontSize=14,
                                   textColor=colors.HexColor('#1e293b'), spaceBefore=20, spaceAfter=10)
        footer_style = ParagraphStyle('F', parent=styles['Normal'], fontSize=9,
                                      textColor=colors.HexColor('#94a3b8'), alignment=TA_CENTER)
        note_style = ParagraphStyle('N', parent=styles['Normal'], fontSize=10,
                                    textColor=colors.HexColor('#64748b'), spaceAfter=8)

        story = []
        story.append(Paragraph(title, title_style))
        story.append(Paragraph(f"Period: {meta['start_date'][:10]} to {meta['end_date'][:10]}", sub_style))
        story.append(Spacer(1, 20))

        # --- Summary (all types) ---
        s = data['summary']
        story.append(Paragraph("Summary", sec_style))
        story.append(self._pdf_table(
            [['Metric', 'Value'],
             ['Total Packets', f"{s['total_traffic_packets']:,}"],
             ['Packets Dropped', f"{s['total_dropped']:,}"],
             ['Attacks Detected', str(s['attacks_detected'])],
             ['Attacks Mitigated', str(s['attacks_mitigated'])],
             ['Availability', f"{s['availability_pct']}%"]],
            [3*inch, 2.5*inch], '#6366f1'))
        story.append(Spacer(1, 20))

        # --- Traffic Analysis ---
        if 'traffic_analysis' in data:
            t = data['traffic_analysis']
            story.append(Paragraph("Traffic Analysis", sec_style))
            story.append(self._pdf_table(
                [['Metric', 'Value'],
                 ['Peak RX PPS', f"{t['peak_pps']:,}"],
                 ['Avg RX PPS', f"{t['avg_pps']:,}"],
                 ['Peak RX BPS', f"{t['peak_bps']:,}"],
                 ['Avg RX BPS', f"{t['avg_bps']:,}"],
                 ['Peak TX PPS', f"{t['peak_tx_pps']:,}"],
                 ['Avg TX PPS', f"{t['avg_tx_pps']:,}"]],
                [3*inch, 2.5*inch], '#10b981', '#f0fdf4', '#d1fae5'))
            story.append(Spacer(1, 20))

        # --- Drop Reasons ---
        if 'drops_by_reason' in data and data['drops_by_reason']:
            story.append(Paragraph("Drop Reasons", sec_style))
            rows = [['Reason', 'Count']]
            for reason, count in sorted(data['drops_by_reason'].items(), key=lambda x: -x[1]):
                rows.append([reason, f"{count:,}"])
            story.append(self._pdf_table(rows, [3*inch, 2.5*inch], '#3b82f6', '#eff6ff', '#bfdbfe'))
            story.append(Spacer(1, 20))

        # --- SLA Metrics ---
        if 'sla_metrics' in data:
            sla = data['sla_metrics']
            status = "COMPLIANT" if sla['sla_compliant'] else "SLA BREACH"
            story.append(Paragraph(f"SLA Compliance — {status}", sec_style))
            story.append(self._pdf_table(
                [['Metric', 'Value'],
                 ['Availability', f"{sla['availability_pct']}%"],
                 ['Target', f"{sla['sla_target_pct']}%"],
                 ['Uptime (min)', f"{sla['uptime_minutes']:,}"],
                 ['Downtime (min)', f"{sla['downtime_minutes']:,}"],
                 ['Avg Mitigation (ms)', f"{sla['avg_mitigation_time_ms']:,.0f}"],
                 ['Effectiveness', f"{sla['mitigation_effectiveness_pct']}%"]],
                [3*inch, 2.5*inch], '#8b5cf6', '#faf5ff', '#e9d5ff'))
            story.append(Spacer(1, 20))

        # --- Security Stats ---
        if 'security_stats' in data:
            ss = data['security_stats']
            story.append(Paragraph("Security Statistics", sec_style))
            rows = [['Metric', 'Count']]
            for label, key in [('Blacklist Hits', 'blacklist_hits'), ('Rate Limit Drops', 'rate_limit_drops'),
                               ('Geo Blocks', 'geo_blocks'), ('SYN Proxy Challenges', 'syn_proxy_challenges'),
                               ('Signature Matches', 'signature_matches'), ('Reputation Drops', 'reputation_drops')]:
                rows.append([label, f"{ss.get(key, 0):,}"])
            story.append(self._pdf_table(rows, [3*inch, 2.5*inch], '#ef4444', '#fef2f2', '#fecaca'))
            story.append(Spacer(1, 20))

        # --- Attack Details ---
        if 'attack_details' in data and data['attack_details']:
            story.append(Paragraph("Attack Details", sec_style))
            rows = [['Target', 'Type', 'Severity', 'Duration', 'Peak PPS', 'Dropped']]
            for a in data['attack_details'][:15]:
                dur = f"{a['duration_sec']}s" if a['duration_sec'] else "ongoing"
                rows.append([
                    a['target_ip'], a['attack_type'].replace('_', ' ').title(),
                    a['severity'].upper(), dur, f"{a['peak_pps']:,}", f"{a['packets_dropped']:,}",
                ])
            story.append(self._pdf_table(
                rows, [1.2*inch, 1*inch, 0.8*inch, 0.7*inch, 0.9*inch, 0.9*inch],
                '#f59e0b', '#fffbeb', '#fde68a'))
            story.append(Spacer(1, 20))

        # --- Top Sources ---
        if 'top_sources' in data and data['top_sources']:
            story.append(Paragraph("Top Attack Sources", sec_style))
            rows = [['IP Address', 'Country', 'Packets', 'Bytes']]
            for src in data['top_sources'][:10]:
                rows.append([src['ip'], src['country'], f"{src['packets']:,}", f"{src['bytes']:,}"])
            story.append(self._pdf_table(
                rows, [1.8*inch, 1*inch, 1.3*inch, 1.4*inch],
                '#ef4444', '#fef2f2', '#fecaca'))
            story.append(Spacer(1, 20))

        # --- Security Events ---
        if 'security_events' in data and data['security_events']:
            story.append(Paragraph("Security Events", sec_style))
            rows = [['Timestamp', 'Event', 'Severity', 'Target']]
            for evt in data['security_events'][:10]:
                rows.append([
                    evt['timestamp'][:19], evt['event_type'].replace('_', ' ').title(),
                    evt['severity'].upper(), evt['source_ip'],
                ])
            story.append(self._pdf_table(
                rows, [1.6*inch, 1.5*inch, 1*inch, 1.4*inch],
                '#f59e0b', '#fffbeb', '#fde68a'))
            story.append(Spacer(1, 20))

        # --- Attack Breakdown ---
        if 'attack_breakdown' in data and data['attack_breakdown']:
            story.append(Paragraph("Attack Type Breakdown", sec_style))
            rows = [['Attack Type', 'Count']]
            for atype, cnt in sorted(data['attack_breakdown'].items(), key=lambda x: -x[1]):
                rows.append([atype.replace('_', ' ').title(), str(cnt)])
            story.append(self._pdf_table(rows, [3*inch, 2.5*inch], '#6366f1'))
            story.append(Spacer(1, 20))

        # --- Footer ---
        story.append(Spacer(1, 10))
        story.append(Paragraph(f"Generated by Anti-DDoS Platform | {meta['generated_at']}", footer_style))
        doc.build(story)

    async def delete_report(
        self,
        report_id: str
    ) -> None:
        """Delete a report."""
        reports = self._get_reports_dict()

        if report_id in reports:
            report = reports[report_id]
            # Delete the file from storage
            if report.file_path:
                try:
                    file_path = Path(report.file_path)
                    if file_path.exists():
                        file_path.unlink()
                except Exception as e:
                    logger.warning(f"Failed to delete report file: {e}")
            del reports[report_id]
            logger.info(f"Deleted report {report_id}")

    async def generate_daily_summary(
        self,
        date: datetime
    ) -> Dict[str, Any]:
        """Generate a quick daily summary from real data."""
        start = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)

        db = next(get_db())
        try:
            attack_repo = AttackRepository(db)
            traffic_repo = TrafficRepository(db)

            traffic = traffic_repo.get_summary(start, end)
            attack_stats = attack_repo.get_attack_stats(days=1)
            recent_attacks = attack_repo.get_recent_attacks(hours=24, limit=5)

            total_rx = traffic.get('total_rx_packets', 0)
            total_dropped = traffic.get('total_dropped', 0)
            drop_rate = (total_dropped / max(total_rx, 1)) * 100

            top_events = []
            for a in recent_attacks:
                top_events.append({
                    "time": a.started_at.isoformat(),
                    "type": "attack_detected",
                    "description": f"{a.attack_type.value} attack on {a.target_ip}",
                })

            return {
                "date": date.strftime("%Y-%m-%d"),
                "traffic": {
                    "total_packets": total_rx,
                    "total_bytes": total_rx * 800,
                    "peak_pps": traffic.get('peak_rx_pps', 0),
                    "peak_bps": traffic.get('peak_rx_bps', 0),
                    "drop_rate_pct": round(drop_rate, 2),
                },
                "security": {
                    "attacks_detected": attack_stats.get('total', 0),
                    "attacks_mitigated": attack_stats.get('mitigated', 0),
                    "blacklist_hits": traffic.get('drops_by_reason', {}).get('Blacklist', 0),
                    "avg_mitigation_time_ms": round(attack_stats.get('avg_mitigation_time_ms', 0), 2),
                },
                "sla": {
                    "availability_pct": traffic.get('availability_pct', 100.0),
                    "sla_breaches": 1 if traffic.get('availability_pct', 100.0) < 99.9 else 0,
                },
                "top_events": top_events,
            }
        finally:
            db.close()

    async def generate_attack_summary(
        self,
        attack_id: str
    ) -> Optional[Dict[str, Any]]:
        """Generate attack summary report from real data."""
        db = next(get_db())
        try:
            attack_repo = AttackRepository(db)
            attack = attack_repo.get(attack_id)
            if not attack:
                return None

            duration_minutes = 0
            if attack.ended_at and attack.started_at:
                duration_minutes = int((attack.ended_at - attack.started_at).total_seconds() / 60)

            top_sources = []
            for ip in (attack.top_source_ips or [])[:10]:
                top_sources.append({
                    "ip": ip,
                    "packets": 0,
                    "country": "Unknown",
                })

            return {
                "attack_id": attack_id,
                "generated_at": datetime.utcnow().isoformat(),
                "attack_details": {
                    "type": attack.attack_type.value,
                    "severity": attack.severity.value,
                    "started_at": attack.started_at.isoformat(),
                    "ended_at": attack.ended_at.isoformat() if attack.ended_at else None,
                    "duration_minutes": duration_minutes,
                },
                "impact": {
                    "peak_pps": attack.peak_pps or 0,
                    "peak_bps": attack.peak_bps or 0,
                    "total_packets_dropped": attack.packets_dropped or 0,
                    "total_bytes_dropped": attack.bytes_dropped or 0,
                },
                "mitigation": {
                    "time_to_detect_ms": 0,
                    "time_to_mitigate_ms": attack.mitigation_time_ms or 0,
                    "effectiveness_pct": 100.0 if attack.is_mitigated else 0.0,
                    "actions_taken": [],
                },
                "top_sources": top_sources,
                "recommendations": [],
            }
        finally:
            db.close()

    async def get_sla_status(
        self,
        period: str
    ) -> Dict[str, Any]:
        """Get SLA compliance status from real data."""
        days = {"7d": 7, "30d": 30, "90d": 90}.get(period, 30)
        end = datetime.utcnow()
        start = end - timedelta(days=days)

        db = next(get_db())
        try:
            traffic_repo = TrafficRepository(db)
            attack_repo = AttackRepository(db)

            traffic = traffic_repo.get_summary(start, end)
            attack_stats = attack_repo.get_attack_stats(days=days)

            availability = traffic.get('availability_pct', 100.0)
            total_minutes = traffic.get('total_minutes', 0)
            anomaly_minutes = traffic.get('anomaly_minutes', 0)
            avg_mttm = attack_stats.get('avg_mitigation_time_ms', 0)

            # Calculate mitigation effectiveness
            total_attacks = attack_stats.get('total', 0)
            mitigated = attack_stats.get('mitigated', 0)
            effectiveness = (mitigated / max(total_attacks, 1)) * 100

            return {
                "period": period,
                "period_days": days,
                "metrics": {
                    "availability": {
                        "target_pct": 99.9,
                        "actual_pct": round(availability, 3),
                        "compliant": availability >= 99.9,
                        "downtime_minutes": anomaly_minutes,
                    },
                    "mttd": {
                        "target_ms": 100,
                        "actual_ms": 0,
                        "compliant": True,
                    },
                    "mttr": {
                        "target_ms": 500,
                        "actual_ms": round(avg_mttm, 2),
                        "compliant": avg_mttm <= 500,
                    },
                    "mitigation_effectiveness": {
                        "target_pct": 95,
                        "actual_pct": round(effectiveness, 2),
                        "compliant": effectiveness >= 95,
                    },
                    "false_positive_rate": {
                        "target_pct": 1,
                        "actual_pct": 0,
                        "compliant": True,
                    },
                },
                "breaches": {
                    "total": sum([
                        1 if availability < 99.9 else 0,
                        1 if avg_mttm > 500 else 0,
                        1 if effectiveness < 95 else 0,
                    ]),
                    "by_metric": {
                        "availability": 1 if availability < 99.9 else 0,
                        "mttd": 0,
                        "mttr": 1 if avg_mttm > 500 else 0,
                    },
                },
                "trend": "stable",
            }
        finally:
            db.close()

    async def list_scheduled_reports(
        self,
    ) -> List[Dict[str, Any]]:
        """List scheduled report configurations."""
        return self._scheduled

    async def create_scheduled_report(
        self,
        schedule: Dict[str, Any],
        created_by: str
    ) -> Dict[str, Any]:
        """Create a scheduled report configuration."""
        schedule_id = str(uuid.uuid4())[:8]

        scheduled = {
            "id": schedule_id,
            "frequency": schedule.get("frequency", "daily"),
            "time": schedule.get("time", "00:00"),
            "report_type": schedule.get("report_type", ReportType.TRAFFIC),
            "format": schedule.get("format", ReportFormat.PDF),
            "recipients": schedule.get("recipients", []),
            "enabled": True,
            "created_at": datetime.utcnow().isoformat(),
            "created_by": created_by,
            "last_run": None,
            "next_run": self._calculate_next_run(
                schedule.get("frequency", "daily"),
                schedule.get("time", "00:00")
            ).isoformat(),
        }

        self._scheduled.append(scheduled)

        logger.info(f"Created scheduled report {schedule_id}")
        return scheduled

    async def delete_scheduled_report(
        self,
        schedule_id: str
    ) -> None:
        """Delete a scheduled report configuration."""
        self._scheduled = [
            s for s in self._scheduled
            if s["id"] != schedule_id
        ]
        logger.info(f"Deleted scheduled report {schedule_id}")

    def _calculate_next_run(self, frequency: str, time_str: str) -> datetime:
        """Calculate next scheduled run time."""
        now = datetime.utcnow()
        hour, minute = map(int, time_str.split(":"))

        if frequency == "daily":
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
        elif frequency == "weekly":
            next_run = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
            days_until_monday = (7 - now.weekday()) % 7 or 7
            next_run += timedelta(days=days_until_monday)
        elif frequency == "monthly":
            next_run = now.replace(day=1, hour=hour, minute=minute, second=0, microsecond=0)
            if next_run.month == 12:
                next_run = next_run.replace(year=next_run.year + 1, month=1)
            else:
                next_run = next_run.replace(month=next_run.month + 1)
        else:
            next_run = now + timedelta(days=1)

        return next_run


# Singleton instance
_report_service = None

def get_report_service() -> ReportService:
    """Get or create the report service singleton."""
    global _report_service
    if _report_service is None:
        _report_service = ReportService()
    return _report_service
