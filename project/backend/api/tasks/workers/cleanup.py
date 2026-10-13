"""
Cleanup worker.

Removes expired entries from database tables using existing repository methods.
"""

import logging

logger = logging.getLogger(__name__)


async def cleanup_expired():
    """
    Clean up expired entries from various tables.

    Runs every hour. Calls existing repository cleanup methods:
    - IPListRepository.delete_expired() -- expired IP list entries
    - TokenRepository.delete_expired() -- expired API tokens
    - AuditRepository.delete_old_logs(365) -- audit logs > 1 year
    - ReportRepository.delete_old_reports(90) -- reports > 90 days
    """
    try:
        from ...database.connection import get_db
        from ...database.repositories.iplist_repo import IPListRepository
        from ...database.repositories.token_repo import APITokenRepository as TokenRepository
        from ...database.repositories.audit_repo import AuditLogRepository as AuditRepository
        from ...database.repositories.report_repo import ReportRepository

        db = next(get_db())
        try:
            results = {}
            results['ip_list'] = IPListRepository(db).delete_expired()
            results['tokens'] = TokenRepository(db).delete_expired()
            results['audit'] = AuditRepository(db).delete_old_logs(days=365)
            results['reports'] = ReportRepository(db).delete_old_reports(days=90)

            total = sum(results.values())
            if total > 0:
                logger.info(f"Cleanup: {total} entries removed — {results}")
        finally:
            db.close()

    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
