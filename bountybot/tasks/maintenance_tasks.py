"""
Maintenance tasks for scheduled background jobs.

Provides periodic tasks for system maintenance and housekeeping.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any

from .celery_app import celery_app, is_celery_available

logger = logging.getLogger(__name__)


if is_celery_available():
    @celery_app.task(
        name='bountybot.tasks.maintenance_tasks.cleanup_old_results',
        bind=True
    )
    def cleanup_old_results(self, days: int = 30) -> Dict[str, Any]:
        """
        Clean up old task results and validation data.
        
        Args:
            days: Number of days to keep results
            
        Returns:
            Cleanup statistics
        """
        try:
            logger.info(f"Starting cleanup of results older than {days} days")
            
            # Import here to avoid circular dependencies
            from bountybot.database.session import get_session
            from bountybot.database.models import ValidationReport
            
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            deleted_count = 0
            
            # Clean up database records
            try:
                session = get_session()
                if session:
                    old_reports = session.query(ValidationReport).filter(
                        ValidationReport.created_at < cutoff_date
                    ).all()
                    
                    deleted_count = len(old_reports)
                    
                    for report in old_reports:
                        session.delete(report)
                    
                    session.commit()
                    logger.info(f"Deleted {deleted_count} old validation reports")
            except Exception as e:
                logger.error(f"Failed to clean up database: {e}")
            
            # Clean up Celery results
            try:
                from celery.result import AsyncResult
                # Celery automatically expires results based on result_expires config
                logger.info("Celery results cleaned up automatically")
            except Exception as e:
                logger.error(f"Failed to clean up Celery results: {e}")
            
            result = {
                'deleted_count': deleted_count,
                'cutoff_date': cutoff_date.isoformat(),
                'completed_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Cleanup complete: {deleted_count} records deleted")
            
            return result
            
        except Exception as e:
            logger.error(f"Cleanup task failed: {e}")
            raise
    
    
    @celery_app.task(
        name='bountybot.tasks.maintenance_tasks.backup_database',
        bind=True
    )
    def backup_database(self) -> Dict[str, Any]:
        """
        Create database backup.
        
        Returns:
            Backup result
        """
        try:
            logger.info("Starting database backup")
            
            # Import here to avoid circular dependencies
            from bountybot.backup import BackupManager
            from bountybot.config_loader import load_config
            
            config = load_config()
            backup_config = config.get('backup', {})
            
            if not backup_config.get('enabled', False):
                logger.info("Backup disabled in configuration")
                return {'status': 'skipped', 'reason': 'disabled'}
            
            # Create backup manager
            backup_manager = BackupManager(backup_config)
            
            # Create backup
            metadata = backup_manager.create_backup(
                backup_type='scheduled',
                description='Automated scheduled backup'
            )
            
            result = {
                'status': 'success',
                'backup_id': metadata.backup_id,
                'size_bytes': metadata.size_bytes,
                'completed_at': metadata.completed_at.isoformat()
            }
            
            logger.info(f"Database backup complete: {metadata.backup_id}")
            
            return result
            
        except Exception as e:
            logger.error(f"Backup task failed: {e}")
            raise
    
    
    @celery_app.task(
        name='bountybot.tasks.maintenance_tasks.warm_cache',
        bind=True
    )
    def warm_cache(self) -> Dict[str, Any]:
        """
        Warm cache with frequently accessed data.
        
        Returns:
            Cache warming result
        """
        try:
            logger.info("Starting cache warming")
            
            # Import here to avoid circular dependencies
            from bountybot.cache import CacheWarmer, CacheManager
            
            # Create cache manager and warmer
            cache_manager = CacheManager(namespace='bountybot')
            cache_warmer = CacheWarmer(cache_manager)
            
            # Run all registered warmers
            results = cache_warmer.warm_now()
            
            # Calculate statistics
            total_keys = sum(r.get('keys_cached', 0) for r in results.values() if r.get('success'))
            success_count = sum(1 for r in results.values() if r.get('success'))
            
            result = {
                'status': 'success',
                'warmers_run': len(results),
                'successful': success_count,
                'total_keys_cached': total_keys,
                'completed_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Cache warming complete: {total_keys} keys cached")
            
            return result
            
        except Exception as e:
            logger.error(f"Cache warming task failed: {e}")
            # Don't raise - cache warming is not critical
            return {
                'status': 'failed',
                'error': str(e),
                'completed_at': datetime.utcnow().isoformat()
            }
    
    
    @celery_app.task(
        name='bountybot.tasks.maintenance_tasks.generate_analytics_report',
        bind=True
    )
    def generate_analytics_report(self) -> Dict[str, Any]:
        """
        Generate daily analytics report.
        
        Returns:
            Analytics report
        """
        try:
            logger.info("Starting analytics report generation")
            
            # Import here to avoid circular dependencies
            from bountybot.analytics import MetricsCollector, TrendAnalyzer
            from bountybot.database.session import get_session
            from bountybot.database.models import ValidationReport
            
            session = get_session()
            if not session:
                logger.warning("Database not available for analytics")
                return {'status': 'skipped', 'reason': 'database_unavailable'}
            
            # Get reports from last 24 hours
            yesterday = datetime.utcnow() - timedelta(days=1)
            recent_reports = session.query(ValidationReport).filter(
                ValidationReport.created_at >= yesterday
            ).all()
            
            # Calculate metrics
            total_reports = len(recent_reports)
            valid_count = sum(1 for r in recent_reports if r.verdict == 'VALID')
            invalid_count = sum(1 for r in recent_reports if r.verdict == 'INVALID')
            uncertain_count = sum(1 for r in recent_reports if r.verdict == 'UNCERTAIN')
            
            avg_confidence = sum(r.confidence for r in recent_reports) / total_reports if total_reports > 0 else 0
            avg_processing_time = sum(r.processing_time_seconds for r in recent_reports) / total_reports if total_reports > 0 else 0
            
            result = {
                'status': 'success',
                'period': '24h',
                'total_reports': total_reports,
                'valid': valid_count,
                'invalid': invalid_count,
                'uncertain': uncertain_count,
                'avg_confidence': round(avg_confidence, 2),
                'avg_processing_time': round(avg_processing_time, 2),
                'generated_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Analytics report generated: {total_reports} reports processed")
            
            return result
            
        except Exception as e:
            logger.error(f"Analytics report generation failed: {e}")
            raise
    
    
    @celery_app.task(
        name='bountybot.tasks.maintenance_tasks.check_system_health',
        bind=True
    )
    def check_system_health(self) -> Dict[str, Any]:
        """
        Check system health and create alerts if needed.
        
        Returns:
            Health check result
        """
        try:
            logger.info("Starting system health check")
            
            # Import here to avoid circular dependencies
            from bountybot.monitoring import health_checker, alert_manager
            from bountybot.monitoring.alerts import AlertSeverity
            
            # Run health checks
            health_status = health_checker.check_all()
            
            # Check for unhealthy components
            unhealthy = [
                name for name, status in health_status.items()
                if not status.get('healthy', False)
            ]
            
            # Create alerts for unhealthy components
            if unhealthy:
                for component in unhealthy:
                    alert_manager.create_alert(
                        severity=AlertSeverity.WARNING,
                        title=f"Component Unhealthy: {component}",
                        message=f"Health check failed for {component}",
                        source="health_check_task",
                        metadata={'component': component}
                    )
            
            result = {
                'status': 'success',
                'healthy_components': len(health_status) - len(unhealthy),
                'unhealthy_components': len(unhealthy),
                'unhealthy_list': unhealthy,
                'checked_at': datetime.utcnow().isoformat()
            }
            
            logger.info(f"Health check complete: {len(unhealthy)} unhealthy components")
            
            return result
            
        except Exception as e:
            logger.error(f"Health check task failed: {e}")
            raise

else:
    # Celery not available - provide stub functions
    def cleanup_old_results(days: int = 30) -> Dict[str, Any]:
        """Stub function when Celery not available."""
        logger.warning("Celery not available - cannot execute cleanup task")
        return {'error': 'Celery not available'}
    
    def backup_database() -> Dict[str, Any]:
        """Stub function when Celery not available."""
        logger.warning("Celery not available - cannot execute backup task")
        return {'error': 'Celery not available'}
    
    def warm_cache() -> Dict[str, Any]:
        """Stub function when Celery not available."""
        logger.warning("Celery not available - cannot execute cache warming task")
        return {'error': 'Celery not available'}
    
    def generate_analytics_report() -> Dict[str, Any]:
        """Stub function when Celery not available."""
        logger.warning("Celery not available - cannot execute analytics task")
        return {'error': 'Celery not available'}
    
    def check_system_health() -> Dict[str, Any]:
        """Stub function when Celery not available."""
        logger.warning("Celery not available - cannot execute health check task")
        return {'error': 'Celery not available'}


# Export functions
__all__ = [
    'cleanup_old_results',
    'backup_database',
    'warm_cache',
    'generate_analytics_report',
    'check_system_health'
]

