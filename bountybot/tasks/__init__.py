"""
Task queue module for BountyBot.

Provides distributed task queue and background job processing using Celery:
- Async validation tasks
- Scheduled periodic tasks
- Task retry and failure handling
- Task prioritization
- Result tracking
- Worker management
"""

from .celery_app import celery_app, TaskPriority
from .validation_tasks import (
    validate_report_async,
    validate_batch_async,
    validate_report_with_retry
)
from .maintenance_tasks import (
    cleanup_old_results,
    backup_database,
    warm_cache,
    generate_analytics_report,
    check_system_health
)
from .task_manager import TaskManager, TaskStatus, TaskResult

__all__ = [
    'celery_app',
    'TaskPriority',
    'validate_report_async',
    'validate_batch_async',
    'validate_report_with_retry',
    'cleanup_old_results',
    'backup_database',
    'warm_cache',
    'generate_analytics_report',
    'check_system_health',
    'TaskManager',
    'TaskStatus',
    'TaskResult'
]

__version__ = '1.0.0'

