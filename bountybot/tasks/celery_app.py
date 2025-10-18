"""
Celery application configuration for BountyBot.

Provides distributed task queue with Redis as broker and result backend.
"""

import os
import logging
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

# Try to import Celery
try:
    from celery import Celery
    from celery.schedules import crontab
    CELERY_AVAILABLE = True
except ImportError:
    logger.warning("celery package not installed. Install with: pip install celery[redis]")
    CELERY_AVAILABLE = False
    Celery = None
    crontab = None


class TaskPriority(Enum):
    """Task priority levels."""
    HIGH = 0
    NORMAL = 5
    LOW = 9


def create_celery_app() -> Optional['Celery']:
    """
    Create and configure Celery application.
    
    Returns:
        Configured Celery app or None if Celery not available
    """
    if not CELERY_AVAILABLE:
        logger.warning("Celery not available, task queue disabled")
        return None
    
    # Get Redis configuration from environment
    redis_host = os.getenv('REDIS_HOST', 'localhost')
    redis_port = os.getenv('REDIS_PORT', '6379')
    redis_db = os.getenv('REDIS_DB', '0')
    redis_password = os.getenv('REDIS_PASSWORD', '')
    
    # Build Redis URL
    if redis_password:
        redis_url = f"redis://:{redis_password}@{redis_host}:{redis_port}/{redis_db}"
    else:
        redis_url = f"redis://{redis_host}:{redis_port}/{redis_db}"
    
    # Create Celery app
    app = Celery(
        'bountybot',
        broker=redis_url,
        backend=redis_url,
        include=[
            'bountybot.tasks.validation_tasks',
            'bountybot.tasks.maintenance_tasks'
        ]
    )
    
    # Configure Celery
    app.conf.update(
        # Task execution
        task_serializer='json',
        accept_content=['json'],
        result_serializer='json',
        timezone='UTC',
        enable_utc=True,
        
        # Task routing
        task_routes={
            'bountybot.tasks.validation_tasks.*': {'queue': 'validation'},
            'bountybot.tasks.maintenance_tasks.*': {'queue': 'maintenance'},
        },
        
        # Task priorities
        task_queue_max_priority=10,
        task_default_priority=TaskPriority.NORMAL.value,
        
        # Task results
        result_expires=86400,  # 24 hours
        result_backend_transport_options={
            'master_name': 'mymaster',
            'visibility_timeout': 3600,
        },
        
        # Task execution limits
        task_time_limit=3600,  # 1 hour hard limit
        task_soft_time_limit=3000,  # 50 minutes soft limit
        
        # Worker configuration
        worker_prefetch_multiplier=4,
        worker_max_tasks_per_child=1000,
        worker_disable_rate_limits=False,
        
        # Task retry
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        
        # Monitoring
        worker_send_task_events=True,
        task_send_sent_event=True,
        
        # Beat schedule (periodic tasks)
        beat_schedule={
            'cleanup-old-results': {
                'task': 'bountybot.tasks.maintenance_tasks.cleanup_old_results',
                'schedule': crontab(hour=2, minute=0),  # 2 AM daily
                'options': {'queue': 'maintenance', 'priority': TaskPriority.LOW.value}
            },
            'backup-database': {
                'task': 'bountybot.tasks.maintenance_tasks.backup_database',
                'schedule': crontab(hour=3, minute=0),  # 3 AM daily
                'options': {'queue': 'maintenance', 'priority': TaskPriority.HIGH.value}
            },
            'warm-cache': {
                'task': 'bountybot.tasks.maintenance_tasks.warm_cache',
                'schedule': crontab(minute='*/30'),  # Every 30 minutes
                'options': {'queue': 'maintenance', 'priority': TaskPriority.NORMAL.value}
            },
            'generate-analytics': {
                'task': 'bountybot.tasks.maintenance_tasks.generate_analytics_report',
                'schedule': crontab(hour=1, minute=0),  # 1 AM daily
                'options': {'queue': 'maintenance', 'priority': TaskPriority.NORMAL.value}
            },
            'health-check': {
                'task': 'bountybot.tasks.maintenance_tasks.check_system_health',
                'schedule': crontab(minute='*/5'),  # Every 5 minutes
                'options': {'queue': 'maintenance', 'priority': TaskPriority.HIGH.value}
            }
        }
    )
    
    logger.info(f"Celery app created with broker: {redis_url}")
    
    return app


# Create global Celery app instance
celery_app = create_celery_app()


def get_celery_app() -> Optional['Celery']:
    """
    Get the Celery app instance.
    
    Returns:
        Celery app or None if not available
    """
    return celery_app


def is_celery_available() -> bool:
    """
    Check if Celery is available.
    
    Returns:
        True if Celery is installed and configured
    """
    return CELERY_AVAILABLE and celery_app is not None

