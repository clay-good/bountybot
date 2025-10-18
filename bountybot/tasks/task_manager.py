"""
Task manager for tracking and managing async tasks.

Provides high-level interface for task submission and monitoring.
"""

import logging
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

from .celery_app import celery_app, TaskPriority, is_celery_available

logger = logging.getLogger(__name__)


class TaskStatus(Enum):
    """Task status."""
    PENDING = "pending"
    STARTED = "started"
    SUCCESS = "success"
    FAILURE = "failure"
    RETRY = "retry"
    REVOKED = "revoked"


@dataclass
class TaskResult:
    """Task result information."""
    task_id: str
    task_name: str
    status: TaskStatus
    result: Optional[Any] = None
    error: Optional[str] = None
    submitted_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    retries: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'task_id': self.task_id,
            'task_name': self.task_name,
            'status': self.status.value,
            'result': self.result,
            'error': self.error,
            'submitted_at': self.submitted_at.isoformat() if self.submitted_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'retries': self.retries
        }


class TaskManager:
    """
    High-level task manager for async task submission and monitoring.
    """
    
    def __init__(self):
        """Initialize task manager."""
        self.celery_available = is_celery_available()
        if not self.celery_available:
            logger.warning("Celery not available - task queue disabled")
    
    def submit_validation_task(
        self,
        report_path: str,
        codebase_path: Optional[str] = None,
        target_url: Optional[str] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        **kwargs
    ) -> Optional[str]:
        """
        Submit a validation task.
        
        Args:
            report_path: Path to report file
            codebase_path: Optional codebase path
            target_url: Optional target URL
            priority: Task priority
            **kwargs: Additional options
            
        Returns:
            Task ID or None if Celery not available
        """
        if not self.celery_available:
            logger.error("Cannot submit task - Celery not available")
            return None
        
        try:
            from .validation_tasks import validate_report_async
            
            # Submit task
            task = validate_report_async.apply_async(
                args=[report_path],
                kwargs={
                    'codebase_path': codebase_path,
                    'target_url': target_url,
                    **kwargs
                },
                priority=priority.value,
                queue='validation'
            )
            
            logger.info(f"Submitted validation task: {task.id} for {report_path}")
            
            return task.id
            
        except Exception as e:
            logger.error(f"Failed to submit validation task: {e}")
            return None
    
    def submit_batch_validation_task(
        self,
        report_paths: List[str],
        codebase_path: Optional[str] = None,
        priority: TaskPriority = TaskPriority.NORMAL,
        **kwargs
    ) -> Optional[str]:
        """
        Submit a batch validation task.
        
        Args:
            report_paths: List of report paths
            codebase_path: Optional codebase path
            priority: Task priority
            **kwargs: Additional options
            
        Returns:
            Task ID or None if Celery not available
        """
        if not self.celery_available:
            logger.error("Cannot submit task - Celery not available")
            return None
        
        try:
            from .validation_tasks import validate_batch_async
            
            # Submit task
            task = validate_batch_async.apply_async(
                args=[report_paths],
                kwargs={
                    'codebase_path': codebase_path,
                    **kwargs
                },
                priority=priority.value,
                queue='validation'
            )
            
            logger.info(f"Submitted batch validation task: {task.id} for {len(report_paths)} reports")
            
            return task.id
            
        except Exception as e:
            logger.error(f"Failed to submit batch validation task: {e}")
            return None
    
    def get_task_status(self, task_id: str) -> Optional[TaskResult]:
        """
        Get task status and result.
        
        Args:
            task_id: Task ID
            
        Returns:
            TaskResult or None if not found
        """
        if not self.celery_available:
            logger.error("Cannot get task status - Celery not available")
            return None
        
        try:
            from celery.result import AsyncResult
            
            # Get task result
            async_result = AsyncResult(task_id, app=celery_app)
            
            # Map Celery state to TaskStatus
            status_map = {
                'PENDING': TaskStatus.PENDING,
                'STARTED': TaskStatus.STARTED,
                'SUCCESS': TaskStatus.SUCCESS,
                'FAILURE': TaskStatus.FAILURE,
                'RETRY': TaskStatus.RETRY,
                'REVOKED': TaskStatus.REVOKED
            }
            
            status = status_map.get(async_result.state, TaskStatus.PENDING)
            
            # Create TaskResult
            task_result = TaskResult(
                task_id=task_id,
                task_name=async_result.name or 'unknown',
                status=status,
                result=async_result.result if status == TaskStatus.SUCCESS else None,
                error=str(async_result.result) if status == TaskStatus.FAILURE else None
            )
            
            return task_result
            
        except Exception as e:
            logger.error(f"Failed to get task status: {e}")
            return None
    
    def wait_for_task(self, task_id: str, timeout: int = 600) -> Optional[TaskResult]:
        """
        Wait for task to complete.
        
        Args:
            task_id: Task ID
            timeout: Timeout in seconds
            
        Returns:
            TaskResult or None if timeout/error
        """
        if not self.celery_available:
            logger.error("Cannot wait for task - Celery not available")
            return None
        
        try:
            from celery.result import AsyncResult
            
            # Get task result
            async_result = AsyncResult(task_id, app=celery_app)
            
            # Wait for result
            result = async_result.get(timeout=timeout)
            
            # Get final status
            return self.get_task_status(task_id)
            
        except Exception as e:
            logger.error(f"Failed to wait for task: {e}")
            return None
    
    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a pending or running task.
        
        Args:
            task_id: Task ID
            
        Returns:
            True if cancelled successfully
        """
        if not self.celery_available:
            logger.error("Cannot cancel task - Celery not available")
            return False
        
        try:
            from celery.result import AsyncResult
            
            # Get task result
            async_result = AsyncResult(task_id, app=celery_app)
            
            # Revoke task
            async_result.revoke(terminate=True)
            
            logger.info(f"Cancelled task: {task_id}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to cancel task: {e}")
            return False
    
    def get_active_tasks(self) -> List[Dict[str, Any]]:
        """
        Get list of active tasks.
        
        Returns:
            List of active task information
        """
        if not self.celery_available:
            logger.error("Cannot get active tasks - Celery not available")
            return []
        
        try:
            # Get active tasks from workers
            inspect = celery_app.control.inspect()
            active = inspect.active()
            
            if not active:
                return []
            
            # Flatten tasks from all workers
            tasks = []
            for worker, worker_tasks in active.items():
                for task in worker_tasks:
                    tasks.append({
                        'task_id': task['id'],
                        'task_name': task['name'],
                        'worker': worker,
                        'args': task.get('args', []),
                        'kwargs': task.get('kwargs', {})
                    })
            
            return tasks
            
        except Exception as e:
            logger.error(f"Failed to get active tasks: {e}")
            return []
    
    def get_queue_stats(self) -> Dict[str, Any]:
        """
        Get queue statistics.
        
        Returns:
            Queue statistics
        """
        if not self.celery_available:
            logger.error("Cannot get queue stats - Celery not available")
            return {}
        
        try:
            # Get stats from workers
            inspect = celery_app.control.inspect()
            
            stats = {
                'active_tasks': len(self.get_active_tasks()),
                'registered_tasks': list(celery_app.tasks.keys()),
                'workers': []
            }
            
            # Get worker stats
            worker_stats = inspect.stats()
            if worker_stats:
                for worker, worker_info in worker_stats.items():
                    stats['workers'].append({
                        'name': worker,
                        'pool': worker_info.get('pool', {}).get('implementation', 'unknown'),
                        'max_concurrency': worker_info.get('pool', {}).get('max-concurrency', 0)
                    })
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get queue stats: {e}")
            return {}

