"""
Tests for async task queue system.
"""

import unittest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock

from bountybot.tasks import (
    TaskManager,
    TaskStatus,
    TaskResult,
    TaskPriority
)


class TestTaskPriority(unittest.TestCase):
    """Test task priority enum."""
    
    def test_priority_values(self):
        """Test priority values."""
        self.assertEqual(TaskPriority.HIGH.value, 0)
        self.assertEqual(TaskPriority.NORMAL.value, 5)
        self.assertEqual(TaskPriority.LOW.value, 9)


class TestTaskStatus(unittest.TestCase):
    """Test task status enum."""
    
    def test_status_values(self):
        """Test status values."""
        self.assertEqual(TaskStatus.PENDING.value, "pending")
        self.assertEqual(TaskStatus.STARTED.value, "started")
        self.assertEqual(TaskStatus.SUCCESS.value, "success")
        self.assertEqual(TaskStatus.FAILURE.value, "failure")
        self.assertEqual(TaskStatus.RETRY.value, "retry")
        self.assertEqual(TaskStatus.REVOKED.value, "revoked")


class TestTaskResult(unittest.TestCase):
    """Test TaskResult dataclass."""
    
    def test_task_result_creation(self):
        """Test creating task result."""
        result = TaskResult(
            task_id='test-123',
            task_name='test_task',
            status=TaskStatus.SUCCESS,
            result={'data': 'test'}
        )
        
        self.assertEqual(result.task_id, 'test-123')
        self.assertEqual(result.task_name, 'test_task')
        self.assertEqual(result.status, TaskStatus.SUCCESS)
        self.assertEqual(result.result, {'data': 'test'})
        self.assertIsNone(result.error)
        self.assertIsInstance(result.submitted_at, datetime)
    
    def test_task_result_to_dict(self):
        """Test converting task result to dictionary."""
        result = TaskResult(
            task_id='test-123',
            task_name='test_task',
            status=TaskStatus.SUCCESS,
            result={'data': 'test'}
        )
        
        result_dict = result.to_dict()
        
        self.assertEqual(result_dict['task_id'], 'test-123')
        self.assertEqual(result_dict['task_name'], 'test_task')
        self.assertEqual(result_dict['status'], 'success')
        self.assertEqual(result_dict['result'], {'data': 'test'})
        self.assertIsNone(result_dict['error'])
        self.assertIsNotNone(result_dict['submitted_at'])


class TestTaskManager(unittest.TestCase):
    """Test TaskManager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.task_manager = TaskManager()
    
    def test_initialization(self):
        """Test task manager initialization."""
        self.assertIsNotNone(self.task_manager)
        self.assertIsInstance(self.task_manager.celery_available, bool)
    
    def test_submit_validation_task_without_celery(self):
        """Test submitting validation task without Celery."""
        # Task manager should handle missing Celery gracefully
        task_id = self.task_manager.submit_validation_task(
            report_path='test_report.json'
        )
        
        # Should return None if Celery not available
        if not self.task_manager.celery_available:
            self.assertIsNone(task_id)
    
    def test_submit_batch_validation_task_without_celery(self):
        """Test submitting batch validation task without Celery."""
        task_id = self.task_manager.submit_batch_validation_task(
            report_paths=['report1.json', 'report2.json']
        )
        
        # Should return None if Celery not available
        if not self.task_manager.celery_available:
            self.assertIsNone(task_id)
    
    def test_get_task_status_without_celery(self):
        """Test getting task status without Celery."""
        result = self.task_manager.get_task_status('test-task-id')
        
        # Should return None if Celery not available
        if not self.task_manager.celery_available:
            self.assertIsNone(result)
    
    def test_wait_for_task_without_celery(self):
        """Test waiting for task without Celery."""
        result = self.task_manager.wait_for_task('test-task-id', timeout=1)
        
        # Should return None if Celery not available
        if not self.task_manager.celery_available:
            self.assertIsNone(result)
    
    def test_cancel_task_without_celery(self):
        """Test cancelling task without Celery."""
        success = self.task_manager.cancel_task('test-task-id')
        
        # Should return False if Celery not available
        if not self.task_manager.celery_available:
            self.assertFalse(success)
    
    def test_get_active_tasks_without_celery(self):
        """Test getting active tasks without Celery."""
        tasks = self.task_manager.get_active_tasks()
        
        # Should return empty list if Celery not available
        if not self.task_manager.celery_available:
            self.assertEqual(tasks, [])
    
    def test_get_queue_stats_without_celery(self):
        """Test getting queue stats without Celery."""
        stats = self.task_manager.get_queue_stats()
        
        # Should return empty dict if Celery not available
        if not self.task_manager.celery_available:
            self.assertEqual(stats, {})


class TestCeleryApp(unittest.TestCase):
    """Test Celery app configuration."""
    
    def test_celery_app_import(self):
        """Test importing Celery app."""
        from bountybot.tasks.celery_app import celery_app, is_celery_available
        
        # Should not raise error
        self.assertIsNotNone(is_celery_available)
        
        # celery_app may be None if Celery not installed
        if is_celery_available():
            self.assertIsNotNone(celery_app)
    
    def test_get_celery_app(self):
        """Test getting Celery app."""
        from bountybot.tasks.celery_app import get_celery_app
        
        app = get_celery_app()
        
        # May be None if Celery not installed
        # Should not raise error


class TestValidationTasks(unittest.TestCase):
    """Test validation tasks."""
    
    def test_validation_tasks_import(self):
        """Test importing validation tasks."""
        from bountybot.tasks.validation_tasks import (
            validate_report_async,
            validate_batch_async,
            validate_report_with_retry
        )
        
        # Should not raise error
        self.assertIsNotNone(validate_report_async)
        self.assertIsNotNone(validate_batch_async)
        self.assertIsNotNone(validate_report_with_retry)
    
    def test_validate_report_async_without_celery(self):
        """Test async validation without Celery."""
        from bountybot.tasks.validation_tasks import validate_report_async
        from bountybot.tasks.celery_app import is_celery_available
        
        if not is_celery_available():
            # Should return error dict
            result = validate_report_async('test_report.json')
            self.assertIsInstance(result, dict)
            self.assertIn('error', result)


class TestMaintenanceTasks(unittest.TestCase):
    """Test maintenance tasks."""
    
    def test_maintenance_tasks_import(self):
        """Test importing maintenance tasks."""
        from bountybot.tasks.maintenance_tasks import (
            cleanup_old_results,
            backup_database,
            warm_cache,
            generate_analytics_report,
            check_system_health
        )
        
        # Should not raise error
        self.assertIsNotNone(cleanup_old_results)
        self.assertIsNotNone(backup_database)
        self.assertIsNotNone(warm_cache)
        self.assertIsNotNone(generate_analytics_report)
        self.assertIsNotNone(check_system_health)
    
    def test_cleanup_old_results_without_celery(self):
        """Test cleanup task without Celery."""
        from bountybot.tasks.maintenance_tasks import cleanup_old_results
        from bountybot.tasks.celery_app import is_celery_available
        
        if not is_celery_available():
            # Should return error dict
            result = cleanup_old_results(days=30)
            self.assertIsInstance(result, dict)
            self.assertIn('error', result)
    
    def test_backup_database_without_celery(self):
        """Test backup task without Celery."""
        from bountybot.tasks.maintenance_tasks import backup_database
        from bountybot.tasks.celery_app import is_celery_available
        
        if not is_celery_available():
            # Should return error dict
            result = backup_database()
            self.assertIsInstance(result, dict)
            self.assertIn('error', result)
    
    def test_warm_cache_without_celery(self):
        """Test cache warming task without Celery."""
        from bountybot.tasks.maintenance_tasks import warm_cache
        from bountybot.tasks.celery_app import is_celery_available
        
        if not is_celery_available():
            # Should return error dict
            result = warm_cache()
            self.assertIsInstance(result, dict)
            self.assertIn('error', result)


class TestTasksModule(unittest.TestCase):
    """Test tasks module."""
    
    def test_module_import(self):
        """Test importing tasks module."""
        import bountybot.tasks
        
        # Should not raise error
        self.assertIsNotNone(bountybot.tasks)
    
    def test_module_exports(self):
        """Test module exports."""
        from bountybot.tasks import (
            celery_app,
            TaskPriority,
            TaskManager,
            TaskStatus,
            TaskResult
        )
        
        # Should not raise error
        self.assertIsNotNone(TaskPriority)
        self.assertIsNotNone(TaskManager)
        self.assertIsNotNone(TaskStatus)
        self.assertIsNotNone(TaskResult)


if __name__ == '__main__':
    unittest.main()

