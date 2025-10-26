"""
Continuous Validation Scheduler

Schedules and executes periodic re-validation of vulnerabilities and security controls.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from uuid import uuid4

from .models import (
    ValidationSchedule,
    ScheduleFrequency,
    RegressionStatus,
    VulnerabilityLifecycle
)
from .regression_engine import RegressionTestingEngine

logger = logging.getLogger(__name__)


class ContinuousValidationScheduler:
    """
    Schedules and manages continuous validation of fixed vulnerabilities.
    """
    
    def __init__(
        self,
        regression_engine: RegressionTestingEngine,
        config: Optional[Dict] = None
    ):
        """
        Initialize continuous validation scheduler.
        
        Args:
            regression_engine: RegressionTestingEngine instance
            config: Configuration dictionary
        """
        self.regression_engine = regression_engine
        self.config = config or {}
        self.schedules: Dict[str, ValidationSchedule] = {}
        self.running = False
        self.scheduler_task: Optional[asyncio.Task] = None
        
        # Configuration
        self.check_interval_seconds = self.config.get('check_interval_seconds', 60)
        self.max_concurrent_validations = self.config.get('max_concurrent_validations', 10)
        
        # Callbacks
        self.on_validation_complete: Optional[Callable] = None
        self.on_regression_detected: Optional[Callable] = None
        
        logger.info("ContinuousValidationScheduler initialized")
    
    def create_schedule(
        self,
        vulnerability_id: str,
        frequency: ScheduleFrequency,
        test_config: Optional[Dict] = None,
        custom_cron: Optional[str] = None,
        notification_config: Optional[Dict] = None,
        created_by: Optional[str] = None
    ) -> ValidationSchedule:
        """
        Create validation schedule for vulnerability.
        
        Args:
            vulnerability_id: Vulnerability ID
            frequency: Schedule frequency
            test_config: Test configuration
            custom_cron: Custom cron expression (for CUSTOM frequency)
            notification_config: Notification configuration
            created_by: Who created the schedule
            
        Returns:
            ValidationSchedule object
        """
        schedule = ValidationSchedule(
            schedule_id=str(uuid4()),
            vulnerability_id=vulnerability_id,
            frequency=frequency,
            custom_cron=custom_cron,
            test_config=test_config or {},
            notification_config=notification_config or {},
            created_by=created_by
        )
        
        # Calculate next run time
        schedule.next_run = self._calculate_next_run(frequency, custom_cron)
        
        self.schedules[schedule.schedule_id] = schedule
        logger.info(f"Created validation schedule {schedule.schedule_id} for vulnerability {vulnerability_id}")
        
        return schedule
    
    def update_schedule(
        self,
        schedule_id: str,
        frequency: Optional[ScheduleFrequency] = None,
        enabled: Optional[bool] = None,
        test_config: Optional[Dict] = None,
        notification_config: Optional[Dict] = None
    ) -> ValidationSchedule:
        """
        Update existing validation schedule.
        
        Args:
            schedule_id: Schedule ID
            frequency: New frequency
            enabled: Enable/disable schedule
            test_config: Updated test configuration
            notification_config: Updated notification configuration
            
        Returns:
            Updated ValidationSchedule
        """
        schedule = self.schedules.get(schedule_id)
        if not schedule:
            raise ValueError(f"Schedule {schedule_id} not found")
        
        if frequency is not None:
            schedule.frequency = frequency
            schedule.next_run = self._calculate_next_run(frequency, schedule.custom_cron)
        
        if enabled is not None:
            schedule.enabled = enabled
        
        if test_config is not None:
            schedule.test_config.update(test_config)
        
        if notification_config is not None:
            schedule.notification_config.update(notification_config)
        
        logger.info(f"Updated validation schedule {schedule_id}")
        return schedule
    
    def delete_schedule(self, schedule_id: str):
        """Delete validation schedule."""
        if schedule_id in self.schedules:
            del self.schedules[schedule_id]
            logger.info(f"Deleted validation schedule {schedule_id}")
    
    async def start(self):
        """Start the scheduler."""
        if self.running:
            logger.warning("Scheduler is already running")
            return
        
        self.running = True
        self.scheduler_task = asyncio.create_task(self._scheduler_loop())
        logger.info("Continuous validation scheduler started")
    
    async def stop(self):
        """Stop the scheduler."""
        if not self.running:
            return
        
        self.running = False
        if self.scheduler_task:
            self.scheduler_task.cancel()
            try:
                await self.scheduler_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Continuous validation scheduler stopped")
    
    async def _scheduler_loop(self):
        """Main scheduler loop."""
        logger.info("Scheduler loop started")
        
        while self.running:
            try:
                # Check for due schedules
                due_schedules = self._get_due_schedules()
                
                if due_schedules:
                    logger.info(f"Found {len(due_schedules)} due schedules")
                    await self._execute_due_schedules(due_schedules)
                
                # Wait before next check
                await asyncio.sleep(self.check_interval_seconds)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in scheduler loop: {e}", exc_info=True)
                await asyncio.sleep(self.check_interval_seconds)
    
    def _get_due_schedules(self) -> List[ValidationSchedule]:
        """Get schedules that are due for execution."""
        now = datetime.utcnow()
        due_schedules = []
        
        for schedule in self.schedules.values():
            if not schedule.enabled:
                continue
            
            if schedule.next_run and schedule.next_run <= now:
                due_schedules.append(schedule)
        
        return due_schedules
    
    async def _execute_due_schedules(self, schedules: List[ValidationSchedule]):
        """
        Execute due validation schedules.
        
        Args:
            schedules: List of due schedules
        """
        # Create semaphore for concurrent execution
        semaphore = asyncio.Semaphore(self.max_concurrent_validations)
        
        async def execute_with_semaphore(schedule: ValidationSchedule):
            async with semaphore:
                await self._execute_schedule(schedule)
        
        # Execute all schedules in parallel
        await asyncio.gather(
            *[execute_with_semaphore(schedule) for schedule in schedules],
            return_exceptions=True
        )
    
    async def _execute_schedule(self, schedule: ValidationSchedule):
        """
        Execute single validation schedule.
        
        Args:
            schedule: ValidationSchedule to execute
        """
        logger.info(f"Executing schedule {schedule.schedule_id} for vulnerability {schedule.vulnerability_id}")
        
        try:
            # Create regression test
            test = await self.regression_engine.create_regression_test(
                vulnerability_id=schedule.vulnerability_id,
                test_type=schedule.test_config.get('test_type', 'automated_scan'),
                test_config=schedule.test_config,
                scheduled_at=datetime.utcnow()
            )
            
            # Execute test
            result = await self.regression_engine.execute_regression_test(
                test.test_id,
                target_url=schedule.test_config.get('target_url'),
                codebase_path=schedule.test_config.get('codebase_path')
            )
            
            # Update schedule
            schedule.last_run = datetime.utcnow()
            schedule.total_runs += 1
            schedule.last_status = result.status
            
            if result.status == RegressionStatus.PASSED:
                schedule.successful_runs += 1
            elif result.status in [RegressionStatus.FAILED, RegressionStatus.ERROR]:
                schedule.failed_runs += 1
            
            # Calculate next run
            schedule.next_run = self._calculate_next_run(schedule.frequency, schedule.custom_cron)
            
            # Trigger callbacks
            if self.on_validation_complete:
                await self.on_validation_complete(schedule, result)
            
            if result.regression_detected and self.on_regression_detected:
                await self.on_regression_detected(schedule, result)
            
            # Send notifications if configured
            if schedule.notification_config.get('enabled'):
                await self._send_notification(schedule, result)
            
            logger.info(f"Schedule {schedule.schedule_id} executed successfully: {result.status.value}")
            
        except Exception as e:
            schedule.last_run = datetime.utcnow()
            schedule.total_runs += 1
            schedule.failed_runs += 1
            schedule.last_status = RegressionStatus.ERROR
            schedule.next_run = self._calculate_next_run(schedule.frequency, schedule.custom_cron)
            
            logger.error(f"Error executing schedule {schedule.schedule_id}: {e}", exc_info=True)
    
    def _calculate_next_run(
        self,
        frequency: ScheduleFrequency,
        custom_cron: Optional[str] = None
    ) -> datetime:
        """
        Calculate next run time based on frequency.
        
        Args:
            frequency: Schedule frequency
            custom_cron: Custom cron expression
            
        Returns:
            Next run datetime
        """
        now = datetime.utcnow()
        
        if frequency == ScheduleFrequency.HOURLY:
            return now + timedelta(hours=1)
        elif frequency == ScheduleFrequency.DAILY:
            return now + timedelta(days=1)
        elif frequency == ScheduleFrequency.WEEKLY:
            return now + timedelta(weeks=1)
        elif frequency == ScheduleFrequency.MONTHLY:
            return now + timedelta(days=30)
        elif frequency == ScheduleFrequency.CUSTOM and custom_cron:
            # In production, parse cron expression
            # For now, default to daily
            return now + timedelta(days=1)
        else:
            # Default to weekly
            return now + timedelta(weeks=1)
    
    async def _send_notification(self, schedule: ValidationSchedule, result: Any):
        """
        Send notification about validation result.
        
        Args:
            schedule: ValidationSchedule
            result: Test result
        """
        notification_config = schedule.notification_config
        
        # Check if notification should be sent
        notify_on_success = notification_config.get('notify_on_success', False)
        notify_on_failure = notification_config.get('notify_on_failure', True)
        notify_on_regression = notification_config.get('notify_on_regression', True)
        
        should_notify = False
        if result.status == RegressionStatus.PASSED and notify_on_success:
            should_notify = True
        elif result.status in [RegressionStatus.FAILED, RegressionStatus.ERROR] and notify_on_failure:
            should_notify = True
        elif result.regression_detected and notify_on_regression:
            should_notify = True
        
        if not should_notify:
            return
        
        # In production, send actual notifications (email, Slack, etc.)
        logger.info(f"Notification sent for schedule {schedule.schedule_id}: {result.status.value}")
    
    def get_schedule(self, schedule_id: str) -> Optional[ValidationSchedule]:
        """Get schedule by ID."""
        return self.schedules.get(schedule_id)
    
    def get_schedules_by_vulnerability(self, vulnerability_id: str) -> List[ValidationSchedule]:
        """Get all schedules for a vulnerability."""
        return [s for s in self.schedules.values() if s.vulnerability_id == vulnerability_id]
    
    def get_enabled_schedules(self) -> List[ValidationSchedule]:
        """Get all enabled schedules."""
        return [s for s in self.schedules.values() if s.enabled]
    
    def get_schedule_statistics(self) -> Dict[str, Any]:
        """
        Get scheduler statistics.
        
        Returns:
            Statistics dictionary
        """
        schedules = list(self.schedules.values())
        enabled_schedules = [s for s in schedules if s.enabled]
        
        total_runs = sum(s.total_runs for s in schedules)
        successful_runs = sum(s.successful_runs for s in schedules)
        failed_runs = sum(s.failed_runs for s in schedules)
        
        return {
            'total_schedules': len(schedules),
            'enabled_schedules': len(enabled_schedules),
            'disabled_schedules': len(schedules) - len(enabled_schedules),
            'total_runs': total_runs,
            'successful_runs': successful_runs,
            'failed_runs': failed_runs,
            'success_rate': successful_runs / total_runs if total_runs > 0 else 0.0,
            'scheduler_running': self.running,
            'frequency_distribution': self._get_frequency_distribution()
        }
    
    def _get_frequency_distribution(self) -> Dict[str, int]:
        """Get distribution of schedule frequencies."""
        distribution = {}
        for schedule in self.schedules.values():
            freq = schedule.frequency.value
            distribution[freq] = distribution.get(freq, 0) + 1
        return distribution

