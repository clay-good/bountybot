"""
Backup Scheduler

Automated backup scheduling with retention policies.
"""

import logging
import threading
import time
from datetime import datetime, timedelta
from typing import Optional, Callable, Dict, Any, List
from enum import Enum

from .backup_manager import BackupManager
from .models import BackupType, BackupMetadata, RetentionPolicy

logger = logging.getLogger(__name__)


class ScheduleFrequency(Enum):
    """Backup schedule frequency."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


class BackupScheduler:
    """
    Automated backup scheduler with retention policies.
    
    Features:
    - Scheduled backups (hourly, daily, weekly, monthly)
    - Retention policy enforcement
    - Backup pruning
    - Health monitoring
    """
    
    def __init__(
        self,
        backup_manager: BackupManager,
        retention_policy: Optional[RetentionPolicy] = None
    ):
        """
        Initialize backup scheduler.
        
        Args:
            backup_manager: BackupManager instance
            retention_policy: Retention policy for backups
        """
        self.backup_manager = backup_manager
        self.retention_policy = retention_policy or RetentionPolicy()
        
        self._schedules: Dict[ScheduleFrequency, Dict[str, Any]] = {}
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_backup_times: Dict[ScheduleFrequency, datetime] = {}
        
        logger.info("Backup scheduler initialized")
    
    def schedule_backup(
        self,
        frequency: ScheduleFrequency,
        backup_type: BackupType = BackupType.FULL,
        hour: int = 0,
        minute: int = 0,
        day_of_week: int = 0,  # 0 = Monday, 6 = Sunday
        day_of_month: int = 1,
        enabled: bool = True,
        callback: Optional[Callable[[BackupMetadata], None]] = None
    ):
        """
        Schedule a backup.
        
        Args:
            frequency: Backup frequency
            backup_type: Type of backup
            hour: Hour to run (0-23)
            minute: Minute to run (0-59)
            day_of_week: Day of week for weekly backups (0-6)
            day_of_month: Day of month for monthly backups (1-31)
            enabled: Whether schedule is enabled
            callback: Optional callback function called after backup
        """
        self._schedules[frequency] = {
            'backup_type': backup_type,
            'hour': hour,
            'minute': minute,
            'day_of_week': day_of_week,
            'day_of_month': day_of_month,
            'enabled': enabled,
            'callback': callback
        }
        
        logger.info(f"Scheduled {frequency.value} backup at {hour:02d}:{minute:02d}")
    
    def start(self):
        """Start the backup scheduler."""
        if self._running:
            logger.warning("Backup scheduler already running")
            return
        
        self._running = True
        self._thread = threading.Thread(target=self._run_scheduler, daemon=True)
        self._thread.start()
        
        logger.info("Backup scheduler started")
    
    def stop(self):
        """Stop the backup scheduler."""
        if not self._running:
            return
        
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        
        logger.info("Backup scheduler stopped")
    
    def _run_scheduler(self):
        """Main scheduler loop."""
        while self._running:
            try:
                now = datetime.utcnow()
                
                # Check each schedule
                for frequency, schedule in self._schedules.items():
                    if not schedule['enabled']:
                        continue
                    
                    if self._should_run_backup(frequency, schedule, now):
                        self._execute_backup(frequency, schedule)
                
                # Check retention policy
                self._enforce_retention_policy()
                
                # Sleep for 1 minute
                time.sleep(60)
                
            except Exception as e:
                logger.error(f"Error in backup scheduler: {e}")
                time.sleep(60)
    
    def _should_run_backup(
        self,
        frequency: ScheduleFrequency,
        schedule: Dict[str, Any],
        now: datetime
    ) -> bool:
        """Check if backup should run now."""
        # Get last backup time
        last_backup = self._last_backup_times.get(frequency)
        
        # Check frequency-specific conditions
        if frequency == ScheduleFrequency.HOURLY:
            # Run every hour at specified minute
            if now.minute == schedule['minute']:
                if not last_backup or (now - last_backup) >= timedelta(hours=1):
                    return True
        
        elif frequency == ScheduleFrequency.DAILY:
            # Run daily at specified time
            if now.hour == schedule['hour'] and now.minute == schedule['minute']:
                if not last_backup or (now - last_backup) >= timedelta(days=1):
                    return True
        
        elif frequency == ScheduleFrequency.WEEKLY:
            # Run weekly on specified day and time
            if (now.weekday() == schedule['day_of_week'] and
                now.hour == schedule['hour'] and
                now.minute == schedule['minute']):
                if not last_backup or (now - last_backup) >= timedelta(days=7):
                    return True
        
        elif frequency == ScheduleFrequency.MONTHLY:
            # Run monthly on specified day and time
            if (now.day == schedule['day_of_month'] and
                now.hour == schedule['hour'] and
                now.minute == schedule['minute']):
                if not last_backup or (now - last_backup) >= timedelta(days=28):
                    return True
        
        return False
    
    def _execute_backup(self, frequency: ScheduleFrequency, schedule: Dict[str, Any]):
        """Execute a scheduled backup."""
        try:
            logger.info(f"Executing {frequency.value} backup")
            
            # Create backup
            backup_name = f"{frequency.value}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
            
            # Determine retention days based on frequency
            retention_days = self._get_retention_days(frequency)
            
            metadata = self.backup_manager.create_backup(
                backup_name=backup_name,
                backup_type=schedule['backup_type'],
                tags={'frequency': frequency.value},
                retention_days=retention_days
            )
            
            # Update last backup time
            self._last_backup_times[frequency] = datetime.utcnow()
            
            # Call callback if provided
            if schedule.get('callback'):
                try:
                    schedule['callback'](metadata)
                except Exception as e:
                    logger.error(f"Error in backup callback: {e}")
            
            logger.info(f"Scheduled backup completed: {metadata.backup_id}")
            
        except Exception as e:
            logger.error(f"Failed to execute scheduled backup: {e}")
    
    def _get_retention_days(self, frequency: ScheduleFrequency) -> int:
        """Get retention days for frequency."""
        if frequency == ScheduleFrequency.HOURLY:
            return self.retention_policy.hourly_retention_days
        elif frequency == ScheduleFrequency.DAILY:
            return self.retention_policy.daily_retention_days
        elif frequency == ScheduleFrequency.WEEKLY:
            return self.retention_policy.weekly_retention_days
        elif frequency == ScheduleFrequency.MONTHLY:
            return self.retention_policy.monthly_retention_days
        return 30
    
    def _enforce_retention_policy(self):
        """Enforce retention policy by pruning old backups."""
        try:
            now = datetime.utcnow()
            backups = self.backup_manager.list_backups()
            
            # Group backups by frequency
            backups_by_frequency: Dict[str, List[BackupMetadata]] = {}
            for backup in backups:
                frequency = backup.tags.get('frequency', 'unknown')
                if frequency not in backups_by_frequency:
                    backups_by_frequency[frequency] = []
                backups_by_frequency[frequency].append(backup)
            
            # Check each frequency
            for frequency_str, frequency_backups in backups_by_frequency.items():
                # Sort by start time (oldest first)
                frequency_backups.sort(key=lambda x: x.started_at)
                
                # Get retention days
                if frequency_str == 'hourly':
                    retention_days = self.retention_policy.hourly_retention_days
                elif frequency_str == 'daily':
                    retention_days = self.retention_policy.daily_retention_days
                elif frequency_str == 'weekly':
                    retention_days = self.retention_policy.weekly_retention_days
                elif frequency_str == 'monthly':
                    retention_days = self.retention_policy.monthly_retention_days
                else:
                    retention_days = 30
                
                # Delete expired backups
                for backup in frequency_backups:
                    age_days = (now - backup.started_at).days
                    
                    # Keep minimum number of backups
                    if len(frequency_backups) <= self.retention_policy.min_backups_to_keep:
                        continue
                    
                    # Delete if expired
                    if age_days > retention_days:
                        logger.info(f"Deleting expired backup: {backup.backup_id} (age: {age_days} days)")
                        self.backup_manager.delete_backup(backup.backup_id)
                        frequency_backups.remove(backup)
            
            # Check max backups limit
            if self.retention_policy.max_backups_to_keep:
                if len(backups) > self.retention_policy.max_backups_to_keep:
                    # Delete oldest backups
                    backups.sort(key=lambda x: x.started_at)
                    to_delete = len(backups) - self.retention_policy.max_backups_to_keep
                    for backup in backups[:to_delete]:
                        logger.info(f"Deleting backup (max limit): {backup.backup_id}")
                        self.backup_manager.delete_backup(backup.backup_id)
            
            # Check storage limit
            if self.retention_policy.max_storage_gb:
                total_size_gb = sum(b.compressed_size_bytes for b in backups) / 1024 / 1024 / 1024
                if total_size_gb > self.retention_policy.max_storage_gb:
                    # Delete oldest backups until under limit
                    backups.sort(key=lambda x: x.started_at)
                    for backup in backups:
                        if total_size_gb <= self.retention_policy.max_storage_gb:
                            break
                        logger.info(f"Deleting backup (storage limit): {backup.backup_id}")
                        self.backup_manager.delete_backup(backup.backup_id)
                        total_size_gb -= backup.compressed_size_bytes / 1024 / 1024 / 1024
            
        except Exception as e:
            logger.error(f"Failed to enforce retention policy: {e}")
    
    def get_schedule_status(self) -> Dict[str, Any]:
        """
        Get scheduler status.
        
        Returns:
            Dictionary with scheduler status
        """
        return {
            'running': self._running,
            'schedules': {
                freq.value: {
                    'enabled': schedule['enabled'],
                    'backup_type': schedule['backup_type'].value,
                    'last_backup': self._last_backup_times.get(freq).isoformat() if freq in self._last_backup_times else None
                }
                for freq, schedule in self._schedules.items()
            },
            'retention_policy': self.retention_policy.to_dict()
        }

