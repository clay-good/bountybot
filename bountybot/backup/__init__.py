"""
Backup & Disaster Recovery Module

Provides enterprise-grade data protection:
- Automated backup scheduling
- Multiple storage backends (local, S3, GCS, Azure)
- Backup encryption and compression
- Point-in-time recovery
- Backup verification and integrity checks
- Retention policies and lifecycle management
- Compliance and audit logging
"""

from .backup_manager import BackupManager
from .storage_backends import (
    StorageBackend,
    LocalStorageBackend,
    S3StorageBackend,
    GCSStorageBackend,
    AzureStorageBackend
)
from .backup_scheduler import BackupScheduler
from .restore_manager import RestoreManager
from .models import (
    BackupMetadata,
    BackupType,
    BackupStatus,
    RestoreStatus,
    RetentionPolicy,
    CompressionType,
    EncryptionType
)
from .backup_scheduler import ScheduleFrequency

__all__ = [
    'BackupManager',
    'StorageBackend',
    'LocalStorageBackend',
    'S3StorageBackend',
    'GCSStorageBackend',
    'AzureStorageBackend',
    'BackupScheduler',
    'RestoreManager',
    'BackupMetadata',
    'BackupType',
    'BackupStatus',
    'RestoreStatus',
    'RetentionPolicy',
    'CompressionType',
    'EncryptionType',
    'ScheduleFrequency'
]

