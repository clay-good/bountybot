"""
Backup Models

Data models for backup and disaster recovery.
"""

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any, List


class BackupType(enum.Enum):
    """Backup type."""
    FULL = "full"
    INCREMENTAL = "incremental"
    DIFFERENTIAL = "differential"


class BackupStatus(enum.Enum):
    """Backup status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    VERIFYING = "verifying"
    VERIFIED = "verified"


class RestoreStatus(enum.Enum):
    """Restore status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    VALIDATING = "validating"


class CompressionType(enum.Enum):
    """Compression type."""
    NONE = "none"
    GZIP = "gzip"
    ZSTD = "zstd"
    BZIP2 = "bzip2"


class EncryptionType(enum.Enum):
    """Encryption type."""
    NONE = "none"
    AES256 = "aes256"
    AES128 = "aes128"


@dataclass
class BackupMetadata:
    """Backup metadata."""
    
    # Identification
    backup_id: str
    backup_name: str
    backup_type: BackupType
    
    # Timing
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Status
    status: BackupStatus = BackupStatus.PENDING
    error_message: Optional[str] = None
    
    # Database info
    database_url: str = ""
    database_type: str = ""  # postgresql, sqlite
    database_version: str = ""
    
    # Backup details
    storage_backend: str = ""  # local, s3, gcs, azure
    storage_path: str = ""
    file_size_bytes: int = 0
    compressed_size_bytes: int = 0
    
    # Compression and encryption
    compression_type: CompressionType = CompressionType.GZIP
    encryption_type: EncryptionType = EncryptionType.NONE
    encryption_key_id: Optional[str] = None
    
    # Content
    tables_backed_up: List[str] = field(default_factory=list)
    row_counts: Dict[str, int] = field(default_factory=dict)
    
    # Verification
    checksum_algorithm: str = "sha256"
    checksum: Optional[str] = None
    verified_at: Optional[datetime] = None
    verification_passed: bool = False
    
    # Performance
    duration_seconds: float = 0.0
    backup_rate_mbps: float = 0.0
    
    # Retention
    retention_days: int = 30
    expires_at: Optional[datetime] = None
    
    # Parent backup (for incremental/differential)
    parent_backup_id: Optional[str] = None
    
    # Metadata
    tags: Dict[str, str] = field(default_factory=dict)
    notes: str = ""
    created_by: str = "system"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'backup_id': self.backup_id,
            'backup_name': self.backup_name,
            'backup_type': self.backup_type.value,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'status': self.status.value,
            'error_message': self.error_message,
            'database_url': self._redact_password(self.database_url),
            'database_type': self.database_type,
            'database_version': self.database_version,
            'storage_backend': self.storage_backend,
            'storage_path': self.storage_path,
            'file_size_bytes': self.file_size_bytes,
            'compressed_size_bytes': self.compressed_size_bytes,
            'compression_type': self.compression_type.value,
            'encryption_type': self.encryption_type.value,
            'encryption_key_id': self.encryption_key_id,
            'tables_backed_up': self.tables_backed_up,
            'row_counts': self.row_counts,
            'checksum_algorithm': self.checksum_algorithm,
            'checksum': self.checksum,
            'verified_at': self.verified_at.isoformat() if self.verified_at else None,
            'verification_passed': self.verification_passed,
            'duration_seconds': self.duration_seconds,
            'backup_rate_mbps': self.backup_rate_mbps,
            'retention_days': self.retention_days,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'parent_backup_id': self.parent_backup_id,
            'tags': self.tags,
            'notes': self.notes,
            'created_by': self.created_by
        }
    
    @staticmethod
    def _redact_password(url: str) -> str:
        """Redact password from database URL."""
        if '@' in url and '://' in url:
            protocol, rest = url.split('://', 1)
            if '@' in rest:
                credentials, host = rest.split('@', 1)
                if ':' in credentials:
                    user, _ = credentials.split(':', 1)
                    return f"{protocol}://{user}:***@{host}"
        return url


@dataclass
class RestoreMetadata:
    """Restore operation metadata."""
    
    # Identification
    restore_id: str
    backup_id: str
    
    # Timing
    started_at: datetime
    completed_at: Optional[datetime] = None
    
    # Status
    status: RestoreStatus = RestoreStatus.PENDING
    error_message: Optional[str] = None
    
    # Target database
    target_database_url: str = ""
    target_database_type: str = ""
    
    # Restore options
    point_in_time: Optional[datetime] = None
    tables_to_restore: Optional[List[str]] = None
    skip_tables: Optional[List[str]] = None
    
    # Progress
    tables_restored: List[str] = field(default_factory=list)
    rows_restored: Dict[str, int] = field(default_factory=dict)
    
    # Performance
    duration_seconds: float = 0.0
    restore_rate_mbps: float = 0.0
    
    # Validation
    validation_passed: bool = False
    validation_errors: List[str] = field(default_factory=list)
    
    # Metadata
    notes: str = ""
    created_by: str = "system"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'restore_id': self.restore_id,
            'backup_id': self.backup_id,
            'started_at': self.started_at.isoformat(),
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'status': self.status.value,
            'error_message': self.error_message,
            'target_database_url': BackupMetadata._redact_password(self.target_database_url),
            'target_database_type': self.target_database_type,
            'point_in_time': self.point_in_time.isoformat() if self.point_in_time else None,
            'tables_to_restore': self.tables_to_restore,
            'skip_tables': self.skip_tables,
            'tables_restored': self.tables_restored,
            'rows_restored': self.rows_restored,
            'duration_seconds': self.duration_seconds,
            'restore_rate_mbps': self.restore_rate_mbps,
            'validation_passed': self.validation_passed,
            'validation_errors': self.validation_errors,
            'notes': self.notes,
            'created_by': self.created_by
        }


@dataclass
class RetentionPolicy:
    """Backup retention policy."""
    
    # Retention periods
    hourly_retention_days: int = 1  # Keep hourly backups for 1 day
    daily_retention_days: int = 7   # Keep daily backups for 7 days
    weekly_retention_days: int = 30  # Keep weekly backups for 30 days
    monthly_retention_days: int = 365  # Keep monthly backups for 1 year
    yearly_retention_days: int = 2555  # Keep yearly backups for 7 years
    
    # Minimum backups to keep
    min_backups_to_keep: int = 3
    
    # Maximum backups to keep
    max_backups_to_keep: Optional[int] = None
    
    # Storage limits
    max_storage_gb: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'hourly_retention_days': self.hourly_retention_days,
            'daily_retention_days': self.daily_retention_days,
            'weekly_retention_days': self.weekly_retention_days,
            'monthly_retention_days': self.monthly_retention_days,
            'yearly_retention_days': self.yearly_retention_days,
            'min_backups_to_keep': self.min_backups_to_keep,
            'max_backups_to_keep': self.max_backups_to_keep,
            'max_storage_gb': self.max_storage_gb
        }

