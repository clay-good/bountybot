# Backup & Disaster Recovery System

BountyBot includes a comprehensive backup and disaster recovery system for protecting your security validation data.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
- [Storage Backends](#storage-backends)
- [Backup Types](#backup-types)
- [Scheduling](#scheduling)
- [Retention Policies](#retention-policies)
- [Restore Operations](#restore-operations)
- [Best Practices](#best-practices)
- [API Reference](#api-reference)

## Overview

The backup system provides automated, reliable, and secure backup and restore capabilities for BountyBot databases. It supports multiple storage backends, compression, encryption, and automated scheduling with retention policies.

### Key Features

- **Automated Backups**: Schedule backups at hourly, daily, weekly, or monthly intervals
- **Multiple Storage Backends**: Local filesystem, AWS S3, Google Cloud Storage, Azure Blob Storage
- **Backup Types**: Full, incremental, and differential backups
- **Compression**: Reduce storage costs with gzip, zstd, or bzip2 compression
- **Encryption**: Secure backups with AES-256 or AES-128 encryption
- **Verification**: Automatic integrity checks using SHA-256 checksums
- **Point-in-Time Recovery**: Restore to any previous backup
- **Retention Policies**: Automatic cleanup of old backups
- **Monitoring**: Track backup status, size, and performance

## Quick Start

### Basic Backup

```python
from bountybot.backup import BackupManager, LocalStorageBackend, BackupType

# Configure storage backend
storage = LocalStorageBackend('/var/backups/bountybot')

# Create backup manager
backup_manager = BackupManager(
    database_url='postgresql://user:pass@localhost/bountybot',
    storage_backend=storage
)

# Create a backup
metadata = backup_manager.create_backup(
    backup_name='production_backup',
    backup_type=BackupType.FULL,
    retention_days=30
)

print(f"Backup created: {metadata.backup_id}")
print(f"Size: {metadata.compressed_size_bytes / 1024 / 1024:.2f} MB")
```

### Restore Backup

```python
from bountybot.backup import RestoreManager

# Create restore manager
restore_manager = RestoreManager(
    backup_manager=backup_manager,
    target_database_url='postgresql://user:pass@localhost/bountybot_restored'
)

# Restore backup
restore_metadata = restore_manager.restore_backup(
    backup_id=metadata.backup_id,
    verify=True
)

print(f"Restore completed: {restore_metadata.restore_id}")
```

### Automated Scheduling

```python
from bountybot.backup import BackupScheduler, ScheduleFrequency, RetentionPolicy

# Configure retention policy
retention_policy = RetentionPolicy(
    hourly_retention_days=1,
    daily_retention_days=7,
    weekly_retention_days=30,
    monthly_retention_days=365,
    min_backups_to_keep=3
)

# Create scheduler
scheduler = BackupScheduler(
    backup_manager=backup_manager,
    retention_policy=retention_policy
)

# Schedule daily backups at 2 AM
scheduler.schedule_backup(
    frequency=ScheduleFrequency.DAILY,
    backup_type=BackupType.FULL,
    hour=2,
    minute=0
)

# Start scheduler
scheduler.start()
```

## Storage Backends

### Local Filesystem

Best for development and testing.

```python
from bountybot.backup import LocalStorageBackend

storage = LocalStorageBackend('/var/backups/bountybot')
```

### AWS S3

Scalable cloud storage with automatic redundancy.

```python
from bountybot.backup import S3StorageBackend

storage = S3StorageBackend(
    bucket_name='my-backup-bucket',
    region='us-east-1',
    aws_access_key_id='YOUR_ACCESS_KEY',
    aws_secret_access_key='YOUR_SECRET_KEY'
)
```

### Google Cloud Storage

Google Cloud integration with global availability.

```python
from bountybot.backup import GCSStorageBackend

storage = GCSStorageBackend(
    bucket_name='my-backup-bucket',
    project_id='my-project',
    credentials_path='/path/to/credentials.json'
)
```

### Azure Blob Storage

Microsoft Azure integration with enterprise features.

```python
from bountybot.backup import AzureStorageBackend

storage = AzureStorageBackend(
    container_name='my-container',
    account_name='myaccount',
    account_key='YOUR_ACCOUNT_KEY'
)
```

## Backup Types

### Full Backup

Complete backup of all database tables and data.

```python
metadata = backup_manager.create_backup(
    backup_type=BackupType.FULL
)
```

**Pros:**
- Complete data snapshot
- Fastest restore time
- No dependencies on other backups

**Cons:**
- Largest storage size
- Longest backup time

### Incremental Backup

Only backs up changes since the last backup (full or incremental).

```python
metadata = backup_manager.create_backup(
    backup_type=BackupType.INCREMENTAL
)
```

**Pros:**
- Smallest storage size
- Fastest backup time

**Cons:**
- Requires all previous backups to restore
- Slower restore time

### Differential Backup

Backs up changes since the last full backup.

```python
metadata = backup_manager.create_backup(
    backup_type=BackupType.DIFFERENTIAL
)
```

**Pros:**
- Moderate storage size
- Only requires last full backup to restore

**Cons:**
- Larger than incremental
- Grows over time until next full backup

## Scheduling

### Schedule Frequencies

- **Hourly**: Every hour at specified minute
- **Daily**: Every day at specified hour and minute
- **Weekly**: Every week on specified day at specified time
- **Monthly**: Every month on specified day at specified time

### Example Schedules

```python
# Hourly backups (incremental)
scheduler.schedule_backup(
    frequency=ScheduleFrequency.HOURLY,
    backup_type=BackupType.INCREMENTAL,
    minute=0
)

# Daily backups (full) at 2 AM
scheduler.schedule_backup(
    frequency=ScheduleFrequency.DAILY,
    backup_type=BackupType.FULL,
    hour=2,
    minute=0
)

# Weekly backups (full) on Monday at 3 AM
scheduler.schedule_backup(
    frequency=ScheduleFrequency.WEEKLY,
    backup_type=BackupType.FULL,
    day_of_week=0,  # 0 = Monday
    hour=3,
    minute=0
)

# Monthly backups (full) on 1st at 4 AM
scheduler.schedule_backup(
    frequency=ScheduleFrequency.MONTHLY,
    backup_type=BackupType.FULL,
    day_of_month=1,
    hour=4,
    minute=0
)
```

## Retention Policies

Retention policies automatically delete old backups based on age and frequency.

```python
retention_policy = RetentionPolicy(
    hourly_retention_days=1,      # Keep hourly backups for 1 day
    daily_retention_days=7,       # Keep daily backups for 7 days
    weekly_retention_days=30,     # Keep weekly backups for 30 days
    monthly_retention_days=365,   # Keep monthly backups for 1 year
    yearly_retention_days=2555,   # Keep yearly backups for 7 years
    min_backups_to_keep=3,        # Always keep at least 3 backups
    max_backups_to_keep=100,      # Never keep more than 100 backups
    max_storage_gb=500.0          # Delete oldest if storage exceeds 500 GB
)
```

### Retention Rules

1. Backups are categorized by frequency (hourly, daily, weekly, monthly, yearly)
2. Backups older than retention period are deleted
3. Always keep at least `min_backups_to_keep` backups
4. Never keep more than `max_backups_to_keep` backups
5. Delete oldest backups if storage exceeds `max_storage_gb`

## Restore Operations

### Full Restore

Restore entire database from backup.

```python
restore_metadata = restore_manager.restore_backup(
    backup_id='backup_20231017_120000_abc123',
    verify=True
)
```

### Selective Table Restore

Restore only specific tables.

```python
restore_metadata = restore_manager.restore_backup(
    backup_id='backup_20231017_120000_abc123',
    tables_to_restore=['reports', 'validation_results'],
    verify=True
)
```

### Point-in-Time Recovery

Restore to a specific point in time.

```python
from datetime import datetime

restore_metadata = restore_manager.restore_backup(
    backup_id='backup_20231017_120000_abc123',
    point_in_time=datetime(2023, 10, 17, 12, 0, 0),
    verify=True
)
```

## Best Practices

### 1. Follow the 3-2-1 Rule

- Keep **3** copies of your data
- Store on **2** different media types
- Keep **1** copy offsite

### 2. Test Restores Regularly

```python
# Test restore to temporary database
test_restore_manager = RestoreManager(
    backup_manager=backup_manager,
    target_database_url='postgresql://user:pass@localhost/bountybot_test'
)

restore_metadata = test_restore_manager.restore_backup(
    backup_id=latest_backup_id,
    verify=True
)
```

### 3. Monitor Backup Health

```python
# Get backup statistics
stats = backup_manager.get_backup_stats()

if stats['failed_backups'] > 0:
    # Alert on failures
    send_alert(f"Backup failures detected: {stats['failed_backups']}")

if stats['total_size_gb'] > 100:
    # Alert on storage usage
    send_alert(f"Backup storage high: {stats['total_size_gb']:.2f} GB")
```

### 4. Use Appropriate Backup Types

- **Full backups**: Weekly or monthly
- **Differential backups**: Daily
- **Incremental backups**: Hourly

### 5. Encrypt Sensitive Data

```python
from bountybot.backup import EncryptionType

backup_manager = BackupManager(
    database_url=database_url,
    storage_backend=storage,
    encryption_type=EncryptionType.AES256,
    encryption_key='your-32-byte-encryption-key-here'
)
```

### 6. Set Appropriate Retention

Balance storage costs with recovery needs:

- **Compliance**: Keep backups for required retention period
- **Cost**: Delete old backups to reduce storage costs
- **Recovery**: Keep enough backups for point-in-time recovery

## API Reference

### BackupManager

Main class for creating and managing backups.

**Methods:**
- `create_backup()`: Create a new backup
- `list_backups()`: List all backups
- `get_backup_metadata()`: Get metadata for specific backup
- `delete_backup()`: Delete a backup
- `verify_backup()`: Verify backup integrity
- `get_backup_stats()`: Get backup statistics

### RestoreManager

Class for restoring backups.

**Methods:**
- `restore_backup()`: Restore a backup
- `list_restore_history()`: List restore history

### BackupScheduler

Class for scheduling automated backups.

**Methods:**
- `schedule_backup()`: Schedule a backup
- `start()`: Start scheduler
- `stop()`: Stop scheduler
- `get_schedule_status()`: Get scheduler status

### Storage Backends

Abstract interface for storage backends.

**Implementations:**
- `LocalStorageBackend`: Local filesystem
- `S3StorageBackend`: AWS S3
- `GCSStorageBackend`: Google Cloud Storage
- `AzureStorageBackend`: Azure Blob Storage

## Troubleshooting

### Backup Fails with "Database locked"

SQLite databases may be locked during backup. Use WAL mode:

```sql
PRAGMA journal_mode=WAL;
```

### Restore Fails with "Permission denied"

Ensure the database user has appropriate permissions:

```sql
GRANT ALL PRIVILEGES ON DATABASE bountybot TO backup_user;
```

### Storage Backend Connection Fails

Check credentials and network connectivity:

```python
# Test storage backend
if storage.exists('test.txt'):
    print("Storage backend connected")
else:
    print("Storage backend connection failed")
```

## Support

For issues or questions:
- GitHub Issues: https://github.com/yourusername/bountybot/issues
- Documentation: https://bountybot.readthedocs.io
- Email: support@bountybot.com

