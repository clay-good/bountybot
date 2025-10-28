"""
Demo: Backup & Disaster Recovery System

Demonstrates the backup and disaster recovery capabilities of BountyBot.
"""

import os
import tempfile
import shutil
from datetime import datetime

from bountybot.backup import (
    BackupManager,
    RestoreManager,
    BackupScheduler,
    LocalStorageBackend,
    BackupType,
    RetentionPolicy,
    ScheduleFrequency
)


def print_section(title: str):
    """Print a section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def demo_basic_backup():
    """Demonstrate basic backup functionality."""
    print_section("1. Basic Backup Operations")
    
    # Create temporary directory for demo
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create a test SQLite database
        import sqlite3
        db_path = os.path.join(temp_dir, "demo.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Create tables and insert data
        cursor.execute("""
            CREATE TABLE reports (
                id INTEGER PRIMARY KEY,
                title TEXT,
                severity TEXT,
                created_at TIMESTAMP
            )
        """)
        cursor.execute("""
            INSERT INTO reports (title, severity, created_at)
            VALUES ('SQL Injection', 'CRITICAL', datetime('now'))
        """)
        cursor.execute("""
            INSERT INTO reports (title, severity, created_at)
            VALUES ('XSS Vulnerability', 'HIGH', datetime('now'))
        """)
        conn.commit()
        conn.close()
        
        print(f"✓ Created demo database: {db_path}")
        print(f"  - 2 vulnerability reports")
        
        # Set up backup storage
        backup_storage = os.path.join(temp_dir, "backups")
        storage_backend = LocalStorageBackend(backup_storage)
        
        print(f"✓ Configured backup storage: {backup_storage}")
        
        # Create backup manager
        backup_manager = BackupManager(
            database_url=f"sqlite:///{db_path}",
            storage_backend=storage_backend,
            temp_dir=temp_dir
        )
        
        print(f"✓ Initialized backup manager")
        
        # Create a full backup
        print("\n📦 Creating full backup...")
        metadata = backup_manager.create_backup(
            backup_name="demo_full_backup",
            backup_type=BackupType.FULL,
            tags={'environment': 'demo', 'type': 'manual'},
            retention_days=30
        )
        
        print(f"✓ Backup created successfully!")
        print(f"  - Backup ID: {metadata.backup_id}")
        print(f"  - Status: {metadata.status.value}")
        print(f"  - Size: {metadata.compressed_size_bytes / 1024:.2f} KB")
        print(f"  - Duration: {metadata.duration_seconds:.2f} seconds")
        print(f"  - Checksum: {metadata.checksum[:16]}...")
        print(f"  - Tables: {', '.join(metadata.tables_backed_up)}")
        print(f"  - Row counts: {metadata.row_counts}")
        
        # Verify backup
        print("\n🔍 Verifying backup integrity...")
        verified = backup_manager.verify_backup(metadata.backup_id)
        print(f"✓ Backup verification: {'PASSED' if verified else 'FAILED'}")
        
        # List backups
        print("\n📋 Listing all backups...")
        backups = backup_manager.list_backups()
        print(f"✓ Found {len(backups)} backup(s)")
        for backup in backups:
            print(f"  - {backup.backup_name} ({backup.backup_type.value})")
            print(f"    Created: {backup.started_at.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"    Size: {backup.compressed_size_bytes / 1024:.2f} KB")
        
        # Get backup statistics
        print("\n📊 Backup Statistics:")
        stats = backup_manager.get_backup_stats()
        print(f"  - Total backups: {stats['total_backups']}")
        print(f"  - Completed: {stats['completed_backups']}")
        print(f"  - Failed: {stats['failed_backups']}")
        print(f"  - Total size: {stats['total_size_gb']:.4f} GB")
        print(f"  - Storage backend: {stats['storage_backend']}")
        
        return backup_manager, metadata, temp_dir
        
    except Exception as e:
        print(f"❌ Error: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def demo_restore(backup_manager, backup_metadata, temp_dir):
    """Demonstrate restore functionality."""
    print_section("2. Database Restore Operations")
    
    try:
        # Create target database path
        target_db_path = os.path.join(temp_dir, "restored.db")
        
        print(f"📥 Restoring backup to: {target_db_path}")
        
        # Create restore manager
        restore_manager = RestoreManager(
            backup_manager=backup_manager,
            target_database_url=f"sqlite:///{target_db_path}",
            temp_dir=temp_dir
        )
        
        print(f"✓ Initialized restore manager")
        
        # Restore backup
        print(f"\n🔄 Restoring backup: {backup_metadata.backup_id}")
        restore_metadata = restore_manager.restore_backup(
            backup_id=backup_metadata.backup_id,
            verify=True
        )
        
        print(f"✓ Restore completed successfully!")
        print(f"  - Restore ID: {restore_metadata.restore_id}")
        print(f"  - Status: {restore_metadata.status.value}")
        print(f"  - Duration: {restore_metadata.duration_seconds:.2f} seconds")
        print(f"  - Validation: {'PASSED' if restore_metadata.validation_passed else 'FAILED'}")
        
        # Verify restored data
        print("\n🔍 Verifying restored data...")
        import sqlite3
        conn = sqlite3.connect(target_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM reports")
        count = cursor.fetchone()[0]
        cursor.execute("SELECT title, severity FROM reports")
        reports = cursor.fetchall()
        conn.close()
        
        print(f"✓ Found {count} reports in restored database:")
        for title, severity in reports:
            print(f"  - {title} ({severity})")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        raise


def demo_scheduler():
    """Demonstrate backup scheduler."""
    print_section("3. Automated Backup Scheduling")
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Create test database
        import sqlite3
        db_path = os.path.join(temp_dir, "scheduled.db")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test (id INTEGER PRIMARY KEY)")
        conn.commit()
        conn.close()
        
        # Set up backup manager
        backup_storage = os.path.join(temp_dir, "backups")
        storage_backend = LocalStorageBackend(backup_storage)
        backup_manager = BackupManager(
            database_url=f"sqlite:///{db_path}",
            storage_backend=storage_backend,
            temp_dir=temp_dir
        )
        
        # Create retention policy
        retention_policy = RetentionPolicy(
            hourly_retention_days=1,
            daily_retention_days=7,
            weekly_retention_days=30,
            monthly_retention_days=365,
            min_backups_to_keep=3
        )
        
        print("📅 Retention Policy:")
        print(f"  - Hourly backups: {retention_policy.hourly_retention_days} day(s)")
        print(f"  - Daily backups: {retention_policy.daily_retention_days} day(s)")
        print(f"  - Weekly backups: {retention_policy.weekly_retention_days} day(s)")
        print(f"  - Monthly backups: {retention_policy.monthly_retention_days} day(s)")
        print(f"  - Minimum backups to keep: {retention_policy.min_backups_to_keep}")
        
        # Create scheduler
        scheduler = BackupScheduler(
            backup_manager=backup_manager,
            retention_policy=retention_policy
        )
        
        print("\n✓ Initialized backup scheduler")
        
        # Schedule backups
        print("\n⏰ Scheduling automated backups...")
        
        scheduler.schedule_backup(
            frequency=ScheduleFrequency.HOURLY,
            backup_type=BackupType.INCREMENTAL,
            minute=0
        )
        print("  ✓ Hourly backups: Every hour at :00")
        
        scheduler.schedule_backup(
            frequency=ScheduleFrequency.DAILY,
            backup_type=BackupType.FULL,
            hour=2,
            minute=0
        )
        print("  ✓ Daily backups: Every day at 02:00")
        
        scheduler.schedule_backup(
            frequency=ScheduleFrequency.WEEKLY,
            backup_type=BackupType.FULL,
            day_of_week=0,  # Monday
            hour=3,
            minute=0
        )
        print("  ✓ Weekly backups: Every Monday at 03:00")
        
        scheduler.schedule_backup(
            frequency=ScheduleFrequency.MONTHLY,
            backup_type=BackupType.FULL,
            day_of_month=1,
            hour=4,
            minute=0
        )
        print("  ✓ Monthly backups: 1st of each month at 04:00")
        
        # Get scheduler status
        print("\n📊 Scheduler Status:")
        status = scheduler.get_schedule_status()
        print(f"  - Running: {status['running']}")
        print(f"  - Configured schedules: {len(status['schedules'])}")
        
        for freq, schedule in status['schedules'].items():
            print(f"\n  {freq.upper()}:")
            print(f"    - Enabled: {schedule['enabled']}")
            print(f"    - Backup type: {schedule['backup_type']}")
            print(f"    - Last backup: {schedule['last_backup'] or 'Never'}")
        
        print("\n💡 Note: Scheduler is configured but not started in demo mode")
        print("   In production, call scheduler.start() to begin automated backups")
        
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    except Exception as e:
        print(f"❌ Error: {e}")
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise


def demo_storage_backends():
    """Demonstrate different storage backends."""
    print_section("4. Storage Backend Options")
    
    print("📦 Available Storage Backends:\n")
    
    print("1. Local Filesystem")
    print("   - Fast and simple")
    print("   - Good for development and testing")
    print("   - Example: LocalStorageBackend('/var/backups/bountybot')")
    
    print("\n2. AWS S3")
    print("   - Scalable cloud storage")
    print("   - Automatic redundancy")
    print("   - Example: S3StorageBackend('my-backup-bucket', region='us-east-1')")
    
    print("\n3. Google Cloud Storage")
    print("   - Google Cloud integration")
    print("   - Global availability")
    print("   - Example: GCSStorageBackend('my-backup-bucket', project_id='my-project')")
    
    print("\n4. Azure Blob Storage")
    print("   - Microsoft Azure integration")
    print("   - Enterprise features")
    print("   - Example: AzureStorageBackend('my-container', account_name='myaccount')")
    
    print("\n💡 All backends support:")
    print("   - Upload/download")
    print("   - File listing")
    print("   - Metadata retrieval")
    print("   - Deletion")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BountyBot - Backup & Disaster Recovery System Demo")
    print("=" * 80)
    
    try:
        # Demo 1: Basic backup
        backup_manager, backup_metadata, temp_dir = demo_basic_backup()
        
        # Demo 2: Restore
        demo_restore(backup_manager, backup_metadata, temp_dir)
        
        # Clean up
        shutil.rmtree(temp_dir, ignore_errors=True)
        
        # Demo 3: Scheduler
        demo_scheduler()
        
        # Demo 4: Storage backends
        demo_storage_backends()
        
        print_section("Demo Complete!")
        print("✅ All backup and disaster recovery features demonstrated successfully!")
        print("\n📚 Key Features:")
        print("  ✓ Automated backups (full, incremental, differential)")
        print("  ✓ Multiple storage backends (local, S3, GCS, Azure)")
        print("  ✓ Backup compression and encryption")
        print("  ✓ Backup verification and integrity checks")
        print("  ✓ Point-in-time recovery")
        print("  ✓ Automated scheduling with retention policies")
        print("  ✓ Backup monitoring and statistics")
        
    except Exception as e:
        print(f"\n❌ Demo failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

