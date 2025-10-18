"""
Tests for Backup & Disaster Recovery System
"""

import unittest
import tempfile
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path

from bountybot.backup.models import (
    BackupMetadata,
    BackupType,
    BackupStatus,
    RestoreMetadata,
    RestoreStatus,
    RetentionPolicy,
    CompressionType,
    EncryptionType
)
from bountybot.backup.storage_backends import (
    LocalStorageBackend,
    StorageBackend
)
from bountybot.backup.backup_manager import BackupManager
from bountybot.backup.restore_manager import RestoreManager
from bountybot.backup.backup_scheduler import BackupScheduler, ScheduleFrequency


class TestBackupModels(unittest.TestCase):
    """Test backup data models."""
    
    def test_backup_metadata_creation(self):
        """Test BackupMetadata creation."""
        metadata = BackupMetadata(
            backup_id="test_backup_001",
            backup_name="test_backup",
            backup_type=BackupType.FULL,
            started_at=datetime.utcnow(),
            database_url="postgresql://user:pass@localhost:5432/testdb"
        )
        
        self.assertEqual(metadata.backup_id, "test_backup_001")
        self.assertEqual(metadata.backup_type, BackupType.FULL)
        self.assertEqual(metadata.status, BackupStatus.PENDING)
    
    def test_backup_metadata_to_dict(self):
        """Test BackupMetadata serialization."""
        metadata = BackupMetadata(
            backup_id="test_backup_001",
            backup_name="test_backup",
            backup_type=BackupType.FULL,
            started_at=datetime.utcnow(),
            database_url="postgresql://user:pass@localhost:5432/testdb"
        )
        
        data = metadata.to_dict()
        
        self.assertIn('backup_id', data)
        self.assertIn('backup_type', data)
        self.assertIn('started_at', data)
        # Password should be redacted
        self.assertIn('***', data['database_url'])
    
    def test_restore_metadata_creation(self):
        """Test RestoreMetadata creation."""
        metadata = RestoreMetadata(
            restore_id="restore_001",
            backup_id="backup_001",
            started_at=datetime.utcnow()
        )
        
        self.assertEqual(metadata.restore_id, "restore_001")
        self.assertEqual(metadata.backup_id, "backup_001")
        self.assertEqual(metadata.status, RestoreStatus.PENDING)
    
    def test_retention_policy_defaults(self):
        """Test RetentionPolicy defaults."""
        policy = RetentionPolicy()
        
        self.assertEqual(policy.hourly_retention_days, 1)
        self.assertEqual(policy.daily_retention_days, 7)
        self.assertEqual(policy.weekly_retention_days, 30)
        self.assertEqual(policy.monthly_retention_days, 365)
        self.assertEqual(policy.min_backups_to_keep, 3)


class TestLocalStorageBackend(unittest.TestCase):
    """Test local storage backend."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage = LocalStorageBackend(self.temp_dir)
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_upload_file(self):
        """Test file upload."""
        # Create test file
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("test content")
        
        # Upload file
        result = self.storage.upload(test_file, "backups/test.txt")
        
        self.assertTrue(result)
        self.assertTrue(self.storage.exists("backups/test.txt"))
    
    def test_download_file(self):
        """Test file download."""
        # Create and upload test file
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("test content")
        
        self.storage.upload(test_file, "backups/test.txt")
        
        # Download file
        download_path = os.path.join(self.temp_dir, "downloaded.txt")
        result = self.storage.download("backups/test.txt", download_path)
        
        self.assertTrue(result)
        self.assertTrue(os.path.exists(download_path))
        
        with open(download_path, 'r') as f:
            content = f.read()
        self.assertEqual(content, "test content")
    
    def test_delete_file(self):
        """Test file deletion."""
        # Create and upload test file
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("test content")
        
        self.storage.upload(test_file, "backups/test.txt")
        self.assertTrue(self.storage.exists("backups/test.txt"))
        
        # Delete file
        result = self.storage.delete("backups/test.txt")
        
        self.assertTrue(result)
        self.assertFalse(self.storage.exists("backups/test.txt"))
    
    def test_list_files(self):
        """Test file listing."""
        # Create and upload multiple files
        for i in range(3):
            test_file = os.path.join(self.temp_dir, f"test{i}.txt")
            with open(test_file, 'w') as f:
                f.write(f"test content {i}")
            self.storage.upload(test_file, f"backups/test{i}.txt")
        
        # List files
        files = self.storage.list_files("backups/")
        
        self.assertEqual(len(files), 3)
    
    def test_get_size(self):
        """Test getting file size."""
        # Create and upload test file
        test_file = os.path.join(self.temp_dir, "test.txt")
        content = "test content"
        with open(test_file, 'w') as f:
            f.write(content)
        
        self.storage.upload(test_file, "backups/test.txt")
        
        # Get size
        size = self.storage.get_size("backups/test.txt")
        
        self.assertEqual(size, len(content))
    
    def test_get_metadata(self):
        """Test getting file metadata."""
        # Create and upload test file
        test_file = os.path.join(self.temp_dir, "test.txt")
        with open(test_file, 'w') as f:
            f.write("test content")
        
        self.storage.upload(test_file, "backups/test.txt")
        
        # Get metadata
        metadata = self.storage.get_metadata("backups/test.txt")
        
        self.assertIn('size', metadata)
        self.assertIn('created', metadata)
        self.assertIn('modified', metadata)


class TestBackupManager(unittest.TestCase):
    """Test backup manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage = LocalStorageBackend(os.path.join(self.temp_dir, "backups"))
        
        # Create test SQLite database
        self.db_path = os.path.join(self.temp_dir, "test.db")
        self.database_url = f"sqlite:///{self.db_path}"
        
        # Create database with test data
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
        cursor.execute("INSERT INTO test_table (name) VALUES ('test1')")
        cursor.execute("INSERT INTO test_table (name) VALUES ('test2')")
        conn.commit()
        conn.close()
        
        self.backup_manager = BackupManager(
            database_url=self.database_url,
            storage_backend=self.storage,
            temp_dir=self.temp_dir
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_create_sqlite_backup(self):
        """Test creating SQLite backup."""
        metadata = self.backup_manager.create_backup(
            backup_name="test_backup",
            backup_type=BackupType.FULL
        )
        
        self.assertEqual(metadata.status, BackupStatus.COMPLETED)
        self.assertEqual(metadata.database_type, "sqlite")
        self.assertGreater(metadata.file_size_bytes, 0)
        self.assertIsNotNone(metadata.checksum)
    
    def test_list_backups(self):
        """Test listing backups."""
        # Create multiple backups
        self.backup_manager.create_backup(backup_name="backup1")
        self.backup_manager.create_backup(backup_name="backup2")
        
        # List backups
        backups = self.backup_manager.list_backups()
        
        self.assertEqual(len(backups), 2)
    
    def test_get_backup_metadata(self):
        """Test getting backup metadata."""
        # Create backup
        metadata = self.backup_manager.create_backup(backup_name="test_backup")
        
        # Get metadata
        retrieved_metadata = self.backup_manager.get_backup_metadata(metadata.backup_id)
        
        self.assertIsNotNone(retrieved_metadata)
        self.assertEqual(retrieved_metadata.backup_id, metadata.backup_id)
    
    def test_delete_backup(self):
        """Test deleting backup."""
        # Create backup
        metadata = self.backup_manager.create_backup(backup_name="test_backup")
        
        # Delete backup
        result = self.backup_manager.delete_backup(metadata.backup_id)
        
        self.assertTrue(result)
        
        # Verify deletion
        retrieved_metadata = self.backup_manager.get_backup_metadata(metadata.backup_id)
        self.assertIsNone(retrieved_metadata)
    
    def test_verify_backup(self):
        """Test backup verification."""
        # Create backup
        metadata = self.backup_manager.create_backup(backup_name="test_backup")
        
        # Verify backup
        result = self.backup_manager.verify_backup(metadata.backup_id)
        
        self.assertTrue(result)
    
    def test_get_backup_stats(self):
        """Test getting backup statistics."""
        # Create backups
        self.backup_manager.create_backup(backup_name="backup1")
        self.backup_manager.create_backup(backup_name="backup2")
        
        # Get stats
        stats = self.backup_manager.get_backup_stats()
        
        self.assertEqual(stats['total_backups'], 2)
        self.assertEqual(stats['completed_backups'], 2)
        self.assertGreater(stats['total_size_bytes'], 0)


class TestRestoreManager(unittest.TestCase):
    """Test restore manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage = LocalStorageBackend(os.path.join(self.temp_dir, "backups"))
        
        # Create source database
        self.source_db_path = os.path.join(self.temp_dir, "source.db")
        self.source_database_url = f"sqlite:///{self.source_db_path}"
        
        import sqlite3
        conn = sqlite3.connect(self.source_db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
        cursor.execute("INSERT INTO test_table (name) VALUES ('test1')")
        cursor.execute("INSERT INTO test_table (name) VALUES ('test2')")
        conn.commit()
        conn.close()
        
        # Create backup
        self.backup_manager = BackupManager(
            database_url=self.source_database_url,
            storage_backend=self.storage,
            temp_dir=self.temp_dir
        )
        self.backup_metadata = self.backup_manager.create_backup(backup_name="test_backup")
        
        # Create target database path
        self.target_db_path = os.path.join(self.temp_dir, "target.db")
        self.target_database_url = f"sqlite:///{self.target_db_path}"
        
        self.restore_manager = RestoreManager(
            backup_manager=self.backup_manager,
            target_database_url=self.target_database_url,
            temp_dir=self.temp_dir
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_restore_sqlite_backup(self):
        """Test restoring SQLite backup."""
        metadata = self.restore_manager.restore_backup(
            backup_id=self.backup_metadata.backup_id,
            verify=True
        )
        
        self.assertEqual(metadata.status, RestoreStatus.COMPLETED)
        self.assertTrue(os.path.exists(self.target_db_path))
        
        # Verify data
        import sqlite3
        conn = sqlite3.connect(self.target_db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM test_table")
        count = cursor.fetchone()[0]
        conn.close()
        
        self.assertEqual(count, 2)


class TestBackupScheduler(unittest.TestCase):
    """Test backup scheduler."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.storage = LocalStorageBackend(os.path.join(self.temp_dir, "backups"))
        
        # Create test database
        self.db_path = os.path.join(self.temp_dir, "test.db")
        self.database_url = f"sqlite:///{self.db_path}"
        
        import sqlite3
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test_table (id INTEGER PRIMARY KEY, name TEXT)")
        conn.commit()
        conn.close()
        
        self.backup_manager = BackupManager(
            database_url=self.database_url,
            storage_backend=self.storage,
            temp_dir=self.temp_dir
        )
        
        self.scheduler = BackupScheduler(
            backup_manager=self.backup_manager,
            retention_policy=RetentionPolicy(
                hourly_retention_days=1,
                daily_retention_days=7,
                min_backups_to_keep=2
            )
        )
    
    def tearDown(self):
        """Clean up test fixtures."""
        self.scheduler.stop()
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_schedule_backup(self):
        """Test scheduling a backup."""
        self.scheduler.schedule_backup(
            frequency=ScheduleFrequency.DAILY,
            backup_type=BackupType.FULL,
            hour=2,
            minute=0
        )
        
        status = self.scheduler.get_schedule_status()
        
        self.assertIn('daily', status['schedules'])
        self.assertTrue(status['schedules']['daily']['enabled'])
    
    def test_scheduler_start_stop(self):
        """Test starting and stopping scheduler."""
        self.scheduler.start()
        self.assertTrue(self.scheduler._running)
        
        self.scheduler.stop()
        self.assertFalse(self.scheduler._running)
    
    def test_get_schedule_status(self):
        """Test getting scheduler status."""
        self.scheduler.schedule_backup(
            frequency=ScheduleFrequency.DAILY,
            backup_type=BackupType.FULL
        )
        
        status = self.scheduler.get_schedule_status()
        
        self.assertIn('running', status)
        self.assertIn('schedules', status)
        self.assertIn('retention_policy', status)


if __name__ == '__main__':
    unittest.main()

