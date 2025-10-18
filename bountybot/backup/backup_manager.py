"""
Backup Manager

Core backup functionality for database backups.
"""

import os
import gzip
import hashlib
import logging
import subprocess
import tempfile
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any
from urllib.parse import urlparse

from .models import (
    BackupMetadata,
    BackupType,
    BackupStatus,
    CompressionType,
    EncryptionType
)
from .storage_backends import StorageBackend, LocalStorageBackend

logger = logging.getLogger(__name__)


class BackupManager:
    """
    Manages database backups with support for:
    - Full and incremental backups
    - Multiple storage backends
    - Compression and encryption
    - Backup verification
    """
    
    def __init__(
        self,
        database_url: str,
        storage_backend: StorageBackend,
        compression_type: CompressionType = CompressionType.GZIP,
        encryption_type: EncryptionType = EncryptionType.NONE,
        encryption_key: Optional[str] = None,
        temp_dir: Optional[str] = None
    ):
        """
        Initialize backup manager.
        
        Args:
            database_url: Database connection URL
            storage_backend: Storage backend for backups
            compression_type: Compression algorithm
            encryption_type: Encryption algorithm
            encryption_key: Encryption key (required if encryption enabled)
            temp_dir: Temporary directory for backup files
        """
        self.database_url = database_url
        self.storage_backend = storage_backend
        self.compression_type = compression_type
        self.encryption_type = encryption_type
        self.encryption_key = encryption_key
        self.temp_dir = temp_dir or tempfile.gettempdir()
        
        # Parse database URL
        parsed = urlparse(database_url)
        self.database_type = parsed.scheme.split('+')[0]  # postgresql, sqlite, etc.
        
        # Validate encryption
        if encryption_type != EncryptionType.NONE and not encryption_key:
            raise ValueError("Encryption key required when encryption is enabled")
        
        logger.info(f"Backup manager initialized for {self.database_type} database")
    
    def create_backup(
        self,
        backup_name: Optional[str] = None,
        backup_type: BackupType = BackupType.FULL,
        tags: Optional[Dict[str, str]] = None,
        retention_days: int = 30
    ) -> BackupMetadata:
        """
        Create a database backup.
        
        Args:
            backup_name: Custom backup name (auto-generated if not provided)
            backup_type: Type of backup (full, incremental, differential)
            tags: Custom tags for the backup
            retention_days: Number of days to retain backup
            
        Returns:
            BackupMetadata object
        """
        # Generate backup ID and name
        backup_id = f"backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"
        if not backup_name:
            backup_name = f"{self.database_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        
        # Create metadata
        metadata = BackupMetadata(
            backup_id=backup_id,
            backup_name=backup_name,
            backup_type=backup_type,
            started_at=datetime.utcnow(),
            database_url=self.database_url,
            database_type=self.database_type,
            storage_backend=self.storage_backend.__class__.__name__,
            compression_type=self.compression_type,
            encryption_type=self.encryption_type,
            retention_days=retention_days,
            expires_at=datetime.utcnow() + timedelta(days=retention_days),
            tags=tags or {},
            status=BackupStatus.IN_PROGRESS
        )
        
        try:
            logger.info(f"Starting backup: {backup_id}")
            
            # Create backup file
            if self.database_type == 'postgresql':
                backup_file = self._backup_postgresql(metadata)
            elif self.database_type == 'sqlite':
                backup_file = self._backup_sqlite(metadata)
            else:
                raise ValueError(f"Unsupported database type: {self.database_type}")
            
            # Get file size
            metadata.file_size_bytes = os.path.getsize(backup_file)
            
            # Compress if enabled
            if self.compression_type != CompressionType.NONE:
                backup_file = self._compress_file(backup_file, metadata)
                metadata.compressed_size_bytes = os.path.getsize(backup_file)
            else:
                metadata.compressed_size_bytes = metadata.file_size_bytes
            
            # Encrypt if enabled
            if self.encryption_type != EncryptionType.NONE:
                backup_file = self._encrypt_file(backup_file, metadata)
            
            # Calculate checksum
            metadata.checksum = self._calculate_checksum(backup_file)
            
            # Upload to storage
            remote_path = f"{backup_id}/{os.path.basename(backup_file)}"
            metadata.storage_path = remote_path
            
            if not self.storage_backend.upload(backup_file, remote_path):
                raise RuntimeError("Failed to upload backup to storage")
            
            # Update metadata before saving
            metadata.completed_at = datetime.utcnow()
            metadata.duration_seconds = (metadata.completed_at - metadata.started_at).total_seconds()
            metadata.backup_rate_mbps = (metadata.compressed_size_bytes / 1024 / 1024) / max(metadata.duration_seconds, 0.001)
            metadata.status = BackupStatus.COMPLETED

            # Save metadata
            metadata_path = f"{backup_id}/metadata.json"
            self._save_metadata(metadata, metadata_path)
            
            # Clean up temp file
            try:
                os.unlink(backup_file)
            except:
                pass

            logger.info(f"Backup completed: {backup_id} ({metadata.compressed_size_bytes / 1024 / 1024:.2f} MB)")
            
            return metadata
            
        except Exception as e:
            logger.error(f"Backup failed: {e}")
            metadata.status = BackupStatus.FAILED
            metadata.error_message = str(e)
            metadata.completed_at = datetime.utcnow()
            raise
    
    def _backup_postgresql(self, metadata: BackupMetadata) -> str:
        """Create PostgreSQL backup using pg_dump."""
        try:
            # Parse connection URL
            parsed = urlparse(self.database_url)
            
            # Create temp file
            backup_file = os.path.join(self.temp_dir, f"{metadata.backup_id}.sql")
            
            # Build pg_dump command
            env = os.environ.copy()
            if parsed.password:
                env['PGPASSWORD'] = parsed.password
            
            cmd = [
                'pg_dump',
                '-h', parsed.hostname or 'localhost',
                '-p', str(parsed.port or 5432),
                '-U', parsed.username or 'postgres',
                '-d', parsed.path.lstrip('/'),
                '-F', 'c',  # Custom format (compressed)
                '-f', backup_file,
                '--verbose'
            ]
            
            # Execute pg_dump
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"pg_dump failed: {result.stderr}")
            
            # Get table information
            metadata.tables_backed_up = self._get_postgresql_tables(parsed)
            metadata.row_counts = self._get_postgresql_row_counts(parsed)
            
            logger.info(f"PostgreSQL backup created: {backup_file}")
            return backup_file
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("pg_dump timed out after 1 hour")
        except Exception as e:
            raise RuntimeError(f"Failed to backup PostgreSQL: {e}")
    
    def _backup_sqlite(self, metadata: BackupMetadata) -> str:
        """Create SQLite backup."""
        try:
            import sqlite3

            # Parse connection URL
            # sqlite:///path/to/db.db -> path/to/db.db
            source_db = self.database_url.replace('sqlite:///', '')

            # Ensure the path exists
            if not os.path.exists(source_db):
                raise RuntimeError(f"Database file not found: {source_db}")

            # Create temp file
            backup_file = os.path.join(self.temp_dir, f"{metadata.backup_id}.db")

            # Connect to source database
            source_conn = sqlite3.connect(source_db)
            
            # Create backup
            backup_conn = sqlite3.connect(backup_file)
            source_conn.backup(backup_conn)
            
            # Get table information
            cursor = source_conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            metadata.tables_backed_up = tables
            
            # Get row counts
            row_counts = {}
            for table in tables:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                row_counts[table] = cursor.fetchone()[0]
            metadata.row_counts = row_counts
            
            # Close connections
            backup_conn.close()
            source_conn.close()
            
            logger.info(f"SQLite backup created: {backup_file}")
            return backup_file
            
        except Exception as e:
            raise RuntimeError(f"Failed to backup SQLite: {e}")
    
    def _compress_file(self, file_path: str, metadata: BackupMetadata) -> str:
        """Compress backup file."""
        try:
            compressed_file = f"{file_path}.gz"
            
            if self.compression_type == CompressionType.GZIP:
                with open(file_path, 'rb') as f_in:
                    with gzip.open(compressed_file, 'wb', compresslevel=6) as f_out:
                        f_out.writelines(f_in)
            else:
                raise ValueError(f"Unsupported compression type: {self.compression_type}")
            
            # Remove original file
            os.unlink(file_path)
            
            logger.info(f"Compressed backup: {compressed_file}")
            return compressed_file
            
        except Exception as e:
            raise RuntimeError(f"Failed to compress backup: {e}")
    
    def _encrypt_file(self, file_path: str, metadata: BackupMetadata) -> str:
        """Encrypt backup file."""
        # Placeholder for encryption implementation
        # In production, use proper encryption libraries like cryptography
        logger.warning("Encryption not yet implemented")
        return file_path
    
    def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def _save_metadata(self, metadata: BackupMetadata, remote_path: str):
        """Save backup metadata to storage."""
        try:
            # Create temp metadata file
            metadata_file = os.path.join(self.temp_dir, f"{metadata.backup_id}_metadata.json")
            with open(metadata_file, 'w') as f:
                json.dump(metadata.to_dict(), f, indent=2, default=str)
            
            # Upload metadata
            self.storage_backend.upload(metadata_file, remote_path)
            
            # Clean up
            os.unlink(metadata_file)
            
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")
    
    def _get_postgresql_tables(self, parsed) -> List[str]:
        """Get list of tables from PostgreSQL database."""
        # Placeholder - would use psycopg2 in production
        return []

    def _get_postgresql_row_counts(self, parsed) -> Dict[str, int]:
        """Get row counts from PostgreSQL database."""
        # Placeholder - would use psycopg2 in production
        return {}

    def list_backups(self, prefix: str = "") -> List[BackupMetadata]:
        """
        List all backups.

        Args:
            prefix: Filter backups by prefix

        Returns:
            List of BackupMetadata objects
        """
        try:
            backups = []

            # List all backup directories
            files = self.storage_backend.list_files(prefix)
            backup_ids = set()

            for file in files:
                if '/metadata.json' in file:
                    backup_id = file.split('/')[0]
                    backup_ids.add(backup_id)

            # Load metadata for each backup
            for backup_id in backup_ids:
                try:
                    metadata = self.get_backup_metadata(backup_id)
                    if metadata:
                        backups.append(metadata)
                except Exception as e:
                    logger.warning(f"Failed to load metadata for {backup_id}: {e}")

            # Sort by start time (newest first)
            backups.sort(key=lambda x: x.started_at, reverse=True)

            return backups

        except Exception as e:
            logger.error(f"Failed to list backups: {e}")
            return []

    def get_backup_metadata(self, backup_id: str) -> Optional[BackupMetadata]:
        """
        Get metadata for a specific backup.

        Args:
            backup_id: Backup ID

        Returns:
            BackupMetadata object or None if not found
        """
        try:
            metadata_path = f"{backup_id}/metadata.json"

            # Download metadata to temp file
            temp_file = os.path.join(self.temp_dir, f"{backup_id}_metadata.json")

            if not self.storage_backend.download(metadata_path, temp_file):
                return None

            # Load metadata
            with open(temp_file, 'r') as f:
                data = json.load(f)

            # Clean up
            os.unlink(temp_file)

            # Convert to BackupMetadata
            metadata = BackupMetadata(
                backup_id=data['backup_id'],
                backup_name=data['backup_name'],
                backup_type=BackupType(data['backup_type']),
                started_at=datetime.fromisoformat(data['started_at']),
                completed_at=datetime.fromisoformat(data['completed_at']) if data.get('completed_at') else None,
                status=BackupStatus(data['status']),
                error_message=data.get('error_message'),
                database_url=data.get('database_url', ''),
                database_type=data.get('database_type', ''),
                storage_backend=data.get('storage_backend', ''),
                storage_path=data.get('storage_path', ''),
                file_size_bytes=data.get('file_size_bytes', 0),
                compressed_size_bytes=data.get('compressed_size_bytes', 0),
                compression_type=CompressionType(data.get('compression_type', 'gzip')),
                encryption_type=EncryptionType(data.get('encryption_type', 'none')),
                tables_backed_up=data.get('tables_backed_up', []),
                row_counts=data.get('row_counts', {}),
                checksum=data.get('checksum'),
                verified_at=datetime.fromisoformat(data['verified_at']) if data.get('verified_at') else None,
                verification_passed=data.get('verification_passed', False),
                duration_seconds=data.get('duration_seconds', 0.0),
                backup_rate_mbps=data.get('backup_rate_mbps', 0.0),
                retention_days=data.get('retention_days', 30),
                expires_at=datetime.fromisoformat(data['expires_at']) if data.get('expires_at') else None,
                parent_backup_id=data.get('parent_backup_id'),
                tags=data.get('tags', {}),
                notes=data.get('notes', ''),
                created_by=data.get('created_by', 'system')
            )

            return metadata

        except Exception as e:
            logger.error(f"Failed to get backup metadata for {backup_id}: {e}")
            return None

    def delete_backup(self, backup_id: str) -> bool:
        """
        Delete a backup.

        Args:
            backup_id: Backup ID

        Returns:
            True if successful, False otherwise
        """
        try:
            logger.info(f"Deleting backup: {backup_id}")

            # List all files for this backup
            files = self.storage_backend.list_files(backup_id)

            # Delete all files
            for file in files:
                self.storage_backend.delete(file)

            logger.info(f"Backup deleted: {backup_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete backup {backup_id}: {e}")
            return False

    def verify_backup(self, backup_id: str) -> bool:
        """
        Verify backup integrity.

        Args:
            backup_id: Backup ID

        Returns:
            True if verification passed, False otherwise
        """
        try:
            logger.info(f"Verifying backup: {backup_id}")

            # Get metadata
            metadata = self.get_backup_metadata(backup_id)
            if not metadata:
                logger.error(f"Backup metadata not found: {backup_id}")
                return False

            # Download backup file
            temp_file = os.path.join(self.temp_dir, f"{backup_id}_verify")
            if not self.storage_backend.download(metadata.storage_path, temp_file):
                logger.error(f"Failed to download backup file: {backup_id}")
                return False

            # Calculate checksum
            checksum = self._calculate_checksum(temp_file)

            # Clean up
            os.unlink(temp_file)

            # Compare checksums
            if checksum == metadata.checksum:
                logger.info(f"Backup verification passed: {backup_id}")
                metadata.verified_at = datetime.utcnow()
                metadata.verification_passed = True
                self._save_metadata(metadata, f"{backup_id}/metadata.json")
                return True
            else:
                logger.error(f"Backup verification failed: {backup_id} (checksum mismatch)")
                return False

        except Exception as e:
            logger.error(f"Failed to verify backup {backup_id}: {e}")
            return False

    def get_backup_stats(self) -> Dict[str, Any]:
        """
        Get backup statistics.

        Returns:
            Dictionary with backup statistics
        """
        try:
            backups = self.list_backups()

            total_backups = len(backups)
            total_size = sum(b.compressed_size_bytes for b in backups)
            completed_backups = sum(1 for b in backups if b.status == BackupStatus.COMPLETED)
            failed_backups = sum(1 for b in backups if b.status == BackupStatus.FAILED)

            # Get oldest and newest backup
            oldest_backup = min(backups, key=lambda x: x.started_at) if backups else None
            newest_backup = max(backups, key=lambda x: x.started_at) if backups else None

            return {
                'total_backups': total_backups,
                'completed_backups': completed_backups,
                'failed_backups': failed_backups,
                'total_size_bytes': total_size,
                'total_size_gb': total_size / 1024 / 1024 / 1024,
                'oldest_backup': oldest_backup.backup_id if oldest_backup else None,
                'oldest_backup_date': oldest_backup.started_at.isoformat() if oldest_backup else None,
                'newest_backup': newest_backup.backup_id if newest_backup else None,
                'newest_backup_date': newest_backup.started_at.isoformat() if newest_backup else None,
                'storage_backend': self.storage_backend.__class__.__name__
            }

        except Exception as e:
            logger.error(f"Failed to get backup stats: {e}")
            return {}

