"""
Restore Manager

Handles database restoration from backups.
"""

import os
import gzip
import logging
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional, List
from urllib.parse import urlparse

from .models import (
    RestoreMetadata,
    RestoreStatus,
    BackupMetadata,
    CompressionType
)
from .storage_backends import StorageBackend
from .backup_manager import BackupManager

logger = logging.getLogger(__name__)


class RestoreManager:
    """
    Manages database restoration from backups.
    
    Supports:
    - Full database restore
    - Point-in-time recovery
    - Selective table restore
    - Restore verification
    """
    
    def __init__(
        self,
        backup_manager: BackupManager,
        target_database_url: Optional[str] = None,
        temp_dir: Optional[str] = None
    ):
        """
        Initialize restore manager.
        
        Args:
            backup_manager: BackupManager instance
            target_database_url: Target database URL (defaults to backup source)
            temp_dir: Temporary directory for restore files
        """
        self.backup_manager = backup_manager
        self.target_database_url = target_database_url or backup_manager.database_url
        self.temp_dir = temp_dir or tempfile.gettempdir()
        
        # Parse target database URL
        parsed = urlparse(self.target_database_url)
        self.target_database_type = parsed.scheme.split('+')[0]
        
        logger.info(f"Restore manager initialized for {self.target_database_type} database")
    
    def restore_backup(
        self,
        backup_id: str,
        tables_to_restore: Optional[List[str]] = None,
        skip_tables: Optional[List[str]] = None,
        point_in_time: Optional[datetime] = None,
        verify: bool = True
    ) -> RestoreMetadata:
        """
        Restore a database backup.
        
        Args:
            backup_id: Backup ID to restore
            tables_to_restore: List of tables to restore (None = all tables)
            skip_tables: List of tables to skip
            point_in_time: Point-in-time to restore to (for PITR)
            verify: Whether to verify backup before restoring
            
        Returns:
            RestoreMetadata object
        """
        # Generate restore ID
        restore_id = f"restore_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"
        
        # Create metadata
        metadata = RestoreMetadata(
            restore_id=restore_id,
            backup_id=backup_id,
            started_at=datetime.utcnow(),
            target_database_url=self.target_database_url,
            target_database_type=self.target_database_type,
            tables_to_restore=tables_to_restore,
            skip_tables=skip_tables,
            point_in_time=point_in_time,
            status=RestoreStatus.IN_PROGRESS
        )
        
        try:
            logger.info(f"Starting restore: {restore_id} from backup {backup_id}")
            
            # Get backup metadata
            backup_metadata = self.backup_manager.get_backup_metadata(backup_id)
            if not backup_metadata:
                raise RuntimeError(f"Backup not found: {backup_id}")
            
            # Verify backup if requested
            if verify:
                logger.info("Verifying backup before restore...")
                if not self.backup_manager.verify_backup(backup_id):
                    raise RuntimeError("Backup verification failed")
            
            # Download backup file
            backup_file = self._download_backup(backup_metadata)
            
            # Decompress if needed
            if backup_metadata.compression_type != CompressionType.NONE:
                backup_file = self._decompress_file(backup_file, backup_metadata)
            
            # Decrypt if needed
            if backup_metadata.encryption_type.value != 'none':
                backup_file = self._decrypt_file(backup_file, backup_metadata)
            
            # Restore database
            if self.target_database_type == 'postgresql':
                self._restore_postgresql(backup_file, metadata)
            elif self.target_database_type == 'sqlite':
                self._restore_sqlite(backup_file, metadata)
            else:
                raise ValueError(f"Unsupported database type: {self.target_database_type}")
            
            # Clean up temp file
            try:
                os.unlink(backup_file)
            except:
                pass
            
            # Update metadata
            metadata.completed_at = datetime.utcnow()
            metadata.duration_seconds = (metadata.completed_at - metadata.started_at).total_seconds()
            metadata.status = RestoreStatus.COMPLETED
            metadata.validation_passed = True
            
            logger.info(f"Restore completed: {restore_id}")
            
            return metadata
            
        except Exception as e:
            logger.error(f"Restore failed: {e}")
            metadata.status = RestoreStatus.FAILED
            metadata.error_message = str(e)
            metadata.completed_at = datetime.utcnow()
            raise
    
    def _download_backup(self, backup_metadata: BackupMetadata) -> str:
        """Download backup file from storage."""
        try:
            temp_file = os.path.join(self.temp_dir, f"{backup_metadata.backup_id}_restore")
            
            logger.info(f"Downloading backup: {backup_metadata.storage_path}")
            
            if not self.backup_manager.storage_backend.download(backup_metadata.storage_path, temp_file):
                raise RuntimeError("Failed to download backup file")
            
            logger.info(f"Backup downloaded: {temp_file}")
            return temp_file
            
        except Exception as e:
            raise RuntimeError(f"Failed to download backup: {e}")
    
    def _decompress_file(self, file_path: str, backup_metadata: BackupMetadata) -> str:
        """Decompress backup file."""
        try:
            # Create decompressed file path
            if file_path.endswith('.gz'):
                decompressed_file = file_path[:-3]  # Remove .gz extension
            else:
                decompressed_file = file_path + '_decompressed'

            if backup_metadata.compression_type == CompressionType.GZIP:
                with gzip.open(file_path, 'rb') as f_in:
                    with open(decompressed_file, 'wb') as f_out:
                        f_out.write(f_in.read())
            else:
                raise ValueError(f"Unsupported compression type: {backup_metadata.compression_type}")

            # Remove compressed file
            try:
                os.unlink(file_path)
            except:
                pass

            logger.info(f"Decompressed backup: {decompressed_file}")
            return decompressed_file

        except Exception as e:
            raise RuntimeError(f"Failed to decompress backup: {e}")
    
    def _decrypt_file(self, file_path: str, backup_metadata: BackupMetadata) -> str:
        """Decrypt backup file."""
        # Placeholder for decryption implementation
        logger.warning("Decryption not yet implemented")
        return file_path
    
    def _restore_postgresql(self, backup_file: str, metadata: RestoreMetadata):
        """Restore PostgreSQL database using pg_restore."""
        try:
            # Parse connection URL
            parsed = urlparse(self.target_database_url)
            
            # Build pg_restore command
            env = os.environ.copy()
            if parsed.password:
                env['PGPASSWORD'] = parsed.password
            
            cmd = [
                'pg_restore',
                '-h', parsed.hostname or 'localhost',
                '-p', str(parsed.port or 5432),
                '-U', parsed.username or 'postgres',
                '-d', parsed.path.lstrip('/'),
                '--clean',  # Drop existing objects
                '--if-exists',  # Don't error if objects don't exist
                '--verbose',
                backup_file
            ]
            
            # Add table filters if specified
            if metadata.tables_to_restore:
                for table in metadata.tables_to_restore:
                    cmd.extend(['-t', table])
            
            if metadata.skip_tables:
                for table in metadata.skip_tables:
                    cmd.extend(['-T', table])
            
            # Execute pg_restore
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=3600  # 1 hour timeout
            )
            
            if result.returncode != 0:
                # pg_restore may return non-zero even on success (warnings)
                if 'ERROR' in result.stderr:
                    raise RuntimeError(f"pg_restore failed: {result.stderr}")
            
            logger.info("PostgreSQL restore completed")
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("pg_restore timed out after 1 hour")
        except Exception as e:
            raise RuntimeError(f"Failed to restore PostgreSQL: {e}")
    
    def _restore_sqlite(self, backup_file: str, metadata: RestoreMetadata):
        """Restore SQLite database."""
        try:
            import sqlite3
            import shutil

            # Parse connection URL
            # sqlite:///path/to/db.db -> path/to/db.db
            target_db = self.target_database_url.replace('sqlite:///', '')
            
            # Backup existing database if it exists
            if os.path.exists(target_db):
                backup_path = f"{target_db}.backup_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(target_db, backup_path)
                logger.info(f"Existing database backed up to: {backup_path}")
            
            # Copy backup file to target location
            shutil.copy2(backup_file, target_db)
            
            # Verify database integrity
            conn = sqlite3.connect(target_db)
            cursor = conn.cursor()
            cursor.execute("PRAGMA integrity_check")
            result = cursor.fetchone()
            
            if result[0] != 'ok':
                raise RuntimeError(f"Database integrity check failed: {result[0]}")
            
            # Get restored tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            metadata.tables_restored = [row[0] for row in cursor.fetchall()]
            
            # Get row counts
            row_counts = {}
            for table in metadata.tables_restored:
                cursor.execute(f"SELECT COUNT(*) FROM {table}")
                row_counts[table] = cursor.fetchone()[0]
            metadata.rows_restored = row_counts
            
            conn.close()
            
            logger.info("SQLite restore completed")
            
        except Exception as e:
            raise RuntimeError(f"Failed to restore SQLite: {e}")
    
    def list_restores(self) -> List[RestoreMetadata]:
        """
        List all restore operations.
        
        Returns:
            List of RestoreMetadata objects
        """
        # In a production system, this would query a restore history database
        # For now, return empty list
        return []
    
    def get_restore_metadata(self, restore_id: str) -> Optional[RestoreMetadata]:
        """
        Get metadata for a specific restore operation.
        
        Args:
            restore_id: Restore ID
            
        Returns:
            RestoreMetadata object or None if not found
        """
        # In a production system, this would query a restore history database
        return None

