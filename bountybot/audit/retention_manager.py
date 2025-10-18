"""
Audit Retention Manager

Manages audit log retention policies and archival.
"""

import gzip
import json
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from .models import AuditEvent, AuditEventType


class RetentionPolicy:
    """Retention policy definition."""
    
    def __init__(
        self,
        name: str,
        retention_days: int,
        event_types: Optional[List[AuditEventType]] = None,
        compliance_tags: Optional[List[str]] = None
    ):
        self.name = name
        self.retention_days = retention_days
        self.event_types = event_types or []
        self.compliance_tags = compliance_tags or []


class AuditRetentionManager:
    """
    Audit log retention manager.
    
    Features:
    - Configurable retention policies
    - Automatic archival
    - Compression
    - Compliance-based retention
    """
    
    # Default retention policies
    DEFAULT_POLICIES = [
        RetentionPolicy(
            name="SOC2_Compliance",
            retention_days=2555,  # 7 years
            compliance_tags=["SOC2"]
        ),
        RetentionPolicy(
            name="GDPR_Compliance",
            retention_days=2555,  # 7 years
            compliance_tags=["GDPR"]
        ),
        RetentionPolicy(
            name="HIPAA_Compliance",
            retention_days=2555,  # 7 years
            compliance_tags=["HIPAA"]
        ),
        RetentionPolicy(
            name="Security_Events",
            retention_days=1825,  # 5 years
            event_types=[
                AuditEventType.SECURITY_ALERT,
                AuditEventType.SUSPICIOUS_ACTIVITY,
                AuditEventType.BRUTE_FORCE_DETECTED
            ]
        ),
        RetentionPolicy(
            name="Authentication_Events",
            retention_days=365,  # 1 year
            event_types=[
                AuditEventType.LOGIN_SUCCESS,
                AuditEventType.LOGIN_FAILURE,
                AuditEventType.LOGOUT
            ]
        ),
        RetentionPolicy(
            name="General_Events",
            retention_days=90,  # 90 days
            event_types=[]
        )
    ]
    
    def __init__(
        self,
        log_dir: str = "./audit_logs",
        archive_dir: str = "./audit_archives"
    ):
        self.log_dir = Path(log_dir)
        self.archive_dir = Path(archive_dir)
        self.archive_dir.mkdir(parents=True, exist_ok=True)
        
        self.policies = self.DEFAULT_POLICIES.copy()
    
    def add_policy(self, policy: RetentionPolicy):
        """Add custom retention policy."""
        self.policies.append(policy)
    
    def get_retention_days(self, event: AuditEvent) -> int:
        """Get retention days for event based on policies."""
        max_retention = 90  # Default
        
        for policy in self.policies:
            # Check compliance tags
            if policy.compliance_tags:
                if any(tag in event.compliance_tags for tag in policy.compliance_tags):
                    max_retention = max(max_retention, policy.retention_days)
            
            # Check event types
            if policy.event_types:
                if event.event_type in policy.event_types:
                    max_retention = max(max_retention, policy.retention_days)
        
        return max_retention
    
    def archive_old_logs(self, days_to_keep: int = 90) -> Dict[str, int]:
        """Archive logs older than specified days."""
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        stats = {
            'files_archived': 0,
            'files_deleted': 0,
            'bytes_saved': 0
        }
        
        if not self.log_dir.exists():
            return stats
        
        for log_file in self.log_dir.glob("audit_*.jsonl"):
            # Extract date from filename
            date_str = log_file.stem.replace('audit_', '')
            try:
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                
                if file_date < cutoff_date:
                    # Archive the file
                    archived = self._archive_file(log_file)
                    if archived:
                        stats['files_archived'] += 1
                        
                        # Calculate space saved
                        original_size = log_file.stat().st_size
                        archived_file = self.archive_dir / f"{log_file.stem}.jsonl.gz"
                        compressed_size = archived_file.stat().st_size
                        stats['bytes_saved'] += (original_size - compressed_size)
                        
                        # Delete original
                        log_file.unlink()
            
            except ValueError:
                continue
        
        return stats
    
    def delete_expired_logs(self) -> Dict[str, int]:
        """Delete logs that have exceeded retention period."""
        stats = {
            'files_deleted': 0,
            'events_deleted': 0
        }
        
        # Check archived files
        for archive_file in self.archive_dir.glob("audit_*.jsonl.gz"):
            date_str = archive_file.stem.replace('audit_', '').replace('.jsonl', '')
            try:
                file_date = datetime.strptime(date_str, "%Y-%m-%d")
                
                # Check if file is older than maximum retention
                max_retention_date = datetime.utcnow() - timedelta(days=2555)  # 7 years
                
                if file_date < max_retention_date:
                    # Count events before deletion
                    event_count = self._count_events_in_archive(archive_file)
                    stats['events_deleted'] += event_count
                    
                    # Delete archive
                    archive_file.unlink()
                    stats['files_deleted'] += 1
            
            except ValueError:
                continue
        
        return stats
    
    def get_retention_stats(self) -> Dict[str, any]:
        """Get retention statistics."""
        stats = {
            'active_logs': 0,
            'archived_logs': 0,
            'total_size_mb': 0,
            'archived_size_mb': 0,
            'oldest_log': None,
            'newest_log': None
        }
        
        # Count active logs
        if self.log_dir.exists():
            active_files = list(self.log_dir.glob("audit_*.jsonl"))
            stats['active_logs'] = len(active_files)
            
            if active_files:
                stats['total_size_mb'] = sum(f.stat().st_size for f in active_files) / (1024 * 1024)
                
                # Find oldest and newest
                dates = []
                for f in active_files:
                    date_str = f.stem.replace('audit_', '')
                    try:
                        dates.append(datetime.strptime(date_str, "%Y-%m-%d"))
                    except ValueError:
                        continue
                
                if dates:
                    stats['oldest_log'] = min(dates).strftime("%Y-%m-%d")
                    stats['newest_log'] = max(dates).strftime("%Y-%m-%d")
        
        # Count archived logs
        if self.archive_dir.exists():
            archived_files = list(self.archive_dir.glob("audit_*.jsonl.gz"))
            stats['archived_logs'] = len(archived_files)
            
            if archived_files:
                stats['archived_size_mb'] = sum(f.stat().st_size for f in archived_files) / (1024 * 1024)
        
        return stats
    
    def restore_archive(self, archive_date: str) -> bool:
        """Restore archived log file."""
        archive_file = self.archive_dir / f"audit_{archive_date}.jsonl.gz"
        
        if not archive_file.exists():
            return False
        
        # Decompress to log directory
        output_file = self.log_dir / f"audit_{archive_date}.jsonl"
        
        with gzip.open(archive_file, 'rb') as f_in:
            with open(output_file, 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        return True
    
    def _archive_file(self, log_file: Path) -> bool:
        """Archive a log file with compression."""
        try:
            archive_file = self.archive_dir / f"{log_file.name}.gz"
            
            with open(log_file, 'rb') as f_in:
                with gzip.open(archive_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            return True
        
        except Exception:
            return False
    
    def _count_events_in_archive(self, archive_file: Path) -> int:
        """Count events in archived file."""
        count = 0
        
        try:
            with gzip.open(archive_file, 'rt') as f:
                for line in f:
                    if line.strip():
                        count += 1
        except Exception:
            pass
        
        return count

