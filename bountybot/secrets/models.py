"""
Data models for secrets management.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, Dict, Any
from enum import Enum

logger = logging.getLogger(__name__)


class SecretType(Enum):
    """Secret type enum."""
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"
    DATABASE_CREDENTIALS = "database_credentials"
    ENCRYPTION_KEY = "encryption_key"
    GENERIC = "generic"


@dataclass
class SecretVersion:
    """Secret version information."""
    version: int
    value: str
    created_at: datetime
    created_by: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'version': self.version,
            'value': self.value,
            'created_at': self.created_at.isoformat(),
            'created_by': self.created_by,
            'metadata': self.metadata
        }


@dataclass
class SecretMetadata:
    """Secret metadata."""
    secret_id: str
    secret_type: SecretType
    created_at: datetime
    updated_at: datetime
    created_by: Optional[str] = None
    updated_by: Optional[str] = None
    description: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)
    ttl_seconds: Optional[int] = None
    expires_at: Optional[datetime] = None
    rotation_enabled: bool = False
    rotation_interval_days: Optional[int] = None
    last_rotated_at: Optional[datetime] = None
    access_count: int = 0
    last_accessed_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'secret_id': self.secret_id,
            'secret_type': self.secret_type.value,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'created_by': self.created_by,
            'updated_by': self.updated_by,
            'description': self.description,
            'tags': self.tags,
            'ttl_seconds': self.ttl_seconds,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'rotation_enabled': self.rotation_enabled,
            'rotation_interval_days': self.rotation_interval_days,
            'last_rotated_at': self.last_rotated_at.isoformat() if self.last_rotated_at else None,
            'access_count': self.access_count,
            'last_accessed_at': self.last_accessed_at.isoformat() if self.last_accessed_at else None
        }


@dataclass
class Secret:
    """Secret with metadata and versions."""
    metadata: SecretMetadata
    current_value: str
    current_version: int
    versions: list[SecretVersion] = field(default_factory=list)
    
    def to_dict(self, include_value: bool = False) -> Dict[str, Any]:
        """
        Convert to dictionary.
        
        Args:
            include_value: Whether to include secret value
            
        Returns:
            Dictionary representation
        """
        result = {
            'metadata': self.metadata.to_dict(),
            'current_version': self.current_version,
            'versions_count': len(self.versions)
        }
        
        if include_value:
            result['current_value'] = self.current_value
        
        return result
    
    def is_expired(self) -> bool:
        """Check if secret is expired."""
        if not self.metadata.expires_at:
            return False
        return datetime.utcnow() > self.metadata.expires_at
    
    def needs_rotation(self) -> bool:
        """Check if secret needs rotation."""
        if not self.metadata.rotation_enabled:
            return False
        
        if not self.metadata.rotation_interval_days:
            return False
        
        if not self.metadata.last_rotated_at:
            return True
        
        from datetime import timedelta
        rotation_due = self.metadata.last_rotated_at + timedelta(days=self.metadata.rotation_interval_days)
        return datetime.utcnow() > rotation_due


@dataclass
class SecretAccessLog:
    """Secret access log entry."""
    secret_id: str
    accessed_at: datetime
    accessed_by: Optional[str] = None
    access_type: str = "read"  # read, write, delete, rotate
    ip_address: Optional[str] = None
    success: bool = True
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'secret_id': self.secret_id,
            'accessed_at': self.accessed_at.isoformat(),
            'accessed_by': self.accessed_by,
            'access_type': self.access_type,
            'ip_address': self.ip_address,
            'success': self.success,
            'error_message': self.error_message
        }


__all__ = [
    'SecretType',
    'SecretVersion',
    'SecretMetadata',
    'Secret',
    'SecretAccessLog'
]

