"""
Audit Logger

Core audit logging functionality with tamper protection.
"""

import hashlib
import hmac
import json
import secrets
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional

from .models import (
    AuditEvent,
    AuditEventType,
    AuditEventCategory,
    AuditSeverity
)


class AuditLogger:
    """
    Audit logger with tamper-proof logging.
    
    Features:
    - HMAC signatures for tamper detection
    - Chain of custody with previous event hashing
    - Structured JSON logging
    - Automatic categorization
    - Compliance tagging
    """
    
    def __init__(
        self,
        log_dir: str = "./audit_logs",
        secret_key: Optional[str] = None
    ):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        # Secret key for HMAC signatures
        self.secret_key = secret_key or secrets.token_hex(32)
        
        # In-memory cache of recent events
        self.recent_events: List[AuditEvent] = []
        self.max_cache_size = 1000
        
        # Last event hash for chain of custody
        self.last_event_hash: Optional[str] = None
    
    def log_event(
        self,
        event_type: AuditEventType,
        action: str,
        user_id: Optional[str] = None,
        username: Optional[str] = None,
        org_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        session_id: Optional[str] = None,
        api_endpoint: Optional[str] = None,
        http_method: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None
    ) -> AuditEvent:
        """Log an audit event."""
        
        # Generate event ID
        event_id = f"audit_{secrets.token_hex(16)}"
        
        # Determine category and severity
        category = self._categorize_event(event_type)
        severity = self._determine_severity(event_type, success)
        
        # Create event
        event = AuditEvent(
            event_id=event_id,
            timestamp=datetime.utcnow(),
            event_type=event_type,
            category=category,
            severity=severity,
            user_id=user_id,
            username=username,
            org_id=org_id,
            ip_address=ip_address,
            user_agent=user_agent,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details or {},
            metadata=metadata or {},
            request_id=request_id,
            session_id=session_id,
            api_endpoint=api_endpoint,
            http_method=http_method,
            success=success,
            error_message=error_message,
            previous_event_hash=self.last_event_hash
        )
        
        # Add compliance tags
        event.compliance_tags = self._get_compliance_tags(event_type)
        
        # Sign the event
        event.signature = self._sign_event(event)
        
        # Update chain of custody
        self.last_event_hash = self._hash_event(event)
        
        # Store event
        self._store_event(event)
        
        # Cache event
        self._cache_event(event)
        
        return event
    
    def _categorize_event(self, event_type: AuditEventType) -> AuditEventCategory:
        """Categorize event type."""
        category_map = {
            AuditEventType.LOGIN_SUCCESS: AuditEventCategory.AUTHENTICATION,
            AuditEventType.LOGIN_FAILURE: AuditEventCategory.AUTHENTICATION,
            AuditEventType.LOGOUT: AuditEventCategory.AUTHENTICATION,
            AuditEventType.PASSWORD_CHANGE: AuditEventCategory.AUTHENTICATION,
            AuditEventType.MFA_ENABLED: AuditEventCategory.AUTHENTICATION,
            AuditEventType.MFA_DISABLED: AuditEventCategory.AUTHENTICATION,
            
            AuditEventType.PERMISSION_GRANTED: AuditEventCategory.AUTHORIZATION,
            AuditEventType.PERMISSION_DENIED: AuditEventCategory.AUTHORIZATION,
            AuditEventType.ROLE_ASSIGNED: AuditEventCategory.AUTHORIZATION,
            AuditEventType.ROLE_REVOKED: AuditEventCategory.AUTHORIZATION,
            
            AuditEventType.REPORT_VIEWED: AuditEventCategory.DATA_ACCESS,
            AuditEventType.REPORT_DOWNLOADED: AuditEventCategory.DATA_ACCESS,
            AuditEventType.DATA_EXPORTED: AuditEventCategory.DATA_ACCESS,
            AuditEventType.SEARCH_PERFORMED: AuditEventCategory.DATA_ACCESS,
            
            AuditEventType.REPORT_CREATED: AuditEventCategory.DATA_MODIFICATION,
            AuditEventType.REPORT_UPDATED: AuditEventCategory.DATA_MODIFICATION,
            AuditEventType.REPORT_DELETED: AuditEventCategory.DATA_MODIFICATION,
            AuditEventType.USER_CREATED: AuditEventCategory.DATA_MODIFICATION,
            AuditEventType.USER_UPDATED: AuditEventCategory.DATA_MODIFICATION,
            AuditEventType.USER_DELETED: AuditEventCategory.DATA_MODIFICATION,
            
            AuditEventType.CONFIG_CHANGED: AuditEventCategory.CONFIGURATION,
            AuditEventType.INTEGRATION_ADDED: AuditEventCategory.CONFIGURATION,
            AuditEventType.INTEGRATION_REMOVED: AuditEventCategory.CONFIGURATION,
            AuditEventType.WEBHOOK_CONFIGURED: AuditEventCategory.CONFIGURATION,
            
            AuditEventType.SECURITY_ALERT: AuditEventCategory.SECURITY,
            AuditEventType.SUSPICIOUS_ACTIVITY: AuditEventCategory.SECURITY,
            AuditEventType.RATE_LIMIT_EXCEEDED: AuditEventCategory.SECURITY,
            AuditEventType.INVALID_TOKEN: AuditEventCategory.SECURITY,
            AuditEventType.BRUTE_FORCE_DETECTED: AuditEventCategory.SECURITY,
            
            AuditEventType.DATA_RETENTION_APPLIED: AuditEventCategory.COMPLIANCE,
            AuditEventType.DATA_ANONYMIZED: AuditEventCategory.COMPLIANCE,
            AuditEventType.CONSENT_GRANTED: AuditEventCategory.COMPLIANCE,
            AuditEventType.CONSENT_REVOKED: AuditEventCategory.COMPLIANCE,
            AuditEventType.GDPR_REQUEST: AuditEventCategory.COMPLIANCE,
            
            AuditEventType.SYSTEM_BACKUP: AuditEventCategory.ADMIN,
            AuditEventType.SYSTEM_RESTORE: AuditEventCategory.ADMIN,
            AuditEventType.MAINTENANCE_MODE: AuditEventCategory.ADMIN,
            AuditEventType.TENANT_PROVISIONED: AuditEventCategory.ADMIN,
            AuditEventType.TENANT_SUSPENDED: AuditEventCategory.ADMIN,
            
            AuditEventType.API_KEY_CREATED: AuditEventCategory.API,
            AuditEventType.API_KEY_REVOKED: AuditEventCategory.API,
            AuditEventType.API_CALL: AuditEventCategory.API,
            AuditEventType.QUOTA_EXCEEDED: AuditEventCategory.API,
        }
        
        return category_map.get(event_type, AuditEventCategory.SYSTEM)
    
    def _determine_severity(
        self,
        event_type: AuditEventType,
        success: bool
    ) -> AuditSeverity:
        """Determine event severity."""
        
        # Critical events
        critical_events = {
            AuditEventType.BRUTE_FORCE_DETECTED,
            AuditEventType.SYSTEM_RESTORE,
            AuditEventType.TENANT_SUSPENDED,
        }
        
        # High severity events
        high_events = {
            AuditEventType.SECURITY_ALERT,
            AuditEventType.SUSPICIOUS_ACTIVITY,
            AuditEventType.USER_DELETED,
            AuditEventType.DATA_EXPORTED,
            AuditEventType.SYSTEM_BACKUP,
        }
        
        # Medium severity events
        medium_events = {
            AuditEventType.LOGIN_FAILURE,
            AuditEventType.PERMISSION_DENIED,
            AuditEventType.RATE_LIMIT_EXCEEDED,
            AuditEventType.CONFIG_CHANGED,
        }
        
        if event_type in critical_events:
            return AuditSeverity.CRITICAL
        elif event_type in high_events:
            return AuditSeverity.HIGH
        elif event_type in medium_events:
            return AuditSeverity.MEDIUM
        elif not success:
            return AuditSeverity.MEDIUM
        else:
            return AuditSeverity.INFO
    
    def _get_compliance_tags(self, event_type: AuditEventType) -> List[str]:
        """Get compliance tags for event."""
        tags = []
        
        # SOC 2 relevant events
        soc2_events = {
            AuditEventType.LOGIN_SUCCESS, AuditEventType.LOGIN_FAILURE,
            AuditEventType.PERMISSION_GRANTED, AuditEventType.PERMISSION_DENIED,
            AuditEventType.DATA_EXPORTED, AuditEventType.CONFIG_CHANGED,
            AuditEventType.SYSTEM_BACKUP, AuditEventType.SYSTEM_RESTORE
        }
        if event_type in soc2_events:
            tags.append('SOC2')
        
        # GDPR relevant events
        gdpr_events = {
            AuditEventType.DATA_EXPORTED, AuditEventType.DATA_ANONYMIZED,
            AuditEventType.CONSENT_GRANTED, AuditEventType.CONSENT_REVOKED,
            AuditEventType.GDPR_REQUEST, AuditEventType.DATA_RETENTION_APPLIED
        }
        if event_type in gdpr_events:
            tags.append('GDPR')
        
        # HIPAA relevant events
        hipaa_events = {
            AuditEventType.DATA_EXPORTED, AuditEventType.REPORT_VIEWED,
            AuditEventType.REPORT_DOWNLOADED, AuditEventType.DATA_ANONYMIZED
        }
        if event_type in hipaa_events:
            tags.append('HIPAA')
        
        return tags
    
    def _sign_event(self, event: AuditEvent) -> str:
        """Generate HMAC signature for event."""
        # Create canonical representation
        canonical = json.dumps({
            'event_id': event.event_id,
            'timestamp': event.timestamp.isoformat(),
            'event_type': event.event_type.value,
            'user_id': event.user_id,
            'action': event.action,
            'resource_id': event.resource_id,
            'previous_hash': event.previous_event_hash
        }, sort_keys=True)
        
        # Generate HMAC
        signature = hmac.new(
            self.secret_key.encode(),
            canonical.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _hash_event(self, event: AuditEvent) -> str:
        """Generate hash of event for chain of custody."""
        canonical = json.dumps(event.to_dict(), sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()
    
    def _store_event(self, event: AuditEvent):
        """Store event to disk."""
        # Organize by date
        date_str = event.timestamp.strftime("%Y-%m-%d")
        log_file = self.log_dir / f"audit_{date_str}.jsonl"
        
        # Append to log file
        with open(log_file, 'a') as f:
            f.write(json.dumps(event.to_dict()) + '\n')
    
    def _cache_event(self, event: AuditEvent):
        """Cache event in memory."""
        self.recent_events.append(event)
        
        # Limit cache size
        if len(self.recent_events) > self.max_cache_size:
            self.recent_events = self.recent_events[-self.max_cache_size:]
    
    def verify_event(self, event: AuditEvent) -> bool:
        """Verify event signature."""
        expected_signature = self._sign_event(event)
        return hmac.compare_digest(expected_signature, event.signature or '')
    
    def get_recent_events(self, limit: int = 100) -> List[AuditEvent]:
        """Get recent events from cache."""
        return self.recent_events[-limit:]

