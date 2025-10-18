"""
Audit Logging Models

Data models for audit events and forensic analysis.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, Any, List, Optional


class AuditEventCategory(str, Enum):
    """Audit event categories."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    CONFIGURATION = "configuration"
    SECURITY = "security"
    COMPLIANCE = "compliance"
    ADMIN = "admin"
    API = "api"
    SYSTEM = "system"


class AuditEventType(str, Enum):
    """Specific audit event types."""
    # Authentication events
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILURE = "login_failure"
    LOGOUT = "logout"
    PASSWORD_CHANGE = "password_change"
    MFA_ENABLED = "mfa_enabled"
    MFA_DISABLED = "mfa_disabled"
    
    # Authorization events
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_DENIED = "permission_denied"
    ROLE_ASSIGNED = "role_assigned"
    ROLE_REVOKED = "role_revoked"
    
    # Data access events
    REPORT_VIEWED = "report_viewed"
    REPORT_DOWNLOADED = "report_downloaded"
    DATA_EXPORTED = "data_exported"
    SEARCH_PERFORMED = "search_performed"
    
    # Data modification events
    REPORT_CREATED = "report_created"
    REPORT_UPDATED = "report_updated"
    REPORT_DELETED = "report_deleted"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    
    # Configuration events
    CONFIG_CHANGED = "config_changed"
    INTEGRATION_ADDED = "integration_added"
    INTEGRATION_REMOVED = "integration_removed"
    WEBHOOK_CONFIGURED = "webhook_configured"
    
    # Security events
    SECURITY_ALERT = "security_alert"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    INVALID_TOKEN = "invalid_token"
    BRUTE_FORCE_DETECTED = "brute_force_detected"
    
    # Compliance events
    DATA_RETENTION_APPLIED = "data_retention_applied"
    DATA_ANONYMIZED = "data_anonymized"
    CONSENT_GRANTED = "consent_granted"
    CONSENT_REVOKED = "consent_revoked"
    GDPR_REQUEST = "gdpr_request"
    
    # Admin events
    SYSTEM_BACKUP = "system_backup"
    SYSTEM_RESTORE = "system_restore"
    MAINTENANCE_MODE = "maintenance_mode"
    TENANT_PROVISIONED = "tenant_provisioned"
    TENANT_SUSPENDED = "tenant_suspended"
    
    # API events
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    API_CALL = "api_call"
    QUOTA_EXCEEDED = "quota_exceeded"


class AuditSeverity(str, Enum):
    """Audit event severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Audit event record."""
    event_id: str
    timestamp: datetime
    event_type: AuditEventType
    category: AuditEventCategory
    severity: AuditSeverity
    
    # Actor information
    user_id: Optional[str] = None
    username: Optional[str] = None
    org_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Action details
    action: str = ""
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    
    # Event data
    details: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Request context
    request_id: Optional[str] = None
    session_id: Optional[str] = None
    api_endpoint: Optional[str] = None
    http_method: Optional[str] = None
    
    # Result
    success: bool = True
    error_message: Optional[str] = None
    
    # Tamper protection
    signature: Optional[str] = None
    previous_event_hash: Optional[str] = None
    
    # Compliance
    compliance_tags: List[str] = field(default_factory=list)
    retention_days: int = 2555  # 7 years default
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'category': self.category.value,
            'severity': self.severity.value,
            'user_id': self.user_id,
            'username': self.username,
            'org_id': self.org_id,
            'ip_address': self.ip_address,
            'user_agent': self.user_agent,
            'action': self.action,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'details': self.details,
            'metadata': self.metadata,
            'request_id': self.request_id,
            'session_id': self.session_id,
            'api_endpoint': self.api_endpoint,
            'http_method': self.http_method,
            'success': self.success,
            'error_message': self.error_message,
            'signature': self.signature,
            'previous_event_hash': self.previous_event_hash,
            'compliance_tags': self.compliance_tags,
            'retention_days': self.retention_days
        }


@dataclass
class AuditQuery:
    """Query parameters for audit log search."""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    event_types: List[AuditEventType] = field(default_factory=list)
    categories: List[AuditEventCategory] = field(default_factory=list)
    severities: List[AuditSeverity] = field(default_factory=list)
    user_ids: List[str] = field(default_factory=list)
    org_ids: List[str] = field(default_factory=list)
    resource_types: List[str] = field(default_factory=list)
    resource_ids: List[str] = field(default_factory=list)
    ip_addresses: List[str] = field(default_factory=list)
    success_only: Optional[bool] = None
    text_search: Optional[str] = None
    limit: int = 100
    offset: int = 0
    sort_by: str = "timestamp"
    sort_order: str = "desc"


@dataclass
class AuditReport:
    """Audit report for compliance."""
    report_id: str
    title: str
    description: str
    generated_at: datetime
    start_time: datetime
    end_time: datetime
    total_events: int
    events_by_category: Dict[str, int] = field(default_factory=dict)
    events_by_severity: Dict[str, int] = field(default_factory=dict)
    events_by_user: Dict[str, int] = field(default_factory=dict)
    security_incidents: int = 0
    compliance_violations: int = 0
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)


@dataclass
class ForensicTimeline:
    """Timeline for forensic investigation."""
    timeline_id: str
    title: str
    description: str
    created_at: datetime
    events: List[AuditEvent] = field(default_factory=list)
    actors: List[str] = field(default_factory=list)
    resources: List[str] = field(default_factory=list)
    key_findings: List[str] = field(default_factory=list)
    chain_of_custody: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class AnomalyDetection:
    """Anomaly detection result."""
    anomaly_id: str
    detected_at: datetime
    anomaly_type: str
    severity: AuditSeverity
    description: str
    affected_user: Optional[str] = None
    affected_resource: Optional[str] = None
    related_events: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    recommended_actions: List[str] = field(default_factory=list)
    false_positive: bool = False

