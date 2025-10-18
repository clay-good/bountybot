"""
Authentication Data Models

Defines user, role, permission, session, and organization models.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List, Set, Dict, Any
from enum import Enum
import uuid


class RoleType(str, Enum):
    """Built-in role types."""
    SUPER_ADMIN = "super_admin"  # Full system access
    ORG_ADMIN = "org_admin"      # Organization administrator
    SECURITY_ANALYST = "security_analyst"  # Can validate reports
    VIEWER = "viewer"            # Read-only access
    API_USER = "api_user"        # API access only


class PermissionType(str, Enum):
    """Permission types for fine-grained access control."""
    # Report permissions
    REPORT_VIEW = "report:view"
    REPORT_CREATE = "report:create"
    REPORT_UPDATE = "report:update"
    REPORT_DELETE = "report:delete"
    REPORT_VALIDATE = "report:validate"
    
    # User permissions
    USER_VIEW = "user:view"
    USER_CREATE = "user:create"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    
    # Organization permissions
    ORG_VIEW = "org:view"
    ORG_CREATE = "org:create"
    ORG_UPDATE = "org:update"
    ORG_DELETE = "org:delete"
    
    # Integration permissions
    INTEGRATION_VIEW = "integration:view"
    INTEGRATION_CREATE = "integration:create"
    INTEGRATION_UPDATE = "integration:update"
    INTEGRATION_DELETE = "integration:delete"
    
    # Webhook permissions
    WEBHOOK_VIEW = "webhook:view"
    WEBHOOK_CREATE = "webhook:create"
    WEBHOOK_UPDATE = "webhook:update"
    WEBHOOK_DELETE = "webhook:delete"
    
    # Analytics permissions
    ANALYTICS_VIEW = "analytics:view"
    ANALYTICS_EXPORT = "analytics:export"
    
    # System permissions
    SYSTEM_ADMIN = "system:admin"
    SYSTEM_CONFIG = "system:config"
    AUDIT_VIEW = "audit:view"


@dataclass
class Permission:
    """Permission model."""
    name: PermissionType
    description: str
    resource_type: str  # e.g., "report", "user", "org"
    action: str  # e.g., "view", "create", "update", "delete"


@dataclass
class Role:
    """Role model with permissions."""
    role_id: str
    name: RoleType
    display_name: str
    description: str
    permissions: Set[PermissionType] = field(default_factory=set)
    is_system_role: bool = True  # System roles cannot be deleted
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def has_permission(self, permission: PermissionType) -> bool:
        """Check if role has a specific permission."""
        return permission in self.permissions
    
    def add_permission(self, permission: PermissionType):
        """Add permission to role."""
        self.permissions.add(permission)
        self.updated_at = datetime.utcnow()
    
    def remove_permission(self, permission: PermissionType):
        """Remove permission from role."""
        self.permissions.discard(permission)
        self.updated_at = datetime.utcnow()


@dataclass
class Organization:
    """Organization model for multi-tenancy."""
    org_id: str
    name: str
    slug: str  # URL-friendly identifier
    description: Optional[str] = None
    is_active: bool = True
    
    # Subscription/plan info
    plan: str = "free"  # free, pro, enterprise
    max_users: int = 5
    max_reports_per_month: int = 100
    
    # Settings
    settings: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None  # user_id
    
    # Usage tracking
    current_users: int = 0
    reports_this_month: int = 0
    
    def can_add_user(self) -> bool:
        """Check if organization can add more users."""
        return self.current_users < self.max_users
    
    def can_create_report(self) -> bool:
        """Check if organization can create more reports this month."""
        return self.reports_this_month < self.max_reports_per_month
    
    def increment_report_count(self):
        """Increment monthly report count."""
        self.reports_this_month += 1
        self.updated_at = datetime.utcnow()


@dataclass
class User:
    """User model."""
    user_id: str
    username: str
    email: str
    password_hash: str
    
    # Profile
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    
    # Organization
    org_id: Optional[str] = None
    
    # Roles and permissions
    roles: Set[RoleType] = field(default_factory=set)
    custom_permissions: Set[PermissionType] = field(default_factory=set)
    
    # Status
    is_active: bool = True
    is_verified: bool = False
    is_locked: bool = False
    
    # Security
    failed_login_attempts: int = 0
    last_login: Optional[datetime] = None
    last_password_change: Optional[datetime] = None
    mfa_enabled: bool = False
    mfa_secret: Optional[str] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    last_activity: Optional[datetime] = None
    
    # Preferences
    preferences: Dict[str, Any] = field(default_factory=dict)
    
    def has_role(self, role: RoleType) -> bool:
        """Check if user has a specific role."""
        return role in self.roles
    
    def add_role(self, role: RoleType):
        """Add role to user."""
        self.roles.add(role)
        self.updated_at = datetime.utcnow()
    
    def remove_role(self, role: RoleType):
        """Remove role from user."""
        self.roles.discard(role)
        self.updated_at = datetime.utcnow()
    
    def has_permission(self, permission: PermissionType, role_permissions: Dict[RoleType, Set[PermissionType]]) -> bool:
        """Check if user has a specific permission (from roles or custom)."""
        # Check custom permissions first
        if permission in self.custom_permissions:
            return True
        
        # Check role permissions
        for role in self.roles:
            if role in role_permissions and permission in role_permissions[role]:
                return True
        
        return False
    
    def record_login(self, success: bool = True):
        """Record login attempt."""
        if success:
            self.last_login = datetime.utcnow()
            self.failed_login_attempts = 0
        else:
            self.failed_login_attempts += 1
            # Lock account after 5 failed attempts
            if self.failed_login_attempts >= 5:
                self.is_locked = True
        
        self.updated_at = datetime.utcnow()
    
    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.utcnow()


@dataclass
class Session:
    """User session model."""
    session_id: str
    user_id: str
    token: str  # JWT token
    refresh_token: Optional[str] = None
    
    # Session info
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: datetime = field(default_factory=lambda: datetime.utcnow() + timedelta(hours=24))
    last_activity: datetime = field(default_factory=datetime.utcnow)
    
    # Status
    is_active: bool = True
    revoked: bool = False
    revoked_at: Optional[datetime] = None
    
    def is_valid(self) -> bool:
        """Check if session is valid."""
        if self.revoked or not self.is_active:
            return False
        
        if datetime.utcnow() > self.expires_at:
            return False
        
        return True
    
    def revoke(self):
        """Revoke session."""
        self.revoked = True
        self.revoked_at = datetime.utcnow()
        self.is_active = False
    
    def refresh(self, duration_hours: int = 24):
        """Refresh session expiration."""
        self.expires_at = datetime.utcnow() + timedelta(hours=duration_hours)
        self.last_activity = datetime.utcnow()


@dataclass
class AuditLog:
    """Audit log entry for tracking user actions."""
    log_id: str
    user_id: str
    org_id: Optional[str]
    
    # Action details
    action: str  # e.g., "user.login", "report.create", "user.delete"
    resource_type: str  # e.g., "user", "report", "integration"
    resource_id: Optional[str] = None
    
    # Request details
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Result
    success: bool = True
    error_message: Optional[str] = None
    
    # Additional context
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Timestamp
    timestamp: datetime = field(default_factory=datetime.utcnow)

