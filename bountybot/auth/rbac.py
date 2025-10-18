"""
Role-Based Access Control (RBAC)

Provides role and permission management with decorators for access control.
"""

import logging
from typing import Dict, Set, Optional, Callable
from functools import wraps

from .models import Role, RoleType, PermissionType, User

logger = logging.getLogger(__name__)


class RBACManager:
    """
    Role-Based Access Control Manager.
    
    Manages roles, permissions, and access control checks.
    """
    
    def __init__(self):
        """Initialize RBAC manager with default roles."""
        self.roles: Dict[RoleType, Role] = {}
        self._initialize_default_roles()
    
    def _initialize_default_roles(self):
        """Initialize default system roles with permissions."""
        
        # Super Admin - Full system access
        super_admin = Role(
            role_id="role_super_admin",
            name=RoleType.SUPER_ADMIN,
            display_name="Super Administrator",
            description="Full system access with all permissions",
            permissions={perm for perm in PermissionType},
            is_system_role=True
        )
        
        # Organization Admin - Full organization access
        org_admin = Role(
            role_id="role_org_admin",
            name=RoleType.ORG_ADMIN,
            display_name="Organization Administrator",
            description="Full access within organization",
            permissions={
                # Reports
                PermissionType.REPORT_VIEW,
                PermissionType.REPORT_CREATE,
                PermissionType.REPORT_UPDATE,
                PermissionType.REPORT_DELETE,
                PermissionType.REPORT_VALIDATE,
                # Users
                PermissionType.USER_VIEW,
                PermissionType.USER_CREATE,
                PermissionType.USER_UPDATE,
                PermissionType.USER_DELETE,
                # Organization
                PermissionType.ORG_VIEW,
                PermissionType.ORG_UPDATE,
                # Integrations
                PermissionType.INTEGRATION_VIEW,
                PermissionType.INTEGRATION_CREATE,
                PermissionType.INTEGRATION_UPDATE,
                PermissionType.INTEGRATION_DELETE,
                # Webhooks
                PermissionType.WEBHOOK_VIEW,
                PermissionType.WEBHOOK_CREATE,
                PermissionType.WEBHOOK_UPDATE,
                PermissionType.WEBHOOK_DELETE,
                # Analytics
                PermissionType.ANALYTICS_VIEW,
                PermissionType.ANALYTICS_EXPORT,
                # Audit
                PermissionType.AUDIT_VIEW,
            },
            is_system_role=True
        )
        
        # Security Analyst - Can validate reports
        security_analyst = Role(
            role_id="role_security_analyst",
            name=RoleType.SECURITY_ANALYST,
            display_name="Security Analyst",
            description="Can validate and manage reports",
            permissions={
                # Reports
                PermissionType.REPORT_VIEW,
                PermissionType.REPORT_CREATE,
                PermissionType.REPORT_UPDATE,
                PermissionType.REPORT_VALIDATE,
                # Integrations (view only)
                PermissionType.INTEGRATION_VIEW,
                # Webhooks (view only)
                PermissionType.WEBHOOK_VIEW,
                # Analytics
                PermissionType.ANALYTICS_VIEW,
            },
            is_system_role=True
        )
        
        # Viewer - Read-only access
        viewer = Role(
            role_id="role_viewer",
            name=RoleType.VIEWER,
            display_name="Viewer",
            description="Read-only access to reports and analytics",
            permissions={
                PermissionType.REPORT_VIEW,
                PermissionType.INTEGRATION_VIEW,
                PermissionType.WEBHOOK_VIEW,
                PermissionType.ANALYTICS_VIEW,
            },
            is_system_role=True
        )
        
        # API User - API access only
        api_user = Role(
            role_id="role_api_user",
            name=RoleType.API_USER,
            display_name="API User",
            description="API access for automated systems",
            permissions={
                PermissionType.REPORT_VIEW,
                PermissionType.REPORT_CREATE,
                PermissionType.REPORT_VALIDATE,
            },
            is_system_role=True
        )
        
        # Store roles
        self.roles[RoleType.SUPER_ADMIN] = super_admin
        self.roles[RoleType.ORG_ADMIN] = org_admin
        self.roles[RoleType.SECURITY_ANALYST] = security_analyst
        self.roles[RoleType.VIEWER] = viewer
        self.roles[RoleType.API_USER] = api_user
        
        logger.info("Initialized default RBAC roles")
    
    def get_role(self, role_type: RoleType) -> Optional[Role]:
        """Get role by type."""
        return self.roles.get(role_type)
    
    def get_role_permissions(self, role_type: RoleType) -> Set[PermissionType]:
        """Get all permissions for a role."""
        role = self.roles.get(role_type)
        return role.permissions if role else set()
    
    def user_has_permission(self, user: User, permission: PermissionType) -> bool:
        """
        Check if user has a specific permission.
        
        Args:
            user: User object
            permission: Permission to check
            
        Returns:
            True if user has permission, False otherwise
        """
        # Check custom permissions
        if permission in user.custom_permissions:
            return True
        
        # Check role permissions
        for role_type in user.roles:
            role = self.roles.get(role_type)
            if role and role.has_permission(permission):
                return True
        
        return False
    
    def user_has_role(self, user: User, role_type: RoleType) -> bool:
        """
        Check if user has a specific role.
        
        Args:
            user: User object
            role_type: Role to check
            
        Returns:
            True if user has role, False otherwise
        """
        return role_type in user.roles
    
    def user_has_any_role(self, user: User, role_types: Set[RoleType]) -> bool:
        """
        Check if user has any of the specified roles.
        
        Args:
            user: User object
            role_types: Set of roles to check
            
        Returns:
            True if user has any role, False otherwise
        """
        return bool(user.roles & role_types)
    
    def get_user_permissions(self, user: User) -> Set[PermissionType]:
        """
        Get all permissions for a user (from roles and custom).
        
        Args:
            user: User object
            
        Returns:
            Set of all permissions
        """
        permissions = set(user.custom_permissions)
        
        for role_type in user.roles:
            role = self.roles.get(role_type)
            if role:
                permissions.update(role.permissions)
        
        return permissions
    
    def create_custom_role(
        self,
        role_id: str,
        name: str,
        display_name: str,
        description: str,
        permissions: Set[PermissionType]
    ) -> Role:
        """
        Create a custom role.
        
        Args:
            role_id: Unique role identifier
            name: Role name
            display_name: Display name
            description: Role description
            permissions: Set of permissions
            
        Returns:
            Created role
        """
        # Note: Custom roles use string names, not RoleType enum
        role = Role(
            role_id=role_id,
            name=name,  # type: ignore
            display_name=display_name,
            description=description,
            permissions=permissions,
            is_system_role=False
        )
        
        logger.info(f"Created custom role: {role_id}")
        return role


# Global RBAC manager instance
rbac_manager = RBACManager()


def require_permission(permission: PermissionType):
    """
    Decorator to require a specific permission.
    
    Usage:
        @require_permission(PermissionType.REPORT_CREATE)
        def create_report(user: User, ...):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Try to find user in args or kwargs
            user = None
            if args and isinstance(args[0], User):
                user = args[0]
            elif 'user' in kwargs and isinstance(kwargs['user'], User):
                user = kwargs['user']
            
            if not user:
                raise ValueError("User not found in function arguments")
            
            if not rbac_manager.user_has_permission(user, permission):
                raise PermissionError(
                    f"User {user.username} does not have permission: {permission.value}"
                )
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def require_role(role: RoleType):
    """
    Decorator to require a specific role.
    
    Usage:
        @require_role(RoleType.ORG_ADMIN)
        def delete_user(user: User, ...):
            ...
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Try to find user in args or kwargs
            user = None
            if args and isinstance(args[0], User):
                user = args[0]
            elif 'user' in kwargs and isinstance(kwargs['user'], User):
                user = kwargs['user']
            
            if not user:
                raise ValueError("User not found in function arguments")
            
            if not rbac_manager.user_has_role(user, role):
                raise PermissionError(
                    f"User {user.username} does not have role: {role.value}"
                )
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator

