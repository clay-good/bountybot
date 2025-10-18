"""
Authentication and Authorization Module

Provides comprehensive user authentication, role-based access control,
and session management for BountyBot.
"""

from .models import User, Role, Permission, Session, Organization
from .auth_manager import AuthManager
from .rbac import RBACManager, require_permission, require_role
from .session_manager import SessionManager
from .password_hasher import PasswordHasher

__all__ = [
    'User',
    'Role',
    'Permission',
    'Session',
    'Organization',
    'AuthManager',
    'RBACManager',
    'SessionManager',
    'PasswordHasher',
    'require_permission',
    'require_role',
]

