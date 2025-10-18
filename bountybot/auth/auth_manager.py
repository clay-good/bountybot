"""
Authentication Manager

Main authentication manager that coordinates user management, sessions,
and access control.
"""

import secrets
import logging
from typing import Optional, Dict, List
from datetime import datetime

from .models import User, Organization, RoleType, AuditLog
from .password_hasher import PasswordHasher
from .session_manager import SessionManager
from .rbac import RBACManager

logger = logging.getLogger(__name__)


class AuthManager:
    """
    Main authentication manager.
    
    Coordinates user management, authentication, and authorization.
    """
    
    def __init__(self):
        """Initialize authentication manager."""
        self.users: Dict[str, User] = {}
        self.users_by_email: Dict[str, str] = {}  # email -> user_id
        self.users_by_username: Dict[str, str] = {}  # username -> user_id
        self.organizations: Dict[str, Organization] = {}
        self.audit_logs: List[AuditLog] = []
        
        self.password_hasher = PasswordHasher()
        self.session_manager = SessionManager()
        self.rbac_manager = RBACManager()
        
        logger.info("Initialized AuthManager")
    
    # ==================== User Management ====================
    
    def create_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: Optional[str] = None,
        org_id: Optional[str] = None,
        roles: Optional[set[RoleType]] = None
    ) -> User:
        """
        Create a new user.
        
        Args:
            username: Unique username
            email: User email
            password: Plain text password (will be hashed)
            full_name: User's full name
            org_id: Organization ID
            roles: Set of roles to assign
            
        Returns:
            Created user
            
        Raises:
            ValueError: If username or email already exists
        """
        # Check if username or email already exists
        if username in self.users_by_username:
            raise ValueError(f"Username '{username}' already exists")
        
        if email in self.users_by_email:
            raise ValueError(f"Email '{email}' already exists")
        
        # Check organization limits
        if org_id and org_id in self.organizations:
            org = self.organizations[org_id]
            if not org.can_add_user():
                raise ValueError(f"Organization has reached maximum user limit ({org.max_users})")
        
        # Generate user ID
        user_id = f"user_{secrets.token_hex(8)}"
        
        # Hash password
        password_hash = self.password_hasher.hash_password(password)
        
        # Create user
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            password_hash=password_hash,
            full_name=full_name,
            org_id=org_id,
            roles=roles or {RoleType.VIEWER}  # Default role
        )
        
        # Store user
        self.users[user_id] = user
        self.users_by_email[email] = user_id
        self.users_by_username[username] = user_id
        
        # Update organization user count
        if org_id and org_id in self.organizations:
            self.organizations[org_id].current_users += 1
        
        # Log audit event
        self._log_audit(
            user_id=user_id,
            org_id=org_id,
            action="user.create",
            resource_type="user",
            resource_id=user_id,
            success=True
        )
        
        logger.info(f"Created user: {username} ({user_id})")
        
        return user
    
    def authenticate(
        self,
        username_or_email: str,
        password: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[tuple[User, str]]:
        """
        Authenticate a user and create a session.
        
        Args:
            username_or_email: Username or email
            password: Plain text password
            ip_address: Client IP address
            user_agent: Client user agent
            
        Returns:
            Tuple of (User, JWT token) if successful, None otherwise
        """
        # Find user
        user = self.get_user_by_username(username_or_email)
        if not user:
            user = self.get_user_by_email(username_or_email)
        
        if not user:
            logger.warning(f"Authentication failed: user not found ({username_or_email})")
            return None
        
        # Check if user is locked
        if user.is_locked:
            logger.warning(f"Authentication failed: user locked ({user.username})")
            return None
        
        # Check if user is active
        if not user.is_active:
            logger.warning(f"Authentication failed: user inactive ({user.username})")
            return None
        
        # Verify password
        if not self.password_hasher.verify_password(password, user.password_hash):
            user.record_login(success=False)
            
            # Log failed login
            self._log_audit(
                user_id=user.user_id,
                org_id=user.org_id,
                action="user.login.failed",
                resource_type="user",
                resource_id=user.user_id,
                success=False,
                ip_address=ip_address,
                user_agent=user_agent
            )
            
            logger.warning(f"Authentication failed: invalid password ({user.username})")
            return None
        
        # Record successful login
        user.record_login(success=True)
        
        # Create session
        session = self.session_manager.create_session(user, ip_address, user_agent)
        
        # Log successful login
        self._log_audit(
            user_id=user.user_id,
            org_id=user.org_id,
            action="user.login",
            resource_type="user",
            resource_id=user.user_id,
            success=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        logger.info(f"User authenticated: {user.username}")
        
        return user, session.token
    
    def logout(self, session_id: str) -> bool:
        """
        Logout a user by revoking their session.
        
        Args:
            session_id: Session ID to revoke
            
        Returns:
            True if successful, False otherwise
        """
        session = self.session_manager.get_session(session_id)
        if not session:
            return False
        
        # Log logout
        self._log_audit(
            user_id=session.user_id,
            org_id=None,
            action="user.logout",
            resource_type="user",
            resource_id=session.user_id,
            success=True
        )
        
        return self.session_manager.revoke_session(session_id)
    
    def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID."""
        return self.users.get(user_id)
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        user_id = self.users_by_email.get(email)
        return self.users.get(user_id) if user_id else None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username."""
        user_id = self.users_by_username.get(username)
        return self.users.get(user_id) if user_id else None
    
    def update_user(self, user_id: str, **updates) -> Optional[User]:
        """
        Update user fields.
        
        Args:
            user_id: User ID
            **updates: Fields to update
            
        Returns:
            Updated user if found, None otherwise
        """
        user = self.users.get(user_id)
        if not user:
            return None
        
        # Update allowed fields
        allowed_fields = {'full_name', 'avatar_url', 'preferences', 'is_active'}
        for field, value in updates.items():
            if field in allowed_fields:
                setattr(user, field, value)
        
        user.updated_at = datetime.utcnow()
        
        logger.info(f"Updated user: {user.username}")
        
        return user
    
    def delete_user(self, user_id: str) -> bool:
        """
        Delete a user.
        
        Args:
            user_id: User ID
            
        Returns:
            True if deleted, False if not found
        """
        user = self.users.get(user_id)
        if not user:
            return False
        
        # Revoke all sessions
        self.session_manager.revoke_all_user_sessions(user_id)
        
        # Remove from indexes
        if user.email in self.users_by_email:
            del self.users_by_email[user.email]
        if user.username in self.users_by_username:
            del self.users_by_username[user.username]
        
        # Update organization user count
        if user.org_id and user.org_id in self.organizations:
            self.organizations[user.org_id].current_users -= 1
        
        # Delete user
        del self.users[user_id]
        
        # Log deletion
        self._log_audit(
            user_id=user_id,
            org_id=user.org_id,
            action="user.delete",
            resource_type="user",
            resource_id=user_id,
            success=True
        )
        
        logger.info(f"Deleted user: {user.username} ({user_id})")
        
        return True
    
    # ==================== Organization Management ====================
    
    def create_organization(
        self,
        name: str,
        slug: str,
        description: Optional[str] = None,
        plan: str = "free",
        created_by: Optional[str] = None
    ) -> Organization:
        """Create a new organization."""
        org_id = f"org_{secrets.token_hex(8)}"
        
        org = Organization(
            org_id=org_id,
            name=name,
            slug=slug,
            description=description,
            plan=plan,
            created_by=created_by
        )
        
        self.organizations[org_id] = org
        
        logger.info(f"Created organization: {name} ({org_id})")
        
        return org
    
    def get_organization(self, org_id: str) -> Optional[Organization]:
        """Get organization by ID."""
        return self.organizations.get(org_id)
    
    # ==================== Audit Logging ====================
    
    def _log_audit(
        self,
        user_id: str,
        org_id: Optional[str],
        action: str,
        resource_type: str,
        resource_id: Optional[str] = None,
        success: bool = True,
        error_message: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        metadata: Optional[Dict] = None
    ):
        """Log an audit event."""
        log = AuditLog(
            log_id=f"audit_{secrets.token_hex(8)}",
            user_id=user_id,
            org_id=org_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            success=success,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata=metadata or {}
        )
        
        self.audit_logs.append(log)
    
    def get_audit_logs(
        self,
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100
    ) -> List[AuditLog]:
        """Get audit logs with optional filters."""
        logs = self.audit_logs
        
        if user_id:
            logs = [log for log in logs if log.user_id == user_id]
        
        if org_id:
            logs = [log for log in logs if log.org_id == org_id]
        
        if action:
            logs = [log for log in logs if log.action == action]
        
        # Return most recent logs
        return sorted(logs, key=lambda x: x.timestamp, reverse=True)[:limit]


# Global auth manager instance
auth_manager = AuthManager()

