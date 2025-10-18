"""
Tests for Authentication and Authorization System
"""

import unittest
from datetime import datetime, timedelta

from bountybot.auth.models import (
    User, Role, RoleType, PermissionType, Session, Organization, AuditLog
)
from bountybot.auth.password_hasher import PasswordHasher
from bountybot.auth.session_manager import SessionManager
from bountybot.auth.rbac import RBACManager, require_permission, require_role
from bountybot.auth.auth_manager import AuthManager


class TestPasswordHasher(unittest.TestCase):
    """Test password hashing functionality."""
    
    def setUp(self):
        self.hasher = PasswordHasher()
    
    def test_hash_password(self):
        """Test password hashing."""
        password = "SecurePassword123!"
        password_hash = self.hasher.hash_password(password)
        
        # Check format
        self.assertTrue(password_hash.startswith("pbkdf2_sha256$"))
        parts = password_hash.split('$')
        self.assertEqual(len(parts), 4)
    
    def test_verify_password_success(self):
        """Test successful password verification."""
        password = "SecurePassword123!"
        password_hash = self.hasher.hash_password(password)
        
        self.assertTrue(self.hasher.verify_password(password, password_hash))
    
    def test_verify_password_failure(self):
        """Test failed password verification."""
        password = "SecurePassword123!"
        wrong_password = "WrongPassword456!"
        password_hash = self.hasher.hash_password(password)
        
        self.assertFalse(self.hasher.verify_password(wrong_password, password_hash))
    
    def test_needs_rehash(self):
        """Test rehash detection."""
        password_hash = "pbkdf2_sha256$50000$salt$hash"
        self.assertTrue(self.hasher.needs_rehash(password_hash))
    
    def test_generate_token(self):
        """Test token generation."""
        token = self.hasher.generate_token(32)
        self.assertIsInstance(token, str)
        self.assertGreater(len(token), 0)
    
    def test_generate_api_key(self):
        """Test API key generation."""
        api_key = self.hasher.generate_api_key()
        self.assertTrue(api_key.startswith("bb_"))
    
    def test_hash_token(self):
        """Test token hashing."""
        token = "test_token_123"
        token_hash = self.hasher.hash_token(token)
        self.assertEqual(len(token_hash), 64)  # SHA-256 produces 64 hex chars


class TestModels(unittest.TestCase):
    """Test authentication models."""
    
    def test_user_creation(self):
        """Test user model creation."""
        user = User(
            user_id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash123",
            roles={RoleType.VIEWER}
        )
        
        self.assertEqual(user.user_id, "user_123")
        self.assertEqual(user.username, "testuser")
        self.assertTrue(user.has_role(RoleType.VIEWER))
    
    def test_user_add_remove_role(self):
        """Test adding and removing roles."""
        user = User(
            user_id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash123"
        )
        
        user.add_role(RoleType.SECURITY_ANALYST)
        self.assertTrue(user.has_role(RoleType.SECURITY_ANALYST))
        
        user.remove_role(RoleType.SECURITY_ANALYST)
        self.assertFalse(user.has_role(RoleType.SECURITY_ANALYST))
    
    def test_user_record_login(self):
        """Test login recording."""
        user = User(
            user_id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash123"
        )
        
        # Successful login
        user.record_login(success=True)
        self.assertIsNotNone(user.last_login)
        self.assertEqual(user.failed_login_attempts, 0)
        
        # Failed logins
        for _ in range(5):
            user.record_login(success=False)
        
        self.assertEqual(user.failed_login_attempts, 5)
        self.assertTrue(user.is_locked)
    
    def test_session_validity(self):
        """Test session validity checks."""
        session = Session(
            session_id="sess_123",
            user_id="user_123",
            token="token_123"
        )
        
        self.assertTrue(session.is_valid())
        
        # Revoke session
        session.revoke()
        self.assertFalse(session.is_valid())
    
    def test_session_expiration(self):
        """Test session expiration."""
        session = Session(
            session_id="sess_123",
            user_id="user_123",
            token="token_123",
            expires_at=datetime.utcnow() - timedelta(hours=1)
        )
        
        self.assertFalse(session.is_valid())
    
    def test_organization_limits(self):
        """Test organization limits."""
        org = Organization(
            org_id="org_123",
            name="Test Org",
            slug="test-org",
            max_users=5,
            max_reports_per_month=100,
            current_users=4,
            reports_this_month=95
        )
        
        self.assertTrue(org.can_add_user())
        self.assertTrue(org.can_create_report())
        
        org.current_users = 5
        org.reports_this_month = 100
        
        self.assertFalse(org.can_add_user())
        self.assertFalse(org.can_create_report())


class TestSessionManager(unittest.TestCase):
    """Test session management."""
    
    def setUp(self):
        self.session_manager = SessionManager()
        self.user = User(
            user_id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash123",
            roles={RoleType.VIEWER}
        )
    
    def test_create_session(self):
        """Test session creation."""
        session = self.session_manager.create_session(
            self.user,
            ip_address="127.0.0.1",
            user_agent="TestAgent"
        )
        
        self.assertIsNotNone(session.session_id)
        self.assertIsNotNone(session.token)
        self.assertEqual(session.user_id, self.user.user_id)
        self.assertEqual(session.ip_address, "127.0.0.1")
    
    def test_verify_token(self):
        """Test token verification."""
        session = self.session_manager.create_session(self.user)
        
        payload = self.session_manager.verify_token(session.token)
        
        self.assertIsNotNone(payload)
        self.assertEqual(payload['user_id'], self.user.user_id)
        self.assertEqual(payload['username'], self.user.username)
    
    def test_revoke_session(self):
        """Test session revocation."""
        session = self.session_manager.create_session(self.user)
        
        self.assertTrue(self.session_manager.revoke_session(session.session_id))
        self.assertFalse(session.is_valid())
    
    def test_revoke_all_user_sessions(self):
        """Test revoking all user sessions."""
        # Create multiple sessions
        session1 = self.session_manager.create_session(self.user)
        session2 = self.session_manager.create_session(self.user)
        
        count = self.session_manager.revoke_all_user_sessions(self.user.user_id)
        
        self.assertEqual(count, 2)
        self.assertFalse(session1.is_valid())
        self.assertFalse(session2.is_valid())


class TestRBACManager(unittest.TestCase):
    """Test role-based access control."""
    
    def setUp(self):
        self.rbac = RBACManager()
        self.user = User(
            user_id="user_123",
            username="testuser",
            email="test@example.com",
            password_hash="hash123",
            roles={RoleType.SECURITY_ANALYST}
        )
    
    def test_default_roles_initialized(self):
        """Test that default roles are initialized."""
        self.assertIn(RoleType.SUPER_ADMIN, self.rbac.roles)
        self.assertIn(RoleType.ORG_ADMIN, self.rbac.roles)
        self.assertIn(RoleType.SECURITY_ANALYST, self.rbac.roles)
        self.assertIn(RoleType.VIEWER, self.rbac.roles)
        self.assertIn(RoleType.API_USER, self.rbac.roles)
    
    def test_role_permissions(self):
        """Test role permissions."""
        # Super admin has all permissions
        super_admin_perms = self.rbac.get_role_permissions(RoleType.SUPER_ADMIN)
        self.assertGreater(len(super_admin_perms), 0)
        
        # Viewer has limited permissions
        viewer_perms = self.rbac.get_role_permissions(RoleType.VIEWER)
        self.assertIn(PermissionType.REPORT_VIEW, viewer_perms)
        self.assertNotIn(PermissionType.REPORT_DELETE, viewer_perms)
    
    def test_user_has_permission(self):
        """Test user permission checks."""
        # Security analyst can view reports
        self.assertTrue(
            self.rbac.user_has_permission(self.user, PermissionType.REPORT_VIEW)
        )
        
        # Security analyst cannot delete users
        self.assertFalse(
            self.rbac.user_has_permission(self.user, PermissionType.USER_DELETE)
        )
    
    def test_user_has_role(self):
        """Test user role checks."""
        self.assertTrue(self.rbac.user_has_role(self.user, RoleType.SECURITY_ANALYST))
        self.assertFalse(self.rbac.user_has_role(self.user, RoleType.ORG_ADMIN))
    
    def test_get_user_permissions(self):
        """Test getting all user permissions."""
        permissions = self.rbac.get_user_permissions(self.user)
        
        self.assertIn(PermissionType.REPORT_VIEW, permissions)
        self.assertIn(PermissionType.REPORT_CREATE, permissions)
        self.assertIn(PermissionType.REPORT_VALIDATE, permissions)


class TestAuthManager(unittest.TestCase):
    """Test authentication manager."""
    
    def setUp(self):
        self.auth_manager = AuthManager()
    
    def test_create_user(self):
        """Test user creation."""
        user = self.auth_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="SecurePassword123!",
            full_name="Test User"
        )
        
        self.assertIsNotNone(user.user_id)
        self.assertEqual(user.username, "testuser")
        self.assertEqual(user.email, "test@example.com")
        self.assertTrue(user.has_role(RoleType.VIEWER))
    
    def test_create_duplicate_user(self):
        """Test creating duplicate user fails."""
        self.auth_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="password123"
        )
        
        with self.assertRaises(ValueError):
            self.auth_manager.create_user(
                username="testuser",
                email="different@example.com",
                password="password123"
            )
    
    def test_authenticate_success(self):
        """Test successful authentication."""
        self.auth_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="SecurePassword123!"
        )
        
        result = self.auth_manager.authenticate("testuser", "SecurePassword123!")
        
        self.assertIsNotNone(result)
        user, token = result
        self.assertEqual(user.username, "testuser")
        self.assertIsNotNone(token)
    
    def test_authenticate_failure(self):
        """Test failed authentication."""
        self.auth_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="SecurePassword123!"
        )
        
        result = self.auth_manager.authenticate("testuser", "WrongPassword!")
        
        self.assertIsNone(result)
    
    def test_get_user_by_email(self):
        """Test getting user by email."""
        user = self.auth_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="password123"
        )
        
        found_user = self.auth_manager.get_user_by_email("test@example.com")
        
        self.assertIsNotNone(found_user)
        self.assertEqual(found_user.user_id, user.user_id)
    
    def test_delete_user(self):
        """Test user deletion."""
        user = self.auth_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="password123"
        )
        
        self.assertTrue(self.auth_manager.delete_user(user.user_id))
        self.assertIsNone(self.auth_manager.get_user(user.user_id))
    
    def test_create_organization(self):
        """Test organization creation."""
        org = self.auth_manager.create_organization(
            name="Test Organization",
            slug="test-org",
            description="A test organization"
        )
        
        self.assertIsNotNone(org.org_id)
        self.assertEqual(org.name, "Test Organization")
        self.assertEqual(org.slug, "test-org")
    
    def test_audit_logging(self):
        """Test audit logging."""
        user = self.auth_manager.create_user(
            username="testuser",
            email="test@example.com",
            password="password123"
        )
        
        # Should have audit log for user creation
        logs = self.auth_manager.get_audit_logs(user_id=user.user_id)
        
        self.assertGreater(len(logs), 0)
        self.assertEqual(logs[0].action, "user.create")


if __name__ == '__main__':
    unittest.main()

