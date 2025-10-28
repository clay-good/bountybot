"""
Authentication & Authorization System Demo

Demonstrates the comprehensive authentication and authorization features.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from bountybot.auth.auth_manager import AuthManager
from bountybot.auth.models import RoleType, PermissionType
from bountybot.auth.rbac import RBACManager

console = Console()


def print_banner():
    """Print demo banner."""
    banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║              🔐 BOUNTYBOT AUTHENTICATION & AUTHORIZATION DEMO 🔐             ║
║                                                                              ║
║                    Enterprise User Management System                         ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bold cyan")


def demo_overview():
    """Show authentication system overview."""
    console.print("\n╔══════════════════════════════════════════════════════════════════════════════╗", style="bold")
    console.print("║ 1. Authentication System Overview                                            ║", style="bold")
    console.print("╚══════════════════════════════════════════════════════════════════════════════╝\n", style="bold")
    
    console.print("The BountyBot Authentication System provides:\n")
    
    table = Table(title="Authentication Features", show_header=True, header_style="bold magenta")
    table.add_column("Feature", style="cyan", width=30)
    table.add_column("Description", style="white", width=50)
    table.add_column("Status", style="green", width=10)
    
    features = [
        ("User Management", "Create, update, delete users with profiles", "✓ Complete"),
        ("Password Security", "PBKDF2-HMAC-SHA256 with 100k iterations", "✓ Complete"),
        ("Session Management", "JWT tokens with refresh capability", "✓ Complete"),
        ("Role-Based Access Control", "5 built-in roles with fine-grained permissions", "✓ Complete"),
        ("Multi-Tenancy", "Organization isolation with usage limits", "✓ Complete"),
        ("Audit Logging", "Complete audit trail for compliance", "✓ Complete"),
        ("Account Security", "Auto-lock after failed login attempts", "✓ Complete"),
        ("Token Management", "Secure token generation and validation", "✓ Complete"),
    ]
    
    for feature, description, status in features:
        table.add_row(feature, description, status)
    
    console.print(table)


def demo_roles_and_permissions():
    """Show roles and permissions."""
    console.print("\n╔══════════════════════════════════════════════════════════════════════════════╗", style="bold")
    console.print("║ 2. Roles and Permissions                                                     ║", style="bold")
    console.print("╚══════════════════════════════════════════════════════════════════════════════╝\n", style="bold")
    
    rbac = RBACManager()
    
    # Roles table
    roles_table = Table(title="Built-in Roles", show_header=True, header_style="bold magenta")
    roles_table.add_column("Role", style="cyan", width=20)
    roles_table.add_column("Description", style="white", width=40)
    roles_table.add_column("Permissions", style="yellow", width=15)
    
    for role_type in [RoleType.SUPER_ADMIN, RoleType.ORG_ADMIN, RoleType.SECURITY_ANALYST, RoleType.VIEWER, RoleType.API_USER]:
        role = rbac.get_role(role_type)
        if role:
            roles_table.add_row(
                role.display_name,
                role.description,
                str(len(role.permissions))
            )
    
    console.print(roles_table)
    
    # Permissions table
    console.print("\n")
    perms_table = Table(title="Permission Types", show_header=True, header_style="bold magenta")
    perms_table.add_column("Category", style="cyan", width=20)
    perms_table.add_column("Permissions", style="white", width=60)
    
    permission_categories = {
        "Reports": ["report:view", "report:create", "report:update", "report:delete", "report:validate"],
        "Users": ["user:view", "user:create", "user:update", "user:delete"],
        "Organizations": ["org:view", "org:create", "org:update", "org:delete"],
        "Integrations": ["integration:view", "integration:create", "integration:update", "integration:delete"],
        "Webhooks": ["webhook:view", "webhook:create", "webhook:update", "webhook:delete"],
        "Analytics": ["analytics:view", "analytics:export"],
        "System": ["system:admin", "system:config", "audit:view"],
    }
    
    for category, perms in permission_categories.items():
        perms_table.add_row(category, ", ".join(perms))
    
    console.print(perms_table)


def demo_user_management():
    """Demonstrate user management."""
    console.print("\n╔══════════════════════════════════════════════════════════════════════════════╗", style="bold")
    console.print("║ 3. User Management Demo                                                      ║", style="bold")
    console.print("╚══════════════════════════════════════════════════════════════════════════════╝\n", style="bold")
    
    auth_manager = AuthManager()
    
    # Create organization
    console.print("[bold cyan]Creating organization...[/bold cyan]")
    org = auth_manager.create_organization(
        name="Acme Security",
        slug="acme-security",
        description="Acme Corporation Security Team",
        plan="enterprise"
    )
    console.print(f"✓ Created organization: {org.name} ({org.org_id})\n")
    
    # Create users with different roles
    console.print("[bold cyan]Creating users with different roles...[/bold cyan]")
    
    users = []
    
    # Admin user
    admin = auth_manager.create_user(
        username="admin",
        email="admin@acme.com",
        password="SecureAdmin123!",
        full_name="Admin User",
        org_id=org.org_id,
        roles={RoleType.ORG_ADMIN}
    )
    users.append(("Admin", admin))
    console.print(f"✓ Created admin user: {admin.username}")
    
    # Security analyst
    analyst = auth_manager.create_user(
        username="analyst",
        email="analyst@acme.com",
        password="SecureAnalyst123!",
        full_name="Security Analyst",
        org_id=org.org_id,
        roles={RoleType.SECURITY_ANALYST}
    )
    users.append(("Analyst", analyst))
    console.print(f"✓ Created analyst user: {analyst.username}")
    
    # Viewer
    viewer = auth_manager.create_user(
        username="viewer",
        email="viewer@acme.com",
        password="SecureViewer123!",
        full_name="Report Viewer",
        org_id=org.org_id,
        roles={RoleType.VIEWER}
    )
    users.append(("Viewer", viewer))
    console.print(f"✓ Created viewer user: {viewer.username}\n")
    
    # Show users table
    users_table = Table(title="Created Users", show_header=True, header_style="bold magenta")
    users_table.add_column("Type", style="cyan", width=15)
    users_table.add_column("Username", style="white", width=15)
    users_table.add_column("Email", style="white", width=25)
    users_table.add_column("Roles", style="yellow", width=25)
    
    for user_type, user in users:
        users_table.add_row(
            user_type,
            user.username,
            user.email,
            ", ".join([r.value for r in user.roles])
        )
    
    console.print(users_table)
    
    return auth_manager, users


def demo_authentication():
    """Demonstrate authentication flow."""
    console.print("\n╔══════════════════════════════════════════════════════════════════════════════╗", style="bold")
    console.print("║ 4. Authentication Flow Demo                                                  ║", style="bold")
    console.print("╚══════════════════════════════════════════════════════════════════════════════╝\n", style="bold")
    
    auth_manager = AuthManager()
    
    # Create a test user
    user = auth_manager.create_user(
        username="testuser",
        email="test@example.com",
        password="TestPassword123!",
        full_name="Test User"
    )
    
    console.print("[bold cyan]1. User Login[/bold cyan]")
    console.print(f"   Username: {user.username}")
    console.print(f"   Password: TestPassword123!\n")
    
    # Authenticate
    result = auth_manager.authenticate(
        "testuser",
        "TestPassword123!",
        ip_address="192.168.1.100",
        user_agent="Mozilla/5.0"
    )
    
    if result:
        authenticated_user, token = result
        console.print(f"✓ Authentication successful!")
        console.print(f"   User ID: {authenticated_user.user_id}")
        console.print(f"   JWT Token: {token[:50]}...\n")
        
        # Verify token
        console.print("[bold cyan]2. Token Verification[/bold cyan]")
        payload = auth_manager.session_manager.verify_token(token)
        if payload:
            console.print(f"✓ Token verified successfully!")
            console.print(f"   User ID: {payload['user_id']}")
            console.print(f"   Username: {payload['username']}")
            console.print(f"   Roles: {', '.join(payload['roles'])}\n")
    
    # Failed login attempt
    console.print("[bold cyan]3. Failed Login Attempt[/bold cyan]")
    result = auth_manager.authenticate("testuser", "WrongPassword!")
    if not result:
        console.print("✗ Authentication failed (as expected)")
        console.print(f"   Failed attempts: {user.failed_login_attempts}\n")


def demo_authorization():
    """Demonstrate authorization checks."""
    console.print("\n╔══════════════════════════════════════════════════════════════════════════════╗", style="bold")
    console.print("║ 5. Authorization Demo                                                        ║", style="bold")
    console.print("╚══════════════════════════════════════════════════════════════════════════════╝\n", style="bold")
    
    auth_manager = AuthManager()
    rbac = auth_manager.rbac_manager
    
    # Create users with different roles
    admin = auth_manager.create_user(
        username="admin2",
        email="admin2@example.com",
        password="password",
        roles={RoleType.ORG_ADMIN}
    )
    
    analyst = auth_manager.create_user(
        username="analyst2",
        email="analyst2@example.com",
        password="password",
        roles={RoleType.SECURITY_ANALYST}
    )
    
    viewer = auth_manager.create_user(
        username="viewer2",
        email="viewer2@example.com",
        password="password",
        roles={RoleType.VIEWER}
    )
    
    # Permission checks
    console.print("[bold cyan]Permission Checks:[/bold cyan]\n")
    
    permissions_to_check = [
        PermissionType.REPORT_VIEW,
        PermissionType.REPORT_CREATE,
        PermissionType.REPORT_DELETE,
        PermissionType.USER_DELETE,
    ]
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Permission", style="cyan", width=25)
    table.add_column("Admin", style="white", width=10)
    table.add_column("Analyst", style="white", width=10)
    table.add_column("Viewer", style="white", width=10)
    
    for perm in permissions_to_check:
        admin_has = "✓" if rbac.user_has_permission(admin, perm) else "✗"
        analyst_has = "✓" if rbac.user_has_permission(analyst, perm) else "✗"
        viewer_has = "✓" if rbac.user_has_permission(viewer, perm) else "✗"
        
        table.add_row(perm.value, admin_has, analyst_has, viewer_has)
    
    console.print(table)


def demo_audit_logging():
    """Demonstrate audit logging."""
    console.print("\n╔══════════════════════════════════════════════════════════════════════════════╗", style="bold")
    console.print("║ 6. Audit Logging Demo                                                        ║", style="bold")
    console.print("╚══════════════════════════════════════════════════════════════════════════════╝\n", style="bold")
    
    auth_manager = AuthManager()
    
    # Create user and perform actions
    user = auth_manager.create_user(
        username="audituser",
        email="audit@example.com",
        password="password"
    )
    
    # Authenticate
    auth_manager.authenticate("audituser", "password", ip_address="10.0.0.1")
    
    # Get audit logs
    logs = auth_manager.get_audit_logs(user_id=user.user_id, limit=10)
    
    console.print(f"[bold cyan]Audit Logs for {user.username}:[/bold cyan]\n")
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Timestamp", style="cyan", width=20)
    table.add_column("Action", style="white", width=20)
    table.add_column("Resource", style="yellow", width=15)
    table.add_column("Success", style="green", width=10)
    table.add_column("IP Address", style="white", width=15)
    
    for log in logs:
        timestamp = log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        success = "✓" if log.success else "✗"
        table.add_row(
            timestamp,
            log.action,
            log.resource_type,
            success,
            log.ip_address or "N/A"
        )
    
    console.print(table)


def main():
    """Run all demos."""
    print_banner()
    demo_overview()
    demo_roles_and_permissions()
    demo_user_management()
    demo_authentication()
    demo_authorization()
    demo_audit_logging()
    
    console.print("\n╔══════════════════════════════════════════════════════════════════════════════╗", style="bold green")
    console.print("║                                                                              ║", style="bold green")
    console.print("║              🎉 AUTHENTICATION SYSTEM DEMO COMPLETE! 🎉                      ║", style="bold green")
    console.print("║                                                                              ║", style="bold green")
    console.print("║                  Ready for Enterprise Deployment!                            ║", style="bold green")
    console.print("║                                                                              ║", style="bold green")
    console.print("╚══════════════════════════════════════════════════════════════════════════════╝\n", style="bold green")


if __name__ == "__main__":
    main()

