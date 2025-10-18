"""
Tenant Context

Thread-local context for current tenant.
"""

import threading
from typing import Optional
from contextlib import contextmanager


# Thread-local storage for tenant context
_tenant_context = threading.local()


class TenantContext:
    """Tenant context manager."""
    
    def __init__(self, org_id: str, user_id: Optional[str] = None):
        """Initialize tenant context."""
        self.org_id = org_id
        self.user_id = user_id
    
    def __enter__(self):
        """Enter context."""
        set_current_tenant(self.org_id, self.user_id)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Exit context."""
        clear_current_tenant()


def get_current_tenant() -> Optional[str]:
    """Get current tenant ID from context."""
    return getattr(_tenant_context, 'org_id', None)


def get_current_user() -> Optional[str]:
    """Get current user ID from context."""
    return getattr(_tenant_context, 'user_id', None)


def set_current_tenant(org_id: str, user_id: Optional[str] = None):
    """Set current tenant in context."""
    _tenant_context.org_id = org_id
    _tenant_context.user_id = user_id


def clear_current_tenant():
    """Clear current tenant from context."""
    if hasattr(_tenant_context, 'org_id'):
        delattr(_tenant_context, 'org_id')
    if hasattr(_tenant_context, 'user_id'):
        delattr(_tenant_context, 'user_id')


@contextmanager
def tenant_context(org_id: str, user_id: Optional[str] = None):
    """Context manager for tenant operations."""
    set_current_tenant(org_id, user_id)
    try:
        yield
    finally:
        clear_current_tenant()

