"""
Tenant Isolation

Middleware and decorators for tenant isolation.
"""

from functools import wraps
from typing import Optional, Callable
from .tenant_context import get_current_tenant, set_current_tenant


class TenantIsolationError(Exception):
    """Raised when tenant isolation is violated."""
    pass


class TenantIsolationMiddleware:
    """Middleware for tenant isolation in web applications."""
    
    def __init__(self, app):
        """Initialize middleware."""
        self.app = app
    
    def __call__(self, environ, start_response):
        """Process request with tenant context."""
        # Extract tenant from request
        # This could be from:
        # - Subdomain (tenant.example.com)
        # - Header (X-Tenant-ID)
        # - JWT token
        # - Query parameter
        
        org_id = self._extract_tenant(environ)
        
        if org_id:
            set_current_tenant(org_id)
        
        try:
            return self.app(environ, start_response)
        finally:
            # Clear context after request
            from .tenant_context import clear_current_tenant
            clear_current_tenant()
    
    def _extract_tenant(self, environ) -> Optional[str]:
        """Extract tenant ID from request."""
        # Try header first
        tenant_header = environ.get('HTTP_X_TENANT_ID')
        if tenant_header:
            return tenant_header
        
        # Try subdomain
        host = environ.get('HTTP_HOST', '')
        if '.' in host:
            subdomain = host.split('.')[0]
            if subdomain and subdomain != 'www':
                return subdomain
        
        return None


def tenant_required(func: Callable) -> Callable:
    """Decorator to require tenant context."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        org_id = get_current_tenant()
        if not org_id:
            raise TenantIsolationError("Tenant context required but not set")
        return func(*args, **kwargs)
    return wrapper


def tenant_isolated(func: Callable) -> Callable:
    """Decorator to ensure tenant isolation."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        org_id = get_current_tenant()
        if not org_id:
            raise TenantIsolationError("Tenant context required for isolated operation")
        
        # Add org_id to kwargs if not present
        if 'org_id' not in kwargs:
            kwargs['org_id'] = org_id
        
        return func(*args, **kwargs)
    return wrapper


def validate_tenant_access(org_id: str, resource_org_id: str):
    """Validate that current tenant can access resource."""
    current_org_id = get_current_tenant()
    
    if not current_org_id:
        raise TenantIsolationError("No tenant context set")
    
    if current_org_id != resource_org_id:
        raise TenantIsolationError(
            f"Tenant {current_org_id} cannot access resource from tenant {resource_org_id}"
        )


class TenantFilter:
    """Filter for tenant-specific queries."""
    
    @staticmethod
    def filter_by_tenant(query, org_id_field: str = 'org_id'):
        """Add tenant filter to query."""
        org_id = get_current_tenant()
        if not org_id:
            raise TenantIsolationError("Tenant context required for query")
        
        # This would be implemented based on your ORM
        # For SQLAlchemy: query.filter(Model.org_id == org_id)
        # For Django: query.filter(org_id=org_id)
        return query
    
    @staticmethod
    def ensure_tenant_field(data: dict, org_id_field: str = 'org_id') -> dict:
        """Ensure tenant field is set in data."""
        org_id = get_current_tenant()
        if not org_id:
            raise TenantIsolationError("Tenant context required")
        
        data[org_id_field] = org_id
        return data

