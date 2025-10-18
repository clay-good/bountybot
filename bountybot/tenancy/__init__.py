"""
Multi-Tenancy & Organization Management System

Provides comprehensive multi-tenant architecture for SaaS deployments.
"""

from .models import (
    Organization,
    OrganizationStatus,
    OrganizationType,
    Subscription,
    SubscriptionPlan,
    SubscriptionStatus,
    UsageQuota,
    QuotaType,
    TenantConfig,
    BillingInfo,
    Invoice,
    InvoiceStatus,
    Feature,
    FeatureFlag
)

from .tenant_manager import TenantManager
from .subscription_manager import SubscriptionManager
from .quota_manager import QuotaManager, QuotaExceededException
from .billing_manager import BillingManager
from .tenant_context import TenantContext, get_current_tenant, set_current_tenant
from .tenant_isolation import TenantIsolationMiddleware, tenant_required
from .provisioning import TenantProvisioner

__all__ = [
    # Models
    'Organization',
    'OrganizationStatus',
    'OrganizationType',
    'Subscription',
    'SubscriptionPlan',
    'SubscriptionStatus',
    'UsageQuota',
    'QuotaType',
    'TenantConfig',
    'BillingInfo',
    'Invoice',
    'InvoiceStatus',
    'Feature',
    'FeatureFlag',
    
    # Core managers
    'TenantManager',
    'SubscriptionManager',
    'QuotaManager',
    'QuotaExceededException',
    'BillingManager',
    
    # Context management
    'TenantContext',
    'get_current_tenant',
    'set_current_tenant',
    
    # Isolation
    'TenantIsolationMiddleware',
    'tenant_required',
    
    # Provisioning
    'TenantProvisioner'
]

