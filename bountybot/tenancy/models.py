"""
Multi-Tenancy Data Models
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
import secrets


class OrganizationStatus(str, Enum):
    """Organization status."""
    ACTIVE = "active"
    SUSPENDED = "suspended"
    TRIAL = "trial"
    PENDING = "pending"
    CANCELLED = "cancelled"


class OrganizationType(str, Enum):
    """Organization type."""
    ENTERPRISE = "enterprise"
    BUSINESS = "business"
    STARTUP = "startup"
    INDIVIDUAL = "individual"
    NON_PROFIT = "non_profit"


class SubscriptionPlan(str, Enum):
    """Subscription plans."""
    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    BUSINESS = "business"
    ENTERPRISE = "enterprise"


class SubscriptionStatus(str, Enum):
    """Subscription status."""
    ACTIVE = "active"
    TRIAL = "trial"
    PAST_DUE = "past_due"
    CANCELLED = "cancelled"
    EXPIRED = "expired"


class QuotaType(str, Enum):
    """Usage quota types."""
    REPORTS_PER_MONTH = "reports_per_month"
    API_CALLS_PER_DAY = "api_calls_per_day"
    STORAGE_GB = "storage_gb"
    USERS = "users"
    INTEGRATIONS = "integrations"
    WEBHOOKS = "webhooks"
    SCANS_PER_MONTH = "scans_per_month"
    AI_VALIDATIONS_PER_MONTH = "ai_validations_per_month"


class InvoiceStatus(str, Enum):
    """Invoice status."""
    DRAFT = "draft"
    PENDING = "pending"
    PAID = "paid"
    OVERDUE = "overdue"
    CANCELLED = "cancelled"


@dataclass
class Organization:
    """Organization/Tenant entity."""
    org_id: str
    name: str
    slug: str  # URL-friendly identifier
    
    # Organization details
    status: OrganizationStatus = OrganizationStatus.ACTIVE
    org_type: OrganizationType = OrganizationType.BUSINESS
    
    # Hierarchy
    parent_org_id: Optional[str] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    # Contact info
    primary_contact_email: Optional[str] = None
    primary_contact_name: Optional[str] = None
    
    # Settings
    settings: Dict[str, Any] = field(default_factory=dict)
    
    # White-label customization
    branding: Dict[str, Any] = field(default_factory=dict)  # logo, colors, etc.
    custom_domain: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Subscription:
    """Subscription for an organization."""
    subscription_id: str
    org_id: str
    plan: SubscriptionPlan
    status: SubscriptionStatus = SubscriptionStatus.ACTIVE
    
    # Billing cycle
    billing_cycle: str = "monthly"  # monthly, yearly
    
    # Dates
    start_date: datetime = field(default_factory=datetime.utcnow)
    end_date: Optional[datetime] = None
    trial_end_date: Optional[datetime] = None
    next_billing_date: Optional[datetime] = None
    
    # Pricing
    price_per_month: float = 0.0
    currency: str = "USD"
    
    # Features
    features: List[str] = field(default_factory=list)
    
    # Auto-renewal
    auto_renew: bool = True
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class UsageQuota:
    """Usage quota for a tenant."""
    quota_id: str
    org_id: str
    quota_type: QuotaType
    
    # Limits
    limit: int  # Maximum allowed
    used: int = 0  # Current usage
    
    # Period
    period: str = "monthly"  # daily, monthly, yearly, lifetime
    period_start: datetime = field(default_factory=datetime.utcnow)
    period_end: Optional[datetime] = None
    
    # Soft limit (warning threshold)
    soft_limit: Optional[int] = None
    soft_limit_reached: bool = False
    
    # Hard limit reached
    hard_limit_reached: bool = False
    
    def get_remaining(self) -> int:
        """Get remaining quota."""
        return max(0, self.limit - self.used)
    
    def get_usage_percentage(self) -> float:
        """Get usage percentage."""
        if self.limit == 0:
            return 0.0
        return (self.used / self.limit) * 100
    
    def is_exceeded(self) -> bool:
        """Check if quota is exceeded."""
        return self.used >= self.limit


@dataclass
class TenantConfig:
    """Tenant-specific configuration."""
    org_id: str
    
    # Feature flags
    feature_flags: Dict[str, bool] = field(default_factory=dict)
    
    # API configuration
    api_rate_limit: int = 1000  # requests per hour
    api_burst_limit: int = 100  # burst requests
    
    # Storage configuration
    storage_backend: str = "s3"
    storage_region: str = "us-east-1"
    
    # Security settings
    require_mfa: bool = False
    allowed_ip_ranges: List[str] = field(default_factory=list)
    session_timeout_minutes: int = 60
    
    # Integration settings
    enabled_integrations: List[str] = field(default_factory=list)
    
    # Notification settings
    notification_channels: List[str] = field(default_factory=list)
    
    # Custom settings
    custom_settings: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BillingInfo:
    """Billing information for an organization."""
    org_id: str
    
    # Payment method
    payment_method: str = "credit_card"  # credit_card, invoice, wire_transfer
    
    # Billing address
    billing_email: str = ""
    billing_name: str = ""
    billing_address: str = ""
    billing_city: str = ""
    billing_state: str = ""
    billing_zip: str = ""
    billing_country: str = ""
    
    # Tax info
    tax_id: Optional[str] = None
    tax_exempt: bool = False
    
    # Payment details (encrypted)
    payment_details: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Invoice:
    """Invoice for a subscription."""
    invoice_id: str
    org_id: str
    subscription_id: str
    
    # Invoice details
    invoice_number: str
    status: InvoiceStatus = InvoiceStatus.DRAFT
    
    # Dates
    issue_date: datetime = field(default_factory=datetime.utcnow)
    due_date: Optional[datetime] = None
    paid_date: Optional[datetime] = None
    
    # Amounts
    subtotal: float = 0.0
    tax: float = 0.0
    total: float = 0.0
    currency: str = "USD"
    
    # Line items
    line_items: List[Dict[str, Any]] = field(default_factory=list)
    
    # Payment
    payment_method: Optional[str] = None
    payment_reference: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Feature:
    """Feature definition."""
    feature_id: str
    name: str
    description: str
    
    # Availability
    available_in_plans: List[SubscriptionPlan] = field(default_factory=list)
    
    # Default state
    default_enabled: bool = True
    
    # Dependencies
    depends_on: List[str] = field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeatureFlag:
    """Feature flag for a tenant."""
    flag_id: str
    org_id: str
    feature_id: str
    
    # State
    enabled: bool = False
    
    # Rollout
    rollout_percentage: int = 100  # 0-100
    
    # Dates
    enabled_at: Optional[datetime] = None
    disabled_at: Optional[datetime] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

