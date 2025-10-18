"""
Tenant Manager

Manages organizations and tenant lifecycle.
"""

import secrets
from datetime import datetime
from typing import Dict, List, Optional
from .models import (
    Organization,
    OrganizationStatus,
    OrganizationType,
    TenantConfig
)


class TenantManager:
    """Manages tenants/organizations."""
    
    def __init__(self):
        """Initialize tenant manager."""
        self.organizations: Dict[str, Organization] = {}
        self.configs: Dict[str, TenantConfig] = {}
        self.slug_to_org: Dict[str, str] = {}  # slug -> org_id mapping
    
    def create_organization(
        self,
        name: str,
        slug: str,
        org_type: OrganizationType = OrganizationType.BUSINESS,
        primary_contact_email: Optional[str] = None,
        primary_contact_name: Optional[str] = None,
        parent_org_id: Optional[str] = None,
        settings: Optional[Dict] = None,
        branding: Optional[Dict] = None
    ) -> Organization:
        """Create a new organization."""
        # Validate slug uniqueness
        if slug in self.slug_to_org:
            raise ValueError(f"Organization slug '{slug}' already exists")
        
        org_id = f"org_{secrets.token_hex(8)}"
        
        org = Organization(
            org_id=org_id,
            name=name,
            slug=slug,
            org_type=org_type,
            status=OrganizationStatus.ACTIVE,
            primary_contact_email=primary_contact_email,
            primary_contact_name=primary_contact_name,
            parent_org_id=parent_org_id,
            settings=settings or {},
            branding=branding or {}
        )
        
        self.organizations[org_id] = org
        self.slug_to_org[slug] = org_id
        
        # Create default config
        config = TenantConfig(org_id=org_id)
        self.configs[org_id] = config
        
        return org
    
    def get_organization(self, org_id: str) -> Optional[Organization]:
        """Get organization by ID."""
        return self.organizations.get(org_id)
    
    def get_organization_by_slug(self, slug: str) -> Optional[Organization]:
        """Get organization by slug."""
        org_id = self.slug_to_org.get(slug)
        if org_id:
            return self.organizations.get(org_id)
        return None
    
    def update_organization(
        self,
        org_id: str,
        name: Optional[str] = None,
        status: Optional[OrganizationStatus] = None,
        settings: Optional[Dict] = None,
        branding: Optional[Dict] = None,
        custom_domain: Optional[str] = None
    ) -> Optional[Organization]:
        """Update organization."""
        org = self.organizations.get(org_id)
        if not org:
            return None
        
        if name:
            org.name = name
        if status:
            org.status = status
        if settings:
            org.settings.update(settings)
        if branding:
            org.branding.update(branding)
        if custom_domain is not None:
            org.custom_domain = custom_domain
        
        org.updated_at = datetime.utcnow()
        return org
    
    def delete_organization(self, org_id: str) -> bool:
        """Delete organization (soft delete by setting status)."""
        org = self.organizations.get(org_id)
        if not org:
            return False
        
        org.status = OrganizationStatus.CANCELLED
        org.updated_at = datetime.utcnow()
        return True
    
    def list_organizations(
        self,
        status: Optional[OrganizationStatus] = None,
        org_type: Optional[OrganizationType] = None,
        parent_org_id: Optional[str] = None
    ) -> List[Organization]:
        """List organizations with filters."""
        orgs = list(self.organizations.values())
        
        if status:
            orgs = [o for o in orgs if o.status == status]
        if org_type:
            orgs = [o for o in orgs if o.org_type == org_type]
        if parent_org_id is not None:
            orgs = [o for o in orgs if o.parent_org_id == parent_org_id]
        
        return orgs
    
    def get_child_organizations(self, parent_org_id: str) -> List[Organization]:
        """Get child organizations."""
        return [
            org for org in self.organizations.values()
            if org.parent_org_id == parent_org_id
        ]
    
    def get_organization_hierarchy(self, org_id: str) -> List[Organization]:
        """Get organization hierarchy (parent chain)."""
        hierarchy = []
        current_org = self.organizations.get(org_id)
        
        while current_org:
            hierarchy.append(current_org)
            if current_org.parent_org_id:
                current_org = self.organizations.get(current_org.parent_org_id)
            else:
                break
        
        return hierarchy
    
    def get_config(self, org_id: str) -> Optional[TenantConfig]:
        """Get tenant configuration."""
        return self.configs.get(org_id)
    
    def update_config(
        self,
        org_id: str,
        feature_flags: Optional[Dict[str, bool]] = None,
        api_rate_limit: Optional[int] = None,
        require_mfa: Optional[bool] = None,
        enabled_integrations: Optional[List[str]] = None,
        custom_settings: Optional[Dict] = None
    ) -> Optional[TenantConfig]:
        """Update tenant configuration."""
        config = self.configs.get(org_id)
        if not config:
            return None
        
        if feature_flags:
            config.feature_flags.update(feature_flags)
        if api_rate_limit is not None:
            config.api_rate_limit = api_rate_limit
        if require_mfa is not None:
            config.require_mfa = require_mfa
        if enabled_integrations is not None:
            config.enabled_integrations = enabled_integrations
        if custom_settings:
            config.custom_settings.update(custom_settings)
        
        return config
    
    def is_feature_enabled(self, org_id: str, feature_name: str) -> bool:
        """Check if a feature is enabled for tenant."""
        config = self.configs.get(org_id)
        if not config:
            return False
        
        return config.feature_flags.get(feature_name, False)
    
    def get_tenant_stats(self, org_id: str) -> Dict:
        """Get tenant statistics."""
        org = self.organizations.get(org_id)
        if not org:
            return {}
        
        child_orgs = self.get_child_organizations(org_id)
        
        return {
            'org_id': org_id,
            'name': org.name,
            'status': org.status.value,
            'type': org.org_type.value,
            'created_at': org.created_at.isoformat(),
            'child_organizations': len(child_orgs),
            'has_parent': org.parent_org_id is not None,
            'custom_domain': org.custom_domain,
            'has_branding': bool(org.branding)
        }
    
    def suspend_organization(self, org_id: str, reason: Optional[str] = None) -> bool:
        """Suspend an organization."""
        org = self.organizations.get(org_id)
        if not org:
            return False
        
        org.status = OrganizationStatus.SUSPENDED
        org.updated_at = datetime.utcnow()
        
        if reason:
            org.metadata['suspension_reason'] = reason
            org.metadata['suspended_at'] = datetime.utcnow().isoformat()
        
        return True
    
    def reactivate_organization(self, org_id: str) -> bool:
        """Reactivate a suspended organization."""
        org = self.organizations.get(org_id)
        if not org:
            return False
        
        if org.status == OrganizationStatus.SUSPENDED:
            org.status = OrganizationStatus.ACTIVE
            org.updated_at = datetime.utcnow()
            
            if 'suspension_reason' in org.metadata:
                org.metadata['reactivated_at'] = datetime.utcnow().isoformat()
            
            return True
        
        return False

