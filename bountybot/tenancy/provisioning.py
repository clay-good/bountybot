"""
Tenant Provisioning

Automated tenant provisioning and onboarding.
"""

import secrets
from datetime import datetime
from typing import Dict, List, Optional
from .models import (
    Organization,
    OrganizationType,
    SubscriptionPlan,
    QuotaType
)
from .tenant_manager import TenantManager
from .subscription_manager import SubscriptionManager
from .quota_manager import QuotaManager
from .billing_manager import BillingManager


class ProvisioningError(Exception):
    """Raised when provisioning fails."""
    pass


class TenantProvisioner:
    """Provisions new tenants with all required resources."""
    
    def __init__(
        self,
        tenant_manager: TenantManager,
        subscription_manager: SubscriptionManager,
        quota_manager: QuotaManager,
        billing_manager: BillingManager
    ):
        """Initialize provisioner."""
        self.tenant_manager = tenant_manager
        self.subscription_manager = subscription_manager
        self.quota_manager = quota_manager
        self.billing_manager = billing_manager
        
        self.provisioning_log: List[Dict] = []
    
    def provision_tenant(
        self,
        name: str,
        slug: str,
        plan: SubscriptionPlan = SubscriptionPlan.FREE,
        org_type: OrganizationType = OrganizationType.BUSINESS,
        primary_contact_email: Optional[str] = None,
        primary_contact_name: Optional[str] = None,
        billing_email: Optional[str] = None,
        trial_days: Optional[int] = None,
        custom_settings: Optional[Dict] = None
    ) -> Dict:
        """Provision a new tenant with all resources."""
        provisioning_id = f"prov_{secrets.token_hex(8)}"
        start_time = datetime.utcnow()
        
        log_entry = {
            'provisioning_id': provisioning_id,
            'name': name,
            'slug': slug,
            'plan': plan.value,
            'start_time': start_time.isoformat(),
            'steps': []
        }
        
        try:
            # Step 1: Create organization
            log_entry['steps'].append({'step': 'create_organization', 'status': 'started'})
            org = self.tenant_manager.create_organization(
                name=name,
                slug=slug,
                org_type=org_type,
                primary_contact_email=primary_contact_email,
                primary_contact_name=primary_contact_name,
                settings=custom_settings or {}
            )
            log_entry['steps'][-1]['status'] = 'completed'
            log_entry['steps'][-1]['org_id'] = org.org_id
            
            # Step 2: Create subscription
            log_entry['steps'].append({'step': 'create_subscription', 'status': 'started'})
            subscription = self.subscription_manager.create_subscription(
                org_id=org.org_id,
                plan=plan,
                trial_days=trial_days
            )
            log_entry['steps'][-1]['status'] = 'completed'
            log_entry['steps'][-1]['subscription_id'] = subscription.subscription_id
            
            # Step 3: Initialize quotas
            log_entry['steps'].append({'step': 'initialize_quotas', 'status': 'started'})
            self.quota_manager.initialize_quotas(org.org_id, plan)
            log_entry['steps'][-1]['status'] = 'completed'
            
            # Step 4: Set up billing (if not free plan)
            if plan != SubscriptionPlan.FREE and billing_email:
                log_entry['steps'].append({'step': 'setup_billing', 'status': 'started'})
                self.billing_manager.set_billing_info(
                    org_id=org.org_id,
                    billing_email=billing_email,
                    billing_name=primary_contact_name or name
                )
                log_entry['steps'][-1]['status'] = 'completed'
            
            # Step 5: Create initial resources (databases, storage, etc.)
            log_entry['steps'].append({'step': 'create_resources', 'status': 'started'})
            self._create_tenant_resources(org.org_id)
            log_entry['steps'][-1]['status'] = 'completed'
            
            # Step 6: Send welcome email
            log_entry['steps'].append({'step': 'send_welcome_email', 'status': 'started'})
            self._send_welcome_email(org, primary_contact_email)
            log_entry['steps'][-1]['status'] = 'completed'
            
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            log_entry['status'] = 'success'
            log_entry['end_time'] = end_time.isoformat()
            log_entry['duration_seconds'] = duration
            
            self.provisioning_log.append(log_entry)
            
            return {
                'success': True,
                'provisioning_id': provisioning_id,
                'org_id': org.org_id,
                'subscription_id': subscription.subscription_id,
                'duration_seconds': duration,
                'message': f'Tenant {name} provisioned successfully'
            }
            
        except Exception as e:
            log_entry['status'] = 'failed'
            log_entry['error'] = str(e)
            log_entry['end_time'] = datetime.utcnow().isoformat()
            
            self.provisioning_log.append(log_entry)
            
            # Rollback if possible
            self._rollback_provisioning(log_entry)
            
            raise ProvisioningError(f"Failed to provision tenant: {e}")
    
    def _create_tenant_resources(self, org_id: str):
        """Create tenant-specific resources."""
        # This would create:
        # - Database schema/tables
        # - Storage buckets
        # - API keys
        # - Default configurations
        # - Initial data
        pass
    
    def _send_welcome_email(self, org: Organization, email: Optional[str]):
        """Send welcome email to new tenant."""
        if not email:
            return
        
        # This would send an actual email
        # For now, just log it
        pass
    
    def _rollback_provisioning(self, log_entry: Dict):
        """Rollback failed provisioning."""
        # Rollback in reverse order
        for step in reversed(log_entry.get('steps', [])):
            if step.get('status') == 'completed':
                try:
                    if step['step'] == 'create_organization':
                        org_id = step.get('org_id')
                        if org_id:
                            self.tenant_manager.delete_organization(org_id)
                    # Add more rollback logic as needed
                except Exception:
                    pass  # Best effort rollback
    
    def deprovision_tenant(self, org_id: str, delete_data: bool = False) -> Dict:
        """Deprovision a tenant."""
        provisioning_id = f"deprov_{secrets.token_hex(8)}"
        start_time = datetime.utcnow()
        
        try:
            # Cancel subscription
            self.subscription_manager.cancel_subscription(org_id, immediate=True)
            
            # Delete organization (soft delete)
            self.tenant_manager.delete_organization(org_id)
            
            # Optionally delete all data
            if delete_data:
                self._delete_tenant_data(org_id)
            
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            return {
                'success': True,
                'provisioning_id': provisioning_id,
                'org_id': org_id,
                'duration_seconds': duration,
                'data_deleted': delete_data,
                'message': f'Tenant {org_id} deprovisioned successfully'
            }
            
        except Exception as e:
            raise ProvisioningError(f"Failed to deprovision tenant: {e}")
    
    def _delete_tenant_data(self, org_id: str):
        """Delete all tenant data."""
        # This would delete:
        # - Database records
        # - Storage files
        # - Cached data
        # - Logs
        pass
    
    def get_provisioning_status(self, provisioning_id: str) -> Optional[Dict]:
        """Get provisioning status."""
        for log in self.provisioning_log:
            if log['provisioning_id'] == provisioning_id:
                return log
        return None
    
    def list_provisioning_logs(self, limit: int = 100) -> List[Dict]:
        """List recent provisioning logs."""
        return self.provisioning_log[-limit:]

