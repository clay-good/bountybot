"""
Quota Manager

Manages usage quotas and rate limiting per tenant.
"""

import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from .models import UsageQuota, QuotaType, SubscriptionPlan
from .subscription_manager import PLAN_DEFINITIONS


class QuotaExceededException(Exception):
    """Raised when quota is exceeded."""
    pass


class QuotaManager:
    """Manages usage quotas for tenants."""
    
    def __init__(self):
        """Initialize quota manager."""
        self.quotas: Dict[str, Dict[QuotaType, UsageQuota]] = {}  # org_id -> {quota_type -> quota}
    
    def initialize_quotas(self, org_id: str, plan: SubscriptionPlan):
        """Initialize quotas for an organization based on plan."""
        plan_def = PLAN_DEFINITIONS.get(plan)
        if not plan_def:
            return
        
        quotas_def = plan_def.get('quotas', {})
        
        if org_id not in self.quotas:
            self.quotas[org_id] = {}
        
        # Create quota for each type
        for quota_name, limit in quotas_def.items():
            try:
                quota_type = QuotaType(quota_name)
            except ValueError:
                continue
            
            # Determine period based on quota type
            if 'per_month' in quota_name:
                period = 'monthly'
                period_end = datetime.utcnow() + timedelta(days=30)
            elif 'per_day' in quota_name:
                period = 'daily'
                period_end = datetime.utcnow() + timedelta(days=1)
            else:
                period = 'lifetime'
                period_end = None
            
            # Set soft limit at 80% of hard limit
            soft_limit = int(limit * 0.8) if limit > 0 else None
            
            quota = UsageQuota(
                quota_id=f"quota_{secrets.token_hex(8)}",
                org_id=org_id,
                quota_type=quota_type,
                limit=limit,
                used=0,
                period=period,
                period_end=period_end,
                soft_limit=soft_limit
            )
            
            self.quotas[org_id][quota_type] = quota
    
    def get_quota(self, org_id: str, quota_type: QuotaType) -> Optional[UsageQuota]:
        """Get quota for organization."""
        if org_id not in self.quotas:
            return None
        
        return self.quotas[org_id].get(quota_type)
    
    def check_quota(self, org_id: str, quota_type: QuotaType, amount: int = 1) -> bool:
        """Check if quota allows the operation."""
        quota = self.get_quota(org_id, quota_type)
        if not quota:
            return True  # No quota defined, allow
        
        # Check if period has expired and reset if needed
        self._check_and_reset_period(quota)
        
        # Unlimited quota
        if quota.limit < 0:
            return True
        
        # Check if adding amount would exceed limit
        return (quota.used + amount) <= quota.limit
    
    def consume_quota(
        self,
        org_id: str,
        quota_type: QuotaType,
        amount: int = 1,
        raise_on_exceeded: bool = True
    ) -> bool:
        """Consume quota."""
        quota = self.get_quota(org_id, quota_type)
        if not quota:
            return True  # No quota defined, allow
        
        # Check if period has expired and reset if needed
        self._check_and_reset_period(quota)
        
        # Unlimited quota
        if quota.limit < 0:
            quota.used += amount
            return True
        
        # Check if quota would be exceeded
        if (quota.used + amount) > quota.limit:
            quota.hard_limit_reached = True
            if raise_on_exceeded:
                raise QuotaExceededException(
                    f"Quota exceeded for {quota_type.value}: {quota.used}/{quota.limit}"
                )
            return False
        
        # Consume quota
        quota.used += amount
        
        # Check soft limit
        if quota.soft_limit and quota.used >= quota.soft_limit:
            quota.soft_limit_reached = True
        
        return True
    
    def _check_and_reset_period(self, quota: UsageQuota):
        """Check if quota period has expired and reset if needed."""
        if not quota.period_end:
            return  # Lifetime quota, no reset
        
        now = datetime.utcnow()
        if now >= quota.period_end:
            # Reset quota
            quota.used = 0
            quota.soft_limit_reached = False
            quota.hard_limit_reached = False
            quota.period_start = now
            
            # Set new period end
            if quota.period == 'daily':
                quota.period_end = now + timedelta(days=1)
            elif quota.period == 'monthly':
                quota.period_end = now + timedelta(days=30)
    
    def get_usage_summary(self, org_id: str) -> Dict:
        """Get usage summary for organization."""
        if org_id not in self.quotas:
            return {}
        
        summary = {}
        for quota_type, quota in self.quotas[org_id].items():
            self._check_and_reset_period(quota)
            
            summary[quota_type.value] = {
                'limit': quota.limit,
                'used': quota.used,
                'remaining': quota.get_remaining(),
                'usage_percentage': quota.get_usage_percentage(),
                'soft_limit_reached': quota.soft_limit_reached,
                'hard_limit_reached': quota.hard_limit_reached,
                'period': quota.period,
                'period_end': quota.period_end.isoformat() if quota.period_end else None
            }
        
        return summary
    
    def reset_quota(self, org_id: str, quota_type: QuotaType):
        """Manually reset a quota."""
        quota = self.get_quota(org_id, quota_type)
        if quota:
            quota.used = 0
            quota.soft_limit_reached = False
            quota.hard_limit_reached = False
            quota.period_start = datetime.utcnow()
            
            if quota.period == 'daily':
                quota.period_end = datetime.utcnow() + timedelta(days=1)
            elif quota.period == 'monthly':
                quota.period_end = datetime.utcnow() + timedelta(days=30)
    
    def update_quota_limit(self, org_id: str, quota_type: QuotaType, new_limit: int) -> bool:
        """Update quota limit."""
        quota = self.get_quota(org_id, quota_type)
        if not quota:
            return False
        
        quota.limit = new_limit
        
        # Update soft limit
        if new_limit > 0:
            quota.soft_limit = int(new_limit * 0.8)
        else:
            quota.soft_limit = None
        
        # Reset flags if new limit is higher
        if new_limit < 0 or quota.used < new_limit:
            quota.hard_limit_reached = False
        
        if quota.soft_limit and quota.used < quota.soft_limit:
            quota.soft_limit_reached = False
        
        return True
    
    def get_quota_alerts(self, org_id: str) -> List[Dict]:
        """Get quota alerts for organization."""
        if org_id not in self.quotas:
            return []
        
        alerts = []
        for quota_type, quota in self.quotas[org_id].items():
            self._check_and_reset_period(quota)
            
            if quota.hard_limit_reached:
                alerts.append({
                    'severity': 'critical',
                    'quota_type': quota_type.value,
                    'message': f'Hard limit reached for {quota_type.value}',
                    'usage': quota.used,
                    'limit': quota.limit
                })
            elif quota.soft_limit_reached:
                alerts.append({
                    'severity': 'warning',
                    'quota_type': quota_type.value,
                    'message': f'Soft limit reached for {quota_type.value}',
                    'usage': quota.used,
                    'limit': quota.limit,
                    'soft_limit': quota.soft_limit
                })
        
        return alerts
    
    def get_all_quotas(self, org_id: str) -> List[UsageQuota]:
        """Get all quotas for organization."""
        if org_id not in self.quotas:
            return []
        
        quotas = list(self.quotas[org_id].values())
        
        # Reset expired periods
        for quota in quotas:
            self._check_and_reset_period(quota)
        
        return quotas
    
    def bulk_consume(self, org_id: str, consumptions: Dict[QuotaType, int]) -> Dict[QuotaType, bool]:
        """Consume multiple quotas at once."""
        results = {}
        
        for quota_type, amount in consumptions.items():
            try:
                success = self.consume_quota(org_id, quota_type, amount, raise_on_exceeded=False)
                results[quota_type] = success
            except Exception:
                results[quota_type] = False
        
        return results

