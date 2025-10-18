"""
Subscription Manager

Manages subscriptions and plans.
"""

import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from .models import (
    Subscription,
    SubscriptionPlan,
    SubscriptionStatus,
    Feature,
    FeatureFlag
)


# Plan definitions with features and pricing
PLAN_DEFINITIONS = {
    SubscriptionPlan.FREE: {
        'name': 'Free',
        'price_monthly': 0,
        'price_yearly': 0,
        'features': ['basic_validation', 'api_access', 'email_notifications'],
        'quotas': {
            'reports_per_month': 10,
            'api_calls_per_day': 100,
            'storage_gb': 1,
            'users': 1,
            'integrations': 1
        }
    },
    SubscriptionPlan.STARTER: {
        'name': 'Starter',
        'price_monthly': 49,
        'price_yearly': 490,
        'features': ['basic_validation', 'api_access', 'email_notifications', 'slack_integration', 'basic_analytics'],
        'quotas': {
            'reports_per_month': 100,
            'api_calls_per_day': 1000,
            'storage_gb': 10,
            'users': 5,
            'integrations': 3
        }
    },
    SubscriptionPlan.PROFESSIONAL: {
        'name': 'Professional',
        'price_monthly': 199,
        'price_yearly': 1990,
        'features': ['advanced_validation', 'api_access', 'all_integrations', 'advanced_analytics', 'priority_support'],
        'quotas': {
            'reports_per_month': 500,
            'api_calls_per_day': 10000,
            'storage_gb': 50,
            'users': 20,
            'integrations': 10
        }
    },
    SubscriptionPlan.BUSINESS: {
        'name': 'Business',
        'price_monthly': 499,
        'price_yearly': 4990,
        'features': ['advanced_validation', 'api_access', 'all_integrations', 'advanced_analytics', 'priority_support', 'custom_branding', 'sso'],
        'quotas': {
            'reports_per_month': 2000,
            'api_calls_per_day': 50000,
            'storage_gb': 200,
            'users': 100,
            'integrations': 50
        }
    },
    SubscriptionPlan.ENTERPRISE: {
        'name': 'Enterprise',
        'price_monthly': 1999,
        'price_yearly': 19990,
        'features': ['all_features', 'dedicated_support', 'custom_sla', 'on_premise_option'],
        'quotas': {
            'reports_per_month': -1,  # unlimited
            'api_calls_per_day': -1,
            'storage_gb': -1,
            'users': -1,
            'integrations': -1
        }
    }
}


class SubscriptionManager:
    """Manages subscriptions and billing."""
    
    def __init__(self):
        """Initialize subscription manager."""
        self.subscriptions: Dict[str, Subscription] = {}
        self.org_subscriptions: Dict[str, str] = {}  # org_id -> subscription_id
        self.features: Dict[str, Feature] = {}
        self.feature_flags: Dict[str, Dict[str, FeatureFlag]] = {}  # org_id -> {feature_id -> flag}
        
        self._initialize_features()
    
    def _initialize_features(self):
        """Initialize feature definitions."""
        features = [
            Feature(
                feature_id='basic_validation',
                name='Basic Validation',
                description='Basic AI-powered validation',
                available_in_plans=[SubscriptionPlan.FREE, SubscriptionPlan.STARTER, SubscriptionPlan.PROFESSIONAL, SubscriptionPlan.BUSINESS, SubscriptionPlan.ENTERPRISE]
            ),
            Feature(
                feature_id='advanced_validation',
                name='Advanced Validation',
                description='Advanced AI validation with multiple providers',
                available_in_plans=[SubscriptionPlan.PROFESSIONAL, SubscriptionPlan.BUSINESS, SubscriptionPlan.ENTERPRISE]
            ),
            Feature(
                feature_id='api_access',
                name='API Access',
                description='REST and GraphQL API access',
                available_in_plans=[SubscriptionPlan.FREE, SubscriptionPlan.STARTER, SubscriptionPlan.PROFESSIONAL, SubscriptionPlan.BUSINESS, SubscriptionPlan.ENTERPRISE]
            ),
            Feature(
                feature_id='all_integrations',
                name='All Integrations',
                description='Access to all third-party integrations',
                available_in_plans=[SubscriptionPlan.PROFESSIONAL, SubscriptionPlan.BUSINESS, SubscriptionPlan.ENTERPRISE]
            ),
            Feature(
                feature_id='custom_branding',
                name='Custom Branding',
                description='White-label customization',
                available_in_plans=[SubscriptionPlan.BUSINESS, SubscriptionPlan.ENTERPRISE]
            ),
            Feature(
                feature_id='sso',
                name='Single Sign-On',
                description='SSO with SAML/OAuth',
                available_in_plans=[SubscriptionPlan.BUSINESS, SubscriptionPlan.ENTERPRISE]
            )
        ]
        
        for feature in features:
            self.features[feature.feature_id] = feature
    
    def create_subscription(
        self,
        org_id: str,
        plan: SubscriptionPlan,
        billing_cycle: str = "monthly",
        trial_days: Optional[int] = None
    ) -> Subscription:
        """Create a new subscription."""
        subscription_id = f"sub_{secrets.token_hex(8)}"
        
        plan_def = PLAN_DEFINITIONS[plan]
        price = plan_def['price_monthly'] if billing_cycle == 'monthly' else plan_def['price_yearly']
        
        start_date = datetime.utcnow()
        trial_end_date = None
        status = SubscriptionStatus.ACTIVE
        
        if trial_days:
            trial_end_date = start_date + timedelta(days=trial_days)
            status = SubscriptionStatus.TRIAL
        
        # Calculate next billing date
        if billing_cycle == 'monthly':
            next_billing_date = start_date + timedelta(days=30)
        else:
            next_billing_date = start_date + timedelta(days=365)
        
        subscription = Subscription(
            subscription_id=subscription_id,
            org_id=org_id,
            plan=plan,
            status=status,
            billing_cycle=billing_cycle,
            start_date=start_date,
            trial_end_date=trial_end_date,
            next_billing_date=next_billing_date,
            price_per_month=price,
            features=plan_def['features']
        )
        
        self.subscriptions[subscription_id] = subscription
        self.org_subscriptions[org_id] = subscription_id
        
        # Initialize feature flags
        self._initialize_feature_flags(org_id, plan)
        
        return subscription
    
    def _initialize_feature_flags(self, org_id: str, plan: SubscriptionPlan):
        """Initialize feature flags for organization based on plan."""
        if org_id not in self.feature_flags:
            self.feature_flags[org_id] = {}
        
        for feature_id, feature in self.features.items():
            enabled = plan in feature.available_in_plans
            
            flag = FeatureFlag(
                flag_id=f"flag_{secrets.token_hex(8)}",
                org_id=org_id,
                feature_id=feature_id,
                enabled=enabled,
                enabled_at=datetime.utcnow() if enabled else None
            )
            
            self.feature_flags[org_id][feature_id] = flag
    
    def get_subscription(self, subscription_id: str) -> Optional[Subscription]:
        """Get subscription by ID."""
        return self.subscriptions.get(subscription_id)
    
    def get_organization_subscription(self, org_id: str) -> Optional[Subscription]:
        """Get active subscription for organization."""
        subscription_id = self.org_subscriptions.get(org_id)
        if subscription_id:
            return self.subscriptions.get(subscription_id)
        return None
    
    def upgrade_subscription(self, org_id: str, new_plan: SubscriptionPlan) -> Optional[Subscription]:
        """Upgrade subscription to a new plan."""
        subscription = self.get_organization_subscription(org_id)
        if not subscription:
            return None
        
        plan_def = PLAN_DEFINITIONS[new_plan]
        
        subscription.plan = new_plan
        subscription.features = plan_def['features']
        subscription.price_per_month = plan_def['price_monthly'] if subscription.billing_cycle == 'monthly' else plan_def['price_yearly']
        
        # Update feature flags
        self._initialize_feature_flags(org_id, new_plan)
        
        return subscription
    
    def cancel_subscription(self, org_id: str, immediate: bool = False) -> bool:
        """Cancel subscription."""
        subscription = self.get_organization_subscription(org_id)
        if not subscription:
            return False
        
        if immediate:
            subscription.status = SubscriptionStatus.CANCELLED
            subscription.end_date = datetime.utcnow()
        else:
            # Cancel at end of billing period
            subscription.auto_renew = False
            subscription.metadata['cancellation_scheduled'] = True
            subscription.metadata['cancellation_date'] = subscription.next_billing_date.isoformat() if subscription.next_billing_date else None
        
        return True
    
    def is_feature_available(self, org_id: str, feature_id: str) -> bool:
        """Check if feature is available for organization."""
        if org_id not in self.feature_flags:
            return False
        
        flag = self.feature_flags[org_id].get(feature_id)
        if not flag:
            return False
        
        return flag.enabled
    
    def get_plan_quotas(self, plan: SubscriptionPlan) -> Dict:
        """Get quotas for a plan."""
        plan_def = PLAN_DEFINITIONS.get(plan)
        if not plan_def:
            return {}
        
        return plan_def.get('quotas', {})
    
    def get_subscription_summary(self, org_id: str) -> Dict:
        """Get subscription summary."""
        subscription = self.get_organization_subscription(org_id)
        if not subscription:
            return {'status': 'no_subscription'}
        
        plan_def = PLAN_DEFINITIONS[subscription.plan]
        
        return {
            'subscription_id': subscription.subscription_id,
            'plan': subscription.plan.value,
            'plan_name': plan_def['name'],
            'status': subscription.status.value,
            'billing_cycle': subscription.billing_cycle,
            'price': subscription.price_per_month,
            'currency': subscription.currency,
            'next_billing_date': subscription.next_billing_date.isoformat() if subscription.next_billing_date else None,
            'trial_end_date': subscription.trial_end_date.isoformat() if subscription.trial_end_date else None,
            'features': subscription.features,
            'quotas': plan_def['quotas'],
            'auto_renew': subscription.auto_renew
        }

