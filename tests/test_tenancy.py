"""
Tests for Multi-Tenancy & Organization Management
"""

import unittest
from datetime import datetime, timedelta
from bountybot.tenancy import (
    TenantManager,
    SubscriptionManager,
    QuotaManager,
    BillingManager,
    TenantProvisioner,
    TenantContext,
    get_current_tenant,
    set_current_tenant,
    tenant_required,
    OrganizationType,
    OrganizationStatus,
    SubscriptionPlan,
    SubscriptionStatus,
    QuotaType,
    InvoiceStatus,
    QuotaExceededException
)


class TestTenantManager(unittest.TestCase):
    """Test tenant manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = TenantManager()
    
    def test_create_organization(self):
        """Test creating organization."""
        org = self.manager.create_organization(
            name='Test Corp',
            slug='test-corp',
            org_type=OrganizationType.BUSINESS,
            primary_contact_email='admin@test.com'
        )
        
        self.assertIsNotNone(org.org_id)
        self.assertEqual(org.name, 'Test Corp')
        self.assertEqual(org.slug, 'test-corp')
        self.assertEqual(org.status, OrganizationStatus.ACTIVE)
    
    def test_get_organization_by_slug(self):
        """Test getting organization by slug."""
        org = self.manager.create_organization(
            name='Test Corp',
            slug='test-corp'
        )
        
        retrieved = self.manager.get_organization_by_slug('test-corp')
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.org_id, org.org_id)
    
    def test_organization_hierarchy(self):
        """Test organization hierarchy."""
        parent = self.manager.create_organization(
            name='Parent Corp',
            slug='parent-corp'
        )
        
        child = self.manager.create_organization(
            name='Child Corp',
            slug='child-corp',
            parent_org_id=parent.org_id
        )
        
        children = self.manager.get_child_organizations(parent.org_id)
        self.assertEqual(len(children), 1)
        self.assertEqual(children[0].org_id, child.org_id)
    
    def test_suspend_organization(self):
        """Test suspending organization."""
        org = self.manager.create_organization(
            name='Test Corp',
            slug='test-corp'
        )
        
        success = self.manager.suspend_organization(org.org_id, reason='Payment overdue')
        self.assertTrue(success)
        
        retrieved = self.manager.get_organization(org.org_id)
        self.assertEqual(retrieved.status, OrganizationStatus.SUSPENDED)


class TestSubscriptionManager(unittest.TestCase):
    """Test subscription manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = SubscriptionManager()
    
    def test_create_subscription(self):
        """Test creating subscription."""
        subscription = self.manager.create_subscription(
            org_id='org_123',
            plan=SubscriptionPlan.PROFESSIONAL,
            billing_cycle='monthly'
        )
        
        self.assertIsNotNone(subscription.subscription_id)
        self.assertEqual(subscription.plan, SubscriptionPlan.PROFESSIONAL)
        self.assertEqual(subscription.status, SubscriptionStatus.ACTIVE)
        self.assertGreater(subscription.price_per_month, 0)
    
    def test_create_trial_subscription(self):
        """Test creating trial subscription."""
        subscription = self.manager.create_subscription(
            org_id='org_123',
            plan=SubscriptionPlan.BUSINESS,
            trial_days=14
        )
        
        self.assertEqual(subscription.status, SubscriptionStatus.TRIAL)
        self.assertIsNotNone(subscription.trial_end_date)
    
    def test_upgrade_subscription(self):
        """Test upgrading subscription."""
        subscription = self.manager.create_subscription(
            org_id='org_123',
            plan=SubscriptionPlan.STARTER
        )
        
        upgraded = self.manager.upgrade_subscription('org_123', SubscriptionPlan.PROFESSIONAL)
        self.assertIsNotNone(upgraded)
        self.assertEqual(upgraded.plan, SubscriptionPlan.PROFESSIONAL)
    
    def test_feature_availability(self):
        """Test feature availability."""
        self.manager.create_subscription(
            org_id='org_123',
            plan=SubscriptionPlan.BUSINESS
        )
        
        # Business plan should have custom_branding
        has_branding = self.manager.is_feature_available('org_123', 'custom_branding')
        self.assertTrue(has_branding)
        
        # But not available in starter
        self.manager.create_subscription(
            org_id='org_456',
            plan=SubscriptionPlan.STARTER
        )
        has_branding = self.manager.is_feature_available('org_456', 'custom_branding')
        self.assertFalse(has_branding)


class TestQuotaManager(unittest.TestCase):
    """Test quota manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = QuotaManager()
    
    def test_initialize_quotas(self):
        """Test initializing quotas."""
        self.manager.initialize_quotas('org_123', SubscriptionPlan.PROFESSIONAL)
        
        quota = self.manager.get_quota('org_123', QuotaType.REPORTS_PER_MONTH)
        self.assertIsNotNone(quota)
        self.assertEqual(quota.limit, 500)
    
    def test_consume_quota(self):
        """Test consuming quota."""
        self.manager.initialize_quotas('org_123', SubscriptionPlan.STARTER)
        
        # Consume some quota
        success = self.manager.consume_quota('org_123', QuotaType.REPORTS_PER_MONTH, 10)
        self.assertTrue(success)
        
        quota = self.manager.get_quota('org_123', QuotaType.REPORTS_PER_MONTH)
        self.assertEqual(quota.used, 10)
    
    def test_quota_exceeded(self):
        """Test quota exceeded."""
        self.manager.initialize_quotas('org_123', SubscriptionPlan.FREE)
        
        # Free plan has 10 reports per month
        # Try to consume 15
        with self.assertRaises(QuotaExceededException):
            self.manager.consume_quota('org_123', QuotaType.REPORTS_PER_MONTH, 15)
    
    def test_soft_limit_warning(self):
        """Test soft limit warning."""
        self.manager.initialize_quotas('org_123', SubscriptionPlan.FREE)
        
        # Consume 9 out of 10 (90%, above 80% soft limit)
        self.manager.consume_quota('org_123', QuotaType.REPORTS_PER_MONTH, 9)
        
        quota = self.manager.get_quota('org_123', QuotaType.REPORTS_PER_MONTH)
        self.assertTrue(quota.soft_limit_reached)
    
    def test_unlimited_quota(self):
        """Test unlimited quota."""
        self.manager.initialize_quotas('org_123', SubscriptionPlan.ENTERPRISE)
        
        # Enterprise has unlimited quotas (-1)
        quota = self.manager.get_quota('org_123', QuotaType.REPORTS_PER_MONTH)
        self.assertEqual(quota.limit, -1)
        
        # Should be able to consume any amount
        success = self.manager.consume_quota('org_123', QuotaType.REPORTS_PER_MONTH, 10000)
        self.assertTrue(success)


class TestBillingManager(unittest.TestCase):
    """Test billing manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = BillingManager()
    
    def test_set_billing_info(self):
        """Test setting billing info."""
        billing_info = self.manager.set_billing_info(
            org_id='org_123',
            billing_email='billing@test.com',
            billing_name='Test Corp',
            billing_country='US'
        )
        
        self.assertEqual(billing_info.billing_email, 'billing@test.com')
        self.assertEqual(billing_info.billing_country, 'US')
    
    def test_create_invoice(self):
        """Test creating invoice."""
        line_items = [
            {'description': 'Professional Plan', 'quantity': 1, 'unit_price': 199, 'amount': 199}
        ]
        
        invoice = self.manager.create_invoice(
            org_id='org_123',
            subscription_id='sub_123',
            line_items=line_items
        )
        
        self.assertIsNotNone(invoice.invoice_id)
        self.assertEqual(invoice.status, InvoiceStatus.PENDING)
        self.assertEqual(invoice.subtotal, 199)
        self.assertGreater(invoice.total, invoice.subtotal)  # Tax added
    
    def test_mark_invoice_paid(self):
        """Test marking invoice as paid."""
        line_items = [{'description': 'Test', 'amount': 100}]
        invoice = self.manager.create_invoice('org_123', 'sub_123', line_items)
        
        success = self.manager.mark_invoice_paid(
            invoice.invoice_id,
            payment_method='credit_card',
            payment_reference='ch_123'
        )
        
        self.assertTrue(success)
        
        retrieved = self.manager.get_invoice(invoice.invoice_id)
        self.assertEqual(retrieved.status, InvoiceStatus.PAID)
        self.assertIsNotNone(retrieved.paid_date)


class TestTenantContext(unittest.TestCase):
    """Test tenant context."""
    
    def test_tenant_context_manager(self):
        """Test tenant context manager."""
        with TenantContext('org_123', 'user_456'):
            self.assertEqual(get_current_tenant(), 'org_123')
        
        # Context should be cleared after exiting
        self.assertIsNone(get_current_tenant())
    
    def test_set_current_tenant(self):
        """Test setting current tenant."""
        set_current_tenant('org_123')
        self.assertEqual(get_current_tenant(), 'org_123')
    
    def test_tenant_required_decorator(self):
        """Test tenant required decorator."""
        @tenant_required
        def protected_function():
            return "success"
        
        # Should raise error without tenant context
        with self.assertRaises(Exception):
            protected_function()
        
        # Should work with tenant context
        set_current_tenant('org_123')
        result = protected_function()
        self.assertEqual(result, "success")


class TestTenantProvisioner(unittest.TestCase):
    """Test tenant provisioner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.tenant_manager = TenantManager()
        self.subscription_manager = SubscriptionManager()
        self.quota_manager = QuotaManager()
        self.billing_manager = BillingManager()
        
        self.provisioner = TenantProvisioner(
            self.tenant_manager,
            self.subscription_manager,
            self.quota_manager,
            self.billing_manager
        )
    
    def test_provision_tenant(self):
        """Test provisioning tenant."""
        result = self.provisioner.provision_tenant(
            name='Test Corp',
            slug='test-corp',
            plan=SubscriptionPlan.PROFESSIONAL,
            primary_contact_email='admin@test.com',
            billing_email='billing@test.com'
        )
        
        self.assertTrue(result['success'])
        self.assertIn('org_id', result)
        self.assertIn('subscription_id', result)
        
        # Verify organization was created
        org = self.tenant_manager.get_organization(result['org_id'])
        self.assertIsNotNone(org)
        
        # Verify subscription was created
        subscription = self.subscription_manager.get_organization_subscription(result['org_id'])
        self.assertIsNotNone(subscription)
        
        # Verify quotas were initialized
        quota = self.quota_manager.get_quota(result['org_id'], QuotaType.REPORTS_PER_MONTH)
        self.assertIsNotNone(quota)


if __name__ == '__main__':
    unittest.main()

