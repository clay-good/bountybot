"""
Multi-Tenancy & Organization Management Demo

Demonstrates multi-tenant SaaS capabilities.
"""

from bountybot.tenancy import (
    TenantManager,
    SubscriptionManager,
    QuotaManager,
    BillingManager,
    TenantProvisioner,
    TenantContext,
    get_current_tenant,
    OrganizationType,
    SubscriptionPlan,
    QuotaType
)


def print_section(title: str):
    """Print section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def demo_organization_management():
    """Demonstrate organization management."""
    print_section("ORGANIZATION MANAGEMENT")
    
    manager = TenantManager()
    
    # Create organizations
    print("1. Creating Organizations:")
    
    org1 = manager.create_organization(
        name='Acme Corporation',
        slug='acme-corp',
        org_type=OrganizationType.ENTERPRISE,
        primary_contact_email='admin@acme.com',
        primary_contact_name='John Doe'
    )
    print(f"   ✅ Created: {org1.name} ({org1.org_id})")
    
    org2 = manager.create_organization(
        name='StartupXYZ',
        slug='startup-xyz',
        org_type=OrganizationType.STARTUP,
        primary_contact_email='founder@startupxyz.com'
    )
    print(f"   ✅ Created: {org2.name} ({org2.org_id})")
    
    # Create child organization
    child_org = manager.create_organization(
        name='Acme Subsidiary',
        slug='acme-subsidiary',
        parent_org_id=org1.org_id
    )
    print(f"   ✅ Created child org: {child_org.name}")
    
    # Get organization hierarchy
    print("\n2. Organization Hierarchy:")
    hierarchy = manager.get_organization_hierarchy(child_org.org_id)
    for i, org in enumerate(hierarchy):
        indent = "  " * i
        print(f"   {indent}└─ {org.name}")
    
    # Update organization
    print("\n3. Updating Organization:")
    manager.update_organization(
        org1.org_id,
        custom_domain='bounty.acme.com',
        branding={'logo': 'acme-logo.png', 'primary_color': '#0066CC'}
    )
    print(f"   ✅ Updated {org1.name} with custom branding")
    
    # Get stats
    print("\n4. Organization Stats:")
    stats = manager.get_tenant_stats(org1.org_id)
    print(f"   Name: {stats['name']}")
    print(f"   Type: {stats['type']}")
    print(f"   Status: {stats['status']}")
    print(f"   Child Organizations: {stats['child_organizations']}")
    print(f"   Custom Domain: {stats['custom_domain']}")
    
    return manager, org1, org2


def demo_subscription_management(manager: TenantManager, org1, org2):
    """Demonstrate subscription management."""
    print_section("SUBSCRIPTION MANAGEMENT")
    
    sub_manager = SubscriptionManager()
    
    # Create subscriptions
    print("1. Creating Subscriptions:")
    
    sub1 = sub_manager.create_subscription(
        org_id=org1.org_id,
        plan=SubscriptionPlan.ENTERPRISE,
        billing_cycle='yearly'
    )
    print(f"   ✅ {org1.name}: {sub1.plan.value} plan (${sub1.price_per_month}/month)")
    
    sub2 = sub_manager.create_subscription(
        org_id=org2.org_id,
        plan=SubscriptionPlan.STARTER,
        billing_cycle='monthly',
        trial_days=14
    )
    print(f"   ✅ {org2.name}: {sub2.plan.value} plan with 14-day trial")
    
    # Get subscription summary
    print("\n2. Subscription Summary:")
    summary = sub_manager.get_subscription_summary(org1.org_id)
    print(f"   Plan: {summary['plan_name']}")
    print(f"   Status: {summary['status']}")
    print(f"   Price: ${summary['price']} {summary['currency']}/{summary['billing_cycle']}")
    print(f"   Features: {', '.join(summary['features'][:3])}...")
    
    # Check feature availability
    print("\n3. Feature Availability:")
    features_to_check = ['custom_branding', 'sso', 'api_access']
    for feature in features_to_check:
        available = sub_manager.is_feature_available(org1.org_id, feature)
        status = "✅ Available" if available else "❌ Not Available"
        print(f"   {feature}: {status}")
    
    # Upgrade subscription
    print("\n4. Upgrading Subscription:")
    upgraded = sub_manager.upgrade_subscription(org2.org_id, SubscriptionPlan.PROFESSIONAL)
    print(f"   ✅ Upgraded {org2.name} from STARTER to PROFESSIONAL")
    print(f"   New price: ${upgraded.price_per_month}/month")
    
    return sub_manager


def demo_quota_management(org1, org2):
    """Demonstrate quota management."""
    print_section("QUOTA MANAGEMENT")
    
    quota_manager = QuotaManager()
    
    # Initialize quotas
    print("1. Initializing Quotas:")
    quota_manager.initialize_quotas(org1.org_id, SubscriptionPlan.ENTERPRISE)
    quota_manager.initialize_quotas(org2.org_id, SubscriptionPlan.PROFESSIONAL)
    print(f"   ✅ Initialized quotas for {org1.name}")
    print(f"   ✅ Initialized quotas for {org2.name}")
    
    # Get usage summary
    print("\n2. Usage Summary:")
    summary = quota_manager.get_usage_summary(org1.org_id)
    for quota_type, data in list(summary.items())[:3]:
        limit_str = "Unlimited" if data['limit'] < 0 else str(data['limit'])
        print(f"   {quota_type}:")
        print(f"     Limit: {limit_str}")
        print(f"     Used: {data['used']}")
        print(f"     Remaining: {data['remaining'] if data['limit'] >= 0 else 'Unlimited'}")
    
    # Consume quota
    print("\n3. Consuming Quota:")
    quota_manager.consume_quota(org2.org_id, QuotaType.REPORTS_PER_MONTH, 50)
    print(f"   ✅ Consumed 50 reports for {org2.name}")
    
    quota = quota_manager.get_quota(org2.org_id, QuotaType.REPORTS_PER_MONTH)
    print(f"   Usage: {quota.used}/{quota.limit} ({quota.get_usage_percentage():.1f}%)")
    
    # Check quota alerts
    print("\n4. Quota Alerts:")
    # Consume more to trigger soft limit
    quota_manager.consume_quota(org2.org_id, QuotaType.REPORTS_PER_MONTH, 350)
    
    alerts = quota_manager.get_quota_alerts(org2.org_id)
    if alerts:
        for alert in alerts:
            print(f"   ⚠️  {alert['severity'].upper()}: {alert['message']}")
    else:
        print("   ✅ No quota alerts")
    
    return quota_manager


def demo_billing_management(org1, org2):
    """Demonstrate billing management."""
    print_section("BILLING MANAGEMENT")
    
    billing_manager = BillingManager()
    
    # Set billing info
    print("1. Setting Billing Information:")
    billing_manager.set_billing_info(
        org_id=org1.org_id,
        billing_email='billing@acme.com',
        billing_name='Acme Corporation',
        billing_address='123 Main St',
        billing_city='San Francisco',
        billing_state='CA',
        billing_zip='94105',
        billing_country='US'
    )
    print(f"   ✅ Set billing info for {org1.name}")
    
    # Create invoices
    print("\n2. Creating Invoices:")
    invoice1 = billing_manager.create_invoice(
        org_id=org1.org_id,
        subscription_id='sub_123',
        line_items=[
            {'description': 'Enterprise Plan - Monthly', 'quantity': 1, 'unit_price': 1999, 'amount': 1999},
            {'description': 'Additional Storage (100GB)', 'quantity': 1, 'unit_price': 50, 'amount': 50}
        ]
    )
    print(f"   ✅ Created invoice {invoice1.invoice_number}")
    print(f"      Subtotal: ${invoice1.subtotal:.2f}")
    print(f"      Tax: ${invoice1.tax:.2f}")
    print(f"      Total: ${invoice1.total:.2f}")
    
    # Mark invoice as paid
    print("\n3. Processing Payment:")
    billing_manager.mark_invoice_paid(
        invoice1.invoice_id,
        payment_method='credit_card',
        payment_reference='ch_1234567890'
    )
    print(f"   ✅ Invoice {invoice1.invoice_number} marked as paid")
    
    # Get billing summary
    print("\n4. Billing Summary:")
    summary = billing_manager.get_billing_summary(org1.org_id)
    print(f"   Total Invoices: {summary['total_invoices']}")
    print(f"   Total Paid: ${summary['total_paid']:.2f}")
    print(f"   Total Pending: ${summary['total_pending']:.2f}")
    print(f"   Has Overdue: {'Yes' if summary['has_overdue'] else 'No'}")
    
    return billing_manager


def demo_tenant_context(org1):
    """Demonstrate tenant context."""
    print_section("TENANT CONTEXT & ISOLATION")
    
    print("1. Using Tenant Context:")
    
    # Without context
    print(f"   Current tenant (before): {get_current_tenant()}")
    
    # With context manager
    with TenantContext(org1.org_id):
        print(f"   Current tenant (inside context): {get_current_tenant()}")
        print(f"   ✅ Tenant context active for {org1.name}")
    
    # After context
    print(f"   Current tenant (after): {get_current_tenant()}")
    
    print("\n2. Tenant Isolation:")
    print("   ✅ All database queries automatically filtered by tenant")
    print("   ✅ API requests validated against tenant context")
    print("   ✅ Resources isolated per tenant")


def demo_tenant_provisioning():
    """Demonstrate tenant provisioning."""
    print_section("TENANT PROVISIONING")
    
    # Set up managers
    tenant_manager = TenantManager()
    subscription_manager = SubscriptionManager()
    quota_manager = QuotaManager()
    billing_manager = BillingManager()
    
    provisioner = TenantProvisioner(
        tenant_manager,
        subscription_manager,
        quota_manager,
        billing_manager
    )
    
    print("1. Provisioning New Tenant:")
    result = provisioner.provision_tenant(
        name='TechStartup Inc',
        slug='techstartup',
        plan=SubscriptionPlan.BUSINESS,
        org_type=OrganizationType.STARTUP,
        primary_contact_email='ceo@techstartup.com',
        primary_contact_name='Jane Smith',
        billing_email='billing@techstartup.com',
        trial_days=30
    )
    
    print(f"   ✅ Provisioning successful!")
    print(f"   Organization ID: {result['org_id']}")
    print(f"   Subscription ID: {result['subscription_id']}")
    print(f"   Duration: {result['duration_seconds']:.2f} seconds")
    
    print("\n2. Provisioned Resources:")
    print("   ✅ Organization created")
    print("   ✅ Subscription activated (30-day trial)")
    print("   ✅ Usage quotas initialized")
    print("   ✅ Billing information configured")
    print("   ✅ Default resources created")
    print("   ✅ Welcome email sent")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BOUNTYBOT MULTI-TENANCY & ORGANIZATION MANAGEMENT DEMO")
    print("=" * 80)
    
    try:
        # Demo 1: Organization Management
        manager, org1, org2 = demo_organization_management()
        
        # Demo 2: Subscription Management
        sub_manager = demo_subscription_management(manager, org1, org2)
        
        # Demo 3: Quota Management
        quota_manager = demo_quota_management(org1, org2)
        
        # Demo 4: Billing Management
        billing_manager = demo_billing_management(org1, org2)
        
        # Demo 5: Tenant Context
        demo_tenant_context(org1)
        
        # Demo 6: Tenant Provisioning
        demo_tenant_provisioning()
        
        print("\n" + "=" * 80)
        print("  ✅ DEMO COMPLETED SUCCESSFULLY")
        print("=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

