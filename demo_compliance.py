"""
Compliance & Regulatory Framework Demo

Demonstrates compliance management features.
"""

import json
from datetime import datetime, timedelta
from bountybot.compliance import (
    ComplianceManager,
    PIIDetector,
    PIIType,
    DataAnonymizer,
    AnonymizationStrategy,
    PolicyEngine,
    RetentionManager,
    ConsentManager,
    ComplianceFramework,
    ComplianceControl,
    ControlStatus,
    DataClassification,
    DataRetentionPolicy,
    DataProcessingActivity
)


def print_section(title: str):
    """Print section header."""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def demo_pii_detection():
    """Demonstrate PII detection."""
    print_section("PII DETECTION")
    
    detector = PIIDetector()
    
    # Sample text with PII
    text = """
    User Report:
    Name: John Doe
    Email: john.doe@example.com
    Phone: (555) 123-4567
    IP Address: 192.168.1.100
    
    The user reported a vulnerability in the authentication system.
    """
    
    print("Sample Text:")
    print(text)
    
    # Detect PII
    matches = detector.detect(text)
    
    print(f"\nDetected {len(matches)} PII instances:")
    for match in matches:
        print(f"  - {match.pii_type.value}: {match.value} (confidence: {match.confidence:.2f})")
    
    # Get summary
    summary = detector.get_pii_summary(text)
    print(f"\nPII Summary:")
    for pii_type, count in summary.items():
        print(f"  - {pii_type.value}: {count}")


def demo_data_anonymization():
    """Demonstrate data anonymization."""
    print_section("DATA ANONYMIZATION")
    
    anonymizer = DataAnonymizer()
    
    text = "Contact John Doe at john.doe@example.com or call (555) 123-4567"
    
    print(f"Original: {text}\n")
    
    # Try different strategies
    strategies = [
        AnonymizationStrategy.REDACT,
        AnonymizationStrategy.MASK,
        AnonymizationStrategy.GENERALIZE,
        AnonymizationStrategy.PSEUDONYMIZE
    ]
    
    for strategy in strategies:
        result = anonymizer.anonymize_text(text, strategy)
        print(f"{strategy.value.upper()}: {result}")
    
    # Anonymize dictionary
    print("\n\nDictionary Anonymization:")
    data = {
        'user': {
            'name': 'Jane Smith',
            'email': 'jane@example.com',
            'phone': '555-987-6543'
        },
        'report': {
            'title': 'SQL Injection',
            'description': 'Found vulnerability'
        }
    }
    
    print(f"Original: {json.dumps(data, indent=2)}")
    
    anonymized = anonymizer.anonymize_dict(data, AnonymizationStrategy.REDACT)
    print(f"\nAnonymized: {json.dumps(anonymized, indent=2)}")


def demo_policy_enforcement():
    """Demonstrate policy enforcement."""
    print_section("POLICY ENFORCEMENT")
    
    engine = PolicyEngine()
    
    # Check data classification
    print("1. Data Classification Check:")
    data_with_pii = {'email': 'user@example.com', 'name': 'John Doe'}
    violations = engine.check_data_classification(
        data_with_pii,
        DataClassification.PUBLIC,
        'user_profile',
        'user_123'
    )
    
    if violations:
        print(f"   ❌ Found {len(violations)} violation(s):")
        for v in violations:
            print(f"      - {v.description}")
            print(f"        Severity: {v.severity}")
    else:
        print("   ✅ No violations found")
    
    # Check retention policy
    print("\n2. Retention Policy Check:")
    policy = DataRetentionPolicy(
        policy_id='test_policy',
        name='User Data Retention',
        description='Retain user data for 1 year',
        retention_period_days=365,
        auto_delete=True
    )
    
    violations = engine.check_retention_policy(
        data_age_days=400,
        policy=policy,
        resource_type='user_data',
        resource_id='data_123'
    )
    
    if violations:
        print(f"   ❌ Found {len(violations)} violation(s):")
        for v in violations:
            print(f"      - {v.description}")
            print(f"        Remediation: {', '.join(v.remediation_steps)}")
    
    # Check encryption
    print("\n3. Encryption Requirements Check:")
    violations = engine.check_encryption_requirements(
        is_encrypted=False,
        data_classification=DataClassification.PII,
        resource_type='database',
        resource_id='db_123'
    )
    
    if violations:
        print(f"   ❌ Found {len(violations)} violation(s):")
        for v in violations:
            print(f"      - {v.description}")
            print(f"        Severity: {v.severity}")


def demo_retention_management():
    """Demonstrate retention management."""
    print_section("DATA RETENTION MANAGEMENT")
    
    manager = RetentionManager()
    
    # Create default policies
    print("Creating default retention policies...")
    policies = manager.create_default_policies()
    
    print(f"\nCreated {len(policies)} policies:")
    for policy in policies:
        print(f"  - {policy.name}: {policy.retention_period_days} days")
    
    # Check retention for sample data
    print("\n\nChecking retention for sample data:")
    
    test_data = [
        {
            'id': 'data_1',
            'type': 'audit_log',
            'created_at': datetime.utcnow() - timedelta(days=100),
            'classification': None
        },
        {
            'id': 'data_2',
            'type': 'temp_file',
            'created_at': datetime.utcnow() - timedelta(days=45),
            'classification': None
        },
        {
            'id': 'data_3',
            'type': 'user_profile',
            'created_at': datetime.utcnow() - timedelta(days=1200),
            'classification': None
        }
    ]
    
    for item in test_data:
        decision = manager.check_retention(
            data_id=item['id'],
            data_type=item['type'],
            created_at=item['created_at']
        )
        
        print(f"\n  {item['id']} ({item['type']}):")
        print(f"    Action: {decision['action']}")
        print(f"    Reason: {decision['reason']}")


def demo_consent_management():
    """Demonstrate consent management."""
    print_section("CONSENT MANAGEMENT (GDPR)")
    
    manager = ConsentManager()
    
    # Record consent
    print("1. Recording user consent:")
    consent1 = manager.record_consent(
        user_id='user_123',
        purpose='marketing',
        consent_given=True,
        consent_text='I agree to receive marketing emails',
        ip_address='192.168.1.100'
    )
    print(f"   ✅ Recorded consent: {consent1.consent_id}")
    
    consent2 = manager.record_consent(
        user_id='user_123',
        purpose='analytics',
        consent_given=True,
        consent_text='I agree to analytics tracking'
    )
    print(f"   ✅ Recorded consent: {consent2.consent_id}")
    
    # Check consent
    print("\n2. Checking consent:")
    has_marketing = manager.check_consent('user_123', 'marketing')
    has_advertising = manager.check_consent('user_123', 'advertising')
    
    print(f"   Marketing consent: {'✅ Yes' if has_marketing else '❌ No'}")
    print(f"   Advertising consent: {'✅ Yes' if has_advertising else '❌ No'}")
    
    # Withdraw consent
    print("\n3. Withdrawing consent:")
    withdrawn = manager.withdraw_consent('user_123', 'marketing')
    print(f"   ✅ Withdrew {len(withdrawn)} consent(s)")
    
    has_marketing = manager.check_consent('user_123', 'marketing')
    print(f"   Marketing consent after withdrawal: {'✅ Yes' if has_marketing else '❌ No'}")
    
    # Export user data
    print("\n4. Exporting user consent data (GDPR Article 20):")
    export = manager.export_user_consents('user_123')
    print(f"   Total consents: {export['total_consents']}")
    print(f"   Export date: {export['export_date']}")


def demo_compliance_framework():
    """Demonstrate compliance framework management."""
    print_section("COMPLIANCE FRAMEWORK MANAGEMENT")
    
    manager = ComplianceManager()
    
    # Show initialized controls
    print("1. Initialized Compliance Controls:")
    soc2_controls = [c for c in manager.controls.values() if c.framework == ComplianceFramework.SOC2_TYPE2]
    print(f"   SOC 2 Type II: {len(soc2_controls)} controls")
    
    for control in soc2_controls[:3]:
        print(f"     - {control.control_number}: {control.title}")
    
    # Update control status
    print("\n2. Updating Control Status:")
    if soc2_controls:
        control = soc2_controls[0]
        manager.update_control_status(
            control.control_id,
            ControlStatus.IMPLEMENTED,
            implementation_notes="Implemented access controls with MFA"
        )
        print(f"   ✅ Updated {control.control_number} to IMPLEMENTED")
    
    # Assess framework
    print("\n3. Assessing SOC 2 Compliance:")
    report = manager.assess_framework(
        ComplianceFramework.SOC2_TYPE2,
        assessor='compliance_team'
    )
    
    print(f"   Report ID: {report.report_id}")
    print(f"   Status: {report.status.value}")
    print(f"   Compliance Score: {report.compliance_score:.1f}%")
    print(f"   Total Controls: {report.total_controls}")
    print(f"   Implemented: {report.implemented_controls}")
    print(f"   Compliant: {report.compliant_controls}")
    print(f"   Gaps: {len(report.gaps)}")
    
    if report.recommendations:
        print(f"\n   Recommendations:")
        for rec in report.recommendations[:3]:
            print(f"     - {rec}")
    
    # Compliance dashboard
    print("\n4. Compliance Dashboard:")
    dashboard = manager.get_compliance_dashboard()
    
    print(f"   Total Controls: {dashboard['total_controls']}")
    print(f"   Implementation Rate: {dashboard['implementation_rate']:.1f}%")
    print(f"   Open Violations: {dashboard['open_violations']}")
    print(f"   Retention Policies: {dashboard['retention_policies']}")
    print(f"   Consent Records: {dashboard['consent_records']}")


def main():
    """Run all demos."""
    print("\n" + "=" * 80)
    print("  BOUNTYBOT COMPLIANCE & REGULATORY FRAMEWORK DEMO")
    print("=" * 80)
    
    try:
        demo_pii_detection()
        demo_data_anonymization()
        demo_policy_enforcement()
        demo_retention_management()
        demo_consent_management()
        demo_compliance_framework()
        
        print("\n" + "=" * 80)
        print("  ✅ DEMO COMPLETED SUCCESSFULLY")
        print("=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error during demo: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()

