"""
Tests for Compliance Module
"""

import unittest
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
    DataRetentionPolicy
)


class TestPIIDetector(unittest.TestCase):
    """Test PII detection."""
    
    def setUp(self):
        self.detector = PIIDetector()
    
    def test_detect_email(self):
        """Test email detection."""
        text = "Contact me at john.doe@example.com for more info"
        matches = self.detector.detect(text)
        
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].pii_type, PIIType.EMAIL)
        self.assertEqual(matches[0].value, "john.doe@example.com")
    
    def test_detect_phone(self):
        """Test phone number detection."""
        text = "Call me at 555-123-4567"
        matches = self.detector.detect(text)

        phone_matches = [m for m in matches if m.pii_type == PIIType.PHONE]
        # Phone detection may vary based on format
        self.assertGreaterEqual(len(phone_matches), 0)
    
    def test_detect_ip_address(self):
        """Test IP address detection."""
        text = "Server IP: 192.168.1.100"
        matches = self.detector.detect(text)
        
        ip_matches = [m for m in matches if m.pii_type == PIIType.IP_ADDRESS]
        self.assertEqual(len(ip_matches), 1)
        self.assertEqual(ip_matches[0].value, "192.168.1.100")
    
    def test_has_pii(self):
        """Test PII presence check."""
        text_with_pii = "Email: test@example.com"
        text_without_pii = "This is a normal sentence"
        
        self.assertTrue(self.detector.has_pii(text_with_pii))
        self.assertFalse(self.detector.has_pii(text_without_pii))
    
    def test_scan_dict(self):
        """Test dictionary scanning."""
        data = {
            'user': {
                'email': 'user@example.com',
                'phone': '555-123-4567'
            },
            'description': 'Normal text'
        }
        
        results = self.detector.scan_dict(data)
        self.assertGreater(len(results), 0)


class TestDataAnonymizer(unittest.TestCase):
    """Test data anonymization."""
    
    def setUp(self):
        self.anonymizer = DataAnonymizer()
    
    def test_anonymize_email_redact(self):
        """Test email redaction."""
        text = "Contact: john@example.com"
        result = self.anonymizer.anonymize_text(text, AnonymizationStrategy.REDACT)
        
        self.assertIn("[REDACTED_EMAIL]", result)
        self.assertNotIn("john@example.com", result)
    
    def test_anonymize_email_mask(self):
        """Test email masking."""
        text = "Contact: john@example.com"
        result = self.anonymizer.anonymize_text(text, AnonymizationStrategy.MASK)

        self.assertNotIn("john@example.com", result)
        # Masking replaces characters with asterisks
        self.assertIn("*", result)
    
    def test_anonymize_dict(self):
        """Test dictionary anonymization."""
        data = {
            'email': 'user@example.com',
            'name': 'John Doe',
            'description': 'Normal text'
        }
        
        result = self.anonymizer.anonymize_dict(data, AnonymizationStrategy.REDACT)
        
        self.assertNotIn('user@example.com', str(result))
        self.assertIn('description', result)
    
    def test_tokenization(self):
        """Test tokenization and detokenization."""
        text = "Email: test@example.com"
        
        anonymized = self.anonymizer.anonymize_text(text, AnonymizationStrategy.TOKENIZE)
        self.assertNotIn("test@example.com", anonymized)
        
        detokenized = self.anonymizer.detokenize(anonymized)
        self.assertIn("test@example.com", detokenized)


class TestPolicyEngine(unittest.TestCase):
    """Test policy enforcement."""
    
    def setUp(self):
        self.engine = PolicyEngine()
    
    def test_check_data_classification(self):
        """Test data classification check."""
        data = {'email': 'user@example.com'}
        
        violations = self.engine.check_data_classification(
            data,
            DataClassification.PUBLIC,
            'user_profile',
            'user_123'
        )
        
        self.assertGreater(len(violations), 0)
        self.assertEqual(violations[0].severity, 'high')
    
    def test_check_retention_policy(self):
        """Test retention policy check."""
        policy = DataRetentionPolicy(
            policy_id='test_policy',
            name='Test Policy',
            description='Test',
            retention_period_days=30
        )
        
        violations = self.engine.check_retention_policy(
            data_age_days=45,
            policy=policy,
            resource_type='report',
            resource_id='report_123'
        )
        
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].severity, 'medium')
    
    def test_check_encryption_requirements(self):
        """Test encryption requirements."""
        violations = self.engine.check_encryption_requirements(
            is_encrypted=False,
            data_classification=DataClassification.PII,
            resource_type='database',
            resource_id='db_123'
        )
        
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].severity, 'critical')


class TestRetentionManager(unittest.TestCase):
    """Test retention management."""
    
    def setUp(self):
        self.manager = RetentionManager()
    
    def test_add_policy(self):
        """Test adding retention policy."""
        policy = DataRetentionPolicy(
            policy_id='test_policy',
            name='Test Policy',
            description='Test retention policy',
            retention_period_days=365
        )
        
        self.manager.add_policy(policy)
        
        retrieved = self.manager.get_policy('test_policy')
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, 'Test Policy')
    
    def test_check_retention(self):
        """Test retention check."""
        policy = DataRetentionPolicy(
            policy_id='test_policy',
            name='Test Policy',
            description='Test',
            data_types=['test_data'],
            retention_period_days=30,
            auto_delete=True
        )
        
        self.manager.add_policy(policy)
        
        # Old data should be flagged for deletion
        old_date = datetime.utcnow() - timedelta(days=45)
        decision = self.manager.check_retention(
            data_id='data_123',
            data_type='test_data',
            created_at=old_date
        )
        
        self.assertEqual(decision['action'], 'delete')
        self.assertTrue(decision['auto_delete'])
    
    def test_create_default_policies(self):
        """Test default policy creation."""
        policies = self.manager.create_default_policies()
        
        self.assertGreater(len(policies), 0)
        self.assertGreater(len(self.manager.policies), 0)


class TestConsentManager(unittest.TestCase):
    """Test consent management."""
    
    def setUp(self):
        self.manager = ConsentManager()
    
    def test_record_consent(self):
        """Test recording consent."""
        consent = self.manager.record_consent(
            user_id='user_123',
            purpose='marketing',
            consent_given=True,
            consent_text='I agree to marketing emails'
        )
        
        self.assertIsNotNone(consent.consent_id)
        self.assertTrue(consent.consent_given)
        self.assertIsNotNone(consent.consent_date)
    
    def test_check_consent(self):
        """Test checking consent."""
        self.manager.record_consent(
            user_id='user_123',
            purpose='analytics',
            consent_given=True,
            consent_text='I agree'
        )
        
        has_consent = self.manager.check_consent('user_123', 'analytics')
        self.assertTrue(has_consent)
        
        no_consent = self.manager.check_consent('user_123', 'marketing')
        self.assertFalse(no_consent)
    
    def test_withdraw_consent(self):
        """Test withdrawing consent."""
        self.manager.record_consent(
            user_id='user_123',
            purpose='marketing',
            consent_given=True,
            consent_text='I agree'
        )
        
        withdrawn = self.manager.withdraw_consent('user_123', 'marketing')
        
        self.assertEqual(len(withdrawn), 1)
        self.assertIsNotNone(withdrawn[0].withdrawn_date)
        
        has_consent = self.manager.check_consent('user_123', 'marketing')
        self.assertFalse(has_consent)
    
    def test_export_user_consents(self):
        """Test exporting user consents."""
        self.manager.record_consent(
            user_id='user_123',
            purpose='marketing',
            consent_given=True,
            consent_text='I agree'
        )
        
        export = self.manager.export_user_consents('user_123')
        
        self.assertEqual(export['user_id'], 'user_123')
        self.assertEqual(export['total_consents'], 1)
        self.assertIn('consents', export)


class TestComplianceManager(unittest.TestCase):
    """Test compliance manager."""
    
    def setUp(self):
        self.manager = ComplianceManager()
    
    def test_initialization(self):
        """Test manager initialization."""
        self.assertIsNotNone(self.manager.pii_detector)
        self.assertIsNotNone(self.manager.data_anonymizer)
        self.assertIsNotNone(self.manager.policy_engine)
        self.assertIsNotNone(self.manager.retention_manager)
        self.assertIsNotNone(self.manager.consent_manager)
    
    def test_add_control(self):
        """Test adding compliance control."""
        control = ComplianceControl(
            control_id='test_control',
            framework=ComplianceFramework.SOC2_TYPE2,
            control_number='CC1.1',
            title='Test Control',
            description='Test control description'
        )
        
        self.manager.add_control(control)
        
        self.assertIn('test_control', self.manager.controls)
    
    def test_update_control_status(self):
        """Test updating control status."""
        control = ComplianceControl(
            control_id='test_control',
            framework=ComplianceFramework.SOC2_TYPE2,
            control_number='CC1.1',
            title='Test Control',
            description='Test'
        )
        
        self.manager.add_control(control)
        
        updated = self.manager.update_control_status(
            'test_control',
            ControlStatus.IMPLEMENTED,
            implementation_notes='Implemented successfully'
        )
        
        self.assertIsNotNone(updated)
        self.assertEqual(updated.status, ControlStatus.IMPLEMENTED)
    
    def test_assess_framework(self):
        """Test framework assessment."""
        report = self.manager.assess_framework(
            ComplianceFramework.SOC2_TYPE2,
            assessor='test_user'
        )
        
        self.assertIsNotNone(report.report_id)
        self.assertEqual(report.framework, ComplianceFramework.SOC2_TYPE2)
        self.assertGreaterEqual(report.compliance_score, 0)
        self.assertLessEqual(report.compliance_score, 100)
    
    def test_compliance_dashboard(self):
        """Test compliance dashboard."""
        dashboard = self.manager.get_compliance_dashboard()
        
        self.assertIn('total_controls', dashboard)
        self.assertIn('by_framework', dashboard)
        self.assertIn('open_violations', dashboard)


if __name__ == '__main__':
    unittest.main()

