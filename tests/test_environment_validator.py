"""
Tests for environment-specific validator.
"""

import unittest

from bountybot.validators.environment_validator import (
    EnvironmentValidator,
    EnvironmentConfig,
    EnvironmentType,
    AccessLevel,
    ApplicabilityLevel,
    ApplicabilityCheck
)


class TestEnvironmentValidator(unittest.TestCase):
    """Test environment validator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.validator = EnvironmentValidator()
        
        # Create production environment
        self.prod_config = EnvironmentConfig(
            environment_type=EnvironmentType.PRODUCTION,
            network_topology={'type': 'cloud', 'provider': 'aws'},
            feature_flags={'new_feature': True, 'beta_feature': False},
            access_controls={
                '/api/public': AccessLevel.PUBLIC,
                '/api/admin': AccessLevel.ADMIN,
                '/api/user': AccessLevel.AUTHENTICATED
            },
            deployed_services=['web-app', 'api-server', 'database'],
            public_endpoints=['/api/public', '/health'],
            authentication_required=True
        )
        self.validator.add_environment('production', self.prod_config)
        
        # Create staging environment
        self.staging_config = EnvironmentConfig(
            environment_type=EnvironmentType.STAGING,
            feature_flags={'new_feature': True, 'beta_feature': True},
            deployed_services=['web-app', 'api-server'],
            public_endpoints=['/api/public'],
            authentication_required=False
        )
        self.validator.add_environment('staging', self.staging_config)
    
    def test_initialization(self):
        """Test validator initialization."""
        validator = EnvironmentValidator()
        self.assertIsNotNone(validator)
        self.assertEqual(len(validator.environments), 0)
    
    def test_add_environment(self):
        """Test adding environment configuration."""
        self.assertEqual(len(self.validator.environments), 2)
        self.assertIn('production', self.validator.environments)
        self.assertIn('staging', self.validator.environments)
    
    def test_check_network_accessibility_public(self):
        """Test network accessibility check for public endpoint."""
        vulnerability_report = {
            'affected_endpoint': '/api/public',
            'vulnerability_type': 'sql_injection'
        }
        
        check = self.validator._check_network_accessibility(
            vulnerability_report, self.prod_config
        )
        
        self.assertTrue(check.applicable)
        self.assertIn('publicly accessible', check.reason)
    
    def test_check_network_accessibility_internal(self):
        """Test network accessibility check for internal endpoint."""
        vulnerability_report = {
            'affected_endpoint': '/internal/admin',
            'vulnerability_type': 'sql_injection'
        }
        
        check = self.validator._check_network_accessibility(
            vulnerability_report, self.prod_config
        )
        
        self.assertFalse(check.applicable)
        self.assertIn('not publicly accessible', check.reason)
    
    def test_check_feature_flags_enabled(self):
        """Test feature flag check when feature is enabled."""
        vulnerability_report = {
            'affected_feature': 'new_feature',
            'vulnerability_type': 'xss'
        }
        
        check = self.validator._check_feature_flags(
            vulnerability_report, self.prod_config
        )
        
        self.assertTrue(check.applicable)
        self.assertIn('enabled', check.reason)
    
    def test_check_feature_flags_disabled(self):
        """Test feature flag check when feature is disabled."""
        vulnerability_report = {
            'affected_feature': 'beta_feature',
            'vulnerability_type': 'xss'
        }
        
        check = self.validator._check_feature_flags(
            vulnerability_report, self.prod_config
        )
        
        self.assertFalse(check.applicable)
        self.assertIn('disabled', check.reason)
    
    def test_check_access_controls_public(self):
        """Test access control check for public endpoint."""
        vulnerability_report = {
            'affected_endpoint': '/api/public',
            'requires_authentication': False
        }
        
        check = self.validator._check_access_controls(
            vulnerability_report, self.prod_config
        )
        
        self.assertTrue(check.applicable)
        self.assertIn('publicly accessible', check.reason)
    
    def test_check_access_controls_admin(self):
        """Test access control check for admin endpoint."""
        vulnerability_report = {
            'affected_endpoint': '/api/admin',
            'requires_authentication': True
        }
        
        check = self.validator._check_access_controls(
            vulnerability_report, self.prod_config
        )
        
        self.assertFalse(check.applicable)
        self.assertIn('protected', check.reason)
    
    def test_check_deployed_services_deployed(self):
        """Test deployed services check when service is deployed."""
        vulnerability_report = {
            'affected_service': 'api-server',
            'vulnerability_type': 'command_injection'
        }
        
        check = self.validator._check_deployed_services(
            vulnerability_report, self.prod_config
        )
        
        self.assertTrue(check.applicable)
        self.assertIn('is deployed', check.reason)
    
    def test_check_deployed_services_not_deployed(self):
        """Test deployed services check when service is not deployed."""
        vulnerability_report = {
            'affected_service': 'legacy-service',
            'vulnerability_type': 'command_injection'
        }
        
        check = self.validator._check_deployed_services(
            vulnerability_report, self.prod_config
        )
        
        self.assertFalse(check.applicable)
        self.assertIn('not deployed', check.reason)
    
    def test_check_authentication(self):
        """Test authentication requirements check."""
        vulnerability_report = {
            'requires_authentication': False
        }
        
        check = self.validator._check_authentication(
            vulnerability_report, self.prod_config
        )
        
        # Production requires auth but vuln doesn't - not applicable
        self.assertFalse(check.applicable)
    
    def test_calculate_applicability_applicable(self):
        """Test applicability calculation when most checks pass."""
        checks = [
            ApplicabilityCheck('check1', True, 'reason1'),
            ApplicabilityCheck('check2', True, 'reason2'),
            ApplicabilityCheck('check3', True, 'reason3'),
            ApplicabilityCheck('check4', True, 'reason4'),
            ApplicabilityCheck('check5', False, 'reason5'),
        ]
        
        applicability = self.validator._calculate_applicability(checks)
        self.assertEqual(applicability, ApplicabilityLevel.APPLICABLE)
    
    def test_calculate_applicability_partially(self):
        """Test applicability calculation when some checks pass."""
        checks = [
            ApplicabilityCheck('check1', True, 'reason1'),
            ApplicabilityCheck('check2', True, 'reason2'),
            ApplicabilityCheck('check3', False, 'reason3'),
            ApplicabilityCheck('check4', False, 'reason4'),
            ApplicabilityCheck('check5', False, 'reason5'),
        ]
        
        applicability = self.validator._calculate_applicability(checks)
        self.assertEqual(applicability, ApplicabilityLevel.PARTIALLY_APPLICABLE)
    
    def test_calculate_applicability_not_applicable(self):
        """Test applicability calculation when most checks fail."""
        checks = [
            ApplicabilityCheck('check1', False, 'reason1'),
            ApplicabilityCheck('check2', False, 'reason2'),
            ApplicabilityCheck('check3', False, 'reason3'),
            ApplicabilityCheck('check4', False, 'reason4'),
            ApplicabilityCheck('check5', True, 'reason5'),
        ]
        
        applicability = self.validator._calculate_applicability(checks)
        self.assertEqual(applicability, ApplicabilityLevel.NOT_APPLICABLE)
    
    def test_calculate_confidence(self):
        """Test confidence calculation."""
        checks = [
            ApplicabilityCheck('check1', True, 'reason1', confidence=0.9),
            ApplicabilityCheck('check2', True, 'reason2', confidence=0.8),
            ApplicabilityCheck('check3', False, 'reason3', confidence=0.7),
        ]
        
        confidence = self.validator._calculate_confidence(checks)
        self.assertAlmostEqual(confidence, 0.8, places=1)
    
    def test_validate_specific_environment(self):
        """Test validation for specific environment."""
        vulnerability_report = {
            'affected_endpoint': '/api/public',
            'affected_service': 'api-server',
            'vulnerability_type': 'sql_injection',
            'requires_authentication': False
        }
        
        result = self.validator.validate(vulnerability_report, 'production')
        
        self.assertIsNotNone(result)
        self.assertGreater(len(result.checks_performed), 0)
        self.assertGreater(result.confidence, 0.0)
    
    def test_validate_all_environments(self):
        """Test validation across all environments."""
        vulnerability_report = {
            'affected_endpoint': '/api/public',
            'affected_service': 'api-server',
            'vulnerability_type': 'sql_injection'
        }
        
        result = self.validator.validate(vulnerability_report)
        
        self.assertIsNotNone(result)
        # Should check both production and staging
        self.assertGreaterEqual(len(result.checks_performed), 5)
        self.assertGreater(len(result.affected_environments), 0)
    
    def test_validate_nonexistent_environment(self):
        """Test validation for nonexistent environment."""
        vulnerability_report = {
            'vulnerability_type': 'xss'
        }
        
        result = self.validator.validate(vulnerability_report, 'nonexistent')
        
        self.assertEqual(result.applicability, ApplicabilityLevel.UNKNOWN)
        self.assertEqual(result.confidence, 0.0)
        self.assertIn('not found', result.details)
    
    def test_validate_public_endpoint_applicable(self):
        """Test that public endpoint vulnerability is applicable."""
        vulnerability_report = {
            'affected_endpoint': '/api/public',
            'affected_service': 'api-server',
            'affected_feature': 'new_feature',
            'vulnerability_type': 'sql_injection',
            'requires_authentication': False
        }
        
        result = self.validator.validate(vulnerability_report, 'production')
        
        # Should be applicable since endpoint is public and service is deployed
        self.assertIn(result.applicability, [
            ApplicabilityLevel.APPLICABLE,
            ApplicabilityLevel.PARTIALLY_APPLICABLE
        ])
    
    def test_validate_disabled_feature_not_applicable(self):
        """Test that disabled feature vulnerability is not applicable."""
        vulnerability_report = {
            'affected_feature': 'beta_feature',
            'vulnerability_type': 'xss'
        }
        
        result = self.validator.validate(vulnerability_report, 'production')
        
        # Should have low applicability since feature is disabled
        self.assertIn(result.applicability, [
            ApplicabilityLevel.NOT_APPLICABLE,
            ApplicabilityLevel.PARTIALLY_APPLICABLE
        ])
    
    def test_generate_recommendations_applicable(self):
        """Test recommendation generation for applicable vulnerability."""
        checks = [
            ApplicabilityCheck('check1', True, 'reason1'),
            ApplicabilityCheck('check2', True, 'reason2'),
        ]
        
        recommendations = self.validator._generate_recommendations(
            ApplicabilityLevel.APPLICABLE,
            [EnvironmentType.PRODUCTION],
            checks
        )
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any('CRITICAL' in r for r in recommendations))
    
    def test_generate_recommendations_not_applicable(self):
        """Test recommendation generation for non-applicable vulnerability."""
        checks = [
            ApplicabilityCheck('check1', False, 'reason1'),
            ApplicabilityCheck('check2', False, 'reason2'),
        ]
        
        recommendations = self.validator._generate_recommendations(
            ApplicabilityLevel.NOT_APPLICABLE,
            [],
            checks
        )
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any('does not apply' in r for r in recommendations))


if __name__ == '__main__':
    unittest.main()

