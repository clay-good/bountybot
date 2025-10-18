"""
Tests for BountyBot integrations.
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from bountybot.integrations import (
    IntegrationConfig,
    IntegrationStatus,
    IntegrationType,
    JiraIntegration,
    SlackIntegration,
    GitHubIntegration,
    PagerDutyIntegration,
    EmailIntegration,
    IntegrationManager,
)
from bountybot.models import Report, ValidationResult, Verdict


class TestIntegrationConfig(unittest.TestCase):
    """Test IntegrationConfig dataclass."""
    
    def test_integration_config_creation(self):
        """Test creating integration config."""
        config = IntegrationConfig(
            name="test_integration",
            type=IntegrationType.NOTIFICATION,
            enabled=True,
            config={'key': 'value'},
            trigger_on_valid=True,
            min_severity="HIGH",
            min_confidence=70
        )
        
        self.assertEqual(config.name, "test_integration")
        self.assertEqual(config.type, IntegrationType.NOTIFICATION)
        self.assertTrue(config.enabled)
        self.assertEqual(config.config['key'], 'value')
        self.assertTrue(config.trigger_on_valid)
        self.assertEqual(config.min_severity, "HIGH")
        self.assertEqual(config.min_confidence, 70)


class TestJiraIntegration(unittest.TestCase):
    """Test JIRA integration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = IntegrationConfig(
            name="jira",
            type=IntegrationType.ISSUE_TRACKER,
            config={
                'url': 'https://test.atlassian.net',
                'username': 'test@example.com',
                'api_token': 'test_token',
                'project_key': 'SEC',
                'issue_type': 'Bug'
            }
        )
        self.integration = JiraIntegration(self.config)
        
        # Create mock validation result
        self.report = Report(
            title="SQL Injection in Login",
            vulnerability_type="SQL Injection",
            severity="HIGH",
            researcher="test_researcher"
        )
        self.validation_result = ValidationResult(
            report=self.report,
            verdict=Verdict.VALID,
            confidence=85
        )
    
    @patch('bountybot.integrations.jira_integration.requests.get')
    def test_connection_success(self, mock_get):
        """Test successful connection test."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = self.integration.test_connection()
        self.assertTrue(result)
    
    @patch('bountybot.integrations.jira_integration.requests.post')
    def test_create_issue_success(self, mock_post):
        """Test successful issue creation."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {'key': 'SEC-123'}
        mock_post.return_value = mock_response
        
        result = self.integration.create_issue(self.validation_result)
        
        self.assertEqual(result.status, IntegrationStatus.SUCCESS)
        self.assertEqual(result.external_id, 'SEC-123')
        self.assertIn('SEC-123', result.message)


class TestSlackIntegration(unittest.TestCase):
    """Test Slack integration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = IntegrationConfig(
            name="slack",
            type=IntegrationType.NOTIFICATION,
            config={
                'webhook_url': 'https://hooks.slack.com/test',
                'channel': '#security',
                'username': 'BountyBot'
            }
        )
        self.integration = SlackIntegration(self.config)
        
        self.report = Report(
            title="XSS Vulnerability",
            vulnerability_type="XSS",
            severity="MEDIUM",
            researcher="test_researcher"
        )
        self.validation_result = ValidationResult(
            report=self.report,
            verdict=Verdict.VALID,
            confidence=75
        )
    
    @patch('bountybot.integrations.slack_integration.requests.post')
    def test_send_notification_success(self, mock_post):
        """Test successful notification."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        result = self.integration.send_notification(
            self.validation_result,
            "Test notification"
        )
        
        self.assertEqual(result.status, IntegrationStatus.SUCCESS)
        self.assertIn("sent", result.message.lower())


class TestGitHubIntegration(unittest.TestCase):
    """Test GitHub integration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = IntegrationConfig(
            name="github",
            type=IntegrationType.VERSION_CONTROL,
            config={
                'token': 'test_token',
                'owner': 'test_org',
                'repo': 'security',
                'labels': ['security', 'bountybot']
            }
        )
        self.integration = GitHubIntegration(self.config)
        
        self.report = Report(
            title="CSRF Vulnerability",
            vulnerability_type="CSRF",
            severity="HIGH",
            researcher="test_researcher"
        )
        self.validation_result = ValidationResult(
            report=self.report,
            verdict=Verdict.VALID,
            confidence=90
        )
    
    @patch('bountybot.integrations.github_integration.requests.get')
    def test_connection_success(self, mock_get):
        """Test successful connection test."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        result = self.integration.test_connection()
        self.assertTrue(result)
    
    @patch('bountybot.integrations.github_integration.requests.post')
    def test_create_issue_success(self, mock_post):
        """Test successful issue creation."""
        mock_response = Mock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            'number': 42,
            'html_url': 'https://github.com/test_org/security/issues/42'
        }
        mock_post.return_value = mock_response
        
        result = self.integration.create_issue(self.validation_result)
        
        self.assertEqual(result.status, IntegrationStatus.SUCCESS)
        self.assertEqual(result.external_id, '42')
        self.assertIn('42', result.message)


class TestPagerDutyIntegration(unittest.TestCase):
    """Test PagerDuty integration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = IntegrationConfig(
            name="pagerduty",
            type=IntegrationType.INCIDENT_MANAGEMENT,
            config={
                'integration_key': 'test_integration_key_with_sufficient_length_for_validation'
            }
        )
        self.integration = PagerDutyIntegration(self.config)
        
        self.report = Report(
            title="Critical RCE",
            vulnerability_type="RCE",
            severity="CRITICAL",
            researcher="test_researcher"
        )
        self.validation_result = ValidationResult(
            report=self.report,
            verdict=Verdict.VALID,
            confidence=95
        )
    
    def test_connection_success(self):
        """Test successful connection test."""
        result = self.integration.test_connection()
        self.assertTrue(result)
    
    @patch('bountybot.integrations.pagerduty_integration.requests.post')
    def test_create_incident_success(self, mock_post):
        """Test successful incident creation."""
        mock_response = Mock()
        mock_response.status_code = 202
        mock_response.json.return_value = {'dedup_key': 'test_dedup_key'}
        mock_post.return_value = mock_response
        
        result = self.integration.create_issue(self.validation_result)
        
        self.assertEqual(result.status, IntegrationStatus.SUCCESS)
        self.assertEqual(result.external_id, 'test_dedup_key')


class TestEmailIntegration(unittest.TestCase):
    """Test Email integration."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = IntegrationConfig(
            name="email",
            type=IntegrationType.EMAIL,
            config={
                'smtp_host': 'smtp.test.com',
                'smtp_port': 587,
                'smtp_username': 'test@example.com',
                'smtp_password': 'test_password',
                'from_address': 'bountybot@example.com',
                'to_addresses': ['security@example.com']
            }
        )
        self.integration = EmailIntegration(self.config)
        
        self.report = Report(
            title="Path Traversal",
            vulnerability_type="Path Traversal",
            severity="MEDIUM",
            researcher="test_researcher"
        )
        self.validation_result = ValidationResult(
            report=self.report,
            verdict=Verdict.VALID,
            confidence=80
        )
    
    @patch('bountybot.integrations.email_integration.smtplib.SMTP')
    def test_send_notification_success(self, mock_smtp):
        """Test successful email notification."""
        mock_server = MagicMock()
        mock_smtp.return_value = mock_server
        
        result = self.integration.send_notification(
            self.validation_result,
            "Test email"
        )
        
        self.assertEqual(result.status, IntegrationStatus.SUCCESS)
        mock_server.sendmail.assert_called_once()


class TestIntegrationManager(unittest.TestCase):
    """Test Integration Manager."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'integrations': {
                'enabled': True,
                'slack': {
                    'enabled': True,
                    'type': 'slack',
                    'config': {
                        'webhook_url': 'https://hooks.slack.com/test'
                    },
                    'trigger_on_valid': True,
                    'trigger_on_invalid': False
                }
            }
        }
        
        self.report = Report(
            title="Test Vulnerability",
            vulnerability_type="Test",
            severity="HIGH",
            researcher="test_researcher"
        )
        self.validation_result = ValidationResult(
            report=self.report,
            verdict=Verdict.VALID,
            confidence=85
        )
    
    def test_manager_initialization(self):
        """Test manager initialization."""
        manager = IntegrationManager(self.config)
        self.assertGreater(len(manager.integrations), 0)
        self.assertIn('slack', manager.enabled_integrations)
    
    @patch('bountybot.integrations.slack_integration.requests.post')
    def test_execute_integrations(self, mock_post):
        """Test executing integrations."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        manager = IntegrationManager(self.config)
        results = manager.execute_integrations(self.validation_result)
        
        self.assertGreater(len(results), 0)
        self.assertEqual(results[0].status, IntegrationStatus.SUCCESS)
    
    def test_list_integrations(self):
        """Test listing integrations."""
        manager = IntegrationManager(self.config)
        integrations_list = manager.list_integrations()
        
        self.assertGreater(len(integrations_list), 0)
        self.assertIn('name', integrations_list[0])
        self.assertIn('type', integrations_list[0])


if __name__ == '__main__':
    unittest.main()

