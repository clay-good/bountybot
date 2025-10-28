"""
Tests for security control verifier.
"""

import unittest
import asyncio
import pytest
from unittest.mock import Mock, patch, AsyncMock

from bountybot.validators.security_control_verifier import (
    SecurityControlVerifier,
    ControlType,
    ControlEffectiveness,
    ControlTest,
    ControlVerificationResult
)


class TestSecurityControlVerifier(unittest.TestCase):
    """Test security control verifier."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.verifier = SecurityControlVerifier()
    
    def test_initialization(self):
        """Test verifier initialization."""
        self.assertIsNotNone(self.verifier)
        self.assertEqual(self.verifier.timeout, 10)
        self.assertTrue(self.verifier.verify_ssl)
    
    def test_custom_config(self):
        """Test verifier with custom configuration."""
        verifier = SecurityControlVerifier({
            'timeout': 5,
            'verify_ssl': False,
            'max_tests_per_type': 2
        })
        self.assertEqual(verifier.timeout, 5)
        self.assertFalse(verifier.verify_ssl)
        self.assertEqual(verifier.max_tests, 2)
    
    def test_is_blocked_status_code(self):
        """Test detection of blocked requests by status code."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        
        self.assertTrue(self.verifier._is_blocked(mock_response))
    
    def test_is_blocked_response_text(self):
        """Test detection of blocked requests by response text."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Request blocked by WAF"
        
        self.assertTrue(self.verifier._is_blocked(mock_response))
    
    def test_is_not_blocked(self):
        """Test detection when request is not blocked."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Welcome to the application"
        
        self.assertFalse(self.verifier._is_blocked(mock_response))
    
    def test_is_sanitized(self):
        """Test detection of sanitized payloads."""
        mock_response = Mock()
        mock_response.text = "&lt;script&gt;alert('XSS')&lt;/script&gt;"
        
        payload = "<script>alert('XSS')</script>"
        self.assertTrue(self.verifier._is_sanitized(mock_response, payload))
    
    def test_is_not_sanitized(self):
        """Test detection when payload is not sanitized."""
        mock_response = Mock()
        mock_response.text = "<script>alert('XSS')</script>"
        
        payload = "<script>alert('XSS')</script>"
        self.assertFalse(self.verifier._is_sanitized(mock_response, payload))
    
    def test_get_test_payloads_sql_injection(self):
        """Test getting test payloads for SQL injection."""
        payloads = self.verifier._get_test_payloads('sql_injection', None)
        
        self.assertGreater(len(payloads), 0)
        self.assertTrue(any("'" in p for p in payloads))
    
    def test_get_test_payloads_with_poc(self):
        """Test getting test payloads with PoC payload."""
        poc = "custom' OR '1'='1"
        payloads = self.verifier._get_test_payloads('sql_injection', poc)
        
        self.assertEqual(payloads[0], poc)
    
    def test_calculate_overall_effectiveness_all_effective(self):
        """Test effectiveness calculation when all tests are effective."""
        tests = [
            ControlTest(
                control_type=ControlType.WAF,
                test_payload="test",
                expected_behavior="block",
                effectiveness=ControlEffectiveness.EFFECTIVE
            )
            for _ in range(3)
        ]
        
        effectiveness = self.verifier._calculate_overall_effectiveness(tests)
        self.assertEqual(effectiveness, ControlEffectiveness.EFFECTIVE)
    
    def test_calculate_overall_effectiveness_partially_effective(self):
        """Test effectiveness calculation when some tests are effective."""
        tests = [
            ControlTest(
                control_type=ControlType.WAF,
                test_payload="test1",
                expected_behavior="block",
                effectiveness=ControlEffectiveness.EFFECTIVE
            ),
            ControlTest(
                control_type=ControlType.WAF,
                test_payload="test2",
                expected_behavior="block",
                effectiveness=ControlEffectiveness.INEFFECTIVE
            )
        ]
        
        effectiveness = self.verifier._calculate_overall_effectiveness(tests)
        self.assertEqual(effectiveness, ControlEffectiveness.PARTIALLY_EFFECTIVE)
    
    def test_calculate_overall_effectiveness_ineffective(self):
        """Test effectiveness calculation when all tests are ineffective."""
        tests = [
            ControlTest(
                control_type=ControlType.WAF,
                test_payload="test",
                expected_behavior="block",
                effectiveness=ControlEffectiveness.INEFFECTIVE
            )
            for _ in range(3)
        ]
        
        effectiveness = self.verifier._calculate_overall_effectiveness(tests)
        self.assertEqual(effectiveness, ControlEffectiveness.INEFFECTIVE)
    
    def test_calculate_confidence(self):
        """Test confidence calculation."""
        tests = [
            ControlTest(
                control_type=ControlType.WAF,
                test_payload="test",
                expected_behavior="block",
                effectiveness=ControlEffectiveness.EFFECTIVE
            )
            for _ in range(3)
        ]
        
        confidence = self.verifier._calculate_confidence(tests)
        self.assertGreater(confidence, 0.8)  # High confidence with 3 consistent tests
    
    def test_generate_recommendations_ineffective(self):
        """Test recommendation generation for ineffective controls."""
        tests = [
            ControlTest(
                control_type=ControlType.WAF,
                test_payload="test",
                expected_behavior="block",
                effectiveness=ControlEffectiveness.INEFFECTIVE
            )
        ]
        
        recommendations = self.verifier._generate_recommendations(tests, 'sql_injection')
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any('not effectively blocking' in r for r in recommendations))
    
    def test_generate_recommendations_effective(self):
        """Test recommendation generation for effective controls."""
        tests = [
            ControlTest(
                control_type=ControlType.WAF,
                test_payload="test",
                expected_behavior="block",
                effectiveness=ControlEffectiveness.EFFECTIVE
            )
        ]
        
        recommendations = self.verifier._generate_recommendations(tests, 'sql_injection')
        
        self.assertGreater(len(recommendations), 0)
        self.assertTrue(any('appear effective' in r for r in recommendations))
    
    @pytest.mark.asyncio
    @patch('requests.get')
    async def test_test_payload_blocked(self, mock_get):
        """Test payload testing when request is blocked."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Blocked by WAF"
        mock_get.return_value = mock_response

        test = await self.verifier._test_payload('http://example.com', "' OR '1'='1", 'sql_injection')

        self.assertEqual(test.effectiveness, ControlEffectiveness.EFFECTIVE)
        self.assertIn('blocked', test.details.lower())
    
    @pytest.mark.asyncio
    @patch('requests.get')
    async def test_test_payload_not_blocked(self, mock_get):
        """Test payload testing when request is not blocked."""
        payload = "' OR '1'='1"
        mock_response = Mock()
        mock_response.status_code = 200
        # Include payload in response to show it wasn't sanitized
        mock_response.text = f"Welcome {payload}"
        mock_get.return_value = mock_response

        test = await self.verifier._test_payload('http://example.com', payload, 'sql_injection')

        self.assertEqual(test.effectiveness, ControlEffectiveness.INEFFECTIVE)
    
    @pytest.mark.asyncio
    @patch('requests.get')
    async def test_verify_controls_integration(self, mock_get):
        """Test full control verification workflow."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Blocked by security control"
        mock_get.return_value = mock_response

        result = await self.verifier.verify_controls('http://example.com', 'sql_injection')

        self.assertIsInstance(result, ControlVerificationResult)
        self.assertGreater(len(result.controls_tested), 0)
        self.assertTrue(result.vulnerability_blocked)
        self.assertGreater(result.confidence, 0.0)
    
    @pytest.mark.asyncio
    @patch('requests.get')
    async def test_verify_controls_with_poc(self, mock_get):
        """Test control verification with PoC payload."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Not blocked"
        mock_get.return_value = mock_response

        result = await self.verifier.verify_controls(
            'http://example.com',
            'sql_injection',
            poc_payload="custom' OR '1'='1"
        )

        # First test should use the PoC payload
        self.assertEqual(result.controls_tested[0].test_payload, "custom' OR '1'='1")


if __name__ == '__main__':
    unittest.main()

