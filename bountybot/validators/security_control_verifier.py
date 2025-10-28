"""
Security Control Verifier - Tests effectiveness of security controls.

This module verifies that security controls (WAF, IPS, input validation, etc.)
actually protect against reported vulnerabilities by testing them with attack payloads.
"""

import logging
import asyncio
import requests
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ControlType(Enum):
    """Types of security controls."""
    WAF = "waf"
    IPS = "ips"
    INPUT_VALIDATION = "input_validation"
    OUTPUT_ENCODING = "output_encoding"
    RATE_LIMITING = "rate_limiting"
    CSRF_PROTECTION = "csrf_protection"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"


class ControlEffectiveness(Enum):
    """Effectiveness levels of security controls."""
    EFFECTIVE = "effective"  # Control blocks attack
    PARTIALLY_EFFECTIVE = "partially_effective"  # Control reduces impact
    INEFFECTIVE = "ineffective"  # Control doesn't block attack
    NOT_PRESENT = "not_present"  # Control not found
    ERROR = "error"  # Error testing control


@dataclass
class ControlTest:
    """Represents a test of a security control."""
    control_type: ControlType
    test_payload: str
    expected_behavior: str  # What should happen if control is effective
    actual_behavior: str = ""
    effectiveness: ControlEffectiveness = ControlEffectiveness.NOT_PRESENT
    details: str = ""


@dataclass
class ControlVerificationResult:
    """Results from security control verification."""
    controls_tested: List[ControlTest]
    overall_effectiveness: ControlEffectiveness
    vulnerability_blocked: bool
    confidence: float
    recommendations: List[str] = field(default_factory=list)


class SecurityControlVerifier:
    """
    Verifies effectiveness of security controls against reported vulnerabilities.
    """
    
    # Test payloads for different vulnerability types
    TEST_PAYLOADS = {
        'sql_injection': [
            "' OR '1'='1",
            "1' UNION SELECT NULL--",
            "admin'--",
            "1; DROP TABLE users--",
        ],
        'xss': [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
        ],
        'command_injection': [
            "; ls -la",
            "| cat /etc/passwd",
            "`whoami`",
            "$(id)",
        ],
        'path_traversal': [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
        ],
        'ssrf': [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:22",
            "file:///etc/passwd",
        ],
    }
    
    # Indicators that a control is blocking attacks
    BLOCK_INDICATORS = [
        'blocked', 'forbidden', '403', '406', 'not acceptable',
        'security', 'firewall', 'waf', 'rejected', 'denied',
        'invalid input', 'malicious', 'suspicious'
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize security control verifier."""
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.verify_ssl = self.config.get('verify_ssl', True)
        self.max_tests = self.config.get('max_tests_per_type', 3)
    
    async def verify_controls(self, target_url: str, vulnerability_type: str,
                             poc_payload: Optional[str] = None) -> ControlVerificationResult:
        """
        Verify security controls for a specific vulnerability.
        
        Args:
            target_url: Target URL to test
            vulnerability_type: Type of vulnerability
            poc_payload: Proof-of-concept payload from report
        
        Returns:
            ControlVerificationResult with test results
        """
        logger.info(f"Verifying security controls for {vulnerability_type} at {target_url}")
        
        controls_tested = []
        
        # Get test payloads
        payloads = self._get_test_payloads(vulnerability_type, poc_payload)
        
        # Test each payload
        for payload in payloads[:self.max_tests]:
            test = await self._test_payload(target_url, payload, vulnerability_type)
            controls_tested.append(test)
        
        # Analyze results
        overall_effectiveness = self._calculate_overall_effectiveness(controls_tested)
        vulnerability_blocked = overall_effectiveness in [
            ControlEffectiveness.EFFECTIVE,
            ControlEffectiveness.PARTIALLY_EFFECTIVE
        ]
        confidence = self._calculate_confidence(controls_tested)
        recommendations = self._generate_recommendations(controls_tested, vulnerability_type)
        
        return ControlVerificationResult(
            controls_tested=controls_tested,
            overall_effectiveness=overall_effectiveness,
            vulnerability_blocked=vulnerability_blocked,
            confidence=confidence,
            recommendations=recommendations
        )
    
    async def _test_payload(self, target_url: str, payload: str,
                           vulnerability_type: str) -> ControlTest:
        """
        Test a single payload against the target.
        
        Args:
            target_url: Target URL
            payload: Attack payload to test
            vulnerability_type: Type of vulnerability
        
        Returns:
            ControlTest with results
        """
        test = ControlTest(
            control_type=ControlType.WAF,  # Assume WAF for now
            test_payload=payload,
            expected_behavior="Request should be blocked or sanitized"
        )
        
        try:
            # Send request with payload
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    requests.get,
                    target_url,
                    params={'test': payload},
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False
                ),
                timeout=self.timeout
            )
            
            test.actual_behavior = f"Status: {response.status_code}"
            
            # Check if blocked
            if self._is_blocked(response):
                test.effectiveness = ControlEffectiveness.EFFECTIVE
                test.details = "Request was blocked by security control"
            elif self._is_sanitized(response, payload):
                test.effectiveness = ControlEffectiveness.PARTIALLY_EFFECTIVE
                test.details = "Payload was sanitized but request allowed"
            else:
                test.effectiveness = ControlEffectiveness.INEFFECTIVE
                test.details = "Payload was not blocked or sanitized"
        
        except asyncio.TimeoutError:
            test.effectiveness = ControlEffectiveness.ERROR
            test.actual_behavior = "Request timed out"
            test.details = "Could not complete test due to timeout"
        
        except Exception as e:
            test.effectiveness = ControlEffectiveness.ERROR
            test.actual_behavior = f"Error: {str(e)}"
            test.details = f"Test failed: {str(e)}"
        
        return test
    
    def _is_blocked(self, response: requests.Response) -> bool:
        """Check if response indicates request was blocked."""
        # Check status code
        if response.status_code in [403, 406, 429]:
            return True
        
        # Check response body for block indicators
        response_text = response.text.lower()
        return any(indicator in response_text for indicator in self.BLOCK_INDICATORS)
    
    def _is_sanitized(self, response: requests.Response, payload: str) -> bool:
        """Check if payload was sanitized in response."""
        # If payload doesn't appear in response, it may have been sanitized
        if payload not in response.text:
            return True
        
        # Check for HTML encoding
        import html
        if html.escape(payload) in response.text:
            return True
        
        return False
    
    def _get_test_payloads(self, vulnerability_type: str,
                          poc_payload: Optional[str]) -> List[str]:
        """Get test payloads for vulnerability type."""
        vuln_key = vulnerability_type.lower().replace(' ', '_').replace('-', '_')
        payloads = self.TEST_PAYLOADS.get(vuln_key, [])
        
        # Add PoC payload if provided
        if poc_payload:
            payloads = [poc_payload] + payloads
        
        return payloads
    
    def _calculate_overall_effectiveness(self, tests: List[ControlTest]) -> ControlEffectiveness:
        """Calculate overall effectiveness from test results."""
        if not tests:
            return ControlEffectiveness.NOT_PRESENT
        
        # Count effectiveness levels
        effective_count = sum(1 for t in tests if t.effectiveness == ControlEffectiveness.EFFECTIVE)
        partial_count = sum(1 for t in tests if t.effectiveness == ControlEffectiveness.PARTIALLY_EFFECTIVE)
        ineffective_count = sum(1 for t in tests if t.effectiveness == ControlEffectiveness.INEFFECTIVE)
        
        total_valid_tests = effective_count + partial_count + ineffective_count
        
        if total_valid_tests == 0:
            return ControlEffectiveness.ERROR
        
        # If all tests blocked, control is effective
        if effective_count == total_valid_tests:
            return ControlEffectiveness.EFFECTIVE
        
        # If most tests blocked, partially effective
        if effective_count + partial_count >= total_valid_tests * 0.5:
            return ControlEffectiveness.PARTIALLY_EFFECTIVE
        
        # Otherwise, ineffective
        return ControlEffectiveness.INEFFECTIVE
    
    def _calculate_confidence(self, tests: List[ControlTest]) -> float:
        """Calculate confidence in verification results."""
        if not tests:
            return 0.0
        
        valid_tests = [t for t in tests if t.effectiveness != ControlEffectiveness.ERROR]
        if not valid_tests:
            return 0.0
        
        # Base confidence on number of tests and consistency
        base_confidence = min(len(valid_tests) / 3.0, 1.0)  # Max confidence with 3+ tests
        
        # Check consistency
        effectiveness_values = [t.effectiveness for t in valid_tests]
        if len(set(effectiveness_values)) == 1:
            # All tests agree - high confidence
            base_confidence = min(base_confidence + 0.2, 1.0)
        
        return base_confidence
    
    def _generate_recommendations(self, tests: List[ControlTest],
                                 vulnerability_type: str) -> List[str]:
        """Generate security recommendations based on test results."""
        recommendations = []
        
        effective_count = sum(1 for t in tests if t.effectiveness == ControlEffectiveness.EFFECTIVE)
        ineffective_count = sum(1 for t in tests if t.effectiveness == ControlEffectiveness.INEFFECTIVE)
        
        if ineffective_count > 0:
            recommendations.append(
                f"Security controls are not effectively blocking {vulnerability_type} attacks"
            )
            recommendations.append(
                "Consider implementing or strengthening WAF rules for this vulnerability type"
            )
        
        if effective_count > 0 and ineffective_count > 0:
            recommendations.append(
                "Controls are inconsistent - some payloads blocked, others not"
            )
            recommendations.append(
                "Review and update security rules to cover all attack variations"
            )
        
        if effective_count == len(tests):
            recommendations.append(
                "Security controls appear effective - verify reported vulnerability is not a false positive"
            )
        
        return recommendations

