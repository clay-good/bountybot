import unittest
from unittest.mock import Mock, patch, MagicMock
import requests

from bountybot.scanners import DynamicScanner, ScanResult
from bountybot.scanners.dynamic_scanner import ScanSeverity, ScanFinding


class TestDynamicScanner(unittest.TestCase):
    """Tests for dynamic security scanner."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.config = {
            'timeout': 5,
            'max_requests': 50,
            'delay': 0.1,
            'verify_ssl': False,
        }
        self.scanner = DynamicScanner(self.config)
    
    def tearDown(self):
        """Clean up."""
        self.scanner.close()
    
    def test_scanner_initialization(self):
        """Test scanner initializes correctly."""
        self.assertEqual(self.scanner.timeout, 5)
        self.assertEqual(self.scanner.max_requests, 50)
        self.assertEqual(self.scanner.delay_between_requests, 0.1)
        self.assertFalse(self.scanner.verify_ssl)
        self.assertIsNotNone(self.scanner.session)
    
    @patch('bountybot.scanners.dynamic_scanner.requests.Session')
    def test_verify_target_success(self, mock_session_class):
        """Test target verification succeeds."""
        mock_session = Mock()
        mock_response = Mock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        mock_session_class.return_value = mock_session
        
        scanner = DynamicScanner(self.config)
        scanner.session = mock_session
        
        result = scanner._verify_target("http://example.com")
        self.assertTrue(result)
    
    @patch('bountybot.scanners.dynamic_scanner.requests.Session')
    def test_verify_target_failure(self, mock_session_class):
        """Test target verification fails."""
        mock_session = Mock()
        mock_session.get.side_effect = requests.exceptions.ConnectionError()
        mock_session_class.return_value = mock_session
        
        scanner = DynamicScanner(self.config)
        scanner.session = mock_session
        
        result = scanner._verify_target("http://invalid.com")
        self.assertFalse(result)
    
    @patch('bountybot.scanners.dynamic_scanner.requests.Session')
    @patch('bountybot.scanners.dynamic_scanner.time.sleep')
    def test_sql_injection_detection(self, mock_sleep, mock_session_class):
        """Test SQL injection vulnerability detection."""
        mock_session = Mock()

        # Mock responses - need one for verify and one that triggers SQL error
        verify_response = Mock()
        verify_response.status_code = 200

        # Payload triggers SQL error (matches pattern: "SQL syntax.*MySQL")
        sqli_response = Mock()
        sqli_response.status_code = 200
        sqli_response.text = "Error: You have an error in your SQL syntax near 'OR 1=1' at line 1 - MySQL"

        # Return sqli_response for all subsequent requests
        mock_session.get.side_effect = [verify_response] + [sqli_response] * 10
        mock_session_class.return_value = mock_session

        scanner = DynamicScanner(self.config)
        scanner.session = mock_session

        result = scanner.scan("http://example.com?id=1", scan_types=['sqli'])

        self.assertGreater(len(result.findings), 0)
        self.assertEqual(result.findings[0].vulnerability_type, "SQL Injection")
        self.assertEqual(result.findings[0].severity, ScanSeverity.CRITICAL)
    
    @patch('bountybot.scanners.dynamic_scanner.requests.Session')
    def test_xss_detection(self, mock_session_class):
        """Test XSS vulnerability detection."""
        mock_session = Mock()
        
        verify_response = Mock()
        verify_response.status_code = 200
        
        xss_response = Mock()
        xss_response.status_code = 200
        xss_response.text = "<script>alert('XSS')</script>"
        
        mock_session.get.side_effect = [verify_response, xss_response]
        mock_session_class.return_value = mock_session
        
        scanner = DynamicScanner(self.config)
        scanner.session = mock_session
        
        result = scanner.scan("http://example.com?search=test", scan_types=['xss'])
        
        self.assertGreater(len(result.findings), 0)
        self.assertEqual(result.findings[0].vulnerability_type, "Cross-Site Scripting (XSS)")
        self.assertEqual(result.findings[0].severity, ScanSeverity.HIGH)
    
    @patch('bountybot.scanners.dynamic_scanner.requests.Session')
    def test_command_injection_detection(self, mock_session_class):
        """Test command injection vulnerability detection."""
        mock_session = Mock()
        
        verify_response = Mock()
        verify_response.status_code = 200
        
        cmdi_response = Mock()
        cmdi_response.status_code = 200
        cmdi_response.text = "vulnerable"
        
        mock_session.get.side_effect = [verify_response, cmdi_response]
        mock_session_class.return_value = mock_session
        
        scanner = DynamicScanner(self.config)
        scanner.session = mock_session
        
        result = scanner.scan("http://example.com?cmd=ls", scan_types=['cmdi'])
        
        self.assertGreater(len(result.findings), 0)
        self.assertEqual(result.findings[0].vulnerability_type, "Command Injection")
        self.assertEqual(result.findings[0].severity, ScanSeverity.CRITICAL)
    
    @patch('bountybot.scanners.dynamic_scanner.requests.Session')
    def test_path_traversal_detection(self, mock_session_class):
        """Test path traversal vulnerability detection."""
        mock_session = Mock()
        
        verify_response = Mock()
        verify_response.status_code = 200
        
        path_response = Mock()
        path_response.status_code = 200
        path_response.text = "root:x:0:0:root:/root:/bin/bash"
        
        mock_session.get.side_effect = [verify_response, path_response]
        mock_session_class.return_value = mock_session
        
        scanner = DynamicScanner(self.config)
        scanner.session = mock_session
        
        result = scanner.scan("http://example.com?file=test.txt", scan_types=['path_traversal'])
        
        self.assertGreater(len(result.findings), 0)
        self.assertEqual(result.findings[0].vulnerability_type, "Path Traversal")
        self.assertEqual(result.findings[0].severity, ScanSeverity.HIGH)
    
    @patch('bountybot.scanners.dynamic_scanner.requests.Session')
    def test_open_redirect_detection(self, mock_session_class):
        """Test open redirect vulnerability detection."""
        mock_session = Mock()
        
        verify_response = Mock()
        verify_response.status_code = 200
        
        redirect_response = Mock()
        redirect_response.status_code = 302
        redirect_response.headers = {'Location': 'https://evil.com'}
        
        mock_session.get.side_effect = [verify_response, redirect_response]
        mock_session_class.return_value = mock_session
        
        scanner = DynamicScanner(self.config)
        scanner.session = mock_session
        
        result = scanner.scan("http://example.com?redirect=/home", scan_types=['open_redirect'])
        
        self.assertGreater(len(result.findings), 0)
        self.assertEqual(result.findings[0].vulnerability_type, "Open Redirect")
        self.assertEqual(result.findings[0].severity, ScanSeverity.MEDIUM)
    
    @patch('bountybot.scanners.dynamic_scanner.requests.Session')
    def test_no_vulnerabilities_found(self, mock_session_class):
        """Test scan with no vulnerabilities."""
        mock_session = Mock()
        
        safe_response = Mock()
        safe_response.status_code = 200
        safe_response.text = "Safe response"
        
        mock_session.get.return_value = safe_response
        mock_session_class.return_value = mock_session
        
        scanner = DynamicScanner(self.config)
        scanner.session = mock_session
        
        result = scanner.scan("http://example.com?id=1", scan_types=['sqli', 'xss'])
        
        self.assertEqual(len(result.findings), 0)
        self.assertGreater(result.requests_sent, 0)
    
    @patch('bountybot.scanners.dynamic_scanner.requests.Session')
    def test_max_requests_limit(self, mock_session_class):
        """Test max requests limit is enforced."""
        mock_session = Mock()
        
        response = Mock()
        response.status_code = 200
        response.text = "Safe"
        
        mock_session.get.return_value = response
        mock_session_class.return_value = mock_session
        
        config = self.config.copy()
        config['max_requests'] = 5
        scanner = DynamicScanner(config)
        scanner.session = mock_session
        
        result = scanner.scan("http://example.com?id=1", scan_types=['sqli', 'xss'])
        
        self.assertLessEqual(result.requests_sent, 5)
    
    def test_scan_result_to_dict(self):
        """Test ScanResult serialization."""
        finding = ScanFinding(
            vulnerability_type="SQL Injection",
            severity=ScanSeverity.CRITICAL,
            url="http://example.com",
            method="GET",
            parameter="id",
            payload="' OR '1'='1",
            evidence="SQL error detected",
            description="SQL injection found",
            remediation="Use prepared statements",
            confidence=90,
        )
        
        result = ScanResult(
            target_url="http://example.com",
            scan_duration=10.5,
            findings=[finding],
            requests_sent=25,
            scan_types=['sqli', 'xss'],
        )
        
        result_dict = result.to_dict()
        
        self.assertEqual(result_dict['target_url'], "http://example.com")
        self.assertEqual(result_dict['scan_duration'], 10.5)
        self.assertEqual(result_dict['findings_count'], 1)
        self.assertEqual(result_dict['requests_sent'], 25)
        self.assertIn('severity_breakdown', result_dict)
        self.assertEqual(result_dict['severity_breakdown']['CRITICAL'], 1)


if __name__ == '__main__':
    unittest.main()

