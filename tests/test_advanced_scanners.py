import pytest
from unittest.mock import Mock, patch, MagicMock
import base64
import json

from bountybot.scanners.dynamic_scanner import DynamicScanner, ScanResult, ScanFinding, ScanSeverity


class TestSSTIScanner:
    """Test Server-Side Template Injection scanner."""

    def setup_method(self):
        """Set up test fixtures."""
        config = {'timeout': 5, 'max_requests': 10}
        self.scanner = DynamicScanner(config)
    
    def test_ssti_detection_jinja2(self):
        """Test SSTI detection with Jinja2 payload."""
        result = ScanResult(target_url="http://example.com/test", scan_duration=0)
        
        # Mock response with evaluated template expression
        with patch.object(self.scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.text = "Result: 49"  # 7*7 = 49
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            self.scanner._scan_ssti("http://example.com/test?name=test", result)
            
            assert len(result.findings) > 0
            finding = result.findings[0]
            assert finding.vulnerability_type == "SSTI"
            assert finding.severity == ScanSeverity.CRITICAL
            assert finding.confidence >= 90
    
    def test_ssti_no_vulnerability(self):
        """Test SSTI scanner with no vulnerability."""
        result = ScanResult(target_url="http://example.com/test", scan_duration=0)
        
        with patch.object(self.scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.text = "Result: {{7*7}}"  # Not evaluated
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            self.scanner._scan_ssti("http://example.com/test?name=test", result)
            
            assert len(result.findings) == 0
    
    def test_ssti_multiple_payloads(self):
        """Test SSTI with multiple template engines."""
        result = ScanResult(target_url="http://example.com/test", scan_duration=0)
        
        # Test different payload formats
        payloads_tested = []
        
        def mock_get_side_effect(url, **kwargs):
            params = kwargs.get('params', {})
            for key, value in params.items():
                if isinstance(value, list):
                    payloads_tested.append(value[0])
            
            mock_response = Mock()
            mock_response.text = "No template"
            mock_response.status_code = 200
            return mock_response
        
        with patch.object(self.scanner.session, 'get', side_effect=mock_get_side_effect):
            self.scanner._scan_ssti("http://example.com/test?name=test", result)
            
            # Verify multiple payloads were tested
            assert len(payloads_tested) > 0
            assert any('{{' in p for p in payloads_tested)
            assert any('${' in p for p in payloads_tested)


class TestXXEScanner:
    """Test XML External Entity scanner."""

    def setup_method(self):
        """Set up test fixtures."""
        config = {'timeout': 5, 'max_requests': 10}
        self.scanner = DynamicScanner(config)
    
    def test_xxe_detection(self):
        """Test XXE detection with file read."""
        result = ScanResult(target_url="http://example.com/api", scan_duration=0)
        
        with patch.object(self.scanner.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.text = "hostname: localhost"  # File content leaked
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            
            self.scanner._scan_xxe("http://example.com/api", result)
            
            assert len(result.findings) > 0
            finding = result.findings[0]
            assert finding.vulnerability_type == "XXE"
            assert finding.severity == ScanSeverity.HIGH
            assert finding.confidence >= 80
    
    def test_xxe_parser_error(self):
        """Test XXE detection via parser error."""
        result = ScanResult(target_url="http://example.com/api", scan_duration=0)
        
        with patch.object(self.scanner.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.text = "XML parsing error: External entity not allowed"
            mock_response.status_code = 400
            mock_post.return_value = mock_response
            
            self.scanner._scan_xxe("http://example.com/api", result)
            
            assert len(result.findings) > 0
            assert "XXE" in result.findings[0].vulnerability_type
    
    def test_xxe_no_vulnerability(self):
        """Test XXE scanner with secure parser."""
        result = ScanResult(target_url="http://example.com/api", scan_duration=0)
        
        with patch.object(self.scanner.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.text = "<root><data>test</data></root>"
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            
            self.scanner._scan_xxe("http://example.com/api", result)
            
            assert len(result.findings) == 0
    
    def test_xxe_content_type_header(self):
        """Test XXE sends correct Content-Type header."""
        result = ScanResult(target_url="http://example.com/api", scan_duration=0)
        
        with patch.object(self.scanner.session, 'post') as mock_post:
            mock_response = Mock()
            mock_response.text = "OK"
            mock_response.status_code = 200
            mock_post.return_value = mock_response
            
            self.scanner._scan_xxe("http://example.com/api", result)
            
            # Verify Content-Type header was set
            assert mock_post.called
            call_kwargs = mock_post.call_args[1]
            assert 'headers' in call_kwargs
            assert call_kwargs['headers']['Content-Type'] == 'application/xml'


class TestJWTScanner:
    """Test JWT vulnerability scanner."""

    def setup_method(self):
        """Set up test fixtures."""
        config = {'timeout': 5, 'max_requests': 10}
        self.scanner = DynamicScanner(config)
    
    def create_jwt(self, header, payload):
        """Helper to create a JWT token."""
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip('=')
        return f"{header_b64}.{payload_b64}.fake_signature"
    
    def test_jwt_none_algorithm(self):
        """Test detection of 'none' algorithm vulnerability."""
        result = ScanResult(target_url="http://example.com/api", scan_duration=0)
        
        jwt_token = self.create_jwt(
            {"alg": "none", "typ": "JWT"},
            {"sub": "user123", "role": "admin"}
        )
        
        with patch.object(self.scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.text = f"Token: {jwt_token}"
            mock_response.headers = {}
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            self.scanner._scan_jwt("http://example.com/api", result)
            
            assert len(result.findings) > 0
            # Find the 'none' algorithm finding
            none_findings = [f for f in result.findings if 'Algorithm None' in f.vulnerability_type]
            assert len(none_findings) > 0
            assert none_findings[0].severity == ScanSeverity.CRITICAL
    
    def test_jwt_weak_algorithm(self):
        """Test detection of weak HMAC algorithms."""
        result = ScanResult(target_url="http://example.com/api", scan_duration=0)
        
        jwt_token = self.create_jwt(
            {"alg": "HS256", "typ": "JWT"},
            {"sub": "user123", "exp": 9999999999}
        )
        
        with patch.object(self.scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.text = f"Token: {jwt_token}"
            mock_response.headers = {}
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            self.scanner._scan_jwt("http://example.com/api", result)
            
            weak_alg_findings = [f for f in result.findings if 'Weak Algorithm' in f.vulnerability_type]
            assert len(weak_alg_findings) > 0
    
    def test_jwt_missing_expiration(self):
        """Test detection of missing expiration claim."""
        result = ScanResult(target_url="http://example.com/api", scan_duration=0)
        
        jwt_token = self.create_jwt(
            {"alg": "RS256", "typ": "JWT"},
            {"sub": "user123", "role": "user"}  # No 'exp' claim
        )
        
        with patch.object(self.scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.text = f"Token: {jwt_token}"
            mock_response.headers = {}
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            self.scanner._scan_jwt("http://example.com/api", result)
            
            exp_findings = [f for f in result.findings if 'Missing Expiration' in f.vulnerability_type]
            assert len(exp_findings) > 0
    
    def test_jwt_sensitive_data(self):
        """Test detection of sensitive data in JWT payload."""
        result = ScanResult(target_url="http://example.com/api", scan_duration=0)
        
        jwt_token = self.create_jwt(
            {"alg": "RS256", "typ": "JWT"},
            {"sub": "user123", "password": "secret123", "exp": 9999999999}
        )
        
        with patch.object(self.scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.text = f"Token: {jwt_token}"
            mock_response.headers = {}
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            self.scanner._scan_jwt("http://example.com/api", result)
            
            sensitive_findings = [f for f in result.findings if 'Sensitive Data' in f.vulnerability_type]
            assert len(sensitive_findings) > 0
            assert sensitive_findings[0].severity == ScanSeverity.HIGH
    
    def test_jwt_from_authorization_header(self):
        """Test JWT extraction from Authorization header."""
        result = ScanResult(target_url="http://example.com/api", scan_duration=0)
        
        jwt_token = self.create_jwt(
            {"alg": "RS256", "typ": "JWT"},
            {"sub": "user123", "exp": 9999999999}
        )
        
        with patch.object(self.scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.text = "OK"
            mock_response.headers = {'Authorization': f'Bearer {jwt_token}'}
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            self.scanner._scan_jwt("http://example.com/api", result)
            
            # Should have analyzed the token
            assert result.requests_sent > 0
    
    def test_jwt_no_token_found(self):
        """Test JWT scanner when no token is present."""
        result = ScanResult(target_url="http://example.com/api", scan_duration=0)
        
        with patch.object(self.scanner.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.text = "No JWT here"
            mock_response.headers = {}
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            self.scanner._scan_jwt("http://example.com/api", result)
            
            # Should not find any vulnerabilities
            assert len(result.findings) == 0


class TestIntegratedScanning:
    """Test integrated scanning with all new vulnerability types."""

    def setup_method(self):
        """Set up test fixtures."""
        config = {'timeout': 5, 'max_requests': 50}
        self.scanner = DynamicScanner(config)
    
    def test_scan_with_all_types(self):
        """Test scanning with all vulnerability types enabled."""
        scan_types = ['sqli', 'xss', 'cmdi', 'path_traversal', 'ssrf', 'open_redirect', 'ssti', 'xxe', 'jwt']
        
        with patch.object(self.scanner, '_verify_target', return_value=True):
            with patch.object(self.scanner, '_scan_sql_injection'):
                with patch.object(self.scanner, '_scan_xss'):
                    with patch.object(self.scanner, '_scan_command_injection'):
                        with patch.object(self.scanner, '_scan_path_traversal'):
                            with patch.object(self.scanner, '_scan_ssrf'):
                                with patch.object(self.scanner, '_scan_open_redirect'):
                                    with patch.object(self.scanner, '_scan_ssti'):
                                        with patch.object(self.scanner, '_scan_xxe'):
                                            with patch.object(self.scanner, '_scan_jwt'):
                                                result = self.scanner.scan("http://example.com", scan_types)
                                                
                                                assert result.target_url == "http://example.com"
                                                assert result.scan_types == scan_types
    
    def test_scan_type_selection(self):
        """Test that only selected scan types are executed."""
        scan_types = ['ssti', 'xxe', 'jwt']
        
        with patch.object(self.scanner, '_verify_target', return_value=True):
            with patch.object(self.scanner, '_scan_ssti') as mock_ssti:
                with patch.object(self.scanner, '_scan_xxe') as mock_xxe:
                    with patch.object(self.scanner, '_scan_jwt') as mock_jwt:
                        with patch.object(self.scanner, '_scan_sql_injection') as mock_sqli:
                            result = self.scanner.scan("http://example.com", scan_types)
                            
                            # New scanners should be called
                            assert mock_ssti.called
                            assert mock_xxe.called
                            assert mock_jwt.called
                            
                            # Old scanners should not be called
                            assert not mock_sqli.called

