import pytest
from bountybot.extractors import HTTPRequestExtractor, HTTPRequest
from bountybot.models import Report


class TestHTTPRequestExtractor:
    """Test HTTP request extraction functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.extractor = HTTPRequestExtractor()
    
    def test_extract_raw_http_request(self):
        """Test extraction of raw HTTP request."""
        text = """
POST /api/users HTTP/1.1
Host: example.com
Content-Type: application/json
Authorization: Bearer token123

{"username": "test", "password": "pass123"}
"""
        requests = self.extractor._extract_raw_http(text)
        
        assert len(requests) == 1
        req = requests[0]
        assert req.method == "POST"
        assert req.url == "https://example.com/api/users"
        assert req.headers["Content-Type"] == "application/json"
        assert req.body == '{"username": "test", "password": "pass123"}'
        assert req.extraction_confidence == 0.95
    
    def test_extract_curl_command(self):
        """Test extraction of curl command."""
        text = """
curl -X POST https://example.com/api/search \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer abc123' \
  -d '{"query": "test"}'
"""
        requests = self.extractor._extract_curl(text)
        
        assert len(requests) == 1
        req = requests[0]
        assert req.method == "POST"
        assert req.url == "https://example.com/api/search"
        assert req.headers["Content-Type"] == "application/json"
        assert req.body == '{"query": "test"}'
        assert req.extraction_confidence == 0.90
    
    def test_extract_simple_url(self):
        """Test extraction of simple URL."""
        text = "Visit https://example.com/api/users?id=123&admin=true for more info"
        
        requests = self.extractor._extract_urls(text)
        
        assert len(requests) == 1
        req = requests[0]
        assert req.method == "GET"
        assert req.url == "https://example.com/api/users?id=123&admin=true"
        assert "id" in req.query_params
        assert req.extraction_confidence == 0.70
    
    def test_identify_sql_injection_payload(self):
        """Test identification of SQL injection payload."""
        text = "' OR '1'='1"
        assert self.extractor._looks_like_payload(text) is True
        
        text = "UNION SELECT username, password FROM users"
        assert self.extractor._looks_like_payload(text) is True
    
    def test_identify_xss_payload(self):
        """Test identification of XSS payload."""
        text = "<script>alert('xss')</script>"
        assert self.extractor._looks_like_payload(text) is True
        
        text = "javascript:alert(1)"
        assert self.extractor._looks_like_payload(text) is True
        
        text = "<img src=x onerror=alert(1)>"
        assert self.extractor._looks_like_payload(text) is True
    
    def test_identify_command_injection_payload(self):
        """Test identification of command injection payload."""
        text = "; cat /etc/passwd"
        assert self.extractor._looks_like_payload(text) is True
        
        text = "| whoami"
        assert self.extractor._looks_like_payload(text) is False  # Simple pipe not detected
    
    def test_validate_valid_request(self):
        """Test validation of valid HTTP request."""
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/users",
            headers={"Content-Type": "application/json"},
            body='{"test": "data"}'
        )
        
        is_valid, issues = self.extractor.validate_request(request)
        assert is_valid is True
        assert len(issues) == 0
    
    def test_validate_invalid_method(self):
        """Test validation of invalid HTTP method."""
        request = HTTPRequest(
            method="INVALID",
            url="https://example.com/api/users"
        )
        
        is_valid, issues = self.extractor.validate_request(request)
        assert is_valid is False
        assert any("Invalid HTTP method" in issue for issue in issues)
    
    def test_validate_missing_content_type(self):
        """Test validation of POST request without Content-Type."""
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/users",
            body='{"test": "data"}'
        )
        
        is_valid, issues = self.extractor.validate_request(request)
        assert is_valid is False
        assert any("Content-Type" in issue for issue in issues)
    
    def test_validate_missing_url_scheme(self):
        """Test validation of URL without scheme."""
        request = HTTPRequest(
            method="GET",
            url="example.com/api/users"
        )
        
        is_valid, issues = self.extractor.validate_request(request)
        assert is_valid is False
        assert any("missing scheme" in issue for issue in issues)
    
    def test_extract_from_report(self):
        """Test extraction from complete report."""
        report = Report(
            title="SQL Injection Test",
            proof_of_concept="""
curl -X POST https://example.com/api/search \
  -H 'Content-Type: application/json' \
  -d '{"query": "' OR '1'='1"}'
""",
            reproduction_steps=[
                "Navigate to https://example.com/search?q=test",
                "Submit the payload"
            ]
        )
        
        requests = self.extractor.extract_from_report(report)
        
        # Should extract curl command and URL from steps
        assert len(requests) >= 1
        assert any(req.method == "POST" for req in requests)
    
    def test_deduplicate_requests(self):
        """Test deduplication of identical requests."""
        req1 = HTTPRequest(method="GET", url="https://example.com/api/users")
        req2 = HTTPRequest(method="GET", url="https://example.com/api/users")
        req3 = HTTPRequest(method="POST", url="https://example.com/api/users")
        
        requests = [req1, req2, req3]
        unique = self.extractor._deduplicate_requests(requests)
        
        assert len(unique) == 2  # req1 and req2 are duplicates
    
    def test_to_curl_conversion(self):
        """Test conversion of HTTPRequest to curl command."""
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/users",
            headers={"Content-Type": "application/json", "Authorization": "Bearer token"},
            body='{"test": "data"}'
        )
        
        curl = request.to_curl()
        
        assert "curl" in curl
        assert "-X POST" in curl
        assert "https://example.com/api/users" in curl
        assert "Content-Type: application/json" in curl
        assert "Authorization: Bearer token" in curl
        assert '{"test": "data"}' in curl
    
    def test_to_python_requests_conversion(self):
        """Test conversion of HTTPRequest to Python requests code."""
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/users",
            headers={"Content-Type": "application/json"},
            body='{"test": "data"}'
        )
        
        python_code = request.to_python_requests()
        
        assert "import requests" in python_code
        assert "requests.post" in python_code
        assert "https://example.com/api/users" in python_code
        assert "headers=headers" in python_code
    
    def test_payload_location_detection(self):
        """Test detection of payload locations in request."""
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/search?q=' OR '1'='1",
            headers={"X-Custom": "<script>alert(1)</script>"},
            body='{"query": "UNION SELECT * FROM users"}',
            cookies={"session": "abc123"}
        )
        
        locations = self.extractor._identify_payload_locations(request)
        
        # Should detect payloads in query param, header, and body
        assert any("query_param" in loc for loc in locations)
        assert any("header" in loc for loc in locations)
        assert "body" in locations
    
    def test_extract_multiple_curl_commands(self):
        """Test extraction of multiple curl commands from text."""
        text = """
First request:
curl https://example.com/api/users

Second request:
curl -X POST https://example.com/api/login -d 'user=admin'
"""
        requests = self.extractor._extract_curl(text)
        
        assert len(requests) == 2
        assert requests[0].method == "GET"
        assert requests[1].method == "POST"
    
    def test_extract_with_cookies(self):
        """Test extraction of request with cookies."""
        text = """
curl https://example.com/api/users \
  -b 'session_id=abc123; user_token=xyz789'
"""
        requests = self.extractor._extract_curl(text)
        
        assert len(requests) == 1
        req = requests[0]
        assert "session_id" in req.cookies
        assert req.cookies["session_id"] == "abc123"
        assert "user_token" in req.cookies


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

