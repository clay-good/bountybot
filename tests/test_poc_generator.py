import pytest
from bountybot.generators import PoCGenerator, ProofOfConcept
from bountybot.extractors import HTTPRequest
from bountybot.models import Report, Severity


class TestPoCGenerator:
    """Test PoC generation functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.generator = PoCGenerator()
    
    def test_generate_sql_injection_poc(self):
        """Test generation of SQL injection PoC."""
        report = Report(
            title="SQL Injection in User Search",
            vulnerability_type="SQL Injection",
            severity=Severity.HIGH,
            impact_description="Allows database access"
        )
        
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/search",
            headers={"Content-Type": "application/json"},
            body='{"query": "\' OR \'1\'=\'1"}',
            payload_locations=["body"]
        )
        
        poc = self.generator._generate_sql_injection_poc(report, request)
        
        assert poc.vulnerability_type == "SQL Injection"
        assert poc.curl_command is not None
        assert poc.python_code is not None
        assert "import requests" in poc.python_code
        assert len(poc.safety_notes) > 0
        assert len(poc.prerequisites) > 0
        assert poc.expected_result is not None
    
    def test_generate_xss_poc(self):
        """Test generation of XSS PoC."""
        report = Report(
            title="XSS in Comment Section",
            vulnerability_type="Cross-Site Scripting",
            severity=Severity.MEDIUM,
            impact_description="Allows JavaScript execution"
        )
        
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/comments",
            headers={"Content-Type": "application/json"},
            body='{"comment": "<script>alert(1)</script>"}',
            payload_locations=["body"]
        )
        
        poc = self.generator._generate_xss_poc(report, request)
        
        assert poc.vulnerability_type == "Cross-Site Scripting (XSS)"
        assert poc.curl_command is not None
        assert poc.python_code is not None
        assert poc.javascript_code is not None
        assert "fetch" in poc.javascript_code or "window.location" in poc.javascript_code
        assert len(poc.safety_notes) > 0
    
    def test_generate_csrf_poc(self):
        """Test generation of CSRF PoC."""
        report = Report(
            title="CSRF in Account Settings",
            vulnerability_type="CSRF",
            severity=Severity.MEDIUM,
            impact_description="Allows unauthorized actions"
        )
        
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/account/update",
            body="email=attacker@evil.com&password=newpass"
        )
        
        poc = self.generator._generate_csrf_poc(report, request)
        
        assert poc.vulnerability_type == "Cross-Site Request Forgery (CSRF)"
        assert poc.javascript_code is not None
        assert "<form" in poc.javascript_code
        assert "action=" in poc.javascript_code
        assert len(poc.prerequisites) > 0
    
    def test_generate_ssrf_poc(self):
        """Test generation of SSRF PoC."""
        report = Report(
            title="SSRF in Image Fetcher",
            vulnerability_type="SSRF",
            severity=Severity.HIGH,
            impact_description="Allows internal network access"
        )
        
        request = HTTPRequest(
            method="GET",
            url="https://example.com/api/fetch?url=http://internal.server",
            query_params={"url": ["http://internal.server"]}
        )
        
        poc = self.generator._generate_ssrf_poc(report, request)
        
        assert poc.vulnerability_type == "Server-Side Request Forgery (SSRF)"
        assert poc.python_code is not None
        assert "169.254.169.254" in poc.python_code  # AWS metadata
        assert len(poc.safety_notes) > 0
    
    def test_generate_generic_poc(self):
        """Test generation of generic PoC."""
        report = Report(
            title="Generic Vulnerability",
            vulnerability_type="Unknown",
            severity=Severity.LOW,
            impact_description="Some impact"
        )
        
        request = HTTPRequest(
            method="GET",
            url="https://example.com/api/test"
        )
        
        poc = self.generator._generate_generic_poc(report, request)
        
        assert poc.vulnerability_type == "Unknown"
        assert poc.curl_command is not None
        assert poc.python_code is not None
    
    def test_generate_minimal_poc_no_requests(self):
        """Test generation of minimal PoC when no requests available."""
        report = Report(
            title="Test Vulnerability",
            vulnerability_type="Test",
            proof_of_concept="Manual steps to reproduce"
        )
        
        poc = self.generator._generate_minimal_poc(report)
        
        assert poc.title == "PoC - Test Vulnerability"
        assert "Manual steps to reproduce" in poc.description
    
    def test_generate_with_template_based(self):
        """Test template-based PoC generation."""
        report = Report(
            title="SQL Injection Test",
            vulnerability_type="SQL Injection",
            severity=Severity.CRITICAL
        )
        
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/search",
            body='{"query": "test"}'
        )
        
        poc = self.generator.generate(report, [request])
        
        assert poc is not None
        assert poc.title is not None
        assert poc.curl_command is not None
    
    def test_poc_to_dict(self):
        """Test conversion of PoC to dictionary."""
        poc = ProofOfConcept(
            vulnerability_type="SQL Injection",
            title="Test PoC",
            description="Test description",
            curl_command="curl https://example.com",
            python_code="import requests",
            severity="High",
            prerequisites=["prereq1"],
            safety_notes=["note1"]
        )
        
        poc_dict = poc.to_dict()
        
        assert poc_dict["vulnerability_type"] == "SQL Injection"
        assert poc_dict["title"] == "Test PoC"
        assert poc_dict["curl_command"] == "curl https://example.com"
        assert len(poc_dict["prerequisites"]) == 1
        assert len(poc_dict["safety_notes"]) == 1
    
    def test_prepare_context(self):
        """Test context preparation for AI generation."""
        report = Report(
            title="Test Vulnerability",
            vulnerability_type="SQL Injection",
            severity=Severity.HIGH,
            impact_description="Database access",
            reproduction_steps=["Step 1", "Step 2"]
        )
        
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/test",
            payload_locations=["body"]
        )
        
        context = self.generator._prepare_context(report, [request], None)
        
        assert "Test Vulnerability" in context
        assert "SQL Injection" in context
        assert "Step 1" in context
        assert "POST" in context
        assert "https://example.com/api/test" in context
    
    def test_generate_multiple_requests(self):
        """Test PoC generation with multiple requests."""
        report = Report(
            title="Multi-Step Attack",
            vulnerability_type="Authentication Bypass",
            severity=Severity.CRITICAL
        )
        
        requests = [
            HTTPRequest(method="GET", url="https://example.com/api/login"),
            HTTPRequest(method="POST", url="https://example.com/api/login", body='{"user":"admin"}')
        ]
        
        poc = self.generator.generate(report, requests)
        
        assert poc is not None
        assert len(poc.http_requests) > 0
    
    def test_safety_notes_included(self):
        """Test that safety notes are always included."""
        report = Report(
            title="Test",
            vulnerability_type="SQL Injection",
            severity=Severity.HIGH
        )
        
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/test"
        )
        
        poc = self.generator._generate_sql_injection_poc(report, request)
        
        assert len(poc.safety_notes) > 0
        assert any("permission" in note.lower() for note in poc.safety_notes)
    
    def test_prerequisites_included(self):
        """Test that prerequisites are included."""
        report = Report(
            title="Test",
            vulnerability_type="XSS",
            severity=Severity.MEDIUM
        )
        
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/test"
        )
        
        poc = self.generator._generate_xss_poc(report, request)
        
        assert len(poc.prerequisites) > 0
    
    def test_expected_result_included(self):
        """Test that expected result is included."""
        report = Report(
            title="Test",
            vulnerability_type="SQL Injection",
            severity=Severity.HIGH
        )
        
        request = HTTPRequest(
            method="POST",
            url="https://example.com/api/test"
        )
        
        poc = self.generator._generate_sql_injection_poc(report, request)
        
        assert poc.expected_result is not None
        assert len(poc.expected_result) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

