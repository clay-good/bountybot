import pytest
from bountybot.validators.report_validator import ReportValidator
from bountybot.models import Report, Severity


class TestReportValidator:
    """Tests for report validator."""
    
    def test_validate_complete_report(self):
        """Test validation of complete report."""
        report = Report(
            title="SQL Injection in Login Endpoint",
            description="A SQL injection vulnerability was found in the login endpoint that allows attackers to bypass authentication.",
            steps_to_reproduce="1. Navigate to /login\n2. Enter username: admin' OR 1=1--\n3. Enter any password\n4. Click login",
            proof_of_concept="curl -X POST https://example.com/login -d \"username=admin' OR 1=1--&password=test\"",
            impact="Attackers can bypass authentication and gain unauthorized access to user accounts.",
            affected_component="/api/v1/login",
            vulnerability_type="sql injection",
            severity=Severity.HIGH
        )
        
        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)
        
        assert is_valid
        assert len(errors) == 0
        assert len(warnings) == 0
    
    def test_validate_minimal_report(self):
        """Test validation of minimal report."""
        report = Report(
            title="Bug",
            description="Short"
        )
        
        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)
        
        assert not is_valid
        assert len(errors) > 0
        assert len(warnings) > 0
    
    def test_validate_missing_title(self):
        """Test validation with missing title."""
        report = Report(
            title="",
            description="This is a valid description with enough characters to pass validation."
        )
        
        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)
        
        assert not is_valid
        assert any("Title" in error for error in errors)
    
    def test_validate_missing_description(self):
        """Test validation with missing description."""
        report = Report(
            title="Valid Title Here",
            description=""
        )
        
        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)
        
        assert not is_valid
        assert any("Description" in error for error in errors)
    
    def test_validate_high_severity_without_poc(self):
        """Test validation of high severity report without PoC."""
        report = Report(
            title="Critical SQL Injection",
            description="A critical SQL injection vulnerability was discovered in the application.",
            severity=Severity.HIGH
        )
        
        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)
        
        assert not is_valid
        assert any("proof of concept" in error.lower() for error in errors)
    
    def test_quality_score_complete_report(self):
        """Test quality score calculation for complete report."""
        report = Report(
            title="SQL Injection in Login Endpoint",
            description="A SQL injection vulnerability was found in the login endpoint. " * 10,
            steps_to_reproduce="1. Navigate to /login\n2. Enter payload\n3. Observe results",
            proof_of_concept="' OR 1=1--",
            impact="Authentication bypass possible",
            affected_component="/api/login",
            vulnerability_type="sql injection",
            severity=Severity.HIGH
        )
        
        validator = ReportValidator()
        score = validator.get_quality_score(report)
        
        assert score >= 80
        assert score <= 100
    
    def test_quality_score_minimal_report(self):
        """Test quality score calculation for minimal report."""
        report = Report(
            title="Bug Report",
            description="Short description"
        )
        
        validator = ReportValidator()
        score = validator.get_quality_score(report)
        
        assert score < 50
    
    def test_validate_vague_title(self):
        """Test validation with vague title."""
        report = Report(
            title="Bug",
            description="This is a valid description with enough characters to pass validation."
        )
        
        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)
        
        assert any("vague" in warning.lower() for warning in warnings)
    
    def test_validate_missing_steps(self):
        """Test validation with missing reproduction steps."""
        report = Report(
            title="SQL Injection Vulnerability",
            description="A SQL injection vulnerability was found in the application.",
            impact="Data breach possible"
        )
        
        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)
        
        assert any("steps to reproduce" in warning.lower() for warning in warnings)
    
    def test_validate_numbered_steps(self):
        """Test validation recognizes numbered steps."""
        report = Report(
            title="XSS Vulnerability in Comments",
            description="Cross-site scripting vulnerability found in comment section.",
            steps_to_reproduce="1. Go to comments\n2. Submit script\n3. Script executes",
            impact="Session hijacking possible"
        )
        
        validator = ReportValidator()
        score = validator.get_quality_score(report)
        
        # Should get points for numbered steps
        assert score > 40

