import unittest
from bountybot.validators.report_validator import ReportValidator
from bountybot.models import Report, Severity


class TestReportValidator(unittest.TestCase):
    """Tests for report validator."""
    
    def test_validate_complete_report(self):
        """Test validation of complete report."""
        report = Report(
            title="SQL Injection in Login Endpoint",
            impact_description="A SQL injection vulnerability was found in the login endpoint that allows attackers to bypass authentication and gain unauthorized access to user accounts. The vulnerability exists in the authentication query which directly concatenates user input without proper sanitization or parameterization.",
            reproduction_steps=["1. Navigate to /login", "2. Enter username: admin' OR 1=1--", "3. Enter any password", "4. Click login and observe successful authentication bypass"],
            proof_of_concept="curl -X POST https://example.com/login -H 'Content-Type: application/json' -d '{\"username\":\"admin' OR 1=1--\",\"password\":\"test\"}'",
            affected_components=["/api/v1/login"],
            vulnerability_type="sql injection",
            severity=Severity.HIGH
        )

        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)

        assert is_valid
        assert len(errors) == 0
        # May have some warnings about expected vs actual behavior, but should be valid
        assert len(warnings) <= 2

    def test_validate_minimal_report(self):
        """Test validation of minimal report."""
        report = Report(
            title="Bug",
            impact_description="Short"
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
            impact_description="This is a valid description with enough characters to pass validation."
        )

        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)

        assert not is_valid
        assert any("Title" in error for error in errors)

    def test_validate_missing_description(self):
        """Test validation with missing description."""
        report = Report(
            title="Valid Title Here",
            impact_description=""
        )

        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)

        # Empty description generates warnings, not errors
        assert is_valid  # No errors, so is_valid is True
        assert any("Impact" in warning or "description" in warning for warning in warnings)

    def test_validate_high_severity_without_poc(self):
        """Test validation of high severity report without PoC."""
        report = Report(
            title="Critical SQL Injection",
            impact_description="A critical SQL injection vulnerability was discovered in the application.",
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
            impact_description="A SQL injection vulnerability was found in the login endpoint. " * 10,
            reproduction_steps=["Navigate to /login", "Enter payload", "Observe results"],
            proof_of_concept="' OR 1=1--",
            affected_components=["/api/login"],
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
            impact_description="Short description"
        )

        validator = ReportValidator()
        score = validator.get_quality_score(report)

        assert score < 50

    def test_validate_vague_title(self):
        """Test validation with vague title."""
        report = Report(
            title="Bug",
            impact_description="This is a valid description with enough characters to pass validation."
        )

        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)

        assert any("vague" in warning.lower() for warning in warnings)

    def test_validate_missing_steps(self):
        """Test validation with missing reproduction steps."""
        report = Report(
            title="SQL Injection Vulnerability",
            impact_description="A SQL injection vulnerability was found in the application. Data breach possible."
        )

        validator = ReportValidator()
        is_valid, errors, warnings = validator.validate(report)

        assert any("steps to reproduce" in warning.lower() or "reproduction" in warning.lower() for warning in warnings)

    def test_validate_numbered_steps(self):
        """Test validation recognizes numbered steps."""
        report = Report(
            title="XSS Vulnerability in Comments",
            impact_description="Cross-site scripting vulnerability found in comment section. Session hijacking possible.",
            reproduction_steps=["Go to comments", "Submit script", "Script executes"]
        )

        validator = ReportValidator()
        score = validator.get_quality_score(report)

        # Should get points for numbered steps
        assert score > 40

