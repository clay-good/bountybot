import unittest
from datetime import datetime
from bountybot.scoring import CVSSCalculator, AttackVector, AttackComplexity, ImpactMetric
from bountybot.deduplication import DuplicateDetector, ReportFingerprint
from bountybot.logging import StructuredLogger, SensitiveDataRedactor, PerformanceTracker
from bountybot.models import Report, Severity


class TestCVSSCalculator(unittest.TestCase):
    """Test CVSS v3.1 calculator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.calculator = CVSSCalculator()
    
    def test_sql_injection_scoring(self):
        """Test CVSS scoring for SQL injection."""
        report = Report(
            title="SQL Injection in Login Form",
            vulnerability_type="sql injection",
            severity=Severity.HIGH,
            impact_description="Unauthenticated SQL injection allows full database access",
            affected_components=["login.php"],
            reproduction_steps=["Navigate to login", "Enter payload: ' OR 1=1--"],
            proof_of_concept="' OR 1=1--"
        )
        
        score = self.calculator.calculate_from_report(report)
        
        # SQL injection should be high/critical
        self.assertGreaterEqual(score.base_score, 7.0)
        self.assertIn(score.severity_rating, ["High", "Critical"])
        self.assertEqual(score.attack_vector, AttackVector.NETWORK)
        self.assertEqual(score.attack_complexity, AttackComplexity.LOW)
        self.assertIsNotNone(score.vector_string)
        self.assertTrue(score.vector_string.startswith("CVSS:3.1/"))
    
    def test_xss_scoring(self):
        """Test CVSS scoring for XSS."""
        report = Report(
            title="Reflected XSS in Search",
            vulnerability_type="xss",
            severity=Severity.MEDIUM,
            impact_description="User interaction required to execute JavaScript",
            affected_components=["search.php"],
            reproduction_steps=["Search for: <script>alert(1)</script>"],
            proof_of_concept="<script>alert(document.cookie)</script>"
        )
        
        score = self.calculator.calculate_from_report(report)
        
        # XSS should be medium
        self.assertGreaterEqual(score.base_score, 4.0)
        self.assertLess(score.base_score, 9.0)
        self.assertIn(score.severity_rating, ["Medium", "High"])
    
    def test_cvss_to_dict(self):
        """Test CVSS score serialization."""
        report = Report(
            title="Test Vulnerability",
            vulnerability_type="rce",
            severity=Severity.CRITICAL
        )
        
        score = self.calculator.calculate_from_report(report)
        score_dict = score.to_dict()
        
        self.assertIn("version", score_dict)
        self.assertIn("base_score", score_dict)
        self.assertIn("severity_rating", score_dict)
        self.assertIn("vector_string", score_dict)
        self.assertIn("metrics", score_dict)
        self.assertEqual(score_dict["version"], "3.1")


class TestDuplicateDetector(unittest.TestCase):
    """Test duplicate detection system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = DuplicateDetector()
    
    def test_exact_duplicate_detection(self):
        """Test detection of exact duplicates."""
        report1 = Report(
            title="SQL Injection in Login",
            vulnerability_type="sql injection",
            impact_description="SQL injection allows database access",
            affected_components=["login.php"]
        )

        report2 = Report(
            title="SQL Injection in Login",
            vulnerability_type="sql injection",
            impact_description="SQL injection allows database access",
            affected_components=["login.php"]
        )
        
        # Add first report
        self.detector.add_report(report1, "report1")
        
        # Check second report
        match = self.detector.check_duplicate(report2, "report2")
        
        self.assertTrue(match.is_duplicate)
        self.assertGreater(match.confidence, 0.9)
        self.assertEqual(match.matched_report_id, "report1")
    
    def test_fuzzy_duplicate_detection(self):
        """Test detection of similar but not identical reports."""
        report1 = Report(
            title="SQL Injection in User Login Form",
            vulnerability_type="sql injection",
            impact_description="Allows unauthorized database access",
            affected_components=["login.php"]
        )

        report2 = Report(
            title="SQL Injection in Login Page",
            vulnerability_type="sql injection",
            impact_description="Enables unauthorized DB access",
            affected_components=["login.php"]
        )
        
        self.detector.add_report(report1, "report1")
        match = self.detector.check_duplicate(report2, "report2")
        
        # Should detect as similar
        self.assertGreater(match.confidence, 0.7)
    
    def test_non_duplicate_detection(self):
        """Test that different reports are not marked as duplicates."""
        report1 = Report(
            title="SQL Injection in Login",
            vulnerability_type="sql injection",
            affected_components=["login.php"]
        )

        report2 = Report(
            title="XSS in Search",
            vulnerability_type="xss",
            affected_components=["search.php"]
        )
        
        self.detector.add_report(report1, "report1")
        match = self.detector.check_duplicate(report2, "report2")
        
        self.assertFalse(match.is_duplicate)
        self.assertLess(match.confidence, 0.75)
    
    def test_fingerprint_persistence(self):
        """Test fingerprint export and import."""
        report = Report(
            title="Test Report",
            vulnerability_type="xss",
            affected_components=["test.php"]
        )
        
        self.detector.add_report(report, "report1")
        
        # Export fingerprints
        exported = self.detector.export_fingerprints()
        self.assertEqual(len(exported), 1)
        
        # Create new detector and import
        new_detector = DuplicateDetector()
        new_detector.import_fingerprints(exported)
        
        self.assertEqual(len(new_detector.fingerprints), 1)
        self.assertIn("report1", new_detector.fingerprints)


class TestStructuredLogger(unittest.TestCase):
    """Test structured logging system."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.logger = StructuredLogger("test")
    
    def test_request_id_tracking(self):
        """Test request ID generation and tracking."""
        request_id = self.logger.set_request_id()
        
        self.assertIsNotNone(request_id)
        self.assertIsInstance(request_id, str)
        self.assertGreater(len(request_id), 0)
    
    def test_user_context(self):
        """Test user context setting."""
        context = {"user_id": "123", "role": "admin"}
        self.logger.set_user_context(context)
        
        # Context should be set (no exception)
        self.logger.clear_context()
    
    def test_performance_tracker(self):
        """Test performance tracking context manager."""
        import time
        
        with PerformanceTracker("test_operation", self.logger) as tracker:
            time.sleep(0.1)
            tracker.add_metric("items_processed", 10)
        
        # Should complete without error


class TestSensitiveDataRedactor(unittest.TestCase):
    """Test sensitive data redaction."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.redactor = SensitiveDataRedactor()
    
    def test_api_key_redaction(self):
        """Test API key redaction."""
        text = "api_key=sk_test_1234567890abcdefghij"
        redacted = self.redactor.redact(text)
        
        self.assertNotIn("sk_test_1234567890abcdefghij", redacted)
        self.assertIn("********", redacted)
    
    def test_password_redaction(self):
        """Test password redaction."""
        text = "password=secret123"
        redacted = self.redactor.redact(text)
        
        self.assertNotIn("secret123", redacted)
        self.assertIn("********", redacted)
    
    def test_email_redaction(self):
        """Test email partial redaction."""
        text = "user@example.com"
        redacted = self.redactor.redact(text)
        
        # Should partially redact
        self.assertIn("@example.com", redacted)
        self.assertNotEqual(text, redacted)
    
    def test_jwt_redaction(self):
        """Test JWT token redaction."""
        text = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        redacted = self.redactor.redact(text)
        
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", redacted)
        self.assertIn("********", redacted)
    
    def test_multiple_patterns(self):
        """Test redaction of multiple sensitive patterns."""
        text = "api_key=sk_test_123 password=secret email=user@example.com"
        redacted = self.redactor.redact(text)
        
        self.assertNotIn("sk_test_123", redacted)
        self.assertNotIn("secret", redacted)
        self.assertIn("********", redacted)


if __name__ == "__main__":
    unittest.main()

