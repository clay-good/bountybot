import unittest
import os
from datetime import datetime, timedelta
from fastapi.testclient import TestClient


class TestAPIServer(unittest.TestCase):
    """Test API server endpoints."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test client."""
        # Set test API key
        os.environ['BOUNTYBOT_API_KEY'] = 'test_key_12345'
        
        from bountybot.api.server import app
        cls.client = TestClient(app)
        cls.api_key = 'test_key_12345'
    
    def test_root_endpoint(self):
        """Test root endpoint."""
        response = self.client.get("/")
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data['service'], 'BountyBot API')
        self.assertEqual(data['version'], '2.0.0')
    
    def test_health_check(self):
        """Test health check endpoint."""
        response = self.client.get("/health")
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('status', data)
        self.assertIn('version', data)
        self.assertIn('uptime_seconds', data)
        self.assertIn('database_connected', data)
        self.assertIn('ai_provider_available', data)
    
    def test_metrics_without_auth(self):
        """Test metrics endpoint without authentication."""
        response = self.client.get("/metrics")

        self.assertEqual(response.status_code, 403)
    
    def test_metrics_with_auth(self):
        """Test metrics endpoint with authentication."""
        response = self.client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {self.api_key}"}
        )
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('total_requests', data)
        self.assertIn('successful_requests', data)
        self.assertIn('total_reports_validated', data)


class TestAPIAuth(unittest.TestCase):
    """Test API authentication."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test client."""
        os.environ['BOUNTYBOT_API_KEY'] = 'test_key_12345'
        
        from bountybot.api.server import app
        cls.client = TestClient(app)
        cls.api_key = 'test_key_12345'
    
    def test_invalid_api_key(self):
        """Test with invalid API key."""
        response = self.client.get(
            "/metrics",
            headers={"Authorization": "Bearer invalid_key"}
        )
        
        self.assertEqual(response.status_code, 401)
    
    def test_missing_api_key(self):
        """Test without API key."""
        response = self.client.get("/metrics")

        self.assertEqual(response.status_code, 403)
    
    def test_valid_api_key(self):
        """Test with valid API key."""
        response = self.client.get(
            "/metrics",
            headers={"Authorization": f"Bearer {self.api_key}"}
        )
        
        self.assertEqual(response.status_code, 200)


class TestAPIModels(unittest.TestCase):
    """Test API models."""
    
    def test_report_input_validation(self):
        """Test report input validation."""
        from bountybot.api.models import ReportInput
        
        # Valid report
        report = ReportInput(
            title="Test Vulnerability",
            description="This is a test vulnerability description that is long enough",
            vulnerability_type="XSS",
            severity="HIGH"
        )
        
        self.assertEqual(report.title, "Test Vulnerability")
        self.assertEqual(report.severity, "HIGH")
    
    def test_report_input_invalid_severity(self):
        """Test report input with invalid severity."""
        from bountybot.api.models import ReportInput
        from pydantic import ValidationError
        
        with self.assertRaises(ValidationError):
            ReportInput(
                title="Test",
                description="This is a test vulnerability description",
                severity="INVALID"
            )
    
    def test_validation_options(self):
        """Test validation options."""
        from bountybot.api.models import ValidationOptions
        
        options = ValidationOptions(
            enable_code_analysis=True,
            skip_duplicate_check=False
        )
        
        self.assertTrue(options.enable_code_analysis)
        self.assertFalse(options.skip_duplicate_check)


class TestRateLimiter(unittest.TestCase):
    """Test rate limiter."""
    
    def test_token_bucket(self):
        """Test token bucket rate limiting."""
        from bountybot.api.rate_limiter import TokenBucket
        
        bucket = TokenBucket(capacity=10, refill_rate=1.0)
        
        # Should allow 10 requests
        for _ in range(10):
            self.assertTrue(bucket.consume())
        
        # 11th request should fail
        self.assertFalse(bucket.consume())
    
    def test_rate_limiter(self):
        """Test rate limiter."""
        from bountybot.api.rate_limiter import RateLimiter
        
        limiter = RateLimiter()
        
        # Should allow requests up to limit
        for _ in range(5):
            self.assertTrue(limiter.allow_request("test_key", rate_limit=60))
        
        # Get stats
        stats = limiter.get_stats("test_key")
        self.assertEqual(stats['total_requests'], 5)
        self.assertEqual(stats['allowed_requests'], 5)
    
    def test_sliding_window_rate_limiter(self):
        """Test sliding window rate limiter."""
        from bountybot.api.rate_limiter import SlidingWindowRateLimiter
        
        limiter = SlidingWindowRateLimiter(window_size=60)
        
        # Should allow requests up to limit
        for _ in range(5):
            self.assertTrue(limiter.allow_request("test_key", rate_limit=10))
        
        # Check current count
        count = limiter.get_current_count("test_key")
        self.assertEqual(count, 5)
        
        # Check remaining
        remaining = limiter.get_remaining("test_key", rate_limit=10)
        self.assertEqual(remaining, 5)


class TestAPIKeyAuth(unittest.TestCase):
    """Test API key authentication."""
    
    def test_create_api_key(self):
        """Test API key creation."""
        from bountybot.api.auth import APIKeyAuth
        
        auth = APIKeyAuth()
        
        raw_key, api_key = auth.create_key(
            name="Test Key",
            rate_limit=100
        )
        
        self.assertIsNotNone(raw_key)
        self.assertTrue(raw_key.startswith("bb_"))
        self.assertEqual(api_key.name, "Test Key")
        self.assertEqual(api_key.rate_limit, 100)
    
    def test_verify_api_key(self):
        """Test API key verification."""
        from bountybot.api.auth import APIKeyAuth
        
        auth = APIKeyAuth()
        
        raw_key, created_key = auth.create_key(name="Test Key")
        
        # Verify with correct key
        verified_key = auth.verify_key(raw_key)
        self.assertIsNotNone(verified_key)
        self.assertEqual(verified_key.key_id, created_key.key_id)
        
        # Verify with incorrect key
        invalid_key = auth.verify_key("invalid_key")
        self.assertIsNone(invalid_key)
    
    def test_revoke_api_key(self):
        """Test API key revocation."""
        from bountybot.api.auth import APIKeyAuth
        
        auth = APIKeyAuth()
        
        raw_key, api_key = auth.create_key(name="Test Key")
        
        # Revoke key
        result = auth.revoke_key(api_key.key_id)
        self.assertTrue(result)
        
        # Verify key is no longer valid
        verified_key = auth.verify_key(raw_key)
        self.assertIsNone(verified_key)
    
    def test_api_key_expiration(self):
        """Test API key expiration."""
        from bountybot.api.auth import APIKey
        from datetime import datetime, timedelta
        
        # Create expired key
        expired_key = APIKey(
            key_id="test",
            name="Test",
            key_hash="hash",
            expires_at=datetime.utcnow() - timedelta(days=1)
        )
        
        self.assertFalse(expired_key.is_valid())
        
        # Create valid key
        valid_key = APIKey(
            key_id="test",
            name="Test",
            key_hash="hash",
            expires_at=datetime.utcnow() + timedelta(days=1)
        )
        
        self.assertTrue(valid_key.is_valid())


if __name__ == '__main__':
    unittest.main()

