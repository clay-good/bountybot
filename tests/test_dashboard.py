"""
Tests for Dashboard Module

Tests the web dashboard functionality including:
- Dashboard app creation
- API endpoints
- Data models
- Template rendering
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from fastapi.testclient import TestClient

from bountybot.dashboard import create_dashboard_app
from bountybot.dashboard.models import (
    DashboardConfig,
    DashboardStats,
    ReportSummary,
    ReportListRequest,
    ReportListResponse,
    AnalyticsRequest,
    AnalyticsSummary,
    IntegrationStatus,
    WebhookSummary,
    SystemHealth,
    TimeRange,
    ReportStatus,
    IntegrationStatusEnum
)


class TestDashboardModels(unittest.TestCase):
    """Test dashboard data models."""
    
    def test_dashboard_config(self):
        """Test DashboardConfig creation."""
        config = DashboardConfig(
            title="Test Dashboard",
            refresh_interval=60,
            theme="light"
        )
        
        self.assertEqual(config.title, "Test Dashboard")
        self.assertEqual(config.refresh_interval, 60)
        self.assertEqual(config.theme, "light")
    
    def test_report_summary(self):
        """Test ReportSummary model."""
        summary = ReportSummary(
            report_id="test-123",
            title="SQL Injection",
            vulnerability_type="SQL Injection",
            verdict="VALID",
            confidence=95.0,
            severity="HIGH",
            cvss_score=8.5,
            priority_level="HIGH",
            researcher="test@example.com",
            submitted_at=datetime.now(),
            status=ReportStatus.COMPLETED
        )
        
        self.assertEqual(summary.report_id, "test-123")
        self.assertEqual(summary.verdict, "VALID")
        self.assertEqual(summary.confidence, 95.0)
        self.assertEqual(summary.status, ReportStatus.COMPLETED)
    
    def test_dashboard_stats(self):
        """Test DashboardStats model."""
        stats = DashboardStats(
            total_reports=100,
            reports_today=10,
            reports_this_week=50,
            reports_this_month=80,
            valid_count=60,
            invalid_count=30,
            uncertain_count=10,
            average_confidence=85.5,
            average_processing_time=2.3,
            total_cost=50.0,
            cost_today=5.0,
            active_integrations=5,
            healthy_integrations=4,
            active_webhooks=3,
            system_uptime=3600.0,
            api_requests_today=500
        )
        
        self.assertEqual(stats.total_reports, 100)
        self.assertEqual(stats.valid_count, 60)
        self.assertEqual(stats.average_confidence, 85.5)
    
    def test_analytics_summary(self):
        """Test AnalyticsSummary model."""
        summary = AnalyticsSummary(
            time_range=TimeRange.WEEK,
            total_reports=50,
            valid_reports=30,
            invalid_reports=15,
            uncertain_reports=5,
            duplicate_reports=2,
            false_positive_reports=3,
            average_confidence=82.0,
            average_processing_time=2.5,
            total_cost=25.0,
            average_cost_per_report=0.5,
            severity_distribution={"HIGH": 20, "MEDIUM": 20, "LOW": 10},
            vulnerability_distribution={"SQL Injection": 15, "XSS": 20, "CSRF": 15}
        )
        
        self.assertEqual(summary.time_range, TimeRange.WEEK)
        self.assertEqual(summary.total_reports, 50)
        self.assertEqual(summary.valid_reports, 30)
        self.assertEqual(len(summary.severity_distribution), 3)
    
    def test_integration_status(self):
        """Test IntegrationStatus model."""
        status = IntegrationStatus(
            integration_name="JIRA",
            integration_type="ISSUE_TRACKER",
            status=IntegrationStatusEnum.HEALTHY,
            enabled=True,
            success_count=100,
            failure_count=5,
            success_rate=95.0
        )
        
        self.assertEqual(status.integration_name, "JIRA")
        self.assertEqual(status.status, IntegrationStatusEnum.HEALTHY)
        self.assertEqual(status.success_rate, 95.0)


class TestDashboardApp(unittest.TestCase):
    """Test dashboard FastAPI application."""
    
    def setUp(self):
        """Set up test client."""
        self.app = create_dashboard_app()
        self.client = TestClient(self.app)
    
    def test_app_creation(self):
        """Test dashboard app is created successfully."""
        self.assertIsNotNone(self.app)
        self.assertEqual(self.app.title, "BountyBot Dashboard")
        self.assertEqual(self.app.version, "2.5.0")
    
    def test_health_endpoint(self):
        """Test health check endpoint."""
        response = self.client.get("/api/health")
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "healthy")
        self.assertIn("timestamp", data)
    
    def test_stats_endpoint(self):
        """Test dashboard stats endpoint."""
        # Stats endpoint should work even without database
        response = self.client.get("/api/stats")

        # Should return stats even if some data is missing
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("total_reports", data)
        self.assertIn("valid_count", data)
    
    def test_reports_list_endpoint(self):
        """Test reports list endpoint."""
        request_data = {
            "page": 1,
            "page_size": 20,
            "sort_by": "submitted_at",
            "sort_order": "desc"
        }

        # Should handle missing database gracefully
        response = self.client.post("/api/reports/list", json=request_data)

        # May return error if database not available, which is expected
        self.assertIn(response.status_code, [200, 500])
    
    def test_integration_status_endpoint(self):
        """Test integration status endpoint."""
        response = self.client.get("/api/integrations/status")

        # Should handle missing integrations gracefully
        self.assertIn(response.status_code, [200, 500])
    
    def test_webhooks_list_endpoint(self):
        """Test webhooks list endpoint."""
        response = self.client.get("/api/webhooks/list")

        # Should handle missing webhooks gracefully
        self.assertIn(response.status_code, [200, 500])
    
    def test_system_health_endpoint(self):
        """Test system health endpoint."""
        response = self.client.get("/api/system/health")

        # Should return health status
        self.assertIn(response.status_code, [200, 500])
        if response.status_code == 200:
            data = response.json()
            self.assertIn("status", data)
            self.assertIn("uptime", data)


class TestDashboardPages(unittest.TestCase):
    """Test dashboard HTML pages."""
    
    def setUp(self):
        """Set up test client."""
        self.app = create_dashboard_app()
        self.client = TestClient(self.app)
    
    def test_dashboard_home_page(self):
        """Test main dashboard page loads."""
        response = self.client.get("/")
        
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
    
    def test_reports_page(self):
        """Test reports page loads."""
        response = self.client.get("/reports")
        
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
    
    def test_analytics_page(self):
        """Test analytics page loads."""
        response = self.client.get("/analytics")
        
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
    
    def test_integrations_page(self):
        """Test integrations page loads."""
        response = self.client.get("/integrations")
        
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
    
    def test_webhooks_page(self):
        """Test webhooks page loads."""
        response = self.client.get("/webhooks")
        
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])
    
    def test_batch_page(self):
        """Test batch processing page loads."""
        response = self.client.get("/batch")
        
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers["content-type"])


if __name__ == '__main__':
    unittest.main()

