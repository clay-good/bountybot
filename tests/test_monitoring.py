"""
Tests for Monitoring Module

Tests metrics collection, health checking, alerting, and Prometheus export.
"""

import unittest
import time
from datetime import datetime, timedelta

from bountybot.monitoring import (
    MetricsCollector,
    HealthChecker,
    AlertManager,
    AlertSeverity,
    AlertChannel,
    PrometheusExporter,
    HealthStatus
)
from bountybot.monitoring.metrics import Metric, MetricSummary
from bountybot.monitoring.health import ComponentHealth, SystemHealth
from bountybot.monitoring.alerts import Alert, AlertRule


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.collector = MetricsCollector()
    
    def test_increment_counter(self):
        """Test counter increment."""
        self.collector.increment_counter("test_counter", 1.0)
        self.collector.increment_counter("test_counter", 2.0)
        
        value = self.collector.get_counter("test_counter")
        self.assertEqual(value, 3.0)
    
    def test_counter_with_labels(self):
        """Test counter with labels."""
        self.collector.increment_counter("requests", 1.0, {"method": "GET"})
        self.collector.increment_counter("requests", 1.0, {"method": "POST"})
        self.collector.increment_counter("requests", 1.0, {"method": "GET"})
        
        get_count = self.collector.get_counter("requests", {"method": "GET"})
        post_count = self.collector.get_counter("requests", {"method": "POST"})
        
        self.assertEqual(get_count, 2.0)
        self.assertEqual(post_count, 1.0)
    
    def test_set_gauge(self):
        """Test gauge setting."""
        self.collector.set_gauge("temperature", 25.5)
        self.collector.set_gauge("temperature", 26.0)
        
        value = self.collector.get_gauge("temperature")
        self.assertEqual(value, 26.0)
    
    def test_observe_histogram(self):
        """Test histogram observation."""
        values = [1.0, 2.0, 3.0, 4.0, 5.0]
        for v in values:
            self.collector.observe_histogram("response_time", v)
        
        summary = self.collector.get_histogram_summary("response_time")
        
        self.assertEqual(summary.count, 5)
        self.assertEqual(summary.sum, 15.0)
        self.assertEqual(summary.min, 1.0)
        self.assertEqual(summary.max, 5.0)
        self.assertEqual(summary.avg, 3.0)
    
    def test_track_validation_metrics(self):
        """Test validation metrics tracking."""
        self.collector.track_validation_start("report_123")
        
        self.collector.track_validation_complete(
            report_id="report_123",
            duration_seconds=1.5,
            verdict="valid",
            confidence=0.85,
            success=True
        )
        
        started = self.collector.get_counter("validations_started_total")
        completed = self.collector.get_counter("validations_completed_total", {"verdict": "valid"})
        
        self.assertEqual(started, 1.0)
        self.assertEqual(completed, 1.0)
    
    def test_track_api_metrics(self):
        """Test API metrics tracking."""
        self.collector.track_api_request(
            method="GET",
            endpoint="/api/validate",
            status_code=200,
            duration_seconds=0.5
        )
        
        requests = self.collector.get_counter("api_requests_total", {
            "method": "GET",
            "endpoint": "/api/validate",
            "status": "200"
        })
        
        self.assertEqual(requests, 1.0)
    
    def test_track_ai_metrics(self):
        """Test AI provider metrics tracking."""
        self.collector.track_ai_request(
            provider="anthropic",
            model="claude-3",
            duration_seconds=2.0,
            tokens_used=1000,
            cost=0.05,
            success=True
        )
        
        requests = self.collector.get_counter("ai_requests_total", {
            "provider": "anthropic",
            "model": "claude-3"
        })
        tokens = self.collector.get_counter("ai_tokens_used_total", {
            "provider": "anthropic",
            "model": "claude-3"
        })
        
        self.assertEqual(requests, 1.0)
        self.assertEqual(tokens, 1000.0)
    
    def test_track_db_metrics(self):
        """Test database metrics tracking."""
        self.collector.track_db_query("SELECT", 0.1, success=True)
        self.collector.track_db_query("INSERT", 0.2, success=True)
        
        queries = self.collector.get_counter("db_queries_total", {"operation": "SELECT"})
        self.assertEqual(queries, 1.0)
    
    def test_business_metrics(self):
        """Test business metrics tracking."""
        self.collector.track_report_processed("xss", "high")
        self.collector.track_duplicate_detected()
        self.collector.track_false_positive_detected()
        
        reports = self.collector.get_counter("reports_processed_total", {
            "vulnerability_type": "xss",
            "severity": "high"
        })
        duplicates = self.collector.get_counter("duplicates_detected_total")
        false_positives = self.collector.get_counter("false_positives_detected_total")
        
        self.assertEqual(reports, 1.0)
        self.assertEqual(duplicates, 1.0)
        self.assertEqual(false_positives, 1.0)


class TestHealthChecker(unittest.TestCase):
    """Test health checking."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.checker = HealthChecker()
    
    def test_check_disk_space(self):
        """Test disk space check."""
        health = self.checker.check_disk_space()
        
        self.assertIsNotNone(health)
        self.assertEqual(health.name, "disk_space")
        self.assertIn(health.status, [HealthStatus.HEALTHY, HealthStatus.DEGRADED, HealthStatus.UNHEALTHY])
        self.assertIsNotNone(health.response_time_ms)
    
    def test_check_memory(self):
        """Test memory check."""
        health = self.checker.check_memory()
        
        self.assertIsNotNone(health)
        self.assertEqual(health.name, "memory")
        # Status might be UNKNOWN if psutil not installed
        self.assertIn(health.status, [
            HealthStatus.HEALTHY,
            HealthStatus.DEGRADED,
            HealthStatus.UNHEALTHY,
            HealthStatus.UNKNOWN
        ])
    
    def test_check_all(self):
        """Test checking all components."""
        health = self.checker.check_all()
        
        self.assertIsInstance(health, SystemHealth)
        self.assertIn(health.status, [
            HealthStatus.HEALTHY,
            HealthStatus.DEGRADED,
            HealthStatus.UNHEALTHY
        ])
        self.assertGreater(len(health.components), 0)
        self.assertGreater(health.uptime_seconds, 0)
    
    def test_component_health_structure(self):
        """Test component health structure."""
        health = self.checker.check_disk_space()
        
        self.assertIsInstance(health, ComponentHealth)
        self.assertIsInstance(health.name, str)
        self.assertIsInstance(health.status, HealthStatus)
        self.assertIsInstance(health.message, str)
        self.assertIsInstance(health.last_check, datetime)


class TestAlertManager(unittest.TestCase):
    """Test alert management."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.manager = AlertManager()
    
    def test_create_alert(self):
        """Test alert creation."""
        alert = self.manager.create_alert(
            severity=AlertSeverity.WARNING,
            title="Test Alert",
            message="This is a test alert"
        )
        
        self.assertIsNotNone(alert.alert_id)
        self.assertEqual(alert.severity, AlertSeverity.WARNING)
        self.assertEqual(alert.title, "Test Alert")
        self.assertFalse(alert.resolved)
    
    def test_resolve_alert(self):
        """Test alert resolution."""
        alert = self.manager.create_alert(
            severity=AlertSeverity.INFO,
            title="Test",
            message="Test"
        )
        
        self.manager.resolve_alert(alert.alert_id)
        
        resolved_alert = self.manager.get_alert(alert.alert_id)
        self.assertTrue(resolved_alert.resolved)
        self.assertIsNotNone(resolved_alert.resolved_at)
    
    def test_get_active_alerts(self):
        """Test getting active alerts."""
        alert1 = self.manager.create_alert(AlertSeverity.ERROR, "Alert 1", "Message 1")
        alert2 = self.manager.create_alert(AlertSeverity.WARNING, "Alert 2", "Message 2")
        
        self.manager.resolve_alert(alert1.alert_id)
        
        active = self.manager.get_active_alerts()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].alert_id, alert2.alert_id)
    
    def test_get_alerts_by_severity(self):
        """Test getting alerts by severity."""
        self.manager.create_alert(AlertSeverity.CRITICAL, "Critical", "Message")
        self.manager.create_alert(AlertSeverity.WARNING, "Warning", "Message")
        self.manager.create_alert(AlertSeverity.CRITICAL, "Critical 2", "Message")
        
        critical_alerts = self.manager.get_alerts_by_severity(AlertSeverity.CRITICAL)
        self.assertEqual(len(critical_alerts), 2)
    
    def test_alert_rule(self):
        """Test alert rule."""
        triggered = False
        
        def condition():
            return triggered
        
        rule = AlertRule(
            rule_id="test_rule",
            name="Test Rule",
            condition=condition,
            severity=AlertSeverity.WARNING,
            message_template="Test message",
            channels=[AlertChannel.LOG]
        )
        
        self.manager.add_rule(rule)
        
        # Check when condition is False
        self.manager.check_rules()
        initial_count = len(self.manager.alerts)
        
        # Trigger condition
        triggered = True
        self.manager.check_rules()
        
        # Should have created an alert
        self.assertGreater(len(self.manager.alerts), initial_count)
    
    def test_alert_summary(self):
        """Test alert summary."""
        self.manager.create_alert(AlertSeverity.CRITICAL, "Critical", "Message")
        self.manager.create_alert(AlertSeverity.ERROR, "Error", "Message")
        self.manager.create_alert(AlertSeverity.WARNING, "Warning", "Message")
        
        summary = self.manager.get_alert_summary()
        
        self.assertGreater(summary['total_alerts'], 0)
        self.assertGreater(summary['active_alerts'], 0)
        self.assertIn('by_severity', summary)


class TestPrometheusExporter(unittest.TestCase):
    """Test Prometheus metrics export."""

    def setUp(self):
        """Set up test fixtures."""
        self.exporter = PrometheusExporter()
        # Use the global metrics_collector that the exporter uses
        from bountybot.monitoring import metrics_collector
        self.collector = metrics_collector

    def test_export_counter(self):
        """Test exporting counter metrics."""
        self.collector.increment_counter("test_counter", 5.0)

        output = self.exporter.export_metrics()

        self.assertIn("bountybot_test_counter", output)
        self.assertIn("# TYPE bountybot_test_counter counter", output)

    def test_export_gauge(self):
        """Test exporting gauge metrics."""
        self.collector.set_gauge("test_gauge", 42.0)

        output = self.exporter.export_metrics()

        self.assertIn("bountybot_test_gauge", output)
        self.assertIn("# TYPE bountybot_test_gauge gauge", output)

    def test_export_histogram(self):
        """Test exporting histogram metrics."""
        for i in range(10):
            self.collector.observe_histogram("test_histogram", float(i))

        output = self.exporter.export_metrics()

        self.assertIn("bountybot_test_histogram", output)
        self.assertIn("# TYPE bountybot_test_histogram histogram", output)
        self.assertIn("quantile", output)

    def test_export_with_labels(self):
        """Test exporting metrics with labels."""
        self.collector.increment_counter("requests", 1.0, {"method": "GET", "status": "200"})

        output = self.exporter.export_metrics()

        self.assertIn("bountybot_requests", output)
        self.assertIn('method="GET"', output)
        self.assertIn('status="200"', output)
    
    def test_export_health_metrics(self):
        """Test exporting health metrics."""
        output = self.exporter.export_health_metrics()
        
        self.assertIn("bountybot_health_status", output)
        self.assertIn("bountybot_component_health", output)
        self.assertIn("bountybot_uptime_seconds", output)
    
    def test_export_all(self):
        """Test exporting all metrics."""
        self.collector.increment_counter("test", 1.0)
        
        output = self.exporter.export_all()
        
        self.assertIn("bountybot_", output)
        self.assertIn("# HELP", output)
        self.assertIn("# TYPE", output)


if __name__ == '__main__':
    unittest.main()

