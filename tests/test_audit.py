"""
Tests for Audit Logging & Forensics System
"""

import unittest
import tempfile
import shutil
from datetime import datetime, timedelta
from pathlib import Path

from bountybot.audit import (
    AuditLogger,
    AuditSearch,
    ForensicAnalyzer,
    AuditRetentionManager,
    ComplianceReporter,
    AuditStreamer,
    AuditEventType,
    AuditEventCategory,
    AuditSeverity,
    AuditQuery
)


class TestAuditLogger(unittest.TestCase):
    """Test audit logger."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.logger = AuditLogger(log_dir=self.temp_dir)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_log_event(self):
        """Test logging an event."""
        event = self.logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            action="User logged in",
            user_id="user_123",
            username="john.doe",
            ip_address="192.168.1.1"
        )
        
        self.assertIsNotNone(event.event_id)
        self.assertEqual(event.event_type, AuditEventType.LOGIN_SUCCESS)
        self.assertEqual(event.category, AuditEventCategory.AUTHENTICATION)
        self.assertEqual(event.user_id, "user_123")
        self.assertIsNotNone(event.signature)
    
    def test_event_signature(self):
        """Test event signature verification."""
        event = self.logger.log_event(
            event_type=AuditEventType.REPORT_CREATED,
            action="Created report",
            user_id="user_123"
        )
        
        # Verify signature
        self.assertTrue(self.logger.verify_event(event))
        
        # Tamper with event
        event.action = "Modified action"
        self.assertFalse(self.logger.verify_event(event))
    
    def test_chain_of_custody(self):
        """Test chain of custody."""
        event1 = self.logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            action="Login",
            user_id="user_123"
        )
        
        event2 = self.logger.log_event(
            event_type=AuditEventType.REPORT_VIEWED,
            action="View report",
            user_id="user_123"
        )
        
        # Second event should reference first
        self.assertIsNotNone(event2.previous_event_hash)
        self.assertEqual(event2.previous_event_hash, self.logger._hash_event(event1))
    
    def test_compliance_tags(self):
        """Test compliance tagging."""
        event = self.logger.log_event(
            event_type=AuditEventType.DATA_EXPORTED,
            action="Export data",
            user_id="user_123"
        )
        
        # Should have SOC2, GDPR, and HIPAA tags
        self.assertIn('SOC2', event.compliance_tags)
        self.assertIn('GDPR', event.compliance_tags)
        self.assertIn('HIPAA', event.compliance_tags)


class TestAuditSearch(unittest.TestCase):
    """Test audit search."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.logger = AuditLogger(log_dir=self.temp_dir)
        self.search = AuditSearch(log_dir=self.temp_dir)
        
        # Create test events
        for i in range(10):
            self.logger.log_event(
                event_type=AuditEventType.LOGIN_SUCCESS if i % 2 == 0 else AuditEventType.LOGIN_FAILURE,
                action=f"Login attempt {i}",
                user_id=f"user_{i % 3}",
                ip_address="192.168.1.1"
            )
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_search_all(self):
        """Test searching all events."""
        query = AuditQuery(limit=100)
        events = self.search.search(query)
        
        self.assertEqual(len(events), 10)
    
    def test_search_by_event_type(self):
        """Test searching by event type."""
        query = AuditQuery(
            event_types=[AuditEventType.LOGIN_SUCCESS],
            limit=100
        )
        events = self.search.search(query)
        
        self.assertEqual(len(events), 5)
        for event in events:
            self.assertEqual(event.event_type, AuditEventType.LOGIN_SUCCESS)
    
    def test_search_by_user(self):
        """Test searching by user."""
        query = AuditQuery(
            user_ids=["user_0"],
            limit=100
        )
        events = self.search.search(query)
        
        self.assertGreater(len(events), 0)
        for event in events:
            self.assertEqual(event.user_id, "user_0")
    
    def test_aggregate_by_category(self):
        """Test aggregation by category."""
        query = AuditQuery()
        aggregation = self.search.aggregate_by_category(query)
        
        self.assertIn('authentication', aggregation)
        self.assertEqual(aggregation['authentication'], 10)
    
    def test_export_to_json(self):
        """Test JSON export."""
        query = AuditQuery(limit=5)
        output_file = Path(self.temp_dir) / "export.json"
        
        self.search.export_to_json(query, str(output_file))
        
        self.assertTrue(output_file.exists())


class TestForensicAnalyzer(unittest.TestCase):
    """Test forensic analyzer."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.logger = AuditLogger(log_dir=self.temp_dir)
        self.search = AuditSearch(log_dir=self.temp_dir)
        self.analyzer = ForensicAnalyzer(self.search)
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_create_timeline(self):
        """Test timeline creation."""
        # Create events
        for i in range(5):
            self.logger.log_event(
                event_type=AuditEventType.REPORT_VIEWED,
                action=f"View report {i}",
                user_id="user_123",
                resource_type="report",
                resource_id=f"report_{i}"
            )
        
        query = AuditQuery(user_ids=["user_123"])
        timeline = self.analyzer.create_timeline(
            title="User Activity",
            description="Timeline of user activity",
            query=query
        )
        
        self.assertEqual(len(timeline.events), 5)
        self.assertIn("user_123", timeline.actors)
        self.assertGreater(len(timeline.resources), 0)
    
    def test_detect_brute_force(self):
        """Test brute force detection."""
        # Create multiple failed login attempts
        for i in range(10):
            self.logger.log_event(
                event_type=AuditEventType.LOGIN_FAILURE,
                action="Failed login",
                user_id="user_123",
                ip_address="192.168.1.1",
                success=False
            )
        
        query = AuditQuery()
        anomalies = self.analyzer.detect_anomalies(query)
        
        # Should detect brute force
        brute_force = [a for a in anomalies if a.anomaly_type == "brute_force"]
        self.assertGreater(len(brute_force), 0)
    
    def test_detect_data_exfiltration(self):
        """Test data exfiltration detection."""
        # Create multiple data exports
        for i in range(15):
            self.logger.log_event(
                event_type=AuditEventType.DATA_EXPORTED,
                action="Export data",
                user_id="user_123"
            )
        
        query = AuditQuery()
        anomalies = self.analyzer.detect_anomalies(query)
        
        # Should detect potential exfiltration
        exfiltration = [a for a in anomalies if a.anomaly_type == "data_exfiltration"]
        self.assertGreater(len(exfiltration), 0)
    
    def test_analyze_user_activity(self):
        """Test user activity analysis."""
        # Create user events
        for i in range(5):
            self.logger.log_event(
                event_type=AuditEventType.REPORT_VIEWED,
                action="View report",
                user_id="user_123",
                resource_type="report",
                resource_id=f"report_{i}"
            )
        
        start_time = datetime.utcnow() - timedelta(hours=1)
        end_time = datetime.utcnow() + timedelta(hours=1)
        
        analysis = self.analyzer.analyze_user_activity("user_123", start_time, end_time)
        
        self.assertEqual(analysis['user_id'], "user_123")
        self.assertEqual(analysis['total_events'], 5)
        self.assertGreater(len(analysis['resources_accessed']), 0)


class TestAuditRetentionManager(unittest.TestCase):
    """Test retention manager."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.archive_dir = tempfile.mkdtemp()
        self.logger = AuditLogger(log_dir=self.temp_dir)
        self.retention = AuditRetentionManager(
            log_dir=self.temp_dir,
            archive_dir=self.archive_dir
        )
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        shutil.rmtree(self.archive_dir, ignore_errors=True)
    
    def test_get_retention_days(self):
        """Test retention days calculation."""
        # SOC2 event should have 7 years retention
        event = self.logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            action="Login",
            user_id="user_123"
        )
        
        retention_days = self.retention.get_retention_days(event)
        self.assertEqual(retention_days, 2555)  # 7 years
    
    def test_get_retention_stats(self):
        """Test retention statistics."""
        # Create some events
        self.logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            action="Login",
            user_id="user_123"
        )
        
        stats = self.retention.get_retention_stats()
        
        self.assertGreater(stats['active_logs'], 0)
        self.assertIsNotNone(stats['total_size_mb'])


class TestComplianceReporter(unittest.TestCase):
    """Test compliance reporter."""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.logger = AuditLogger(log_dir=self.temp_dir)
        self.search = AuditSearch(log_dir=self.temp_dir)
        self.reporter = ComplianceReporter(self.search)
        
        # Create test events
        self.logger.log_event(
            event_type=AuditEventType.LOGIN_SUCCESS,
            action="Login",
            user_id="user_123"
        )
        self.logger.log_event(
            event_type=AuditEventType.DATA_EXPORTED,
            action="Export data",
            user_id="user_123"
        )
    
    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_generate_soc2_report(self):
        """Test SOC 2 report generation."""
        start_time = datetime.utcnow() - timedelta(days=1)
        end_time = datetime.utcnow() + timedelta(days=1)
        
        report = self.reporter.generate_soc2_report(start_time, end_time)
        
        self.assertEqual(report.title, "SOC 2 Compliance Report")
        self.assertGreater(report.total_events, 0)
        self.assertIsNotNone(report.summary)
    
    def test_generate_gdpr_report(self):
        """Test GDPR report generation."""
        start_time = datetime.utcnow() - timedelta(days=1)
        end_time = datetime.utcnow() + timedelta(days=1)
        
        report = self.reporter.generate_gdpr_report(start_time, end_time)
        
        self.assertEqual(report.title, "GDPR Compliance Report")
        self.assertIsNotNone(report.summary)


class TestAuditStreamer(unittest.TestCase):
    """Test audit streamer."""
    
    def test_subscribe(self):
        """Test subscription."""
        streamer = AuditStreamer()
        
        events_received = []
        
        def callback(event):
            events_received.append(event)
        
        subscription = streamer.subscribe(
            subscription_id="sub_1",
            callback=callback,
            event_types=[AuditEventType.LOGIN_SUCCESS]
        )
        
        self.assertEqual(subscription.subscription_id, "sub_1")
        self.assertEqual(len(subscription.event_types), 1)
    
    def test_unsubscribe(self):
        """Test unsubscription."""
        streamer = AuditStreamer()
        
        streamer.subscribe(
            subscription_id="sub_1",
            callback=lambda e: None
        )
        
        result = streamer.unsubscribe("sub_1")
        self.assertTrue(result)
        
        result = streamer.unsubscribe("sub_1")
        self.assertFalse(result)


if __name__ == '__main__':
    unittest.main()

