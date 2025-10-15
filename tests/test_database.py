import unittest
import tempfile
import os
from datetime import datetime, timedelta

from bountybot.database import (
    init_database,
    session_scope,
    ReportRepository,
    ValidationResultRepository,
    ResearcherRepository,
    MetricsRepository,
    AuditLogRepository
)
from bountybot.database.models import (
    VerdictEnum,
    SeverityEnum,
    PriorityEnum,
    StatusEnum
)


class TestDatabaseModels(unittest.TestCase):
    """Test database models and basic operations."""
    
    @classmethod
    def setUpClass(cls):
        """Set up test database."""
        # Use in-memory SQLite for testing
        cls.db_file = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        cls.db_file.close()
        cls.db_url = f"sqlite:///{cls.db_file.name}"
        cls.db = init_database(cls.db_url, echo=False, create_tables=True)
    
    @classmethod
    def tearDownClass(cls):
        """Clean up test database."""
        try:
            os.unlink(cls.db_file.name)
        except:
            pass
    
    def test_database_initialization(self):
        """Test database initialization."""
        self.assertIsNotNone(self.db)
        self.assertTrue(self.db.health_check())
    
    def test_create_report(self):
        """Test creating a report."""
        with session_scope() as session:
            repo = ReportRepository(session)
            
            report = repo.create({
                'external_id': 'TEST-001',
                'title': 'Test SQL Injection',
                'vulnerability_type': 'sql_injection',
                'severity': SeverityEnum.HIGH,
                'affected_components': ['login.php'],
                'reproduction_steps': ['Step 1', 'Step 2'],
                'proof_of_concept': 'SELECT * FROM users',
                'impact_description': 'Database compromise',
                'status': StatusEnum.PENDING
            })
            
            self.assertIsNotNone(report.id)
            self.assertEqual(report.title, 'Test SQL Injection')
            self.assertEqual(report.severity, SeverityEnum.HIGH)
    
    def test_get_report_by_id(self):
        """Test retrieving report by ID."""
        with session_scope() as session:
            repo = ReportRepository(session)
            
            # Create report
            report = repo.create({
                'external_id': 'TEST-002',
                'title': 'Test XSS',
                'vulnerability_type': 'xss',
                'severity': SeverityEnum.MEDIUM
            })
            report_id = report.id
        
        # Retrieve in new session
        with session_scope() as session:
            repo = ReportRepository(session)
            retrieved = repo.get_by_id(report_id)
            
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.title, 'Test XSS')
            self.assertEqual(retrieved.external_id, 'TEST-002')
    
    def test_get_report_by_external_id(self):
        """Test retrieving report by external ID."""
        with session_scope() as session:
            repo = ReportRepository(session)
            
            repo.create({
                'external_id': 'EXTERNAL-123',
                'title': 'Test Report',
                'vulnerability_type': 'csrf'
            })
        
        with session_scope() as session:
            repo = ReportRepository(session)
            report = repo.get_by_external_id('EXTERNAL-123')
            
            self.assertIsNotNone(report)
            self.assertEqual(report.title, 'Test Report')
    
    def test_update_report_status(self):
        """Test updating report status."""
        with session_scope() as session:
            repo = ReportRepository(session)
            
            report = repo.create({
                'external_id': 'TEST-003',
                'title': 'Test Status Update',
                'status': StatusEnum.PENDING
            })
            report_id = report.id
            
            repo.update_status(report_id, StatusEnum.IN_PROGRESS, assigned_to='john@example.com')
        
        with session_scope() as session:
            repo = ReportRepository(session)
            report = repo.get_by_id(report_id)
            
            self.assertEqual(report.status, StatusEnum.IN_PROGRESS)
            self.assertEqual(report.assigned_to, 'john@example.com')
    
    def test_create_validation_result(self):
        """Test creating validation result."""
        with session_scope() as session:
            report_repo = ReportRepository(session)
            validation_repo = ValidationResultRepository(session)
            
            # Create report
            report = report_repo.create({
                'external_id': 'TEST-004',
                'title': 'Test Validation',
                'vulnerability_type': 'rce'
            })
            
            # Create validation result
            result = validation_repo.create({
                'report_id': report.id,
                'verdict': VerdictEnum.VALID,
                'confidence': 95,
                'cvss_base_score': 9.8,
                'priority_level': PriorityEnum.CRITICAL,
                'priority_score': 85.5,
                'is_duplicate': False
            })
            
            self.assertIsNotNone(result.id)
            self.assertEqual(result.verdict, VerdictEnum.VALID)
            self.assertEqual(result.confidence, 95)
            self.assertEqual(result.priority_level, PriorityEnum.CRITICAL)
    
    def test_get_validation_by_report(self):
        """Test retrieving validation result by report ID."""
        with session_scope() as session:
            report_repo = ReportRepository(session)
            validation_repo = ValidationResultRepository(session)
            
            report = report_repo.create({
                'external_id': 'TEST-005',
                'title': 'Test Get Validation'
            })
            
            validation_repo.create({
                'report_id': report.id,
                'verdict': VerdictEnum.VALID,
                'confidence': 80
            })
            
            retrieved = validation_repo.get_by_report_id(report.id)
            
            self.assertIsNotNone(retrieved)
            self.assertEqual(retrieved.verdict, VerdictEnum.VALID)
            self.assertEqual(retrieved.confidence, 80)
    
    def test_create_researcher(self):
        """Test creating researcher."""
        with session_scope() as session:
            repo = ResearcherRepository(session)
            
            researcher = repo.create({
                'external_id': 'RES-001',
                'username': 'test_researcher',
                'email': 'researcher@example.com'
            })
            
            self.assertIsNotNone(researcher.id)
            self.assertEqual(researcher.username, 'test_researcher')
            self.assertEqual(researcher.total_reports, 0)
    
    def test_get_or_create_researcher(self):
        """Test get_or_create researcher."""
        with session_scope() as session:
            repo = ResearcherRepository(session)
            
            # First call creates
            researcher1 = repo.get_or_create('new_researcher', 'RES-002')
            id1 = researcher1.id
        
        with session_scope() as session:
            repo = ResearcherRepository(session)
            
            # Second call retrieves
            researcher2 = repo.get_or_create('new_researcher', 'RES-002')
            
            self.assertEqual(researcher2.id, id1)
    
    def test_update_researcher_statistics(self):
        """Test updating researcher statistics."""
        with session_scope() as session:
            report_repo = ReportRepository(session)
            validation_repo = ValidationResultRepository(session)
            researcher_repo = ResearcherRepository(session)
            
            # Create researcher
            researcher = researcher_repo.create({
                'username': 'stats_test',
                'total_reports': 0,
                'valid_reports': 0
            })
            
            # Create report
            report = report_repo.create({
                'external_id': 'TEST-006',
                'title': 'Test Stats',
                'researcher_id': researcher.id
            })
            
            # Create validation
            validation = validation_repo.create({
                'report_id': report.id,
                'verdict': VerdictEnum.VALID,
                'confidence': 90
            })
            
            # Update stats
            researcher_repo.update_statistics(researcher.id, validation)
            
            updated = researcher_repo.get_by_id(researcher.id)
            self.assertEqual(updated.total_reports, 1)
            self.assertEqual(updated.valid_reports, 1)
    
    def test_record_metric(self):
        """Test recording metrics."""
        with session_scope() as session:
            repo = MetricsRepository(session)
            
            repo.record(
                'reports_validated',
                1.0,
                dimensions={'severity': 'high', 'verdict': 'valid'},
                unit='count'
            )
            
            # Verify metric was recorded
            recent = repo.get_recent_metrics(hours=1)
            self.assertGreater(len(recent), 0)
            self.assertEqual(recent[0].metric_name, 'reports_validated')
    
    def test_get_time_series_metrics(self):
        """Test retrieving time series metrics."""
        with session_scope() as session:
            repo = MetricsRepository(session)
            
            # Record multiple metrics
            for i in range(5):
                repo.record('test_metric', float(i), unit='count')
            
            # Retrieve time series
            start = datetime.utcnow() - timedelta(hours=1)
            end = datetime.utcnow() + timedelta(hours=1)
            metrics = repo.get_time_series('test_metric', start, end)
            
            self.assertEqual(len(metrics), 5)
    
    def test_audit_log(self):
        """Test audit logging."""
        with session_scope() as session:
            repo = AuditLogRepository(session)
            
            repo.log(
                action='report_created',
                resource_type='report',
                resource_id=123,
                user='admin@example.com',
                details={'title': 'Test Report'},
                result='success'
            )
            
            # Retrieve logs
            logs = repo.get_by_action('report_created')
            self.assertGreater(len(logs), 0)
            self.assertEqual(logs[0].action, 'report_created')
            self.assertEqual(logs[0].resource_id, 123)
    
    def test_report_statistics(self):
        """Test report statistics."""
        with session_scope() as session:
            repo = ReportRepository(session)
            
            # Create multiple reports
            for i in range(3):
                repo.create({
                    'external_id': f'STATS-{i}',
                    'title': f'Stats Test {i}',
                    'severity': SeverityEnum.HIGH,
                    'status': StatusEnum.PENDING
                })
            
            stats = repo.get_statistics()
            
            self.assertGreater(stats['total_reports'], 0)
            self.assertIn('by_status', stats)
            self.assertIn('by_severity', stats)


if __name__ == '__main__':
    unittest.main()

