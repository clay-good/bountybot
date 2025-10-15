import unittest
from datetime import datetime, timedelta
from bountybot.analytics import (
    MetricsCollector,
    ReportMetrics,
    ResearcherMetrics,
    SystemMetrics,
    TrendAnalyzer,
    TrendData,
    TrendType
)


class MockReport:
    """Mock report for testing."""
    def __init__(self, severity="HIGH", vulnerability_type="XSS", researcher_id="researcher_1"):
        self.severity = severity
        self.vulnerability_type = vulnerability_type
        self.researcher_id = researcher_id
        self.researcher_username = f"user_{researcher_id}"
        self.submission_date = datetime.now()


class MockDuplicateCheck:
    """Mock duplicate check for testing."""
    def __init__(self, is_duplicate=False):
        self.is_duplicate = is_duplicate


class MockCVSSScore:
    """Mock CVSS score for testing."""
    def __init__(self, base_score=7.5):
        self.base_score = base_score


class MockPriorityScore:
    """Mock priority score for testing."""
    def __init__(self, overall_score=75.0, priority_level="HIGH"):
        self.overall_score = overall_score
        self.priority_level = priority_level


class MockValidationResult:
    """Mock validation result for testing."""
    def __init__(self, verdict="VALID", confidence=85.0, severity="HIGH"):
        self.report = MockReport(severity=severity)
        self.verdict = verdict
        self.confidence = confidence
        self.duplicate_check = MockDuplicateCheck(is_duplicate=False)
        self.cvss_score = MockCVSSScore(base_score=7.5)
        self.priority_score = MockPriorityScore(overall_score=75.0)
        self.processing_time_seconds = 15.5
        self.ai_cost = 0.15


class TestMetricsCollector(unittest.TestCase):
    """Test metrics collector."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.collector = MetricsCollector()
    
    def test_collect_from_result(self):
        """Test collecting metrics from validation result."""
        result = MockValidationResult(verdict="VALID", confidence=85.0)
        
        self.collector.collect_from_result(result)
        
        metrics = self.collector.get_report_metrics()
        self.assertEqual(metrics.total_reports, 1)
        self.assertEqual(metrics.valid_reports, 1)
        self.assertEqual(metrics.high_count, 1)
    
    def test_multiple_results(self):
        """Test collecting metrics from multiple results."""
        results = [
            MockValidationResult(verdict="VALID", confidence=85.0, severity="CRITICAL"),
            MockValidationResult(verdict="INVALID", confidence=45.0, severity="LOW"),
            MockValidationResult(verdict="VALID", confidence=90.0, severity="HIGH"),
        ]
        
        for result in results:
            self.collector.collect_from_result(result)
        
        metrics = self.collector.get_report_metrics()
        self.assertEqual(metrics.total_reports, 3)
        self.assertEqual(metrics.valid_reports, 2)
        self.assertEqual(metrics.invalid_reports, 1)
        self.assertEqual(metrics.critical_count, 1)
        self.assertEqual(metrics.high_count, 1)
        self.assertEqual(metrics.low_count, 1)
    
    def test_researcher_metrics(self):
        """Test researcher metrics collection."""
        result = MockValidationResult(verdict="VALID", confidence=85.0)
        
        self.collector.collect_from_result(result)
        
        researcher_metrics = self.collector.get_researcher_metrics()
        self.assertEqual(len(researcher_metrics), 1)
        
        researcher = list(researcher_metrics.values())[0]
        self.assertEqual(researcher.total_reports, 1)
        self.assertEqual(researcher.valid_reports, 1)
    
    def test_system_metrics(self):
        """Test system metrics collection."""
        result = MockValidationResult(verdict="VALID", confidence=85.0)
        
        self.collector.collect_from_result(result)
        
        metrics = self.collector.get_system_metrics()
        self.assertEqual(metrics.total_validations, 1)
        self.assertGreater(metrics.total_validation_time, 0)
        self.assertGreater(metrics.total_ai_cost, 0)
    
    def test_export_all(self):
        """Test exporting all metrics."""
        result = MockValidationResult(verdict="VALID", confidence=85.0)
        self.collector.collect_from_result(result)
        
        export = self.collector.export_all()
        
        self.assertIn('report_metrics', export)
        self.assertIn('researcher_metrics', export)
        self.assertIn('system_metrics', export)
        self.assertIn('top_researchers', export)


class TestTrendAnalyzer(unittest.TestCase):
    """Test trend analyzer."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = TrendAnalyzer()
    
    def test_add_data_point(self):
        """Test adding data points."""
        self.analyzer.add_data_point('reports_per_day', 10.0)
        self.analyzer.add_data_point('reports_per_day', 15.0)
        
        self.assertEqual(len(self.analyzer.data_points['reports_per_day']), 2)
    
    def test_analyze_increasing_trend(self):
        """Test analyzing increasing trend."""
        # Add increasing data points
        base_time = datetime.now()
        for i in range(10):
            timestamp = base_time + timedelta(days=i)
            value = 10.0 + (i * 2.0)  # Increasing by 2 each day
            self.analyzer.add_data_point('reports', value, timestamp=timestamp)
        
        analysis = self.analyzer.analyze_trend('reports')
        
        self.assertIsNotNone(analysis)
        self.assertEqual(analysis.direction, 'up')
        self.assertGreater(analysis.change_percentage, 0)
    
    def test_analyze_decreasing_trend(self):
        """Test analyzing decreasing trend."""
        # Add decreasing data points
        base_time = datetime.now()
        for i in range(10):
            timestamp = base_time + timedelta(days=i)
            value = 100.0 - (i * 5.0)  # Decreasing by 5 each day
            self.analyzer.add_data_point('reports', value, timestamp=timestamp)
        
        analysis = self.analyzer.analyze_trend('reports')
        
        self.assertIsNotNone(analysis)
        self.assertEqual(analysis.direction, 'down')
        self.assertLess(analysis.change_percentage, 0)
    
    def test_analyze_stable_trend(self):
        """Test analyzing stable trend."""
        # Add stable data points
        base_time = datetime.now()
        for i in range(10):
            timestamp = base_time + timedelta(days=i)
            value = 50.0 + (i % 2)  # Oscillating slightly around 50
            self.analyzer.add_data_point('reports', value, timestamp=timestamp)
        
        analysis = self.analyzer.analyze_trend('reports')
        
        self.assertIsNotNone(analysis)
        self.assertEqual(analysis.direction, 'flat')
    
    def test_get_time_series(self):
        """Test getting time series data."""
        base_time = datetime.now()
        for i in range(24):  # 24 hours of data
            timestamp = base_time + timedelta(hours=i)
            value = 10.0 + i
            self.analyzer.add_data_point('hourly_reports', value, timestamp=timestamp)
        
        # Aggregate by day
        time_series = self.analyzer.get_time_series('hourly_reports', interval=timedelta(days=1))
        
        self.assertGreater(len(time_series), 0)
        self.assertIsInstance(time_series[0], TrendData)
    
    def test_compare_periods(self):
        """Test comparing two periods."""
        base_time = datetime.now()
        
        # Period 1: Days 0-4
        for i in range(5):
            timestamp = base_time + timedelta(days=i)
            value = 10.0
            self.analyzer.add_data_point('reports', value, timestamp=timestamp)
        
        # Period 2: Days 5-9
        for i in range(5, 10):
            timestamp = base_time + timedelta(days=i)
            value = 20.0  # Double the value
            self.analyzer.add_data_point('reports', value, timestamp=timestamp)
        
        period1 = (base_time, base_time + timedelta(days=4))
        period2 = (base_time + timedelta(days=5), base_time + timedelta(days=9))
        
        comparison = self.analyzer.compare_periods('reports', period1, period2)
        
        self.assertIn('period1', comparison)
        self.assertIn('period2', comparison)
        self.assertIn('comparison', comparison)
        self.assertEqual(comparison['comparison']['direction'], 'increase')
    
    def test_export_trends(self):
        """Test exporting all trends."""
        base_time = datetime.now()
        
        # Add data for multiple metrics
        for metric in ['reports', 'validations', 'costs']:
            for i in range(10):
                timestamp = base_time + timedelta(days=i)
                value = 10.0 + i
                self.analyzer.add_data_point(metric, value, timestamp=timestamp)
        
        export = self.analyzer.export_trends()
        
        self.assertIn('trends', export)
        self.assertIn('summary', export)
        self.assertEqual(export['summary']['total_metrics'], 3)


class TestReportMetrics(unittest.TestCase):
    """Test report metrics data class."""
    
    def test_to_dict(self):
        """Test converting to dictionary."""
        metrics = ReportMetrics(
            total_reports=100,
            valid_reports=80,
            invalid_reports=15,
            duplicate_reports=5
        )
        
        data = metrics.to_dict()
        
        self.assertEqual(data['total_reports'], 100)
        self.assertEqual(data['valid_reports'], 80)
        self.assertIn('by_severity', data)
        self.assertIn('quality_metrics', data)


class TestResearcherMetrics(unittest.TestCase):
    """Test researcher metrics data class."""
    
    def test_to_dict(self):
        """Test converting to dictionary."""
        metrics = ResearcherMetrics(
            researcher_id="researcher_1",
            username="test_user",
            total_reports=50,
            valid_reports=45,
            quality_score=90.0
        )
        
        data = metrics.to_dict()
        
        self.assertEqual(data['researcher_id'], "researcher_1")
        self.assertEqual(data['username'], "test_user")
        self.assertIn('report_counts', data)
        self.assertIn('quality_metrics', data)


class TestSystemMetrics(unittest.TestCase):
    """Test system metrics data class."""
    
    def test_to_dict(self):
        """Test converting to dictionary."""
        metrics = SystemMetrics(
            total_validations=1000,
            average_validation_time=15.5,
            total_ai_cost=150.0
        )
        
        data = metrics.to_dict()
        
        self.assertEqual(data['performance']['total_validations'], 1000)
        self.assertIn('ai_usage', data)
        self.assertIn('detection_rates', data)


if __name__ == '__main__':
    unittest.main()

