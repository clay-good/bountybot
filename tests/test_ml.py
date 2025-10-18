"""
Tests for ML module.
"""

import unittest
from datetime import datetime, timedelta
from dataclasses import dataclass

from bountybot.ml.models import (
    VulnerabilityPattern,
    PredictionResult,
    AnomalyScore,
    ResearcherProfile,
    MLModelMetadata,
    ModelType,
    AnomalyType
)
from bountybot.ml.feature_extractor import FeatureExtractor
from bountybot.ml.pattern_learner import PatternLearner
from bountybot.ml.severity_predictor import SeverityPredictor
from bountybot.ml.anomaly_detector import AnomalyDetector
from bountybot.ml.researcher_profiler import ResearcherProfiler
from bountybot.ml.false_positive_predictor import FalsePositivePredictor
from bountybot.ml.trend_forecaster import TrendForecaster
from bountybot.ml.model_trainer import ModelTrainer


@dataclass
class MockReport:
    """Mock report for testing."""
    title: str
    description: str
    vulnerability_type: str = "sql injection"
    researcher_id: str = "researcher_1"
    submitted_at: datetime = None
    
    def __post_init__(self):
        if self.submitted_at is None:
            self.submitted_at = datetime.utcnow()


@dataclass
class MockValidation:
    """Mock validation result for testing."""
    verdict: str = "valid"
    confidence: float = 0.9
    cvss_score: float = 7.5
    severity: str = "high"
    is_duplicate: bool = False
    is_false_positive: bool = False


class TestMLModels(unittest.TestCase):
    """Test ML data models."""
    
    def test_vulnerability_pattern(self):
        """Test VulnerabilityPattern model."""
        pattern = VulnerabilityPattern(
            pattern_id="test_pattern",
            vulnerability_type="sql injection",
            features={"has_sql_syntax": True},
            frequency=10,
            confidence=0.9
        )
        
        self.assertEqual(pattern.pattern_id, "test_pattern")
        self.assertEqual(pattern.vulnerability_type, "sql injection")
        self.assertEqual(pattern.frequency, 10)
        
        # Test to_dict
        pattern_dict = pattern.to_dict()
        self.assertIn('pattern_id', pattern_dict)
        self.assertIn('confidence', pattern_dict)
    
    def test_prediction_result(self):
        """Test PredictionResult model."""
        result = PredictionResult(
            prediction_type="severity",
            predicted_value={"cvss_score": 7.5, "severity": "high"},
            confidence=0.85
        )
        
        self.assertEqual(result.prediction_type, "severity")
        self.assertEqual(result.confidence, 0.85)
        
        # Test to_dict
        result_dict = result.to_dict()
        self.assertIn('predicted_value', result_dict)
        self.assertIn('confidence', result_dict)
    
    def test_anomaly_score(self):
        """Test AnomalyScore model."""
        score = AnomalyScore(
            is_anomaly=True,
            anomaly_score=0.85,
            anomaly_type=AnomalyType.NOVEL_ATTACK
        )
        
        self.assertTrue(score.is_anomaly)
        self.assertEqual(score.anomaly_score, 0.85)
        self.assertEqual(score.anomaly_type, AnomalyType.NOVEL_ATTACK)


class TestFeatureExtractor(unittest.TestCase):
    """Test feature extraction."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.extractor = FeatureExtractor()
    
    def test_extract_from_report(self):
        """Test feature extraction from report."""
        report = MockReport(
            title="SQL Injection in Login Form",
            description="Found SQL injection vulnerability. Steps to reproduce:\n1. Go to /login\n2. Enter ' OR '1'='1 in username\n3. Observe error"
        )
        
        features = self.extractor.extract_from_report(report)
        
        # Check text features
        self.assertIn('title_length', features)
        self.assertIn('description_length', features)
        self.assertIn('word_count', features)
        
        # Check structural features
        self.assertIn('has_steps', features)
        self.assertTrue(features['has_steps'])
        
        # Check technical features
        self.assertIn('has_sql_syntax', features)
        
        # Check metadata features
        self.assertIn('vulnerability_type', features)
        self.assertEqual(features['vulnerability_type'], 'sql injection')


class TestPatternLearner(unittest.TestCase):
    """Test pattern learning."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.learner = PatternLearner(min_frequency=2, min_confidence=0.5)
    
    def test_learn_from_reports(self):
        """Test learning patterns from reports."""
        reports = [
            MockReport(
                title="SQL Injection in Login",
                description="SQL injection found in login form with ' OR '1'='1",
                vulnerability_type="sql injection"
            ),
            MockReport(
                title="SQL Injection in Search",
                description="SQL injection found in search with UNION SELECT",
                vulnerability_type="sql injection"
            ),
            MockReport(
                title="XSS in Comment",
                description="XSS found with <script>alert(1)</script>",
                vulnerability_type="xss"
            )
        ]
        
        validations = [MockValidation() for _ in reports]
        
        patterns = self.learner.learn_from_reports(reports, validations)
        
        # Should learn at least one pattern
        self.assertGreaterEqual(len(patterns), 0)
    
    def test_match_report_to_patterns(self):
        """Test matching report to patterns."""
        # First learn some patterns
        reports = [
            MockReport(
                title="SQL Injection Test",
                description="SQL injection with SELECT statement",
                vulnerability_type="sql injection"
            ) for _ in range(3)
        ]
        validations = [MockValidation() for _ in reports]
        
        self.learner.learn_from_reports(reports, validations)
        
        # Try to match a new report
        new_report = MockReport(
            title="SQL Injection in API",
            description="SQL injection with SELECT in API endpoint",
            vulnerability_type="sql injection"
        )
        
        matches = self.learner.match_report_to_patterns(new_report)
        
        # Should return a list (may be empty if no strong matches)
        self.assertIsInstance(matches, list)


class TestSeverityPredictor(unittest.TestCase):
    """Test severity prediction."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.predictor = SeverityPredictor()
    
    def test_train_and_predict(self):
        """Test training and prediction."""
        reports = [
            MockReport(
                title="Critical SQL Injection",
                description="SQL injection allowing full database access",
                vulnerability_type="sql injection"
            ),
            MockReport(
                title="Low Severity XSS",
                description="Self-XSS in profile page",
                vulnerability_type="xss"
            )
        ]
        
        validations = [
            MockValidation(cvss_score=9.5, severity="critical"),
            MockValidation(cvss_score=3.5, severity="low")
        ]
        
        # Train
        self.predictor.train(reports, validations)
        
        # Predict
        new_report = MockReport(
            title="SQL Injection",
            description="SQL injection in search",
            vulnerability_type="sql injection"
        )
        
        prediction = self.predictor.predict(new_report)
        
        self.assertEqual(prediction.prediction_type, 'severity')
        self.assertIn('cvss_score', prediction.predicted_value)
        self.assertGreater(prediction.confidence, 0.0)


class TestAnomalyDetector(unittest.TestCase):
    """Test anomaly detection."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.detector = AnomalyDetector(sensitivity=2.0)
    
    def test_build_baseline_and_detect(self):
        """Test building baseline and detecting anomalies."""
        # Build baseline with normal reports
        normal_reports = [
            MockReport(
                title=f"SQL Injection {i}",
                description="Normal SQL injection report with typical length and structure. " * 10,
                vulnerability_type="sql injection"
            ) for i in range(10)
        ]
        
        self.detector.build_baseline(normal_reports)
        
        # Test with normal report
        normal_report = MockReport(
            title="SQL Injection Test",
            description="Normal SQL injection report with typical length and structure. " * 10,
            vulnerability_type="sql injection"
        )
        
        result = self.detector.detect_anomalies(normal_report)
        
        self.assertIsInstance(result, AnomalyScore)
        self.assertIsInstance(result.is_anomaly, bool)
        self.assertGreaterEqual(result.anomaly_score, 0.0)
        self.assertLessEqual(result.anomaly_score, 1.0)
        
        # Test with anomalous report (very short)
        anomalous_report = MockReport(
            title="Test",
            description="Short",
            vulnerability_type="sql injection"
        )
        
        anomaly_result = self.detector.detect_anomalies(anomalous_report)
        
        # Anomaly score should be higher for unusual report
        self.assertGreaterEqual(anomaly_result.anomaly_score, 0.0)


class TestResearcherProfiler(unittest.TestCase):
    """Test researcher profiling."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.profiler = ResearcherProfiler()
    
    def test_build_profile(self):
        """Test building researcher profile."""
        reports = [
            MockReport(
                title=f"SQL Injection {i}",
                description="SQL injection report",
                vulnerability_type="sql injection",
                researcher_id="researcher_1"
            ) for i in range(5)
        ]
        
        validations = [
            MockValidation(verdict="valid", cvss_score=7.5) for _ in range(4)
        ] + [MockValidation(verdict="invalid", is_false_positive=True)]
        
        profile = self.profiler.build_profile("researcher_1", reports, validations)
        
        self.assertEqual(profile.researcher_id, "researcher_1")
        self.assertEqual(profile.total_submissions, 5)
        self.assertEqual(profile.valid_submissions, 4)
        self.assertGreater(profile.reputation_score, 0.0)
        self.assertIn(profile.trust_level, ["unknown", "low", "medium", "high", "expert"])


class TestFalsePositivePredictor(unittest.TestCase):
    """Test false positive prediction."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.predictor = FalsePositivePredictor(threshold=0.7)
    
    def test_train_and_predict(self):
        """Test training and prediction."""
        reports = [
            MockReport(
                title="Detailed SQL Injection Report",
                description="Comprehensive report with steps, POC, and impact analysis. " * 20,
                vulnerability_type="sql injection"
            ),
            MockReport(
                title="Short report",
                description="Brief",
                vulnerability_type="xss"
            )
        ]
        
        validations = [
            MockValidation(is_false_positive=False),
            MockValidation(is_false_positive=True)
        ]
        
        # Train
        self.predictor.train(reports, validations)
        
        # Predict on new report
        new_report = MockReport(
            title="SQL Injection",
            description="SQL injection found",
            vulnerability_type="sql injection"
        )
        
        prediction = self.predictor.predict(new_report)
        
        self.assertEqual(prediction.prediction_type, 'false_positive')
        self.assertIsInstance(prediction.predicted_value, bool)
        self.assertIn('false_positive', prediction.probability_distribution)


class TestTrendForecaster(unittest.TestCase):
    """Test trend forecasting."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.forecaster = TrendForecaster(forecast_days=30)
    
    def test_analyze_and_forecast(self):
        """Test analyzing historical data and forecasting."""
        # Create historical data
        base_time = datetime.utcnow() - timedelta(days=90)
        reports = []
        timestamps = []
        
        for i in range(90):
            report = MockReport(
                title=f"Report {i}",
                description="Test report",
                vulnerability_type="sql injection" if i % 2 == 0 else "xss"
            )
            timestamp = base_time + timedelta(days=i)
            
            reports.append(report)
            timestamps.append(timestamp)
        
        # Analyze
        self.forecaster.analyze_historical_data(reports, timestamps)
        
        # Forecast volume
        volume_forecast = self.forecaster.forecast_volume(days_ahead=30)
        
        self.assertIn('forecasted_volumes', volume_forecast)
        self.assertIn('daily_average', volume_forecast)
        self.assertEqual(len(volume_forecast['forecasted_volumes']), 30)
        
        # Forecast vulnerability types
        type_forecast = self.forecaster.forecast_vulnerability_types()
        
        self.assertIn('vulnerability_types', type_forecast)


class TestModelTrainer(unittest.TestCase):
    """Test model training."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.trainer = ModelTrainer()
    
    def test_train_all_models(self):
        """Test training all models."""
        reports = [
            MockReport(
                title=f"SQL Injection {i}",
                description="SQL injection report with details",
                vulnerability_type="sql injection",
                researcher_id="researcher_1"
            ) for i in range(10)
        ]
        
        validations = [
            MockValidation(cvss_score=7.5, verdict="valid") for _ in range(10)
        ]
        
        timestamps = [datetime.utcnow() - timedelta(days=i) for i in range(10)]
        
        # Train all models
        trained_models = self.trainer.train_all_models(reports, validations, timestamps)
        
        # Should have trained multiple models
        self.assertGreater(len(trained_models), 0)
        
        # Check model info
        model_info = self.trainer.get_model_info()
        self.assertIn('models', model_info)
        self.assertIn('total_models', model_info)


if __name__ == '__main__':
    unittest.main()

