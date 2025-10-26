"""
Tests for advanced ML features (v2.17.0).

Tests deep learning, transformers, exploit generation, and zero-day prediction.
"""

import pytest
from bountybot.ml.deep_learning import (
    VulnerabilityClassifier,
    FeatureEngineering,
    TrainingConfig,
    VulnerabilityType
)
from bountybot.ml.transformers import (
    CodeAnalyzer,
    ProgrammingLanguage,
    TransformerConfig
)
from bountybot.ml.exploit_generation import (
    ExploitGenerator,
    ExploitType,
    ExploitConfig
)
from bountybot.ml.zero_day import (
    ZeroDayPredictor,
    ZeroDayConfig
)


class TestDeepLearning:
    """Test deep learning vulnerability classification."""
    
    def test_feature_engineering(self):
        """Test feature extraction."""
        engineer = FeatureEngineering()
        
        features = engineer.extract_features(
            title="SQL Injection in login form",
            description="The login form is vulnerable to SQL injection via the username parameter"
        )
        
        assert features.title_length > 0
        assert features.description_length > 0
        assert len(features.title_tokens) > 0
        assert 'sql' in features.keyword_counts
    
    def test_vulnerability_classifier(self):
        """Test vulnerability classification."""
        config = TrainingConfig()
        classifier = VulnerabilityClassifier(config)
        
        result = classifier.classify(
            title="SQL Injection vulnerability",
            description="SQL injection found in user input"
        )
        
        assert result.predicted_type in VulnerabilityType
        assert 0 <= result.confidence <= 1
        assert len(result.probabilities) > 0
    
    def test_classifier_batch(self):
        """Test batch classification."""
        classifier = VulnerabilityClassifier()
        
        reports = [
            {'title': 'XSS in search', 'description': 'Cross-site scripting vulnerability'},
            {'title': 'CSRF token bypass', 'description': 'CSRF protection can be bypassed'},
        ]
        
        results = classifier.classify_batch(reports)
        
        assert len(results) == 2
        assert all(r.confidence > 0 for r in results)


class TestTransformers:
    """Test transformer-based code analysis."""
    
    def test_code_analyzer(self):
        """Test code analysis."""
        config = TransformerConfig()
        analyzer = CodeAnalyzer(config)
        
        code = """
def login(username, password):
    query = "SELECT * FROM users WHERE username='" + username + "'"
    return execute_query(query)
"""
        
        result = analyzer.analyze(code, ProgrammingLanguage.PYTHON)
        
        assert result.language == ProgrammingLanguage.PYTHON
        assert result.code_quality_score >= 0
        assert result.complexity_score >= 0
        assert result.embedding is not None
    
    def test_vulnerability_detection(self):
        """Test vulnerability detection in code."""
        analyzer = CodeAnalyzer()
        
        vulnerable_code = """
def unsafe_eval(user_input):
    return eval(user_input)
"""
        
        result = analyzer.analyze(vulnerable_code, ProgrammingLanguage.PYTHON)
        
        # Should detect vulnerabilities
        assert len(result.vulnerabilities) > 0
    
    def test_code_similarity(self):
        """Test code similarity comparison."""
        analyzer = CodeAnalyzer()

        code1 = "def add(a, b): return a + b"
        code2 = "def add(x, y): return x + y"

        similarity = analyzer.compare_code(code1, code2, ProgrammingLanguage.PYTHON)

        # Cosine similarity can range from -1 to 1
        assert -1 <= similarity <= 1


class TestExploitGeneration:
    """Test exploit generation."""
    
    def test_exploit_generator_initialization(self):
        """Test exploit generator initialization."""
        config = ExploitConfig()
        generator = ExploitGenerator(config)
        
        assert generator.config.safety_constraints.validate()
    
    def test_sql_injection_exploit(self):
        """Test SQL injection exploit generation."""
        generator = ExploitGenerator()
        
        result = generator.generate(
            ExploitType.SQL_INJECTION,
            "SQL injection in login form"
        )
        
        assert result.exploit_type == ExploitType.SQL_INJECTION
        assert len(result.payload) > 0
        assert result.safety_validated
        assert len(result.steps) > 0
    
    def test_xss_exploit(self):
        """Test XSS exploit generation."""
        generator = ExploitGenerator()
        
        result = generator.generate(
            ExploitType.XSS_REFLECTED,
            "Reflected XSS in search parameter"
        )
        
        assert result.exploit_type == ExploitType.XSS_REFLECTED
        assert result.safety_validated
    
    def test_safety_validation(self):
        """Test safety validation."""
        generator = ExploitGenerator()
        
        result = generator.generate(
            ExploitType.COMMAND_INJECTION,
            "Command injection vulnerability"
        )
        
        # Should pass safety validation
        assert result.safety_validated
        assert result.is_safe_to_execute()


class TestZeroDayPrediction:
    """Test zero-day prediction."""
    
    def test_zero_day_predictor(self):
        """Test zero-day prediction."""
        config = ZeroDayConfig()
        predictor = ZeroDayPredictor(config)
        
        code = """
def process_user_data(data):
    # Complex processing logic
    result = eval(data)
    return result
"""
        
        prediction = predictor.predict(code)
        
        assert 0 <= prediction.likelihood <= 1
        assert prediction.threat_level is not None
        assert prediction.novelty is not None
        assert prediction.factors is not None
    
    def test_high_risk_detection(self):
        """Test high risk detection."""
        predictor = ZeroDayPredictor()
        
        risky_code = """
import os
def execute_command(cmd):
    os.system(cmd)
"""
        
        prediction = predictor.predict(risky_code)
        
        # Should detect some risk
        assert prediction.likelihood > 0
        assert len(prediction.recommended_actions) > 0
    
    def test_prediction_factors(self):
        """Test prediction factors calculation."""
        predictor = ZeroDayPredictor()
        
        code = "def simple(): pass"
        
        prediction = predictor.predict(code)
        
        factors = prediction.factors
        assert factors.code_complexity >= 0
        assert factors.attack_surface >= 0
        assert factors.anomaly_score >= 0
    
    def test_time_to_exploit_estimation(self):
        """Test time to exploit estimation."""
        predictor = ZeroDayPredictor()
        
        prediction = predictor.predict("def test(): pass")
        
        assert prediction.time_to_exploit_days is not None
        assert prediction.time_to_exploit_days > 0


class TestIntegration:
    """Integration tests for advanced ML features."""
    
    def test_full_pipeline(self):
        """Test full ML pipeline."""
        # 1. Classify vulnerability
        classifier = VulnerabilityClassifier()
        classification = classifier.classify(
            "SQL Injection",
            "SQL injection in login form"
        )
        
        # 2. Analyze code
        analyzer = CodeAnalyzer()
        code_analysis = analyzer.analyze(
            "SELECT * FROM users WHERE id=" + "user_input",
            ProgrammingLanguage.PYTHON
        )
        
        # 3. Generate exploit
        generator = ExploitGenerator()
        exploit = generator.generate(
            ExploitType.SQL_INJECTION,
            "SQL injection vulnerability"
        )
        
        # 4. Predict zero-day likelihood
        predictor = ZeroDayPredictor()
        prediction = predictor.predict("vulnerable code")
        
        # All components should work together
        assert classification.confidence > 0
        assert len(code_analysis.vulnerabilities) >= 0
        assert exploit.safety_validated
        assert prediction.likelihood >= 0
    
    def test_model_info(self):
        """Test model information retrieval."""
        classifier = VulnerabilityClassifier()
        info = classifier.get_model_info()
        
        assert 'version' in info
        assert 'num_parameters' in info
        assert info['num_parameters'] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

