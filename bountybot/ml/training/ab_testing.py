"""
A/B Testing Framework

Enables safe model deployment through A/B testing with statistical significance testing.
"""

import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from scipy import stats
import logging

from .models import (
    ABTestConfig,
    ABTestResult,
    ModelVersion
)

logger = logging.getLogger(__name__)


class ABTestingFramework:
    """
    A/B testing framework for model comparison.
    
    Features:
    - Traffic splitting
    - Statistical significance testing
    - Automated winner selection
    - Performance monitoring
    - Rollback on degradation
    """
    
    def __init__(self):
        """Initialize A/B testing framework."""
        self.logger = logging.getLogger(__name__)
        self.active_tests: Dict[str, ABTestConfig] = {}
        self.test_results: Dict[str, List[Dict]] = {}  # test_id -> list of results
    
    def create_test(
        self,
        name: str,
        model_a: ModelVersion,
        model_b: ModelVersion,
        traffic_split: float = 0.5,
        min_samples: int = 100,
        confidence_level: float = 0.95,
        description: str = ""
    ) -> ABTestConfig:
        """
        Create new A/B test.
        
        Args:
            name: Test name
            model_a: Control model (baseline)
            model_b: Treatment model (new)
            traffic_split: Fraction of traffic to model B (0-1)
            min_samples: Minimum samples before declaring winner
            confidence_level: Statistical confidence level
            description: Test description
            
        Returns:
            A/B test configuration
        """
        self.logger.info(f"Creating A/B test: {name}")
        
        config = ABTestConfig(
            name=name,
            description=description,
            model_a_version_id=model_a.version_id,
            model_b_version_id=model_b.version_id,
            traffic_split=traffic_split,
            min_samples=min_samples,
            confidence_level=confidence_level
        )
        
        self.active_tests[config.test_id] = config
        self.test_results[config.test_id] = []
        
        self.logger.info(f"Created test {config.test_id}: {model_a.version} vs {model_b.version}")
        
        return config
    
    def route_request(
        self,
        test_id: str,
        request_id: Optional[str] = None
    ) -> str:
        """
        Route request to model A or B based on traffic split.
        
        Args:
            test_id: Test ID
            request_id: Optional request ID for consistent routing
            
        Returns:
            "A" or "B"
        """
        config = self.active_tests.get(test_id)
        if not config or not config.is_active:
            return "A"  # Default to control
        
        # Use request_id for consistent routing if provided
        if request_id:
            # Hash request_id to get consistent routing
            hash_val = hash(request_id) % 100
            return "B" if hash_val < (config.traffic_split * 100) else "A"
        
        # Random routing
        return "B" if np.random.random() < config.traffic_split else "A"
    
    def record_result(
        self,
        test_id: str,
        model_variant: str,
        prediction_correct: bool,
        latency_ms: float,
        metadata: Optional[Dict] = None
    ):
        """
        Record result from A/B test.
        
        Args:
            test_id: Test ID
            model_variant: "A" or "B"
            prediction_correct: Whether prediction was correct
            latency_ms: Prediction latency in milliseconds
            metadata: Additional metadata
        """
        if test_id not in self.test_results:
            return
        
        result = {
            'variant': model_variant,
            'correct': prediction_correct,
            'latency_ms': latency_ms,
            'timestamp': datetime.utcnow(),
            'metadata': metadata or {}
        }
        
        self.test_results[test_id].append(result)
    
    def analyze_test(
        self,
        test_id: str
    ) -> ABTestResult:
        """
        Analyze A/B test results.
        
        Args:
            test_id: Test ID
            
        Returns:
            Test analysis results
        """
        self.logger.info(f"Analyzing A/B test: {test_id}")
        
        config = self.active_tests.get(test_id)
        if not config:
            raise ValueError(f"Test not found: {test_id}")
        
        results = self.test_results.get(test_id, [])
        
        # Separate results by variant
        results_a = [r for r in results if r['variant'] == 'A']
        results_b = [r for r in results if r['variant'] == 'B']
        
        # Calculate metrics
        n_a = len(results_a)
        n_b = len(results_b)
        
        acc_a = np.mean([r['correct'] for r in results_a]) if n_a > 0 else 0.0
        acc_b = np.mean([r['correct'] for r in results_b]) if n_b > 0 else 0.0
        
        latency_a = np.mean([r['latency_ms'] for r in results_a]) if n_a > 0 else 0.0
        latency_b = np.mean([r['latency_ms'] for r in results_b]) if n_b > 0 else 0.0
        
        # Statistical significance test (two-proportion z-test)
        significant = False
        p_value = 1.0
        winner = None
        
        if n_a >= config.min_samples and n_b >= config.min_samples:
            # Perform z-test
            successes_a = sum([r['correct'] for r in results_a])
            successes_b = sum([r['correct'] for r in results_b])
            
            # Calculate pooled proportion
            p_pool = (successes_a + successes_b) / (n_a + n_b)
            
            # Calculate standard error
            se = np.sqrt(p_pool * (1 - p_pool) * (1/n_a + 1/n_b))
            
            # Calculate z-score
            if se > 0:
                z_score = (acc_b - acc_a) / se
                p_value = 2 * (1 - stats.norm.cdf(abs(z_score)))  # Two-tailed test
                
                significant = p_value < (1 - config.confidence_level)
                
                if significant:
                    winner = "B" if acc_b > acc_a else "A"
        
        # Generate recommendation
        recommendation = self._generate_recommendation(
            n_a, n_b, acc_a, acc_b, latency_a, latency_b,
            significant, winner, config.min_samples
        )
        
        result = ABTestResult(
            test_id=test_id,
            model_a_samples=n_a,
            model_b_samples=n_b,
            model_a_accuracy=acc_a,
            model_b_accuracy=acc_b,
            model_a_latency_ms=latency_a,
            model_b_latency_ms=latency_b,
            statistical_significance=significant,
            p_value=p_value,
            winner=winner,
            confidence=1 - p_value if significant else 0.0,
            recommendation=recommendation,
            detailed_metrics={
                'accuracy_improvement': (acc_b - acc_a) / acc_a * 100 if acc_a > 0 else 0.0,
                'latency_change': (latency_b - latency_a) / latency_a * 100 if latency_a > 0 else 0.0,
                'min_samples_reached': n_a >= config.min_samples and n_b >= config.min_samples
            }
        )
        
        self.logger.info(f"Test analysis: winner={winner}, p_value={p_value:.4f}")
        
        return result
    
    def _generate_recommendation(
        self,
        n_a: int,
        n_b: int,
        acc_a: float,
        acc_b: float,
        latency_a: float,
        latency_b: float,
        significant: bool,
        winner: Optional[str],
        min_samples: int
    ) -> str:
        """Generate recommendation based on test results."""
        
        # Not enough samples
        if n_a < min_samples or n_b < min_samples:
            return f"Continue test - need {min_samples - min(n_a, n_b)} more samples"
        
        # No significant difference
        if not significant:
            return "No significant difference detected - keep model A (control)"
        
        # Model B is winner
        if winner == "B":
            acc_improvement = (acc_b - acc_a) / acc_a * 100
            latency_change = (latency_b - latency_a) / latency_a * 100
            
            # Check if latency degradation is acceptable
            if latency_change > 50:  # More than 50% slower
                return f"Model B is more accurate (+{acc_improvement:.1f}%) but significantly slower (+{latency_change:.1f}%). Consider performance optimization before deployment."
            else:
                return f"Deploy model B - accuracy improved by {acc_improvement:.1f}%"
        
        # Model A is winner (B is worse)
        else:
            acc_degradation = (acc_a - acc_b) / acc_a * 100
            return f"Keep model A - model B shows {acc_degradation:.1f}% accuracy degradation"
    
    def stop_test(
        self,
        test_id: str,
        reason: str = ""
    ):
        """
        Stop A/B test.
        
        Args:
            test_id: Test ID
            reason: Reason for stopping
        """
        self.logger.info(f"Stopping A/B test: {test_id} - {reason}")
        
        config = self.active_tests.get(test_id)
        if config:
            config.is_active = False
            config.end_date = datetime.utcnow()
    
    def get_test_status(
        self,
        test_id: str
    ) -> Dict[str, any]:
        """
        Get current status of A/B test.
        
        Args:
            test_id: Test ID
            
        Returns:
            Test status
        """
        config = self.active_tests.get(test_id)
        if not config:
            return {'error': 'Test not found'}
        
        results = self.test_results.get(test_id, [])
        results_a = [r for r in results if r['variant'] == 'A']
        results_b = [r for r in results if r['variant'] == 'B']
        
        return {
            'test_id': test_id,
            'name': config.name,
            'is_active': config.is_active,
            'start_date': config.start_date.isoformat(),
            'samples_a': len(results_a),
            'samples_b': len(results_b),
            'min_samples': config.min_samples,
            'progress': min(len(results_a), len(results_b)) / config.min_samples * 100,
            'traffic_split': config.traffic_split
        }
    
    def auto_rollback_check(
        self,
        test_id: str,
        degradation_threshold: float = 0.05
    ) -> Tuple[bool, str]:
        """
        Check if automatic rollback is needed due to performance degradation.
        
        Args:
            test_id: Test ID
            degradation_threshold: Acceptable degradation (e.g., 0.05 = 5%)
            
        Returns:
            Tuple of (should_rollback, reason)
        """
        result = self.analyze_test(test_id)
        
        # Check if model B is significantly worse
        if result.statistical_significance and result.winner == "A":
            degradation = (result.model_a_accuracy - result.model_b_accuracy) / result.model_a_accuracy
            
            if degradation > degradation_threshold:
                return True, f"Model B shows {degradation*100:.1f}% accuracy degradation"
        
        # Check for severe latency issues
        if result.model_b_latency_ms > result.model_a_latency_ms * 2:
            return True, f"Model B is {result.model_b_latency_ms/result.model_a_latency_ms:.1f}x slower"
        
        return False, "No rollback needed"

