"""Zero-day vulnerability predictor."""

import logging
from typing import Optional, Dict

from bountybot.ml.zero_day.models import (
    ZeroDayPrediction,
    ThreatLevel,
    VulnerabilityNovelty,
    PredictionFactors,
    ZeroDayConfig
)
from bountybot.ml.zero_day.pattern_analyzer import PatternAnalyzer
from bountybot.ml.zero_day.anomaly_detector import AnomalyDetector as ZeroDayAnomalyDetector
from bountybot.ml.zero_day.threat_scorer import ThreatScorer

logger = logging.getLogger(__name__)


class ZeroDayPredictor:
    """
    Predict zero-day vulnerabilities using ML.
    
    Analyzes code patterns, anomalies, and threat indicators to predict
    likelihood of zero-day vulnerabilities.
    """
    
    def __init__(self, config: Optional[ZeroDayConfig] = None):
        """Initialize zero-day predictor."""
        self.config = config or ZeroDayConfig()
        self.pattern_analyzer = PatternAnalyzer(self.config)
        self.anomaly_detector = ZeroDayAnomalyDetector(self.config)
        self.threat_scorer = ThreatScorer(self.config)
        
        logger.info("Initialized ZeroDayPredictor")
    
    def predict(
        self,
        code: str,
        metadata: Optional[Dict] = None
    ) -> ZeroDayPrediction:
        """
        Predict zero-day vulnerability likelihood.
        
        Args:
            code: Source code to analyze
            metadata: Optional metadata (language, dependencies, etc.)
        
        Returns:
            Zero-day prediction with likelihood and factors
        """
        logger.info("Analyzing code for zero-day vulnerabilities...")
        
        metadata = metadata or {}
        
        # Analyze patterns
        pattern_score = self.pattern_analyzer.analyze(code, metadata)
        
        # Detect anomalies
        anomaly_result = self.anomaly_detector.detect(code, metadata)
        
        # Calculate prediction factors
        factors = self._calculate_factors(code, metadata, pattern_score, anomaly_result.score)
        
        # Calculate overall likelihood
        likelihood = factors.get_weighted_score()
        
        # Determine threat level
        threat_level = self._determine_threat_level(likelihood)
        
        # Determine novelty
        novelty = self._determine_novelty(pattern_score)
        
        # Estimate time to exploit
        time_to_exploit = self._estimate_time_to_exploit(likelihood, threat_level)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(likelihood, threat_level, factors)
        
        prediction = ZeroDayPrediction(
            likelihood=likelihood,
            threat_level=threat_level,
            novelty=novelty,
            factors=factors,
            time_to_exploit_days=time_to_exploit,
            potential_impact=self._assess_impact(threat_level),
            recommended_actions=recommendations,
            confidence=0.75
        )
        
        logger.info(
            f"Zero-day prediction: likelihood={likelihood:.2%}, "
            f"threat={threat_level.value}, novelty={novelty.value}"
        )
        
        return prediction
    
    def _calculate_factors(
        self,
        code: str,
        metadata: Dict,
        pattern_score: float,
        anomaly_score: float
    ) -> PredictionFactors:
        """Calculate prediction factors."""
        return PredictionFactors(
            code_complexity=self._calculate_complexity(code),
            attack_surface=self._calculate_attack_surface(code, metadata),
            historical_vulnerability_density=metadata.get('vuln_density', 0.3),
            code_change_frequency=metadata.get('change_frequency', 0.5),
            dependency_risk=metadata.get('dependency_risk', 0.4),
            security_practices_score=metadata.get('security_score', 0.6),
            anomaly_score=anomaly_score,
            pattern_novelty=pattern_score
        )
    
    def _calculate_complexity(self, code: str) -> float:
        """Calculate code complexity (0-1)."""
        lines = code.count('\n') + 1
        # Simplified complexity based on lines and decision points
        decision_points = code.count('if') + code.count('for') + code.count('while')
        complexity = min(1.0, (lines + decision_points * 2) / 1000)
        return complexity
    
    def _calculate_attack_surface(self, code: str, metadata: Dict) -> float:
        """Calculate attack surface (0-1)."""
        # Count potential entry points
        entry_points = (
            code.count('def ') +
            code.count('function ') +
            code.count('public ') +
            code.count('@app.route')
        )
        return min(1.0, entry_points / 50)
    
    def _determine_threat_level(self, likelihood: float) -> ThreatLevel:
        """Determine threat level from likelihood."""
        if likelihood >= 0.8:
            return ThreatLevel.CRITICAL
        elif likelihood >= 0.6:
            return ThreatLevel.HIGH
        elif likelihood >= 0.4:
            return ThreatLevel.MEDIUM
        elif likelihood >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.MINIMAL
    
    def _determine_novelty(self, pattern_score: float) -> VulnerabilityNovelty:
        """Determine vulnerability novelty."""
        if pattern_score >= 0.8:
            return VulnerabilityNovelty.COMPLETELY_NEW
        elif pattern_score >= 0.5:
            return VulnerabilityNovelty.VARIANT_OF_KNOWN
        else:
            return VulnerabilityNovelty.KNOWN_PATTERN
    
    def _estimate_time_to_exploit(self, likelihood: float, threat_level: ThreatLevel) -> int:
        """Estimate time to exploit in days."""
        base_days = {
            ThreatLevel.CRITICAL: 7,
            ThreatLevel.HIGH: 30,
            ThreatLevel.MEDIUM: 90,
            ThreatLevel.LOW: 180,
            ThreatLevel.MINIMAL: 365,
        }
        
        days = base_days[threat_level]
        # Adjust based on likelihood
        days = int(days * (1.0 - likelihood * 0.5))
        return max(1, days)
    
    def _assess_impact(self, threat_level: ThreatLevel) -> str:
        """Assess potential impact."""
        impacts = {
            ThreatLevel.CRITICAL: "Severe: Complete system compromise possible",
            ThreatLevel.HIGH: "High: Significant data breach or service disruption",
            ThreatLevel.MEDIUM: "Moderate: Limited data exposure or functionality impact",
            ThreatLevel.LOW: "Low: Minor security degradation",
            ThreatLevel.MINIMAL: "Minimal: Negligible security impact",
        }
        return impacts[threat_level]
    
    def _generate_recommendations(
        self,
        likelihood: float,
        threat_level: ThreatLevel,
        factors: PredictionFactors
    ) -> list:
        """Generate recommended actions."""
        recommendations = []
        
        if likelihood > 0.7:
            recommendations.append("Immediate security review required")
            recommendations.append("Deploy additional monitoring")
        
        if factors.code_complexity > 0.7:
            recommendations.append("Refactor complex code sections")
        
        if factors.attack_surface > 0.6:
            recommendations.append("Reduce attack surface")
        
        if factors.dependency_risk > 0.6:
            recommendations.append("Update vulnerable dependencies")
        
        recommendations.append("Conduct penetration testing")
        recommendations.append("Implement defense-in-depth measures")
        
        return recommendations

