"""
Anomaly detection for vulnerability reports.
"""

import logging
import statistics
from typing import Dict, List, Any, Optional
from collections import defaultdict
from datetime import datetime, timedelta

from .models import AnomalyScore, AnomalyType
from .feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """
    Detect anomalies in vulnerability reports.
    
    Detects:
    - Novel attack patterns
    - Unusual report characteristics
    - Suspicious researcher behavior
    - Outlier severity scores
    - Abnormal submission timing
    """
    
    def __init__(self, sensitivity: float = 2.0):
        """
        Initialize anomaly detector.
        
        Args:
            sensitivity: Sensitivity threshold (standard deviations)
        """
        self.sensitivity = sensitivity
        self.feature_extractor = FeatureExtractor()
        
        # Baseline statistics
        self.baseline_stats: Dict[str, Dict[str, float]] = {}
        self.historical_reports: List[tuple] = []  # (report, timestamp)
        
        logger.info(f"AnomalyDetector initialized (sensitivity={sensitivity})")
    
    def build_baseline(self, reports: List[Any], timestamps: Optional[List[datetime]] = None):
        """
        Build baseline statistics from historical reports.
        
        Args:
            reports: List of historical reports
            timestamps: Optional timestamps for each report
        """
        logger.info(f"Building baseline from {len(reports)} reports")
        
        # Store historical data
        if timestamps:
            self.historical_reports = list(zip(reports, timestamps))
        else:
            self.historical_reports = [(r, datetime.utcnow()) for r in reports]
        
        # Extract features from all reports
        all_features = []
        for report in reports:
            features = self.feature_extractor.extract_from_report(report)
            all_features.append(features)
        
        # Calculate baseline statistics for each feature
        self.baseline_stats = self._calculate_baseline_stats(all_features)
        
        logger.info(f"Baseline built with {len(self.baseline_stats)} feature statistics")
    
    def detect_anomalies(self, report: Any, timestamp: Optional[datetime] = None) -> AnomalyScore:
        """
        Detect anomalies in a report.
        
        Args:
            report: Vulnerability report to analyze
            timestamp: Optional submission timestamp
            
        Returns:
            AnomalyScore with detection results
        """
        if not self.baseline_stats:
            logger.warning("No baseline available for anomaly detection")
            return AnomalyScore(
                is_anomaly=False,
                anomaly_score=0.0,
                anomaly_type=None,
                explanation="No baseline available for comparison"
            )
        
        # Extract features
        features = self.feature_extractor.extract_from_report(report)
        
        # Calculate anomaly scores for different aspects
        feature_anomalies = self._detect_feature_anomalies(features)
        pattern_anomaly = self._detect_pattern_anomaly(report)
        timing_anomaly = self._detect_timing_anomaly(timestamp) if timestamp else 0.0
        
        # Combine anomaly scores
        combined_score = max(feature_anomalies['max_score'], pattern_anomaly, timing_anomaly)
        
        # Determine if it's an anomaly
        is_anomaly = combined_score > 0.7
        
        # Determine anomaly type
        anomaly_type = self._determine_anomaly_type(
            feature_anomalies, pattern_anomaly, timing_anomaly
        )
        
        # Generate explanation
        explanation = self._generate_explanation(
            features, feature_anomalies, pattern_anomaly, timing_anomaly
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(anomaly_type, combined_score)
        
        # Find similar cases
        similar_cases = self._find_similar_cases(report)
        
        return AnomalyScore(
            is_anomaly=is_anomaly,
            anomaly_score=combined_score,
            anomaly_type=anomaly_type,
            expected_range=(0.0, 0.7),
            actual_value=combined_score,
            deviation_sigma=feature_anomalies['max_deviation'],
            similar_cases=similar_cases,
            explanation=explanation,
            recommendations=recommendations
        )
    
    def _calculate_baseline_stats(self, all_features: List[Dict[str, Any]]) -> Dict[str, Dict[str, float]]:
        """Calculate baseline statistics for features."""
        stats = {}
        
        # Collect values for each feature
        feature_values = defaultdict(list)
        for features in all_features:
            for key, value in features.items():
                if isinstance(value, (int, float, bool)):
                    numeric_value = float(value) if isinstance(value, bool) else value
                    feature_values[key].append(numeric_value)
        
        # Calculate statistics
        for key, values in feature_values.items():
            if len(values) < 2:
                continue
            
            stats[key] = {
                'mean': statistics.mean(values),
                'median': statistics.median(values),
                'stdev': statistics.stdev(values) if len(values) > 1 else 0.0,
                'min': min(values),
                'max': max(values),
                'q1': statistics.quantiles(values, n=4)[0] if len(values) >= 4 else min(values),
                'q3': statistics.quantiles(values, n=4)[2] if len(values) >= 4 else max(values),
            }
        
        return stats
    
    def _detect_feature_anomalies(self, features: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalies in feature values."""
        anomalies = []
        max_deviation = 0.0
        max_score = 0.0
        
        for key, value in features.items():
            if key not in self.baseline_stats:
                continue
            
            if not isinstance(value, (int, float, bool)):
                continue
            
            numeric_value = float(value) if isinstance(value, bool) else value
            stats = self.baseline_stats[key]
            
            # Calculate z-score (standard deviations from mean)
            mean = stats['mean']
            stdev = stats['stdev']
            
            if stdev == 0:
                continue
            
            z_score = abs((numeric_value - mean) / stdev)
            
            # Check if it's an outlier
            if z_score > self.sensitivity:
                anomaly_score = min(1.0, z_score / (self.sensitivity * 2))
                anomalies.append({
                    'feature': key,
                    'value': numeric_value,
                    'expected': mean,
                    'z_score': z_score,
                    'anomaly_score': anomaly_score
                })
                
                max_deviation = max(max_deviation, z_score)
                max_score = max(max_score, anomaly_score)
        
        return {
            'anomalies': anomalies,
            'max_deviation': max_deviation,
            'max_score': max_score
        }
    
    def _detect_pattern_anomaly(self, report: Any) -> float:
        """Detect novel patterns in the report."""
        # Check for unusual combinations of features
        features = self.feature_extractor.extract_from_report(report)
        
        # Calculate how different this report is from typical reports
        differences = 0
        total_features = 0
        
        for key, value in features.items():
            if key not in self.baseline_stats:
                differences += 1
                total_features += 1
                continue
            
            if not isinstance(value, (int, float, bool)):
                continue
            
            total_features += 1
            numeric_value = float(value) if isinstance(value, bool) else value
            stats = self.baseline_stats[key]
            
            # Check if value is outside typical range (Q1-Q3)
            if numeric_value < stats['q1'] or numeric_value > stats['q3']:
                differences += 1
        
        if total_features == 0:
            return 0.0
        
        # Anomaly score based on proportion of unusual features
        pattern_score = differences / total_features
        
        return pattern_score
    
    def _detect_timing_anomaly(self, timestamp: datetime) -> float:
        """Detect anomalies in submission timing."""
        if not self.historical_reports:
            return 0.0
        
        # Extract submission hours from historical data
        historical_hours = [ts.hour for _, ts in self.historical_reports]
        
        if not historical_hours:
            return 0.0
        
        # Calculate typical submission hours
        hour_counts = defaultdict(int)
        for hour in historical_hours:
            hour_counts[hour] += 1
        
        # Check if current hour is unusual
        current_hour = timestamp.hour
        current_count = hour_counts.get(current_hour, 0)
        avg_count = sum(hour_counts.values()) / len(hour_counts)
        
        if avg_count == 0:
            return 0.0
        
        # Anomaly if submission hour is rare
        if current_count < avg_count * 0.3:
            return 0.6
        
        return 0.0
    
    def _determine_anomaly_type(self, feature_anomalies: Dict, pattern_anomaly: float, timing_anomaly: float) -> Optional[AnomalyType]:
        """Determine the type of anomaly."""
        if pattern_anomaly > 0.7:
            return AnomalyType.NOVEL_ATTACK
        
        if feature_anomalies['max_score'] > 0.7:
            # Check which feature is most anomalous
            if feature_anomalies['anomalies']:
                top_anomaly = max(feature_anomalies['anomalies'], key=lambda x: x['anomaly_score'])
                feature_name = top_anomaly['feature']
                
                if 'severity' in feature_name or 'cvss' in feature_name:
                    return AnomalyType.OUTLIER_SEVERITY
                elif 'length' in feature_name or 'complexity' in feature_name:
                    return AnomalyType.UNUSUAL_PATTERN
        
        if timing_anomaly > 0.5:
            return AnomalyType.ABNORMAL_TIMING
        
        return AnomalyType.UNUSUAL_PATTERN
    
    def _generate_explanation(self, features: Dict, feature_anomalies: Dict, pattern_anomaly: float, timing_anomaly: float) -> str:
        """Generate explanation for the anomaly."""
        explanations = []
        
        if feature_anomalies['anomalies']:
            top_anomaly = max(feature_anomalies['anomalies'], key=lambda x: x['anomaly_score'])
            explanations.append(
                f"Feature '{top_anomaly['feature']}' has unusual value {top_anomaly['value']:.2f} "
                f"(expected ~{top_anomaly['expected']:.2f}, {top_anomaly['z_score']:.1f}σ deviation)"
            )
        
        if pattern_anomaly > 0.7:
            explanations.append(
                f"Report exhibits novel pattern not seen in historical data (score: {pattern_anomaly:.2f})"
            )
        
        if timing_anomaly > 0.5:
            explanations.append("Submission timing is unusual compared to historical patterns")
        
        if not explanations:
            return "No significant anomalies detected"
        
        return ". ".join(explanations)
    
    def _generate_recommendations(self, anomaly_type: Optional[AnomalyType], score: float) -> List[str]:
        """Generate recommendations based on anomaly type."""
        recommendations = []
        
        if score > 0.8:
            recommendations.append("High anomaly score - recommend manual review")
        
        if anomaly_type == AnomalyType.NOVEL_ATTACK:
            recommendations.append("Potential novel attack pattern - prioritize for security team review")
            recommendations.append("Consider updating detection rules and patterns")
        
        elif anomaly_type == AnomalyType.OUTLIER_SEVERITY:
            recommendations.append("Severity assessment differs significantly from typical - verify CVSS calculation")
        
        elif anomaly_type == AnomalyType.SUSPICIOUS_BEHAVIOR:
            recommendations.append("Suspicious submission behavior detected - review researcher history")
        
        elif anomaly_type == AnomalyType.ABNORMAL_TIMING:
            recommendations.append("Unusual submission timing - may indicate automated submission")
        
        if not recommendations:
            recommendations.append("Monitor for similar patterns in future submissions")
        
        return recommendations
    
    def _find_similar_cases(self, report: Any, limit: int = 5) -> List[str]:
        """Find similar historical cases."""
        if not self.historical_reports:
            return []
        
        features = self.feature_extractor.extract_from_report(report)
        
        # Calculate similarity to historical reports
        similarities = []
        for hist_report, _ in self.historical_reports[:100]:  # Limit for performance
            hist_features = self.feature_extractor.extract_from_report(hist_report)
            similarity = self._calculate_similarity(features, hist_features)
            similarities.append((hist_report.title, similarity))
        
        # Sort by similarity and return top matches
        similarities.sort(key=lambda x: x[1], reverse=True)
        return [title for title, _ in similarities[:limit]]
    
    def _calculate_similarity(self, features1: Dict, features2: Dict) -> float:
        """Calculate similarity between two feature sets."""
        common_keys = set(features1.keys()) & set(features2.keys())
        
        if not common_keys:
            return 0.0
        
        matches = 0
        for key in common_keys:
            val1 = features1[key]
            val2 = features2[key]
            
            if isinstance(val1, bool) and isinstance(val2, bool):
                if val1 == val2:
                    matches += 1
            elif isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
                # Numeric similarity (within 20%)
                if val1 != 0 and abs(val1 - val2) / abs(val1) < 0.2:
                    matches += 1
            elif val1 == val2:
                matches += 1
        
        return matches / len(common_keys)

