"""
Pattern learning from vulnerability reports.
"""

import logging
import secrets
from typing import Dict, List, Any, Optional
from collections import Counter, defaultdict
from datetime import datetime

from .models import VulnerabilityPattern
from .feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


class PatternLearner:
    """
    Learn vulnerability patterns from historical reports.
    
    Identifies:
    - Common vulnerability patterns
    - Attack signatures
    - Exploit techniques
    - Researcher patterns
    """
    
    def __init__(self, min_frequency: int = 3, min_confidence: float = 0.7):
        """
        Initialize pattern learner.
        
        Args:
            min_frequency: Minimum occurrences to consider a pattern
            min_confidence: Minimum confidence threshold
        """
        self.min_frequency = min_frequency
        self.min_confidence = min_confidence
        self.feature_extractor = FeatureExtractor()
        
        # Storage
        self.patterns: Dict[str, VulnerabilityPattern] = {}
        self.pattern_index: Dict[str, List[str]] = defaultdict(list)  # vuln_type -> pattern_ids
        
        logger.info(f"PatternLearner initialized (min_freq={min_frequency}, min_conf={min_confidence})")
    
    def learn_from_reports(self, reports: List[Any], validation_results: Optional[List[Any]] = None) -> List[VulnerabilityPattern]:
        """
        Learn patterns from a batch of reports.
        
        Args:
            reports: List of vulnerability reports
            validation_results: Optional validation results for each report
            
        Returns:
            List of learned patterns
        """
        logger.info(f"Learning patterns from {len(reports)} reports")
        
        # Group reports by vulnerability type
        grouped_reports = defaultdict(list)
        for i, report in enumerate(reports):
            vuln_type = self._get_vulnerability_type(report)
            validation = validation_results[i] if validation_results and i < len(validation_results) else None
            grouped_reports[vuln_type].append((report, validation))
        
        learned_patterns = []
        
        # Learn patterns for each vulnerability type
        for vuln_type, report_pairs in grouped_reports.items():
            if len(report_pairs) < self.min_frequency:
                logger.debug(f"Skipping {vuln_type}: insufficient samples ({len(report_pairs)})")
                continue
            
            patterns = self._learn_patterns_for_type(vuln_type, report_pairs)
            learned_patterns.extend(patterns)
        
        logger.info(f"Learned {len(learned_patterns)} new patterns")
        
        return learned_patterns
    
    def _learn_patterns_for_type(self, vuln_type: str, report_pairs: List[tuple]) -> List[VulnerabilityPattern]:
        """Learn patterns for a specific vulnerability type."""
        patterns = []
        
        # Extract features from all reports
        all_features = []
        valid_reports = []
        
        for report, validation in report_pairs:
            # Only learn from valid reports
            if validation and hasattr(validation, 'verdict') and validation.verdict != 'valid':
                continue
            
            features = self.feature_extractor.extract_from_report(report)
            all_features.append(features)
            valid_reports.append(report)
        
        if len(valid_reports) < self.min_frequency:
            return patterns
        
        # Identify common patterns
        common_patterns = self._identify_common_patterns(all_features)
        
        # Create pattern objects
        for pattern_features, frequency in common_patterns:
            if frequency < self.min_frequency:
                continue
            
            confidence = frequency / len(valid_reports)
            if confidence < self.min_confidence:
                continue
            
            pattern = VulnerabilityPattern(
                pattern_id=f"pattern_{secrets.token_hex(8)}",
                vulnerability_type=vuln_type,
                features=pattern_features,
                frequency=frequency,
                confidence=confidence,
                examples=[r.title for r in valid_reports[:5]],
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow()
            )
            
            # Extract common characteristics
            pattern.common_keywords = self._extract_common_keywords(valid_reports)
            pattern.common_endpoints = self._extract_common_endpoints(valid_reports)
            pattern.common_parameters = self._extract_common_parameters(valid_reports)
            
            # Store pattern
            self.patterns[pattern.pattern_id] = pattern
            self.pattern_index[vuln_type].append(pattern.pattern_id)
            
            patterns.append(pattern)
            
            logger.debug(f"Learned pattern {pattern.pattern_id} for {vuln_type} (freq={frequency}, conf={confidence:.2f})")
        
        return patterns
    
    def _identify_common_patterns(self, all_features: List[Dict[str, Any]]) -> List[tuple]:
        """Identify common feature patterns."""
        patterns = []
        
        if not all_features:
            return patterns
        
        # Find common feature combinations
        feature_keys = set()
        for features in all_features:
            feature_keys.update(features.keys())
        
        # For each feature, find common values
        common_features = {}
        for key in feature_keys:
            values = [f.get(key) for f in all_features if key in f]
            if not values:
                continue
            
            # For boolean features
            if all(isinstance(v, bool) for v in values):
                true_count = sum(values)
                if true_count >= self.min_frequency:
                    common_features[key] = True
            
            # For numeric features
            elif all(isinstance(v, (int, float)) for v in values):
                avg_value = sum(values) / len(values)
                common_features[key] = avg_value
            
            # For string features
            elif all(isinstance(v, str) for v in values):
                value_counts = Counter(values)
                most_common = value_counts.most_common(1)[0]
                if most_common[1] >= self.min_frequency:
                    common_features[key] = most_common[0]
        
        if common_features:
            # Count how many reports match this pattern
            match_count = sum(
                1 for features in all_features
                if self._matches_pattern(features, common_features)
            )
            patterns.append((common_features, match_count))
        
        return patterns
    
    def _matches_pattern(self, features: Dict[str, Any], pattern: Dict[str, Any], tolerance: float = 0.2) -> bool:
        """Check if features match a pattern."""
        matches = 0
        total = len(pattern)
        
        for key, pattern_value in pattern.items():
            if key not in features:
                continue
            
            feature_value = features[key]
            
            # Boolean match
            if isinstance(pattern_value, bool):
                if feature_value == pattern_value:
                    matches += 1
            
            # Numeric match (with tolerance)
            elif isinstance(pattern_value, (int, float)) and isinstance(feature_value, (int, float)):
                if abs(feature_value - pattern_value) <= abs(pattern_value * tolerance):
                    matches += 1
            
            # String match
            elif isinstance(pattern_value, str):
                if feature_value == pattern_value:
                    matches += 1
        
        return matches / total >= 0.7 if total > 0 else False
    
    def _extract_common_keywords(self, reports: List[Any]) -> List[str]:
        """Extract common keywords from reports."""
        all_words = []
        for report in reports:
            text = f"{report.title} {report.description}".lower()
            words = text.split()
            all_words.extend(words)
        
        word_counts = Counter(all_words)
        # Return top 10 most common words (excluding very common words)
        common_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        return [
            word for word, count in word_counts.most_common(20)
            if word not in common_words and len(word) > 3
        ][:10]
    
    def _extract_common_endpoints(self, reports: List[Any]) -> List[str]:
        """Extract common endpoints from reports."""
        import re
        all_endpoints = []
        
        for report in reports:
            text = f"{report.title} {report.description}"
            endpoints = re.findall(r'/[a-zA-Z0-9/_-]+', text)
            all_endpoints.extend(endpoints)
        
        endpoint_counts = Counter(all_endpoints)
        return [ep for ep, count in endpoint_counts.most_common(10) if count >= 2]
    
    def _extract_common_parameters(self, reports: List[Any]) -> List[str]:
        """Extract common parameters from reports."""
        import re
        all_params = []
        
        for report in reports:
            text = f"{report.title} {report.description}"
            params = re.findall(r'[?&]([a-zA-Z0-9_]+)=', text)
            all_params.extend(params)
        
        param_counts = Counter(all_params)
        return [param for param, count in param_counts.most_common(10) if count >= 2]
    
    def _get_vulnerability_type(self, report: Any) -> str:
        """Get vulnerability type from report."""
        if hasattr(report, 'vulnerability_type') and report.vulnerability_type:
            return report.vulnerability_type.lower()
        
        # Try to infer from title
        title_lower = report.title.lower()
        if 'sql' in title_lower or 'injection' in title_lower:
            return 'sql injection'
        elif 'xss' in title_lower or 'cross-site scripting' in title_lower:
            return 'xss'
        elif 'csrf' in title_lower:
            return 'csrf'
        elif 'ssrf' in title_lower:
            return 'ssrf'
        elif 'rce' in title_lower or 'remote code' in title_lower:
            return 'rce'
        
        return 'unknown'
    
    def get_patterns_for_type(self, vuln_type: str) -> List[VulnerabilityPattern]:
        """Get all patterns for a vulnerability type."""
        pattern_ids = self.pattern_index.get(vuln_type.lower(), [])
        return [self.patterns[pid] for pid in pattern_ids if pid in self.patterns]
    
    def match_report_to_patterns(self, report: Any) -> List[tuple]:
        """
        Match a report to known patterns.
        
        Args:
            report: Vulnerability report
            
        Returns:
            List of (pattern, confidence) tuples
        """
        vuln_type = self._get_vulnerability_type(report)
        patterns = self.get_patterns_for_type(vuln_type)
        
        if not patterns:
            return []
        
        features = self.feature_extractor.extract_from_report(report)
        
        matches = []
        for pattern in patterns:
            if self._matches_pattern(features, pattern.features):
                matches.append((pattern, pattern.confidence))
        
        # Sort by confidence
        matches.sort(key=lambda x: x[1], reverse=True)
        
        return matches

