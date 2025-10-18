"""
ML-based researcher profiling and behavior analysis.
"""

import logging
import statistics
from typing import Dict, List, Any, Optional
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from .models import ResearcherProfile

logger = logging.getLogger(__name__)


class ResearcherProfiler:
    """
    Build and maintain ML-based researcher profiles.
    
    Tracks:
    - Submission patterns
    - Quality metrics
    - Specializations
    - Behavioral patterns
    - Reputation scores
    """
    
    def __init__(self):
        """Initialize researcher profiler."""
        self.profiles: Dict[str, ResearcherProfile] = {}
        logger.info("ResearcherProfiler initialized")
    
    def build_profile(self, researcher_id: str, reports: List[Any], validation_results: List[Any]) -> ResearcherProfile:
        """
        Build or update a researcher profile.
        
        Args:
            researcher_id: Unique researcher identifier
            reports: List of reports from this researcher
            validation_results: Corresponding validation results
            
        Returns:
            ResearcherProfile with comprehensive metrics
        """
        logger.info(f"Building profile for researcher {researcher_id} ({len(reports)} reports)")
        
        # Basic counts
        total_submissions = len(reports)
        valid_submissions = sum(
            1 for v in validation_results
            if hasattr(v, 'verdict') and v.verdict == 'valid'
        )
        
        # Quality metrics
        severities = [
            v.cvss_score for v in validation_results
            if hasattr(v, 'cvss_score') and v.cvss_score is not None
        ]
        avg_severity = statistics.mean(severities) if severities else 0.0
        
        confidences = [
            v.confidence for v in validation_results
            if hasattr(v, 'confidence') and v.confidence is not None
        ]
        avg_confidence = statistics.mean(confidences) if confidences else 0.0
        
        # False positive and duplicate rates
        false_positives = sum(
            1 for v in validation_results
            if hasattr(v, 'is_false_positive') and v.is_false_positive
        )
        false_positive_rate = false_positives / total_submissions if total_submissions > 0 else 0.0
        
        duplicates = sum(
            1 for v in validation_results
            if hasattr(v, 'is_duplicate') and v.is_duplicate
        )
        duplicate_rate = duplicates / total_submissions if total_submissions > 0 else 0.0
        
        # Specializations
        specializations = self._identify_specializations(reports, validation_results)
        
        # Preferred targets
        preferred_targets = self._identify_preferred_targets(reports)
        
        # Behavioral patterns
        submission_frequency = self._calculate_submission_frequency(reports)
        peak_hours = self._identify_peak_hours(reports)
        typical_report_length = self._calculate_typical_length(reports)
        
        # Reputation score
        reputation_score = self._calculate_reputation_score(
            valid_submissions, total_submissions, avg_severity,
            false_positive_rate, duplicate_rate
        )
        
        # Trust level
        trust_level = self._determine_trust_level(reputation_score, total_submissions)
        
        # Predictions
        predicted_next_submission = self._predict_next_submission(reports)
        predicted_quality = self._predict_quality(
            avg_severity, avg_confidence, false_positive_rate
        )
        
        profile = ResearcherProfile(
            researcher_id=researcher_id,
            total_submissions=total_submissions,
            valid_submissions=valid_submissions,
            average_severity=avg_severity,
            average_confidence=avg_confidence,
            false_positive_rate=false_positive_rate,
            duplicate_rate=duplicate_rate,
            specializations=specializations,
            preferred_targets=preferred_targets,
            submission_frequency=submission_frequency,
            peak_hours=peak_hours,
            typical_report_length=typical_report_length,
            reputation_score=reputation_score,
            trust_level=trust_level,
            predicted_next_submission=predicted_next_submission,
            predicted_quality=predicted_quality
        )
        
        # Store profile
        self.profiles[researcher_id] = profile
        
        logger.info(f"Profile built: {trust_level} trust, {reputation_score:.1f} reputation")
        
        return profile
    
    def get_profile(self, researcher_id: str) -> Optional[ResearcherProfile]:
        """Get existing profile for a researcher."""
        return self.profiles.get(researcher_id)
    
    def _identify_specializations(self, reports: List[Any], validation_results: List[Any]) -> List[str]:
        """Identify researcher's vulnerability specializations."""
        # Count vulnerability types in valid reports
        vuln_types = []
        for report, validation in zip(reports, validation_results):
            if hasattr(validation, 'verdict') and validation.verdict == 'valid':
                if hasattr(report, 'vulnerability_type') and report.vulnerability_type:
                    vuln_types.append(report.vulnerability_type.lower())
        
        if not vuln_types:
            return []
        
        # Find types that appear more than 20% of the time
        type_counts = Counter(vuln_types)
        total = len(vuln_types)
        
        specializations = [
            vuln_type for vuln_type, count in type_counts.most_common()
            if count / total >= 0.2
        ]
        
        return specializations[:5]  # Top 5 specializations
    
    def _identify_preferred_targets(self, reports: List[Any]) -> List[str]:
        """Identify researcher's preferred target systems."""
        import re
        
        # Extract domains/targets from reports
        targets = []
        for report in reports:
            text = f"{report.title} {report.description}"
            # Extract domains
            domains = re.findall(r'https?://([a-zA-Z0-9.-]+)', text)
            targets.extend(domains)
        
        if not targets:
            return []
        
        # Return most common targets
        target_counts = Counter(targets)
        return [target for target, _ in target_counts.most_common(5)]
    
    def _calculate_submission_frequency(self, reports: List[Any]) -> float:
        """Calculate average reports per day."""
        if len(reports) < 2:
            return 0.0
        
        # Get timestamps
        timestamps = []
        for report in reports:
            if hasattr(report, 'submitted_at') and report.submitted_at:
                if isinstance(report.submitted_at, datetime):
                    timestamps.append(report.submitted_at)
        
        if len(timestamps) < 2:
            return 0.0
        
        # Calculate time span
        timestamps.sort()
        time_span = (timestamps[-1] - timestamps[0]).days
        
        if time_span == 0:
            return len(reports)
        
        return len(reports) / time_span
    
    def _identify_peak_hours(self, reports: List[Any]) -> List[int]:
        """Identify peak submission hours."""
        hours = []
        for report in reports:
            if hasattr(report, 'submitted_at') and report.submitted_at:
                if isinstance(report.submitted_at, datetime):
                    hours.append(report.submitted_at.hour)
        
        if not hours:
            return []
        
        # Find hours with above-average submissions
        hour_counts = Counter(hours)
        avg_count = sum(hour_counts.values()) / 24
        
        peak_hours = [
            hour for hour, count in hour_counts.items()
            if count > avg_count * 1.5
        ]
        
        return sorted(peak_hours)
    
    def _calculate_typical_length(self, reports: List[Any]) -> int:
        """Calculate typical report length."""
        lengths = [
            len(report.description) for report in reports
            if hasattr(report, 'description')
        ]
        
        if not lengths:
            return 0
        
        return int(statistics.median(lengths))
    
    def _calculate_reputation_score(
        self,
        valid_submissions: int,
        total_submissions: int,
        avg_severity: float,
        false_positive_rate: float,
        duplicate_rate: float
    ) -> float:
        """Calculate reputation score (0-100)."""
        if total_submissions == 0:
            return 0.0
        
        # Base score from validity rate
        validity_rate = valid_submissions / total_submissions
        base_score = validity_rate * 40
        
        # Bonus for severity
        severity_bonus = (avg_severity / 10.0) * 30
        
        # Penalty for false positives
        fp_penalty = false_positive_rate * 20
        
        # Penalty for duplicates
        dup_penalty = duplicate_rate * 10
        
        # Volume bonus (logarithmic)
        import math
        volume_bonus = min(20, math.log10(total_submissions + 1) * 10)
        
        reputation = base_score + severity_bonus + volume_bonus - fp_penalty - dup_penalty
        
        return max(0.0, min(100.0, reputation))
    
    def _determine_trust_level(self, reputation_score: float, total_submissions: int) -> str:
        """Determine trust level based on reputation and experience."""
        if total_submissions < 5:
            return "unknown"
        
        if reputation_score >= 80 and total_submissions >= 20:
            return "expert"
        elif reputation_score >= 60 and total_submissions >= 10:
            return "high"
        elif reputation_score >= 40:
            return "medium"
        else:
            return "low"
    
    def _predict_next_submission(self, reports: List[Any]) -> Optional[datetime]:
        """Predict when the next submission will occur."""
        if len(reports) < 3:
            return None
        
        # Get timestamps
        timestamps = []
        for report in reports:
            if hasattr(report, 'submitted_at') and report.submitted_at:
                if isinstance(report.submitted_at, datetime):
                    timestamps.append(report.submitted_at)
        
        if len(timestamps) < 3:
            return None
        
        # Calculate average time between submissions
        timestamps.sort()
        intervals = [
            (timestamps[i+1] - timestamps[i]).total_seconds()
            for i in range(len(timestamps) - 1)
        ]
        
        avg_interval = statistics.mean(intervals)
        
        # Predict next submission
        last_submission = timestamps[-1]
        predicted = last_submission + timedelta(seconds=avg_interval)
        
        return predicted
    
    def _predict_quality(
        self,
        avg_severity: float,
        avg_confidence: float,
        false_positive_rate: float
    ) -> float:
        """Predict quality of next submission (0-1)."""
        # Combine metrics
        severity_component = avg_severity / 10.0
        confidence_component = avg_confidence
        fp_component = 1.0 - false_positive_rate
        
        # Weighted average
        predicted_quality = (
            severity_component * 0.4 +
            confidence_component * 0.4 +
            fp_component * 0.2
        )
        
        return max(0.0, min(1.0, predicted_quality))
    
    def compare_researchers(self, researcher_id1: str, researcher_id2: str) -> Dict[str, Any]:
        """Compare two researchers."""
        profile1 = self.profiles.get(researcher_id1)
        profile2 = self.profiles.get(researcher_id2)
        
        if not profile1 or not profile2:
            return {'error': 'One or both profiles not found'}
        
        return {
            'reputation_comparison': {
                researcher_id1: profile1.reputation_score,
                researcher_id2: profile2.reputation_score,
                'difference': abs(profile1.reputation_score - profile2.reputation_score)
            },
            'quality_comparison': {
                researcher_id1: {
                    'avg_severity': profile1.average_severity,
                    'avg_confidence': profile1.average_confidence,
                    'fp_rate': profile1.false_positive_rate
                },
                researcher_id2: {
                    'avg_severity': profile2.average_severity,
                    'avg_confidence': profile2.average_confidence,
                    'fp_rate': profile2.false_positive_rate
                }
            },
            'specializations': {
                researcher_id1: profile1.specializations,
                researcher_id2: profile2.specializations,
                'overlap': list(set(profile1.specializations) & set(profile2.specializations))
            }
        }

