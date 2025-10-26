"""
Spam and low-quality researcher detection.
"""

import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from collections import Counter

from .models import ResearcherReputation, SpamIndicators

logger = logging.getLogger(__name__)


class SpamDetector:
    """
    Detects spam and low-quality researcher behavior.
    
    Analyzes patterns such as:
    - High submission rate with low quality
    - Duplicate submission patterns
    - Copy-pasted reports
    - Automated submissions
    - Suspicious behavioral patterns
    
    Example:
        >>> detector = SpamDetector()
        >>> indicators = detector.analyze(reputation)
        >>> if indicators.is_spam:
        ...     print(f"Spam detected with {indicators.confidence:.0%} confidence")
    """
    
    # Thresholds
    HIGH_SUBMISSION_RATE_THRESHOLD = 10  # Reports per day
    LOW_QUALITY_THRESHOLD = 0.3  # 30% accuracy or less
    DUPLICATE_RATE_THRESHOLD = 0.4  # 40% duplicates
    SPAM_CONFIDENCE_THRESHOLD = 0.7  # 70% confidence to flag as spam
    
    def __init__(self):
        """Initialize spam detector."""
        logger.info("SpamDetector initialized")
    
    def analyze(self, reputation: ResearcherReputation) -> SpamIndicators:
        """
        Analyze researcher for spam indicators.
        
        Args:
            reputation: ResearcherReputation to analyze
            
        Returns:
            SpamIndicators with detection results
        """
        indicators = SpamIndicators()
        signals = []
        risk_score = 0.0
        
        # Need minimum data to analyze
        if reputation.total_reports < 3:
            return indicators
        
        # 1. Check submission rate
        if self._check_high_submission_rate(reputation):
            indicators.high_submission_rate = True
            signals.append("High submission rate detected")
            risk_score += 25
        
        # 2. Check quality
        if self._check_low_quality(reputation):
            indicators.low_quality_reports = True
            signals.append("Consistently low quality reports")
            risk_score += 30
        
        # 3. Check duplicate pattern
        if self._check_duplicate_pattern(reputation):
            indicators.duplicate_pattern = True
            signals.append("High duplicate submission rate")
            risk_score += 20
        
        # 4. Check for copy-paste behavior
        if self._check_copy_paste(reputation):
            indicators.copy_paste_detected = True
            signals.append("Possible copy-pasted reports")
            risk_score += 15
        
        # 5. Check for automated submissions
        if self._check_automated(reputation):
            indicators.automated_submission = True
            signals.append("Possible automated submissions")
            risk_score += 20
        
        # Calculate overall spam confidence
        indicators.signals = signals
        indicators.risk_score = min(100, risk_score)
        indicators.confidence = indicators.risk_score / 100.0
        
        # Flag as spam if confidence is high enough
        if indicators.confidence >= self.SPAM_CONFIDENCE_THRESHOLD:
            indicators.is_spam = True
            logger.warning(
                f"Spam detected for {reputation.username}: "
                f"confidence={indicators.confidence:.0%}, "
                f"signals={len(signals)}"
            )
        
        return indicators
    
    def _check_high_submission_rate(self, reputation: ResearcherReputation) -> bool:
        """Check if submission rate is suspiciously high."""
        if not reputation.first_report_date or not reputation.last_report_date:
            return False
        
        # Calculate days active
        days_active = (reputation.last_report_date - reputation.first_report_date).days
        if days_active == 0:
            days_active = 1
        
        reports_per_day = reputation.total_reports / days_active
        
        # High rate + low quality = spam
        if reports_per_day > self.HIGH_SUBMISSION_RATE_THRESHOLD:
            if reputation.accuracy_rate < 0.5:  # Less than 50% valid
                return True
        
        return False
    
    def _check_low_quality(self, reputation: ResearcherReputation) -> bool:
        """Check if reports are consistently low quality."""
        # Low accuracy rate
        if reputation.accuracy_rate <= self.LOW_QUALITY_THRESHOLD:
            return True
        
        # High false positive rate
        if reputation.total_reports > 0:
            fp_rate = reputation.false_positive_reports / reputation.total_reports
            if fp_rate > 0.5:  # More than 50% false positives
                return True
        
        # Low confidence scores
        if reputation.average_confidence < 0.3:
            return True
        
        return False
    
    def _check_duplicate_pattern(self, reputation: ResearcherReputation) -> bool:
        """Check for pattern of submitting duplicates."""
        if reputation.total_reports == 0:
            return False
        
        duplicate_rate = reputation.duplicate_reports / reputation.total_reports
        
        # High duplicate rate is suspicious
        if duplicate_rate >= self.DUPLICATE_RATE_THRESHOLD:
            return True
        
        return False
    
    def _check_copy_paste(self, reputation: ResearcherReputation) -> bool:
        """Check for copy-pasted reports."""
        # Look for patterns in history
        # If multiple reports submitted at exact same time, likely copy-paste
        
        if len(reputation.history) < 5:
            return False
        
        # Check for reports submitted within seconds of each other
        timestamps = [h.timestamp for h in reputation.history[-20:]]  # Last 20
        timestamps.sort()
        
        rapid_submissions = 0
        for i in range(len(timestamps) - 1):
            time_diff = (timestamps[i + 1] - timestamps[i]).total_seconds()
            if time_diff < 60:  # Less than 1 minute apart
                rapid_submissions += 1
        
        # If more than 30% of submissions are rapid, suspicious
        if rapid_submissions / len(timestamps) > 0.3:
            return True
        
        return False
    
    def _check_automated(self, reputation: ResearcherReputation) -> bool:
        """Check for automated submission patterns."""
        if len(reputation.history) < 10:
            return False
        
        # Check for perfectly regular submission intervals
        timestamps = [h.timestamp for h in reputation.history[-20:]]
        timestamps.sort()
        
        intervals = []
        for i in range(len(timestamps) - 1):
            interval = (timestamps[i + 1] - timestamps[i]).total_seconds()
            intervals.append(interval)
        
        if not intervals:
            return False
        
        # Calculate variance in intervals
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        
        # Very low variance = suspiciously regular
        if std_dev < mean_interval * 0.1 and mean_interval < 3600:  # Less than 1 hour
            return True
        
        return False
    
    def get_spam_report(self, reputation: ResearcherReputation) -> Dict[str, Any]:
        """
        Generate detailed spam analysis report.
        
        Args:
            reputation: ResearcherReputation to analyze
            
        Returns:
            Detailed spam analysis report
        """
        indicators = self.analyze(reputation)
        
        return {
            'researcher_id': reputation.researcher_id,
            'username': reputation.username,
            'is_spam': indicators.is_spam,
            'confidence': indicators.confidence,
            'risk_score': indicators.risk_score,
            'signals': indicators.signals,
            'indicators': {
                'high_submission_rate': indicators.high_submission_rate,
                'low_quality_reports': indicators.low_quality_reports,
                'duplicate_pattern': indicators.duplicate_pattern,
                'copy_paste_detected': indicators.copy_paste_detected,
                'automated_submission': indicators.automated_submission,
            },
            'statistics': {
                'total_reports': reputation.total_reports,
                'accuracy_rate': reputation.accuracy_rate,
                'duplicate_rate': reputation.duplicate_reports / reputation.total_reports if reputation.total_reports > 0 else 0,
                'false_positive_rate': reputation.false_positive_reports / reputation.total_reports if reputation.total_reports > 0 else 0,
            },
            'recommendation': self._get_recommendation(indicators)
        }
    
    def _get_recommendation(self, indicators: SpamIndicators) -> str:
        """Get recommendation based on spam indicators."""
        if indicators.is_spam:
            if indicators.confidence > 0.9:
                return "BLOCK: High confidence spam detection. Consider banning researcher."
            elif indicators.confidence > 0.7:
                return "REVIEW: Likely spam. Manual review recommended before accepting reports."
            else:
                return "MONITOR: Possible spam. Monitor closely for additional signals."
        else:
            if indicators.risk_score > 50:
                return "WATCH: Some concerning signals. Monitor for patterns."
            else:
                return "OK: No significant spam indicators detected."

