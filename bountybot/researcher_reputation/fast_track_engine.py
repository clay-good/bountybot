"""
Fast-track validation engine for trusted researchers.
"""

import logging
from typing import Dict, Any

from .models import ResearcherReputation, FastTrackEligibility, TrustLevel

logger = logging.getLogger(__name__)


class FastTrackEngine:
    """
    Determines fast-track eligibility for trusted researchers.
    
    Fast-tracking allows high-reputation researchers to have their
    reports validated with reduced scrutiny, saving time and resources.
    
    Priority Levels:
    - 0: Normal validation (full process)
    - 1: Fast (skip some redundant checks)
    - 2: Express (minimal validation, high confidence)
    - 3: Instant (auto-approve for elite researchers)
    
    Example:
        >>> engine = FastTrackEngine()
        >>> eligibility = engine.check_eligibility(reputation)
        >>> if eligibility.eligible:
        ...     print(f"Fast-track at level {eligibility.priority_level}")
        ...     print(f"Saves ~{eligibility.estimated_time_savings_minutes} minutes")
    """
    
    # Thresholds for fast-tracking
    REPUTATION_THRESHOLD_FAST = 70.0  # Level 1
    REPUTATION_THRESHOLD_EXPRESS = 85.0  # Level 2
    REPUTATION_THRESHOLD_INSTANT = 95.0  # Level 3
    
    ACCURACY_THRESHOLD = 0.80  # 80% accuracy required
    VOLUME_THRESHOLD = 10  # Minimum 10 reports
    
    # Time savings estimates (minutes)
    TIME_SAVINGS = {
        1: 15,  # Fast: ~15 minutes saved
        2: 30,  # Express: ~30 minutes saved
        3: 45,  # Instant: ~45 minutes saved
    }
    
    def __init__(self):
        """Initialize fast-track engine."""
        logger.info("FastTrackEngine initialized")
    
    def check_eligibility(self, reputation: ResearcherReputation) -> FastTrackEligibility:
        """
        Check if researcher is eligible for fast-tracking.
        
        Args:
            reputation: ResearcherReputation to check
            
        Returns:
            FastTrackEligibility with results
        """
        eligibility = FastTrackEligibility()
        
        # Check basic criteria
        eligibility.meets_reputation_threshold = (
            reputation.reputation_score.overall >= self.REPUTATION_THRESHOLD_FAST
        )
        eligibility.meets_accuracy_threshold = (
            reputation.accuracy_rate >= self.ACCURACY_THRESHOLD
        )
        eligibility.meets_volume_threshold = (
            reputation.total_reports >= self.VOLUME_THRESHOLD
        )
        eligibility.no_recent_issues = self._check_no_recent_issues(reputation)
        
        # Must meet all criteria
        all_criteria_met = (
            eligibility.meets_reputation_threshold and
            eligibility.meets_accuracy_threshold and
            eligibility.meets_volume_threshold and
            eligibility.no_recent_issues
        )
        
        if not all_criteria_met:
            eligibility.eligible = False
            eligibility.priority_level = 0
            eligibility.confidence = 0.0
            return eligibility
        
        # Determine priority level based on reputation score
        score = reputation.reputation_score.overall
        
        if score >= self.REPUTATION_THRESHOLD_INSTANT:
            eligibility.priority_level = 3  # Instant
            eligibility.confidence = 0.95
        elif score >= self.REPUTATION_THRESHOLD_EXPRESS:
            eligibility.priority_level = 2  # Express
            eligibility.confidence = 0.85
        elif score >= self.REPUTATION_THRESHOLD_FAST:
            eligibility.priority_level = 1  # Fast
            eligibility.confidence = 0.75
        else:
            eligibility.priority_level = 0  # Normal
            eligibility.confidence = 0.0
        
        # Set eligibility
        eligibility.eligible = eligibility.priority_level > 0
        
        # Calculate time savings
        if eligibility.eligible:
            eligibility.estimated_time_savings_minutes = self.TIME_SAVINGS.get(
                eligibility.priority_level, 0
            )
        
        if eligibility.eligible:
            logger.info(
                f"Fast-track eligible: {reputation.username} "
                f"(level={eligibility.priority_level}, "
                f"saves ~{eligibility.estimated_time_savings_minutes}min)"
            )
        
        return eligibility
    
    def _check_no_recent_issues(self, reputation: ResearcherReputation) -> bool:
        """Check if researcher has no recent issues."""
        # Check last 10 reports for issues
        recent_history = reputation.history[-10:] if len(reputation.history) >= 10 else reputation.history
        
        if not recent_history:
            return True
        
        # Count invalid reports in recent history
        invalid_count = sum(
            1 for h in recent_history
            if h.event and 'INVALID' in h.event.upper()
        )
        
        # If more than 20% of recent reports are invalid, not eligible
        if invalid_count / len(recent_history) > 0.2:
            return False
        
        # Check for spam indicators
        if reputation.spam_indicators.is_spam:
            return False
        
        return True
    
    def get_validation_strategy(self, eligibility: FastTrackEligibility) -> Dict[str, Any]:
        """
        Get recommended validation strategy based on fast-track level.
        
        Args:
            eligibility: FastTrackEligibility result
            
        Returns:
            Validation strategy configuration
        """
        if not eligibility.eligible:
            return {
                'priority_level': 0,
                'strategy': 'full',
                'skip_checks': [],
                'description': 'Full validation with all checks'
            }
        
        level = eligibility.priority_level
        
        if level == 1:  # Fast
            return {
                'priority_level': 1,
                'strategy': 'fast',
                'skip_checks': [
                    'basic_quality_check',  # Skip basic quality checks
                ],
                'description': 'Fast validation - skip basic quality checks',
                'estimated_time_minutes': 30
            }
        
        elif level == 2:  # Express
            return {
                'priority_level': 2,
                'strategy': 'express',
                'skip_checks': [
                    'basic_quality_check',
                    'plausibility_check',  # Skip plausibility analysis
                    'duplicate_check',  # Skip duplicate detection (trusted researcher)
                ],
                'description': 'Express validation - minimal checks only',
                'estimated_time_minutes': 15
            }
        
        elif level == 3:  # Instant
            return {
                'priority_level': 3,
                'strategy': 'instant',
                'skip_checks': [
                    'basic_quality_check',
                    'plausibility_check',
                    'duplicate_check',
                    'false_positive_check',  # Skip FP detection
                ],
                'description': 'Instant validation - auto-approve with minimal verification',
                'estimated_time_minutes': 5,
                'auto_approve': True
            }
        
        return {
            'priority_level': 0,
            'strategy': 'full',
            'skip_checks': [],
            'description': 'Full validation'
        }
    
    def calculate_time_savings(
        self,
        reputations: list[ResearcherReputation]
    ) -> Dict[str, Any]:
        """
        Calculate total time savings from fast-tracking.
        
        Args:
            reputations: List of ResearcherReputation objects
            
        Returns:
            Time savings statistics
        """
        total_researchers = len(reputations)
        fast_track_eligible = 0
        total_time_saved_minutes = 0
        
        by_level = {1: 0, 2: 0, 3: 0}
        
        for reputation in reputations:
            eligibility = self.check_eligibility(reputation)
            if eligibility.eligible:
                fast_track_eligible += 1
                total_time_saved_minutes += eligibility.estimated_time_savings_minutes
                by_level[eligibility.priority_level] += 1
        
        return {
            'total_researchers': total_researchers,
            'fast_track_eligible': fast_track_eligible,
            'fast_track_percentage': (fast_track_eligible / total_researchers * 100) if total_researchers > 0 else 0,
            'total_time_saved_minutes': total_time_saved_minutes,
            'total_time_saved_hours': total_time_saved_minutes / 60,
            'by_level': {
                'fast': by_level[1],
                'express': by_level[2],
                'instant': by_level[3],
            },
            'average_time_saved_per_researcher': (
                total_time_saved_minutes / fast_track_eligible
                if fast_track_eligible > 0 else 0
            )
        }

