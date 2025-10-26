"""
Core reputation management system.
"""

import logging
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import Counter

from .models import (
    ResearcherReputation,
    TrustLevel,
    ReputationScore,
    ReputationHistory,
    ResearcherBadge,
    BadgeType,
)
from .spam_detector import SpamDetector
from .fast_track_engine import FastTrackEngine

logger = logging.getLogger(__name__)


class ReputationManager:
    """
    Manages researcher reputation scoring and tracking.
    
    Features:
    - Multi-dimensional reputation scoring
    - Trust level classification
    - Historical tracking
    - Badge awarding
    - Integration with spam detection and fast-tracking
    
    Example:
        >>> manager = ReputationManager()
        >>> reputation = manager.update_reputation(
        ...     researcher_id="researcher-123",
        ...     validation_result=result
        ... )
        >>> print(f"Trust level: {reputation.trust_level.value}")
        >>> print(f"Should fast-track: {reputation.should_fast_track}")
    """
    
    def __init__(self):
        """Initialize reputation manager."""
        self.reputations: Dict[str, ResearcherReputation] = {}
        self.spam_detector = SpamDetector()
        self.fast_track_engine = FastTrackEngine()
        logger.info("ReputationManager initialized")
    
    def get_or_create_reputation(
        self,
        researcher_id: str,
        username: str
    ) -> ResearcherReputation:
        """
        Get existing reputation or create new one.
        
        Args:
            researcher_id: Unique researcher identifier
            username: Researcher username
            
        Returns:
            ResearcherReputation object
        """
        if researcher_id not in self.reputations:
            self.reputations[researcher_id] = ResearcherReputation(
                researcher_id=researcher_id,
                username=username
            )
            logger.info(f"Created new reputation profile for {username}")
        
        return self.reputations[researcher_id]
    
    def update_reputation(
        self,
        researcher_id: str,
        validation_result: Any,
        username: Optional[str] = None
    ) -> ResearcherReputation:
        """
        Update researcher reputation based on validation result.
        
        Args:
            researcher_id: Unique researcher identifier
            validation_result: ValidationResult object
            username: Optional username (for new researchers)
            
        Returns:
            Updated ResearcherReputation
        """
        # Get or create reputation
        username = username or f"researcher_{researcher_id}"
        reputation = self.get_or_create_reputation(researcher_id, username)
        
        # Update statistics
        reputation.total_reports += 1
        reputation.last_report_date = datetime.utcnow()
        
        if reputation.first_report_date is None:
            reputation.first_report_date = datetime.utcnow()
        
        # Update based on verdict
        verdict = str(validation_result.verdict).upper() if hasattr(validation_result, 'verdict') else 'UNKNOWN'
        
        if verdict == 'VALID':
            reputation.valid_reports += 1
            reputation.current_valid_streak += 1
            reputation.longest_valid_streak = max(
                reputation.longest_valid_streak,
                reputation.current_valid_streak
            )
        elif verdict == 'INVALID':
            reputation.invalid_reports += 1
            reputation.current_valid_streak = 0
        
        # Update false positives and duplicates
        if hasattr(validation_result, 'is_false_positive') and validation_result.is_false_positive:
            reputation.false_positive_reports += 1
        
        if hasattr(validation_result, 'is_duplicate') and validation_result.is_duplicate:
            reputation.duplicate_reports += 1
        
        # Update quality metrics
        if hasattr(validation_result, 'confidence'):
            # Running average
            n = reputation.valid_reports if verdict == 'VALID' else reputation.total_reports
            if n > 0:
                reputation.average_confidence = (
                    (reputation.average_confidence * (n - 1) + validation_result.confidence) / n
                )
        
        if hasattr(validation_result, 'cvss_score') and validation_result.cvss_score:
            # Handle both object and numeric cvss_score
            if hasattr(validation_result.cvss_score, 'overall_score'):
                cvss = validation_result.cvss_score.overall_score
            elif isinstance(validation_result.cvss_score, (int, float)):
                cvss = float(validation_result.cvss_score)
            else:
                cvss = 0.0

            n = reputation.valid_reports
            if n > 0 and cvss > 0:
                reputation.average_cvss_score = (
                    (reputation.average_cvss_score * (n - 1) + cvss) / n
                )
                reputation.average_severity = reputation.average_cvss_score
        
        # Calculate accuracy rate
        if reputation.total_reports > 0:
            reputation.accuracy_rate = reputation.valid_reports / reputation.total_reports
        
        # Calculate reputation score
        reputation.reputation_score = self._calculate_reputation_score(reputation)
        
        # Determine trust level
        reputation.trust_level = self._determine_trust_level(reputation)
        
        # Check for spam
        reputation.spam_indicators = self.spam_detector.analyze(reputation)
        
        # Check fast-track eligibility
        reputation.fast_track = self.fast_track_engine.check_eligibility(reputation)
        
        # Award badges
        self._check_and_award_badges(reputation, validation_result)
        
        # Add to history
        reputation.history.append(ReputationHistory(
            timestamp=datetime.utcnow(),
            reputation_score=reputation.reputation_score.overall,
            trust_level=reputation.trust_level,
            total_reports=reputation.total_reports,
            valid_reports=reputation.valid_reports,
            event=f"Report validated: {verdict}"
        ))
        
        # Keep only last 100 history entries
        if len(reputation.history) > 100:
            reputation.history = reputation.history[-100:]
        
        reputation.updated_at = datetime.utcnow()
        
        logger.info(
            f"Updated reputation for {username}: "
            f"score={reputation.reputation_score.overall:.1f}, "
            f"trust={reputation.trust_level.value}, "
            f"fast_track={reputation.should_fast_track}"
        )
        
        return reputation
    
    def _calculate_reputation_score(self, reputation: ResearcherReputation) -> ReputationScore:
        """Calculate multi-dimensional reputation score."""
        score = ReputationScore()
        
        if reputation.total_reports == 0:
            return score
        
        # 1. Accuracy (0-100): Valid report rate
        score.accuracy = (reputation.valid_reports / reputation.total_reports) * 100
        
        # 2. Quality (0-100): Based on average confidence
        score.quality = reputation.average_confidence
        
        # 3. Severity (0-100): Based on average CVSS score
        score.severity = (reputation.average_cvss_score / 10.0) * 100
        
        # 4. Consistency (0-100): Based on streaks
        max_possible_streak = min(reputation.total_reports, 50)  # Cap at 50
        if max_possible_streak > 0:
            score.consistency = (reputation.longest_valid_streak / max_possible_streak) * 100
        
        # 5. Responsiveness (0-100): Based on report frequency and engagement
        # Score based on how actively the researcher participates
        # Higher score for consistent activity (not too slow, not spammy)
        if reputation.total_reports > 0 and reputation.last_report_date:
            days_since_last = (datetime.utcnow() - reputation.last_report_date).days
            # Optimal: 1-30 days since last report
            if days_since_last <= 30:
                score.responsiveness = 100.0
            elif days_since_last <= 90:
                score.responsiveness = 80.0
            elif days_since_last <= 180:
                score.responsiveness = 60.0
            else:
                score.responsiveness = 40.0
        else:
            score.responsiveness = 75.0  # Default for new researchers
        
        # 6. Volume (0-100): Logarithmic scale
        score.volume = min(100, math.log10(reputation.total_reports + 1) * 50)
        
        # Penalties
        if reputation.total_reports > 0:
            score.false_positive_penalty = (reputation.false_positive_reports / reputation.total_reports) * 30
            score.duplicate_penalty = (reputation.duplicate_reports / reputation.total_reports) * 20
        
        if reputation.spam_indicators.is_spam:
            score.spam_penalty = reputation.spam_indicators.risk_score * 0.5
        
        # Calculate overall score (weighted average minus penalties)
        weights = {
            'accuracy': 0.30,
            'quality': 0.20,
            'severity': 0.20,
            'consistency': 0.15,
            'responsiveness': 0.05,
            'volume': 0.10,
        }
        
        score.overall = (
            score.accuracy * weights['accuracy'] +
            score.quality * weights['quality'] +
            score.severity * weights['severity'] +
            score.consistency * weights['consistency'] +
            score.responsiveness * weights['responsiveness'] +
            score.volume * weights['volume']
        )
        
        # Apply penalties
        score.overall -= (
            score.false_positive_penalty +
            score.duplicate_penalty +
            score.spam_penalty
        )
        
        # Clamp to 0-100
        score.overall = max(0.0, min(100.0, score.overall))
        
        return score
    
    def _determine_trust_level(self, reputation: ResearcherReputation) -> TrustLevel:
        """Determine trust level based on reputation."""
        score = reputation.reputation_score.overall
        total = reputation.total_reports
        
        # Check for ban conditions
        if reputation.spam_indicators.is_spam and reputation.spam_indicators.confidence > 0.8:
            return TrustLevel.BANNED
        
        # Require minimum reports for higher trust levels
        if total < 3:
            return TrustLevel.UNTRUSTED
        
        # Elite: 85+ score, 20+ reports, 80%+ accuracy
        if score >= 85 and total >= 20 and reputation.accuracy_rate >= 0.80:
            return TrustLevel.ELITE
        
        # Trusted: 70+ score, 10+ reports, 70%+ accuracy
        if score >= 70 and total >= 10 and reputation.accuracy_rate >= 0.70:
            return TrustLevel.TRUSTED
        
        # Basic: 50+ score, 5+ reports
        if score >= 50 and total >= 5:
            return TrustLevel.BASIC
        
        return TrustLevel.UNTRUSTED
    
    def _check_and_award_badges(self, reputation: ResearcherReputation, validation_result: Any):
        """Check and award badges based on achievements."""
        existing_badges = {b.badge_type for b in reputation.badges}
        new_badges = []
        
        # First valid report
        if BadgeType.FIRST_VALID not in existing_badges and reputation.valid_reports == 1:
            new_badges.append(ResearcherBadge(
                badge_type=BadgeType.FIRST_VALID,
                earned_at=datetime.utcnow(),
                description="First valid vulnerability report"
            ))
        
        # Streak badges
        if BadgeType.STREAK_10 not in existing_badges and reputation.current_valid_streak >= 10:
            new_badges.append(ResearcherBadge(
                badge_type=BadgeType.STREAK_10,
                earned_at=datetime.utcnow(),
                description="10 valid reports in a row"
            ))
        
        if BadgeType.STREAK_25 not in existing_badges and reputation.current_valid_streak >= 25:
            new_badges.append(ResearcherBadge(
                badge_type=BadgeType.STREAK_25,
                earned_at=datetime.utcnow(),
                description="25 valid reports in a row"
            ))
        
        # Critical finder
        if BadgeType.CRITICAL_FINDER not in existing_badges:
            # Count critical reports (CVSS >= 9.0)
            critical_count = sum(1 for h in reputation.history if h.event and 'VALID' in h.event)
            if critical_count >= 5 and reputation.average_cvss_score >= 7.0:
                new_badges.append(ResearcherBadge(
                    badge_type=BadgeType.CRITICAL_FINDER,
                    earned_at=datetime.utcnow(),
                    description="Found 5+ critical vulnerabilities",
                    metadata={'critical_count': critical_count}
                ))
        
        # Add new badges
        reputation.badges.extend(new_badges)
        
        if new_badges:
            logger.info(f"Awarded {len(new_badges)} new badges to {reputation.username}")

