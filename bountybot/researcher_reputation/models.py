"""
Data models for researcher reputation system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class TrustLevel(Enum):
    """Trust level classification for researchers."""
    UNTRUSTED = "untrusted"  # New or problematic researchers
    BASIC = "basic"  # Established but average quality
    TRUSTED = "trusted"  # Consistently good quality
    ELITE = "elite"  # Top-tier researchers
    BANNED = "banned"  # Banned for spam/abuse


class BadgeType(Enum):
    """Achievement badges for researchers."""
    FIRST_VALID = "first_valid"  # First valid report
    STREAK_10 = "streak_10"  # 10 valid reports in a row
    STREAK_25 = "streak_25"  # 25 valid reports in a row
    CRITICAL_FINDER = "critical_finder"  # Found 5+ critical vulnerabilities
    SPEED_DEMON = "speed_demon"  # Consistently fast, quality reports
    SPECIALIST = "specialist"  # Expert in specific vulnerability type
    POLYGLOT = "polyglot"  # Found vulnerabilities in 5+ languages
    ZERO_DAY_HUNTER = "zero_day_hunter"  # Found zero-day vulnerability
    HALL_OF_FAME = "hall_of_fame"  # Top 10 all-time
    PERFECT_MONTH = "perfect_month"  # 100% valid reports in a month


@dataclass
class ReputationScore:
    """Multi-dimensional reputation score breakdown."""
    
    # Overall score (0-100)
    overall: float = 0.0
    
    # Component scores (0-100 each)
    accuracy: float = 0.0  # Valid vs invalid rate
    quality: float = 0.0  # Report completeness and clarity
    severity: float = 0.0  # Average severity of findings
    consistency: float = 0.0  # Consistency over time
    responsiveness: float = 0.0  # Response time to questions
    volume: float = 0.0  # Number of submissions (logarithmic)
    
    # Penalties (0-100 each, subtracted from overall)
    false_positive_penalty: float = 0.0
    duplicate_penalty: float = 0.0
    spam_penalty: float = 0.0
    
    # Metadata
    calculated_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'overall': round(self.overall, 2),
            'components': {
                'accuracy': round(self.accuracy, 2),
                'quality': round(self.quality, 2),
                'severity': round(self.severity, 2),
                'consistency': round(self.consistency, 2),
                'responsiveness': round(self.responsiveness, 2),
                'volume': round(self.volume, 2),
            },
            'penalties': {
                'false_positive': round(self.false_positive_penalty, 2),
                'duplicate': round(self.duplicate_penalty, 2),
                'spam': round(self.spam_penalty, 2),
            },
            'calculated_at': self.calculated_at.isoformat()
        }


@dataclass
class SpamIndicators:
    """Indicators of spam or low-quality behavior."""
    
    is_spam: bool = False
    confidence: float = 0.0  # 0-1
    
    # Spam signals
    high_submission_rate: bool = False  # Too many reports too fast
    low_quality_reports: bool = False  # Consistently poor quality
    duplicate_pattern: bool = False  # Pattern of submitting duplicates
    copy_paste_detected: bool = False  # Copy-pasted reports
    automated_submission: bool = False  # Appears to be automated
    
    # Details
    signals: List[str] = field(default_factory=list)
    risk_score: float = 0.0  # 0-100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'is_spam': self.is_spam,
            'confidence': round(self.confidence, 2),
            'risk_score': round(self.risk_score, 2),
            'signals': self.signals,
            'indicators': {
                'high_submission_rate': self.high_submission_rate,
                'low_quality_reports': self.low_quality_reports,
                'duplicate_pattern': self.duplicate_pattern,
                'copy_paste_detected': self.copy_paste_detected,
                'automated_submission': self.automated_submission,
            }
        }


@dataclass
class FastTrackEligibility:
    """Fast-track eligibility status."""
    
    eligible: bool = False
    confidence: float = 0.0  # 0-1
    
    # Eligibility criteria
    meets_reputation_threshold: bool = False
    meets_accuracy_threshold: bool = False
    meets_volume_threshold: bool = False
    no_recent_issues: bool = False
    
    # Fast-track level
    priority_level: int = 0  # 0=normal, 1=fast, 2=express, 3=instant
    
    # Estimated time savings
    estimated_time_savings_minutes: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'eligible': self.eligible,
            'confidence': round(self.confidence, 2),
            'priority_level': self.priority_level,
            'estimated_time_savings_minutes': self.estimated_time_savings_minutes,
            'criteria': {
                'reputation': self.meets_reputation_threshold,
                'accuracy': self.meets_accuracy_threshold,
                'volume': self.meets_volume_threshold,
                'no_issues': self.no_recent_issues,
            }
        }


@dataclass
class ResearcherBadge:
    """Achievement badge earned by researcher."""
    
    badge_type: BadgeType
    earned_at: datetime
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'type': self.badge_type.value,
            'earned_at': self.earned_at.isoformat(),
            'description': self.description,
            'metadata': self.metadata
        }


@dataclass
class ReputationHistory:
    """Historical reputation data point."""
    
    timestamp: datetime
    reputation_score: float
    trust_level: TrustLevel
    total_reports: int
    valid_reports: int
    event: Optional[str] = None  # What caused this change
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'timestamp': self.timestamp.isoformat(),
            'reputation_score': round(self.reputation_score, 2),
            'trust_level': self.trust_level.value,
            'total_reports': self.total_reports,
            'valid_reports': self.valid_reports,
            'event': self.event
        }


@dataclass
class ResearcherReputation:
    """Complete reputation profile for a researcher."""
    
    # Identity
    researcher_id: str
    username: str
    
    # Reputation
    reputation_score: ReputationScore = field(default_factory=ReputationScore)
    trust_level: TrustLevel = TrustLevel.UNTRUSTED
    
    # Statistics
    total_reports: int = 0
    valid_reports: int = 0
    invalid_reports: int = 0
    duplicate_reports: int = 0
    false_positive_reports: int = 0
    
    # Quality metrics
    accuracy_rate: float = 0.0  # valid / total
    average_confidence: float = 0.0
    average_severity: float = 0.0
    average_cvss_score: float = 0.0
    
    # Time metrics
    first_report_date: Optional[datetime] = None
    last_report_date: Optional[datetime] = None
    average_response_time_hours: float = 0.0
    
    # Streaks
    current_valid_streak: int = 0
    longest_valid_streak: int = 0
    
    # Specializations
    specializations: List[str] = field(default_factory=list)
    
    # Badges
    badges: List[ResearcherBadge] = field(default_factory=list)
    
    # Spam detection
    spam_indicators: SpamIndicators = field(default_factory=SpamIndicators)
    
    # Fast-track eligibility
    fast_track: FastTrackEligibility = field(default_factory=FastTrackEligibility)
    
    # History
    history: List[ReputationHistory] = field(default_factory=list)
    
    # Rankings
    global_rank: Optional[int] = None
    percentile: Optional[float] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def should_fast_track(self) -> bool:
        """Check if researcher should be fast-tracked."""
        return self.fast_track.eligible and self.trust_level in [TrustLevel.TRUSTED, TrustLevel.ELITE]
    
    @property
    def is_spam_risk(self) -> bool:
        """Check if researcher is a spam risk."""
        return self.spam_indicators.is_spam or self.spam_indicators.risk_score > 70
    
    @property
    def is_banned(self) -> bool:
        """Check if researcher is banned."""
        return self.trust_level == TrustLevel.BANNED
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'researcher_id': self.researcher_id,
            'username': self.username,
            'reputation_score': self.reputation_score.to_dict(),
            'trust_level': self.trust_level.value,
            'statistics': {
                'total_reports': self.total_reports,
                'valid_reports': self.valid_reports,
                'invalid_reports': self.invalid_reports,
                'duplicate_reports': self.duplicate_reports,
                'false_positive_reports': self.false_positive_reports,
                'accuracy_rate': round(self.accuracy_rate * 100, 2),
            },
            'quality': {
                'average_confidence': round(self.average_confidence, 2),
                'average_severity': round(self.average_severity, 2),
                'average_cvss_score': round(self.average_cvss_score, 2),
            },
            'streaks': {
                'current': self.current_valid_streak,
                'longest': self.longest_valid_streak,
            },
            'specializations': self.specializations,
            'badges': [b.to_dict() for b in self.badges],
            'spam_indicators': self.spam_indicators.to_dict(),
            'fast_track': self.fast_track.to_dict(),
            'rankings': {
                'global_rank': self.global_rank,
                'percentile': round(self.percentile, 2) if self.percentile else None,
            },
            'should_fast_track': self.should_fast_track,
            'is_spam_risk': self.is_spam_risk,
            'updated_at': self.updated_at.isoformat()
        }

