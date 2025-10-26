"""
Researcher Reputation System

Comprehensive reputation tracking and management for bug bounty researchers.
Provides intelligent scoring, trust levels, fast-tracking, and spam detection.

Features:
- Multi-dimensional reputation scoring (0-100)
- Trust level classification (Untrusted → Trusted → Elite)
- Automatic fast-track validation for elite researchers
- Spam and low-quality researcher detection
- Historical accuracy tracking
- Response time analysis
- Researcher leaderboards and rankings
- Behavioral pattern analysis

Example:
    >>> from bountybot.researcher_reputation import ReputationManager
    >>> 
    >>> manager = ReputationManager()
    >>> 
    >>> # Update reputation after validation
    >>> reputation = manager.update_reputation(
    ...     researcher_id="researcher-123",
    ...     validation_result=result
    ... )
    >>> 
    >>> # Check if researcher should be fast-tracked
    >>> if reputation.should_fast_track:
    ...     print("Fast-track this report!")
    >>> 
    >>> # Get leaderboard
    >>> top_researchers = manager.get_leaderboard(limit=10)
"""

from .models import (
    ResearcherReputation,
    TrustLevel,
    ReputationScore,
    ReputationHistory,
    ResearcherBadge,
    BadgeType,
    SpamIndicators,
    FastTrackEligibility
)

from .reputation_manager import ReputationManager
from .spam_detector import SpamDetector
from .fast_track_engine import FastTrackEngine
from .leaderboard import LeaderboardManager
from .analytics import ReputationAnalytics

__all__ = [
    # Models
    'ResearcherReputation',
    'TrustLevel',
    'ReputationScore',
    'ReputationHistory',
    'ResearcherBadge',
    'BadgeType',
    'SpamIndicators',
    'FastTrackEligibility',
    
    # Core Components
    'ReputationManager',
    'SpamDetector',
    'FastTrackEngine',
    'LeaderboardManager',
    'ReputationAnalytics',
]

