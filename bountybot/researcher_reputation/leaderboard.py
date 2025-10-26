"""
Researcher leaderboard and rankings.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

from .models import ResearcherReputation, TrustLevel

logger = logging.getLogger(__name__)


class LeaderboardManager:
    """
    Manages researcher leaderboards and rankings.
    
    Features:
    - Global rankings
    - Percentile calculations
    - Time-based leaderboards (monthly, yearly, all-time)
    - Category-specific leaderboards (by vulnerability type)
    - Trend analysis
    
    Example:
        >>> manager = LeaderboardManager()
        >>> top_10 = manager.get_leaderboard(limit=10)
        >>> for rank, reputation in enumerate(top_10, 1):
        ...     print(f"{rank}. {reputation.username}: {reputation.reputation_score.overall:.1f}")
    """
    
    def __init__(self):
        """Initialize leaderboard manager."""
        logger.info("LeaderboardManager initialized")
    
    def get_leaderboard(
        self,
        reputations: List[ResearcherReputation],
        limit: int = 100,
        min_reports: int = 5
    ) -> List[ResearcherReputation]:
        """
        Get global leaderboard.
        
        Args:
            reputations: List of all researcher reputations
            limit: Maximum number of researchers to return
            min_reports: Minimum reports required to be on leaderboard
            
        Returns:
            Sorted list of top researchers
        """
        # Filter by minimum reports
        eligible = [
            r for r in reputations
            if r.total_reports >= min_reports and r.trust_level != TrustLevel.BANNED
        ]
        
        # Sort by reputation score
        sorted_researchers = sorted(
            eligible,
            key=lambda r: r.reputation_score.overall,
            reverse=True
        )
        
        # Update rankings
        for rank, reputation in enumerate(sorted_researchers, 1):
            reputation.global_rank = rank
            reputation.percentile = (1 - (rank / len(sorted_researchers))) * 100
        
        return sorted_researchers[:limit]
    
    def get_monthly_leaderboard(
        self,
        reputations: List[ResearcherReputation],
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get leaderboard for current month.
        
        Args:
            reputations: List of all researcher reputations
            limit: Maximum number of researchers to return
            
        Returns:
            Sorted list of top researchers this month
        """
        now = datetime.utcnow()
        month_start = datetime(now.year, now.month, 1)
        
        monthly_stats = []
        
        for reputation in reputations:
            # Count reports this month
            monthly_reports = sum(
                1 for h in reputation.history
                if h.timestamp >= month_start
            )
            
            if monthly_reports == 0:
                continue
            
            # Count valid reports this month
            monthly_valid = sum(
                1 for h in reputation.history
                if h.timestamp >= month_start and h.event and 'VALID' in h.event.upper()
            )
            
            monthly_accuracy = monthly_valid / monthly_reports if monthly_reports > 0 else 0
            
            monthly_stats.append({
                'researcher_id': reputation.researcher_id,
                'username': reputation.username,
                'monthly_reports': monthly_reports,
                'monthly_valid': monthly_valid,
                'monthly_accuracy': monthly_accuracy,
                'reputation_score': reputation.reputation_score.overall,
                'trust_level': reputation.trust_level.value
            })
        
        # Sort by monthly valid reports, then by accuracy
        sorted_stats = sorted(
            monthly_stats,
            key=lambda x: (x['monthly_valid'], x['monthly_accuracy']),
            reverse=True
        )
        
        return sorted_stats[:limit]
    
    def get_category_leaderboard(
        self,
        reputations: List[ResearcherReputation],
        category: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get leaderboard for specific vulnerability category.
        
        Args:
            reputations: List of all researcher reputations
            category: Vulnerability category (e.g., "xss", "sqli")
            limit: Maximum number of researchers to return
            
        Returns:
            Sorted list of top researchers in category
        """
        category_stats = []
        
        for reputation in reputations:
            # Check if researcher specializes in this category
            if category.lower() not in [s.lower() for s in reputation.specializations]:
                continue
            
            category_stats.append({
                'researcher_id': reputation.researcher_id,
                'username': reputation.username,
                'reputation_score': reputation.reputation_score.overall,
                'total_reports': reputation.total_reports,
                'accuracy_rate': reputation.accuracy_rate,
                'specializations': reputation.specializations,
                'trust_level': reputation.trust_level.value
            })
        
        # Sort by reputation score
        sorted_stats = sorted(
            category_stats,
            key=lambda x: x['reputation_score'],
            reverse=True
        )
        
        return sorted_stats[:limit]
    
    def get_rising_stars(
        self,
        reputations: List[ResearcherReputation],
        limit: int = 20
    ) -> List[Dict[str, Any]]:
        """
        Get rising star researchers (new but high quality).
        
        Args:
            reputations: List of all researcher reputations
            limit: Maximum number of researchers to return
            
        Returns:
            List of rising star researchers
        """
        rising_stars = []
        
        for reputation in reputations:
            # Must be relatively new (less than 50 reports)
            if reputation.total_reports >= 50:
                continue
            
            # Must have minimum reports
            if reputation.total_reports < 5:
                continue
            
            # Must have high quality
            if reputation.reputation_score.overall < 70:
                continue
            
            # Calculate growth rate
            if len(reputation.history) >= 2:
                first_score = reputation.history[0].reputation_score
                current_score = reputation.reputation_score.overall
                growth = current_score - first_score
            else:
                growth = 0
            
            rising_stars.append({
                'researcher_id': reputation.researcher_id,
                'username': reputation.username,
                'reputation_score': reputation.reputation_score.overall,
                'total_reports': reputation.total_reports,
                'accuracy_rate': reputation.accuracy_rate,
                'growth': growth,
                'trust_level': reputation.trust_level.value
            })
        
        # Sort by growth and reputation
        sorted_stars = sorted(
            rising_stars,
            key=lambda x: (x['growth'], x['reputation_score']),
            reverse=True
        )
        
        return sorted_stars[:limit]
    
    def get_hall_of_fame(
        self,
        reputations: List[ResearcherReputation],
        limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get hall of fame (all-time best researchers).
        
        Args:
            reputations: List of all researcher reputations
            limit: Maximum number of researchers to return
            
        Returns:
            Hall of fame researchers
        """
        # Filter elite researchers with significant contributions
        elite = [
            r for r in reputations
            if r.trust_level == TrustLevel.ELITE and r.total_reports >= 50
        ]
        
        # Sort by combination of reputation and volume
        sorted_elite = sorted(
            elite,
            key=lambda r: (r.reputation_score.overall * 0.7 + r.total_reports * 0.3),
            reverse=True
        )
        
        hall_of_fame = []
        for reputation in sorted_elite[:limit]:
            hall_of_fame.append({
                'researcher_id': reputation.researcher_id,
                'username': reputation.username,
                'reputation_score': reputation.reputation_score.overall,
                'total_reports': reputation.total_reports,
                'valid_reports': reputation.valid_reports,
                'accuracy_rate': reputation.accuracy_rate,
                'average_severity': reputation.average_severity,
                'specializations': reputation.specializations,
                'badges': [b.badge_type.value for b in reputation.badges],
                'member_since': reputation.first_report_date.isoformat() if reputation.first_report_date else None
            })
        
        return hall_of_fame
    
    def get_statistics(self, reputations: List[ResearcherReputation]) -> Dict[str, Any]:
        """
        Get overall leaderboard statistics.
        
        Args:
            reputations: List of all researcher reputations
            
        Returns:
            Statistics dictionary
        """
        if not reputations:
            return {
                'total_researchers': 0,
                'average_reputation': 0,
                'trust_level_distribution': {},
                'top_specializations': []
            }
        
        # Trust level distribution
        trust_levels = {}
        for level in TrustLevel:
            count = sum(1 for r in reputations if r.trust_level == level)
            trust_levels[level.value] = count
        
        # Top specializations
        all_specializations = []
        for r in reputations:
            all_specializations.extend(r.specializations)
        
        from collections import Counter
        spec_counts = Counter(all_specializations)
        top_specializations = [
            {'specialization': spec, 'count': count}
            for spec, count in spec_counts.most_common(10)
        ]
        
        # Calculate averages
        total_reputation = sum(r.reputation_score.overall for r in reputations)
        avg_reputation = total_reputation / len(reputations)
        
        total_accuracy = sum(r.accuracy_rate for r in reputations)
        avg_accuracy = total_accuracy / len(reputations)
        
        return {
            'total_researchers': len(reputations),
            'average_reputation': round(avg_reputation, 2),
            'average_accuracy': round(avg_accuracy * 100, 2),
            'trust_level_distribution': trust_levels,
            'top_specializations': top_specializations,
            'elite_researchers': trust_levels.get('elite', 0),
            'trusted_researchers': trust_levels.get('trusted', 0),
        }

