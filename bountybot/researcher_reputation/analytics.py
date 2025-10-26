"""
Reputation analytics and insights.
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict

from .models import ResearcherReputation, TrustLevel

logger = logging.getLogger(__name__)


class ReputationAnalytics:
    """
    Advanced analytics for researcher reputation system.
    
    Provides insights such as:
    - Trend analysis
    - Cohort analysis
    - Retention metrics
    - Quality trends
    - Predictive analytics
    
    Example:
        >>> analytics = ReputationAnalytics()
        >>> trends = analytics.analyze_trends(reputations)
        >>> print(f"Average reputation growing: {trends['reputation_trend']}")
    """
    
    def __init__(self):
        """Initialize analytics engine."""
        logger.info("ReputationAnalytics initialized")
    
    def analyze_trends(
        self,
        reputations: List[ResearcherReputation],
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Analyze reputation trends over time.
        
        Args:
            reputations: List of researcher reputations
            days: Number of days to analyze
            
        Returns:
            Trend analysis results
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Collect data points
        reputation_changes = []
        accuracy_changes = []
        
        for reputation in reputations:
            if not reputation.history or len(reputation.history) < 2:
                continue
            
            # Get historical data within time window
            recent_history = [
                h for h in reputation.history
                if h.timestamp >= cutoff_date
            ]
            
            if len(recent_history) < 2:
                continue
            
            # Calculate change
            first = recent_history[0]
            last = recent_history[-1]
            
            rep_change = last.reputation_score - first.reputation_score
            reputation_changes.append(rep_change)
            
            if last.total_reports > 0 and first.total_reports > 0:
                acc_change = (last.valid_reports / last.total_reports) - (first.valid_reports / first.total_reports)
                accuracy_changes.append(acc_change)
        
        # Calculate trends
        avg_rep_change = sum(reputation_changes) / len(reputation_changes) if reputation_changes else 0
        avg_acc_change = sum(accuracy_changes) / len(accuracy_changes) if accuracy_changes else 0
        
        improving = sum(1 for c in reputation_changes if c > 0)
        declining = sum(1 for c in reputation_changes if c < 0)
        stable = sum(1 for c in reputation_changes if c == 0)
        
        return {
            'period_days': days,
            'researchers_analyzed': len(reputation_changes),
            'average_reputation_change': round(avg_rep_change, 2),
            'average_accuracy_change': round(avg_acc_change * 100, 2),
            'improving_researchers': improving,
            'declining_researchers': declining,
            'stable_researchers': stable,
            'trend': 'improving' if avg_rep_change > 0 else 'declining' if avg_rep_change < 0 else 'stable'
        }
    
    def analyze_cohorts(
        self,
        reputations: List[ResearcherReputation]
    ) -> Dict[str, Any]:
        """
        Analyze researcher cohorts by join date.
        
        Args:
            reputations: List of researcher reputations
            
        Returns:
            Cohort analysis results
        """
        cohorts = defaultdict(list)
        
        for reputation in reputations:
            if not reputation.first_report_date:
                continue
            
            # Group by month
            cohort_key = reputation.first_report_date.strftime('%Y-%m')
            cohorts[cohort_key].append(reputation)
        
        cohort_stats = []
        
        for cohort_key, cohort_researchers in sorted(cohorts.items()):
            if not cohort_researchers:
                continue
            
            total = len(cohort_researchers)
            avg_reputation = sum(r.reputation_score.overall for r in cohort_researchers) / total
            avg_reports = sum(r.total_reports for r in cohort_researchers) / total
            avg_accuracy = sum(r.accuracy_rate for r in cohort_researchers) / total
            
            # Count by trust level
            trust_distribution = {}
            for level in TrustLevel:
                count = sum(1 for r in cohort_researchers if r.trust_level == level)
                trust_distribution[level.value] = count
            
            cohort_stats.append({
                'cohort': cohort_key,
                'total_researchers': total,
                'average_reputation': round(avg_reputation, 2),
                'average_reports': round(avg_reports, 2),
                'average_accuracy': round(avg_accuracy * 100, 2),
                'trust_distribution': trust_distribution
            })
        
        return {
            'total_cohorts': len(cohort_stats),
            'cohorts': cohort_stats
        }
    
    def calculate_retention(
        self,
        reputations: List[ResearcherReputation],
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Calculate researcher retention metrics.
        
        Args:
            reputations: List of researcher reputations
            days: Days to consider for "active"
            
        Returns:
            Retention metrics
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        total_researchers = len(reputations)
        active_researchers = sum(
            1 for r in reputations
            if r.last_report_date and r.last_report_date >= cutoff_date
        )
        
        inactive_researchers = total_researchers - active_researchers
        
        # Calculate by trust level
        retention_by_trust = {}
        for level in TrustLevel:
            level_researchers = [r for r in reputations if r.trust_level == level]
            level_total = len(level_researchers)
            level_active = sum(
                1 for r in level_researchers
                if r.last_report_date and r.last_report_date >= cutoff_date
            )
            
            retention_by_trust[level.value] = {
                'total': level_total,
                'active': level_active,
                'retention_rate': (level_active / level_total * 100) if level_total > 0 else 0
            }
        
        return {
            'period_days': days,
            'total_researchers': total_researchers,
            'active_researchers': active_researchers,
            'inactive_researchers': inactive_researchers,
            'retention_rate': (active_researchers / total_researchers * 100) if total_researchers > 0 else 0,
            'retention_by_trust_level': retention_by_trust
        }
    
    def predict_churn_risk(
        self,
        reputation: ResearcherReputation
    ) -> Dict[str, Any]:
        """
        Predict if researcher is at risk of churning.
        
        Args:
            reputation: ResearcherReputation to analyze
            
        Returns:
            Churn risk prediction
        """
        risk_score = 0.0
        risk_factors = []
        
        # Factor 1: Time since last report
        if reputation.last_report_date:
            days_since_last = (datetime.utcnow() - reputation.last_report_date).days
            if days_since_last > 90:
                risk_score += 40
                risk_factors.append(f"No activity for {days_since_last} days")
            elif days_since_last > 60:
                risk_score += 25
                risk_factors.append(f"Low activity ({days_since_last} days since last report)")
            elif days_since_last > 30:
                risk_score += 10
                risk_factors.append(f"Reduced activity ({days_since_last} days since last report)")
        
        # Factor 2: Declining reputation
        if len(reputation.history) >= 5:
            recent = reputation.history[-5:]
            scores = [h.reputation_score for h in recent]
            if all(scores[i] >= scores[i+1] for i in range(len(scores)-1)):
                risk_score += 20
                risk_factors.append("Reputation declining consistently")
        
        # Factor 3: Recent invalid reports
        if len(reputation.history) >= 3:
            recent = reputation.history[-3:]
            invalid_count = sum(1 for h in recent if h.event and 'INVALID' in h.event.upper())
            if invalid_count >= 2:
                risk_score += 15
                risk_factors.append("Multiple recent invalid reports")
        
        # Factor 4: Low engagement
        if reputation.total_reports < 5 and reputation.first_report_date:
            days_active = (datetime.utcnow() - reputation.first_report_date).days
            if days_active > 30:
                risk_score += 15
                risk_factors.append("Low engagement (few reports over long period)")
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = "high"
        elif risk_score >= 30:
            risk_level = "medium"
        elif risk_score >= 10:
            risk_level = "low"
        else:
            risk_level = "minimal"
        
        return {
            'researcher_id': reputation.researcher_id,
            'username': reputation.username,
            'risk_score': min(100, risk_score),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendation': self._get_churn_recommendation(risk_level)
        }
    
    def _get_churn_recommendation(self, risk_level: str) -> str:
        """Get recommendation based on churn risk."""
        recommendations = {
            'high': "URGENT: Reach out immediately. Offer incentives or support.",
            'medium': "MONITOR: Check in with researcher. Provide encouragement.",
            'low': "WATCH: Keep an eye on activity levels.",
            'minimal': "OK: Researcher is engaged and active."
        }
        return recommendations.get(risk_level, "No action needed")
    
    def get_quality_insights(
        self,
        reputations: List[ResearcherReputation]
    ) -> Dict[str, Any]:
        """
        Get insights about overall researcher quality.
        
        Args:
            reputations: List of researcher reputations
            
        Returns:
            Quality insights
        """
        if not reputations:
            return {}
        
        # Overall metrics
        total_reports = sum(r.total_reports for r in reputations)
        total_valid = sum(r.valid_reports for r in reputations)
        total_invalid = sum(r.invalid_reports for r in reputations)
        total_duplicates = sum(r.duplicate_reports for r in reputations)
        
        # Quality distribution
        high_quality = sum(1 for r in reputations if r.reputation_score.overall >= 80)
        medium_quality = sum(1 for r in reputations if 50 <= r.reputation_score.overall < 80)
        low_quality = sum(1 for r in reputations if r.reputation_score.overall < 50)
        
        return {
            'total_researchers': len(reputations),
            'total_reports': total_reports,
            'overall_accuracy': (total_valid / total_reports * 100) if total_reports > 0 else 0,
            'quality_distribution': {
                'high_quality': high_quality,
                'medium_quality': medium_quality,
                'low_quality': low_quality
            },
            'report_breakdown': {
                'valid': total_valid,
                'invalid': total_invalid,
                'duplicates': total_duplicates
            },
            'average_reputation': sum(r.reputation_score.overall for r in reputations) / len(reputations),
            'median_reputation': sorted([r.reputation_score.overall for r in reputations])[len(reputations) // 2]
        }

