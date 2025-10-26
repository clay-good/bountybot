"""
Tenant Health Scorer

Calculates comprehensive health scores for tenants based on multiple dimensions.
"""

import logging
from typing import Dict, List, Optional

from bountybot.tenant_analytics.models import (
    TenantHealthScore,
    HealthDimension,
    HealthStatus,
    HealthFactor,
)


logger = logging.getLogger(__name__)


class TenantHealthScorer:
    """Calculates tenant health scores."""
    
    def __init__(self):
        """Initialize health scorer."""
        self.health_scores: Dict[str, TenantHealthScore] = {}
        self.stats = {
            'total_scores_calculated': 0,
            'scores_by_status': {},
        }
    
    def calculate_health_score(
        self,
        tenant_id: str,
        usage_metrics: Dict[str, float],
        engagement_metrics: Dict[str, float],
        security_metrics: Dict[str, float],
        performance_metrics: Dict[str, float],
        best_practices_metrics: Dict[str, float],
        support_metrics: Dict[str, float],
        previous_score: Optional[float] = None,
    ) -> TenantHealthScore:
        """
        Calculate comprehensive health score for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            usage_metrics: Usage-related metrics
            engagement_metrics: Engagement-related metrics
            security_metrics: Security-related metrics
            performance_metrics: Performance-related metrics
            best_practices_metrics: Best practices adoption metrics
            support_metrics: Support-related metrics
            previous_score: Previous health score for trend analysis
            
        Returns:
            Tenant health score
        """
        factors = []
        dimension_scores = {}
        
        # 1. Usage Dimension (20% weight)
        usage_score = self._calculate_usage_score(usage_metrics, factors)
        dimension_scores[HealthDimension.USAGE] = usage_score
        
        # 2. Engagement Dimension (25% weight)
        engagement_score = self._calculate_engagement_score(engagement_metrics, factors)
        dimension_scores[HealthDimension.ENGAGEMENT] = engagement_score
        
        # 3. Security Dimension (20% weight)
        security_score = self._calculate_security_score(security_metrics, factors)
        dimension_scores[HealthDimension.SECURITY] = security_score
        
        # 4. Performance Dimension (15% weight)
        performance_score = self._calculate_performance_score(performance_metrics, factors)
        dimension_scores[HealthDimension.PERFORMANCE] = performance_score
        
        # 5. Best Practices Dimension (15% weight)
        best_practices_score = self._calculate_best_practices_score(best_practices_metrics, factors)
        dimension_scores[HealthDimension.BEST_PRACTICES] = best_practices_score
        
        # 6. Support Dimension (5% weight)
        support_score = self._calculate_support_score(support_metrics, factors)
        dimension_scores[HealthDimension.SUPPORT] = support_score
        
        # Calculate weighted overall score
        weights = {
            HealthDimension.USAGE: 0.20,
            HealthDimension.ENGAGEMENT: 0.25,
            HealthDimension.SECURITY: 0.20,
            HealthDimension.PERFORMANCE: 0.15,
            HealthDimension.BEST_PRACTICES: 0.15,
            HealthDimension.SUPPORT: 0.05,
        }
        
        overall_score = sum(
            dimension_scores[dim] * weights[dim]
            for dim in HealthDimension
        )
        
        # Determine status
        if overall_score >= 90:
            status = HealthStatus.EXCELLENT
        elif overall_score >= 75:
            status = HealthStatus.GOOD
        elif overall_score >= 60:
            status = HealthStatus.FAIR
        elif overall_score >= 40:
            status = HealthStatus.POOR
        else:
            status = HealthStatus.CRITICAL
        
        # Calculate trend
        if previous_score is not None:
            score_change = overall_score - previous_score
            if score_change > 5:
                trend = "improving"
            elif score_change < -5:
                trend = "declining"
            else:
                trend = "stable"
        else:
            trend = "new"
            score_change = 0.0
        
        # Identify strengths and weaknesses
        strengths = [
            f"{dim.value.replace('_', ' ').title()}: {score:.0f}/100"
            for dim, score in dimension_scores.items()
            if score >= 80
        ]
        
        weaknesses = [
            f"{dim.value.replace('_', ' ').title()}: {score:.0f}/100"
            for dim, score in dimension_scores.items()
            if score < 60
        ]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(dimension_scores, factors)
        
        health_score = TenantHealthScore(
            tenant_id=tenant_id,
            overall_score=overall_score,
            status=status,
            dimension_scores=dimension_scores,
            factors=factors,
            score_trend=trend,
            previous_score=previous_score,
            score_change=score_change,
            strengths=strengths,
            weaknesses=weaknesses,
            recommendations=recommendations,
        )
        
        # Store health score
        self.health_scores[tenant_id] = health_score
        
        self.stats['total_scores_calculated'] += 1
        if status.value not in self.stats['scores_by_status']:
            self.stats['scores_by_status'][status.value] = 0
        self.stats['scores_by_status'][status.value] += 1
        
        logger.info(
            f"Calculated health score for tenant {tenant_id}: "
            f"score={overall_score:.1f}, status={status.value}"
        )
        
        return health_score
    
    def _calculate_usage_score(self, metrics: Dict[str, float], factors: List[HealthFactor]) -> float:
        """Calculate usage dimension score."""
        score = 100.0
        
        # API calls per day
        api_calls = metrics.get('api_calls_per_day', 0)
        if api_calls < 10:
            score -= 30
            factors.append(HealthFactor(
                name="Low API Usage",
                dimension=HealthDimension.USAGE,
                score=40,
                weight=0.3,
                description="API calls below expected threshold",
                recommendations=["Increase API integration", "Review use cases"],
            ))
        elif api_calls < 50:
            score -= 15
        
        # Validations per month
        validations = metrics.get('validations_per_month', 0)
        if validations < 5:
            score -= 20
            factors.append(HealthFactor(
                name="Low Validation Activity",
                dimension=HealthDimension.USAGE,
                score=50,
                weight=0.2,
                description="Validation activity below expected levels",
                recommendations=["Encourage more validation usage"],
            ))
        
        return max(0, score)
    
    def _calculate_engagement_score(self, metrics: Dict[str, float], factors: List[HealthFactor]) -> float:
        """Calculate engagement dimension score."""
        score = 100.0
        
        # Active users
        active_users = metrics.get('active_users', 0)
        total_users = metrics.get('total_users', 1)
        active_ratio = active_users / total_users if total_users > 0 else 0
        
        if active_ratio < 0.3:
            score -= 40
            factors.append(HealthFactor(
                name="Low User Engagement",
                dimension=HealthDimension.ENGAGEMENT,
                score=30,
                weight=0.4,
                description=f"Only {active_ratio*100:.0f}% of users are active",
                recommendations=["Send re-engagement campaigns", "Improve onboarding"],
            ))
        elif active_ratio < 0.6:
            score -= 20
        
        # Days since last activity
        days_inactive = metrics.get('days_since_last_activity', 0)
        if days_inactive > 14:
            score -= 30
            factors.append(HealthFactor(
                name="Recent Inactivity",
                dimension=HealthDimension.ENGAGEMENT,
                score=40,
                weight=0.3,
                description=f"No activity in {days_inactive} days",
                recommendations=["Reach out to customer", "Offer assistance"],
            ))
        
        # Feature adoption
        features_adopted = metrics.get('features_adopted', 0)
        total_features = metrics.get('total_features', 10)
        adoption_rate = features_adopted / total_features if total_features > 0 else 0
        
        if adoption_rate < 0.3:
            score -= 20
            factors.append(HealthFactor(
                name="Low Feature Adoption",
                dimension=HealthDimension.ENGAGEMENT,
                score=50,
                weight=0.2,
                description=f"Only {adoption_rate*100:.0f}% of features adopted",
                recommendations=["Provide feature training", "Highlight unused features"],
            ))
        
        return max(0, score)
    
    def _calculate_security_score(self, metrics: Dict[str, float], factors: List[HealthFactor]) -> float:
        """Calculate security dimension score."""
        score = 100.0
        
        # Security validations
        security_validations = metrics.get('security_validations', 0)
        if security_validations < 10:
            score -= 20
        
        # False positive rate
        false_positive_rate = metrics.get('false_positive_rate', 0)
        if false_positive_rate > 0.3:
            score -= 25
            factors.append(HealthFactor(
                name="High False Positive Rate",
                dimension=HealthDimension.SECURITY,
                score=50,
                weight=0.25,
                description=f"False positive rate: {false_positive_rate*100:.0f}%",
                recommendations=["Review validation criteria", "Improve detection accuracy"],
            ))
        
        # Critical vulnerabilities
        critical_vulns = metrics.get('critical_vulnerabilities_open', 0)
        if critical_vulns > 5:
            score -= 30
            factors.append(HealthFactor(
                name="Open Critical Vulnerabilities",
                dimension=HealthDimension.SECURITY,
                score=40,
                weight=0.3,
                description=f"{critical_vulns} critical vulnerabilities open",
                recommendations=["Prioritize critical fixes", "Allocate resources"],
            ))
        
        return max(0, score)
    
    def _calculate_performance_score(self, metrics: Dict[str, float], factors: List[HealthFactor]) -> float:
        """Calculate performance dimension score."""
        score = 100.0
        
        # Response time
        response_time = metrics.get('avg_response_time_ms', 0)
        if response_time > 2000:
            score -= 30
            factors.append(HealthFactor(
                name="Slow Response Times",
                dimension=HealthDimension.PERFORMANCE,
                score=40,
                weight=0.3,
                description=f"Average response time: {response_time:.0f}ms",
                recommendations=["Optimize queries", "Review infrastructure"],
            ))
        elif response_time > 1000:
            score -= 15
        
        # Error rate
        error_rate = metrics.get('error_rate', 0)
        if error_rate > 0.05:
            score -= 25
            factors.append(HealthFactor(
                name="High Error Rate",
                dimension=HealthDimension.PERFORMANCE,
                score=50,
                weight=0.25,
                description=f"Error rate: {error_rate*100:.1f}%",
                recommendations=["Investigate errors", "Improve error handling"],
            ))
        
        return max(0, score)
    
    def _calculate_best_practices_score(self, metrics: Dict[str, float], factors: List[HealthFactor]) -> float:
        """Calculate best practices dimension score."""
        score = 100.0
        
        # Automation usage
        automation_rate = metrics.get('automation_rate', 0)
        if automation_rate < 0.3:
            score -= 25
            factors.append(HealthFactor(
                name="Low Automation",
                dimension=HealthDimension.BEST_PRACTICES,
                score=50,
                weight=0.25,
                description=f"Automation rate: {automation_rate*100:.0f}%",
                recommendations=["Enable automation features", "Configure workflows"],
            ))
        
        # Integration usage
        integrations_active = metrics.get('integrations_active', 0)
        if integrations_active < 2:
            score -= 20
        
        return max(0, score)
    
    def _calculate_support_score(self, metrics: Dict[str, float], factors: List[HealthFactor]) -> float:
        """Calculate support dimension score."""
        score = 100.0
        
        # Support tickets
        support_tickets = metrics.get('support_tickets', 0)
        if support_tickets > 10:
            score -= 40
            factors.append(HealthFactor(
                name="High Support Ticket Volume",
                dimension=HealthDimension.SUPPORT,
                score=40,
                weight=0.4,
                description=f"{support_tickets} support tickets",
                recommendations=["Proactive outreach", "Identify pain points"],
            ))
        elif support_tickets > 5:
            score -= 20
        
        return max(0, score)
    
    def _generate_recommendations(
        self,
        dimension_scores: Dict[HealthDimension, float],
        factors: List[HealthFactor],
    ) -> List[str]:
        """Generate recommendations based on scores."""
        recommendations = []
        
        # Add recommendations from low-scoring factors
        for factor in factors:
            if factor.score < 60:
                recommendations.extend(factor.recommendations)
        
        # Add dimension-specific recommendations
        for dim, score in dimension_scores.items():
            if score < 60:
                if dim == HealthDimension.USAGE:
                    recommendations.append("Increase platform usage through training")
                elif dim == HealthDimension.ENGAGEMENT:
                    recommendations.append("Schedule customer success check-in")
                elif dim == HealthDimension.SECURITY:
                    recommendations.append("Review security validation processes")
                elif dim == HealthDimension.PERFORMANCE:
                    recommendations.append("Optimize system performance")
                elif dim == HealthDimension.BEST_PRACTICES:
                    recommendations.append("Adopt recommended best practices")
                elif dim == HealthDimension.SUPPORT:
                    recommendations.append("Address support concerns proactively")
        
        return list(set(recommendations))  # Remove duplicates
    
    def get_health_score(self, tenant_id: str) -> Optional[TenantHealthScore]:
        """Get health score for a tenant."""
        return self.health_scores.get(tenant_id)
    
    def get_unhealthy_tenants(self, max_status: HealthStatus = HealthStatus.FAIR) -> List[TenantHealthScore]:
        """Get tenants with poor health."""
        status_order = {
            HealthStatus.EXCELLENT: 5,
            HealthStatus.GOOD: 4,
            HealthStatus.FAIR: 3,
            HealthStatus.POOR: 2,
            HealthStatus.CRITICAL: 1,
        }
        
        max_level = status_order[max_status]
        
        unhealthy = [
            score for score in self.health_scores.values()
            if status_order[score.status] <= max_level
        ]
        
        # Sort by score ascending (worst first)
        unhealthy.sort(key=lambda s: s.overall_score)
        
        return unhealthy
    
    def get_stats(self) -> Dict:
        """Get health scorer statistics."""
        return {
            'total_scores_calculated': self.stats['total_scores_calculated'],
            'scores_by_status': dict(self.stats['scores_by_status']),
            'average_score': sum(s.overall_score for s in self.health_scores.values()) / len(self.health_scores) if self.health_scores else 0,
        }

