"""
Predictive Analytics Engine

ML-powered predictions for usage trends, cost forecasting, churn risk, and capacity planning.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from bountybot.tenant_analytics.models import (
    UsagePrediction,
    PredictionType,
    ChurnRiskScore,
    ChurnRiskLevel,
    CostForecast,
    UsageMetricType,
    AggregationPeriod,
)


logger = logging.getLogger(__name__)


class PredictiveAnalyticsEngine:
    """Provides predictive analytics for tenants."""
    
    def __init__(self):
        """Initialize predictive analytics engine."""
        self.predictions: Dict[str, List[UsagePrediction]] = {}
        self.churn_scores: Dict[str, ChurnRiskScore] = {}
        self.cost_forecasts: Dict[str, List[CostForecast]] = {}
        self.stats = {
            'total_predictions': 0,
            'predictions_by_type': {},
        }
    
    def predict_usage(
        self,
        tenant_id: str,
        metric_type: UsageMetricType,
        historical_values: List[float],
        forecast_period: AggregationPeriod = AggregationPeriod.MONTHLY,
    ) -> UsagePrediction:
        """
        Predict future usage based on historical data.
        
        Args:
            tenant_id: Tenant identifier
            metric_type: Type of metric to predict
            historical_values: Historical values (ordered by time)
            forecast_period: Period to forecast
            
        Returns:
            Usage prediction
        """
        if len(historical_values) < 2:
            raise ValueError("Need at least 2 historical values for prediction")
        
        # Simple linear regression for trend
        n = len(historical_values)
        x = list(range(n))
        y = historical_values
        
        # Calculate slope and intercept
        x_mean = sum(x) / n
        y_mean = sum(y) / n
        
        numerator = sum((x[i] - x_mean) * (y[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            slope = 0
        else:
            slope = numerator / denominator
        
        intercept = y_mean - slope * x_mean
        
        # Predict next value
        predicted_value = slope * n + intercept
        predicted_value = max(0, predicted_value)  # Can't be negative
        
        # Calculate confidence based on R-squared
        ss_tot = sum((y[i] - y_mean) ** 2 for i in range(n))
        ss_res = sum((y[i] - (slope * x[i] + intercept)) ** 2 for i in range(n))
        
        if ss_tot == 0:
            r_squared = 0
        else:
            r_squared = 1 - (ss_res / ss_tot)
        
        confidence = max(0.0, min(1.0, r_squared))
        
        # Determine trend
        if slope > 0.05 * y_mean:
            trend = "increasing"
            growth_rate = (slope / y_mean) * 100
        elif slope < -0.05 * y_mean:
            trend = "decreasing"
            growth_rate = (slope / y_mean) * 100
        else:
            trend = "stable"
            growth_rate = 0.0
        
        prediction = UsagePrediction(
            tenant_id=tenant_id,
            prediction_type=PredictionType.USAGE_FORECAST,
            metric_type=metric_type,
            predicted_value=predicted_value,
            confidence=confidence,
            forecast_period=forecast_period,
            historical_average=y_mean,
            trend=trend,
            growth_rate=growth_rate,
        )
        
        # Store prediction
        if tenant_id not in self.predictions:
            self.predictions[tenant_id] = []
        self.predictions[tenant_id].append(prediction)
        
        self.stats['total_predictions'] += 1
        
        logger.info(
            f"Predicted {metric_type.value} for tenant {tenant_id}: "
            f"value={predicted_value:.2f}, trend={trend}, confidence={confidence:.2f}"
        )
        
        return prediction
    
    def calculate_churn_risk(
        self,
        tenant_id: str,
        days_since_last_activity: int,
        usage_values: List[float],
        feature_adoption_count: int,
        total_features: int,
        support_tickets_count: int = 0,
    ) -> ChurnRiskScore:
        """
        Calculate churn risk score for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            days_since_last_activity: Days since last activity
            usage_values: Recent usage values
            feature_adoption_count: Number of features adopted
            total_features: Total number of features available
            support_tickets_count: Number of support tickets
            
        Returns:
            Churn risk score
        """
        risk_factors = []
        risk_score = 0.0
        
        # Factor 1: Inactivity (0-30 points)
        if days_since_last_activity > 30:
            risk_score += 30
            risk_factors.append("No activity in over 30 days")
        elif days_since_last_activity > 14:
            risk_score += 20
            risk_factors.append("No activity in over 14 days")
        elif days_since_last_activity > 7:
            risk_score += 10
            risk_factors.append("No activity in over 7 days")
        
        # Factor 2: Usage trend (0-30 points)
        if len(usage_values) >= 2:
            recent_avg = sum(usage_values[-3:]) / min(3, len(usage_values))
            older_avg = sum(usage_values[:-3]) / max(1, len(usage_values) - 3) if len(usage_values) > 3 else recent_avg
            
            if recent_avg < older_avg * 0.5:
                risk_score += 30
                risk_factors.append("Usage declined by >50%")
                usage_trend = "decreasing"
            elif recent_avg < older_avg * 0.8:
                risk_score += 15
                risk_factors.append("Usage declining")
                usage_trend = "decreasing"
            elif recent_avg > older_avg * 1.2:
                usage_trend = "increasing"
            else:
                usage_trend = "stable"
        else:
            usage_trend = "unknown"
        
        # Factor 3: Feature adoption (0-20 points)
        feature_adoption_rate = feature_adoption_count / total_features if total_features > 0 else 0
        
        if feature_adoption_rate < 0.2:
            risk_score += 20
            risk_factors.append("Very low feature adoption (<20%)")
        elif feature_adoption_rate < 0.4:
            risk_score += 10
            risk_factors.append("Low feature adoption (<40%)")
        
        # Factor 4: Support tickets (0-20 points)
        if support_tickets_count > 10:
            risk_score += 20
            risk_factors.append("High number of support tickets")
        elif support_tickets_count > 5:
            risk_score += 10
            risk_factors.append("Elevated support tickets")
        
        # Normalize to 0-1
        risk_score = min(100, risk_score) / 100
        
        # Determine risk level
        if risk_score >= 0.8:
            risk_level = ChurnRiskLevel.VERY_HIGH
        elif risk_score >= 0.6:
            risk_level = ChurnRiskLevel.HIGH
        elif risk_score >= 0.4:
            risk_level = ChurnRiskLevel.MEDIUM
        elif risk_score >= 0.2:
            risk_level = ChurnRiskLevel.LOW
        else:
            risk_level = ChurnRiskLevel.VERY_LOW
        
        # Calculate churn probabilities
        churn_prob_30d = min(0.95, risk_score * 0.3)
        churn_prob_90d = min(0.95, risk_score * 0.6)
        
        # Generate retention actions
        retention_actions = []
        if days_since_last_activity > 7:
            retention_actions.append("Send re-engagement email")
        if feature_adoption_rate < 0.4:
            retention_actions.append("Offer onboarding session")
        if support_tickets_count > 5:
            retention_actions.append("Schedule customer success call")
        if usage_trend == "decreasing":
            retention_actions.append("Investigate usage decline")
        
        churn_score = ChurnRiskScore(
            tenant_id=tenant_id,
            risk_score=risk_score,
            risk_level=risk_level,
            factors=risk_factors,
            days_since_last_activity=days_since_last_activity,
            usage_trend=usage_trend,
            feature_adoption_rate=feature_adoption_rate,
            support_tickets_count=support_tickets_count,
            churn_probability_30d=churn_prob_30d,
            churn_probability_90d=churn_prob_90d,
            retention_actions=retention_actions,
        )
        
        # Store churn score
        self.churn_scores[tenant_id] = churn_score
        
        logger.info(
            f"Calculated churn risk for tenant {tenant_id}: "
            f"score={risk_score:.2f}, level={risk_level.value}"
        )
        
        return churn_score
    
    def forecast_cost(
        self,
        tenant_id: str,
        historical_costs: List[float],
        forecast_period: AggregationPeriod = AggregationPeriod.MONTHLY,
        ai_cost_ratio: float = 0.6,
        infrastructure_cost_ratio: float = 0.25,
        storage_cost_ratio: float = 0.10,
        other_cost_ratio: float = 0.05,
    ) -> CostForecast:
        """
        Forecast future costs for a tenant.
        
        Args:
            tenant_id: Tenant identifier
            historical_costs: Historical cost values
            forecast_period: Period to forecast
            ai_cost_ratio: Ratio of AI costs
            infrastructure_cost_ratio: Ratio of infrastructure costs
            storage_cost_ratio: Ratio of storage costs
            other_cost_ratio: Ratio of other costs
            
        Returns:
            Cost forecast
        """
        if len(historical_costs) < 2:
            raise ValueError("Need at least 2 historical cost values for forecast")
        
        # Use simple moving average with trend
        recent_avg = sum(historical_costs[-3:]) / min(3, len(historical_costs))
        overall_avg = sum(historical_costs) / len(historical_costs)
        
        # Calculate trend
        if recent_avg > overall_avg * 1.1:
            trend = "increasing"
            predicted_cost = recent_avg * 1.1
        elif recent_avg < overall_avg * 0.9:
            trend = "decreasing"
            predicted_cost = recent_avg * 0.9
        else:
            trend = "stable"
            predicted_cost = recent_avg
        
        # Calculate confidence (higher with more data points)
        confidence = min(0.95, 0.5 + (len(historical_costs) * 0.05))
        
        # Break down costs
        forecast = CostForecast(
            tenant_id=tenant_id,
            forecast_period=forecast_period,
            predicted_cost=predicted_cost,
            confidence=confidence,
            ai_cost=predicted_cost * ai_cost_ratio,
            infrastructure_cost=predicted_cost * infrastructure_cost_ratio,
            storage_cost=predicted_cost * storage_cost_ratio,
            other_costs=predicted_cost * other_cost_ratio,
            historical_average_cost=overall_avg,
            cost_trend=trend,
        )
        
        # Store forecast
        if tenant_id not in self.cost_forecasts:
            self.cost_forecasts[tenant_id] = []
        self.cost_forecasts[tenant_id].append(forecast)
        
        logger.info(
            f"Forecasted cost for tenant {tenant_id}: "
            f"${predicted_cost:.2f}, trend={trend}"
        )
        
        return forecast
    
    def get_predictions(
        self,
        tenant_id: str,
        prediction_type: Optional[PredictionType] = None,
    ) -> List[UsagePrediction]:
        """Get predictions for a tenant."""
        predictions = self.predictions.get(tenant_id, [])
        
        if prediction_type:
            predictions = [p for p in predictions if p.prediction_type == prediction_type]
        
        return predictions
    
    def get_churn_risk(self, tenant_id: str) -> Optional[ChurnRiskScore]:
        """Get churn risk score for a tenant."""
        return self.churn_scores.get(tenant_id)
    
    def get_high_risk_tenants(self, min_risk_level: ChurnRiskLevel = ChurnRiskLevel.HIGH) -> List[ChurnRiskScore]:
        """Get tenants with high churn risk."""
        risk_levels = {
            ChurnRiskLevel.VERY_LOW: 0,
            ChurnRiskLevel.LOW: 1,
            ChurnRiskLevel.MEDIUM: 2,
            ChurnRiskLevel.HIGH: 3,
            ChurnRiskLevel.VERY_HIGH: 4,
        }
        
        min_level_value = risk_levels[min_risk_level]
        
        high_risk = [
            score for score in self.churn_scores.values()
            if risk_levels[score.risk_level] >= min_level_value
        ]
        
        # Sort by risk score descending
        high_risk.sort(key=lambda s: s.risk_score, reverse=True)
        
        return high_risk
    
    def get_stats(self) -> Dict:
        """Get predictive analytics statistics."""
        return {
            'total_predictions': self.stats['total_predictions'],
            'total_churn_scores': len(self.churn_scores),
            'total_cost_forecasts': sum(len(f) for f in self.cost_forecasts.values()),
            'high_risk_tenants': len(self.get_high_risk_tenants()),
        }

