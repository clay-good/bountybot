"""
Cost Optimizer

Optimizes scaling decisions based on cost constraints and budget.
"""

import logging
from typing import Dict, Optional, List
from datetime import datetime, timedelta
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CostBudget:
    """Cost budget configuration."""
    hourly_budget: float
    daily_budget: float
    monthly_budget: float
    alert_threshold: float = 0.8  # Alert at 80% of budget


@dataclass
class CostMetrics:
    """Cost tracking metrics."""
    current_hour_cost: float = 0.0
    current_day_cost: float = 0.0
    current_month_cost: float = 0.0
    projected_hour_cost: float = 0.0
    projected_day_cost: float = 0.0
    projected_month_cost: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)


class CostOptimizer:
    """
    Optimizes scaling decisions based on cost.
    
    Features:
    - Budget enforcement
    - Cost-aware scaling decisions
    - Cost projection
    - Budget alerts
    - Cost optimization recommendations
    """
    
    def __init__(self, config: Dict):
        """
        Initialize cost optimizer.
        
        Args:
            config: Cost configuration
        """
        self.config = config
        
        # Budget configuration
        self.budget = CostBudget(
            hourly_budget=config.get('hourly_budget', 10.0),
            daily_budget=config.get('daily_budget', 200.0),
            monthly_budget=config.get('monthly_budget', 5000.0),
            alert_threshold=config.get('alert_threshold', 0.8)
        )
        
        # Cost per worker per hour (infrastructure + AI)
        self.cost_per_worker_hour = config.get('cost_per_worker_hour', 2.0)
        
        # Cost tracking
        self.metrics = CostMetrics()
        self.cost_history: List[CostMetrics] = []
        
        logger.info(f"Initialized CostOptimizer with hourly_budget=${self.budget.hourly_budget}")
    
    def calculate_cost_score(self, current_cost_per_hour: float, 
                            active_workers: int) -> float:
        """
        Calculate cost score for scaling decisions.
        
        Args:
            current_cost_per_hour: Current cost per hour
            active_workers: Current number of workers
            
        Returns:
            Cost score (0.0 = can scale up, 1.0 = must scale down)
        """
        # Update metrics
        self.metrics.current_hour_cost = current_cost_per_hour
        self.metrics.projected_hour_cost = current_cost_per_hour
        
        # Calculate budget utilization
        hourly_utilization = current_cost_per_hour / self.budget.hourly_budget
        
        # Score based on budget utilization
        if hourly_utilization < 0.5:
            # Low utilization, can scale up
            return 0.0
        elif hourly_utilization > 0.9:
            # High utilization, must scale down
            return 1.0
        else:
            # Linear interpolation
            return (hourly_utilization - 0.5) / 0.4
    
    def can_scale_up(self, current_workers: int, target_workers: int) -> tuple[bool, str]:
        """
        Check if scaling up is allowed within budget.
        
        Args:
            current_workers: Current number of workers
            target_workers: Target number of workers
            
        Returns:
            Tuple of (allowed, reason)
        """
        # Calculate additional cost
        additional_workers = target_workers - current_workers
        additional_cost_per_hour = additional_workers * self.cost_per_worker_hour
        
        # Check hourly budget
        projected_hourly_cost = self.metrics.current_hour_cost + additional_cost_per_hour
        
        if projected_hourly_cost > self.budget.hourly_budget:
            return False, f"Would exceed hourly budget (${projected_hourly_cost:.2f} > ${self.budget.hourly_budget:.2f})"
        
        # Check daily budget
        projected_daily_cost = self.metrics.current_day_cost + additional_cost_per_hour
        
        if projected_daily_cost > self.budget.daily_budget:
            return False, f"Would exceed daily budget (${projected_daily_cost:.2f} > ${self.budget.daily_budget:.2f})"
        
        return True, "Within budget"
    
    def should_scale_down_for_cost(self, current_workers: int) -> tuple[bool, int, str]:
        """
        Check if should scale down to save costs.
        
        Args:
            current_workers: Current number of workers
            
        Returns:
            Tuple of (should_scale_down, target_workers, reason)
        """
        # Check if over budget
        hourly_utilization = self.metrics.current_hour_cost / self.budget.hourly_budget
        
        if hourly_utilization > 1.0:
            # Over budget, must scale down
            # Calculate how many workers to remove
            excess_cost = self.metrics.current_hour_cost - self.budget.hourly_budget
            workers_to_remove = int(excess_cost / self.cost_per_worker_hour) + 1
            target_workers = max(1, current_workers - workers_to_remove)
            
            return True, target_workers, f"Over hourly budget by ${excess_cost:.2f}"
        
        if hourly_utilization > self.budget.alert_threshold:
            # Approaching budget limit
            return True, max(1, current_workers - 1), f"Approaching budget limit ({hourly_utilization*100:.1f}%)"
        
        return False, current_workers, "Within budget"
    
    def get_cost_recommendations(self, current_workers: int) -> List[str]:
        """
        Get cost optimization recommendations.
        
        Args:
            current_workers: Current number of workers
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Check budget utilization
        hourly_utilization = self.metrics.current_hour_cost / self.budget.hourly_budget
        
        if hourly_utilization > 0.9:
            recommendations.append("⚠️ High cost utilization - consider scaling down")
        elif hourly_utilization < 0.3:
            recommendations.append("✅ Low cost utilization - can scale up if needed")
        
        # Check daily budget
        daily_utilization = self.metrics.current_day_cost / self.budget.daily_budget
        
        if daily_utilization > 0.8:
            recommendations.append("⚠️ Approaching daily budget limit")
        
        # Calculate potential savings
        if current_workers > 1:
            savings_per_hour = self.cost_per_worker_hour
            savings_per_day = savings_per_hour * 24
            recommendations.append(
                f"💰 Scaling down by 1 worker would save ${savings_per_hour:.2f}/hour (${savings_per_day:.2f}/day)"
            )
        
        # Calculate cost of scaling up
        cost_per_hour = self.cost_per_worker_hour
        cost_per_day = cost_per_hour * 24
        recommendations.append(
            f"📊 Scaling up by 1 worker would cost ${cost_per_hour:.2f}/hour (${cost_per_day:.2f}/day)"
        )
        
        return recommendations
    
    def update_costs(self, hour_cost: float, day_cost: float, month_cost: float):
        """
        Update cost metrics.
        
        Args:
            hour_cost: Cost for current hour
            day_cost: Cost for current day
            month_cost: Cost for current month
        """
        self.metrics.current_hour_cost = hour_cost
        self.metrics.current_day_cost = day_cost
        self.metrics.current_month_cost = month_cost
        self.metrics.timestamp = datetime.utcnow()
        
        # Add to history
        self.cost_history.append(CostMetrics(
            current_hour_cost=hour_cost,
            current_day_cost=day_cost,
            current_month_cost=month_cost,
            timestamp=datetime.utcnow()
        ))
        
        # Keep history manageable (last 1000 entries)
        if len(self.cost_history) > 1000:
            self.cost_history = self.cost_history[-1000:]
    
    def get_budget_status(self) -> Dict:
        """
        Get budget status.
        
        Returns:
            Dictionary with budget status
        """
        hourly_utilization = self.metrics.current_hour_cost / self.budget.hourly_budget
        daily_utilization = self.metrics.current_day_cost / self.budget.daily_budget
        monthly_utilization = self.metrics.current_month_cost / self.budget.monthly_budget
        
        return {
            'hourly': {
                'budget': self.budget.hourly_budget,
                'current': self.metrics.current_hour_cost,
                'utilization': hourly_utilization,
                'remaining': self.budget.hourly_budget - self.metrics.current_hour_cost,
                'status': self._get_status(hourly_utilization)
            },
            'daily': {
                'budget': self.budget.daily_budget,
                'current': self.metrics.current_day_cost,
                'utilization': daily_utilization,
                'remaining': self.budget.daily_budget - self.metrics.current_day_cost,
                'status': self._get_status(daily_utilization)
            },
            'monthly': {
                'budget': self.budget.monthly_budget,
                'current': self.metrics.current_month_cost,
                'utilization': monthly_utilization,
                'remaining': self.budget.monthly_budget - self.metrics.current_month_cost,
                'status': self._get_status(monthly_utilization)
            }
        }
    
    def _get_status(self, utilization: float) -> str:
        """Get status based on utilization."""
        if utilization < 0.5:
            return "healthy"
        elif utilization < self.budget.alert_threshold:
            return "warning"
        elif utilization < 1.0:
            return "critical"
        else:
            return "over_budget"
    
    def get_statistics(self) -> Dict:
        """Get cost optimizer statistics."""
        return {
            'budget_status': self.get_budget_status(),
            'cost_per_worker_hour': self.cost_per_worker_hour,
            'recommendations': self.get_cost_recommendations(1),  # Placeholder
            'history_size': len(self.cost_history)
        }

