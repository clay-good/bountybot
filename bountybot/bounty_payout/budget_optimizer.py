"""
Budget optimization for bounty payouts.
"""

import logging
from typing import Dict, Any, List, Tuple, Optional
from datetime import datetime, timedelta

from .models import BudgetConstraints, PayoutHistory

logger = logging.getLogger(__name__)


class BudgetOptimizer:
    """
    Optimizes bounty payouts within budget constraints.
    
    Features:
    - Budget allocation optimization
    - Spending rate analysis
    - Budget forecasting
    - Constraint enforcement
    - Smart payout adjustments
    
    Example:
        >>> optimizer = BudgetOptimizer()
        >>> optimized_amount, adjustment = optimizer.optimize_payout(
        ...     proposed_amount=5000,
        ...     budget_constraints=constraints
        ... )
        >>> print(f"Optimized: ${optimized_amount} (adjusted by ${adjustment})")
    """
    
    def __init__(self):
        """Initialize budget optimizer."""
        self.payout_history: List[PayoutHistory] = []
        logger.info("BudgetOptimizer initialized")
    
    def optimize_payout(
        self,
        proposed_amount: float,
        budget_constraints: BudgetConstraints
    ) -> Tuple[float, float]:
        """
        Optimize payout amount within budget constraints.

        Args:
            proposed_amount: Proposed payout amount
            budget_constraints: Budget constraints

        Returns:
            Tuple of (optimized_amount, adjustment)
        """
        original_amount = proposed_amount

        # Check if within max single payout limit (highest priority)
        if budget_constraints.max_single_payout:
            if proposed_amount > budget_constraints.max_single_payout:
                proposed_amount = budget_constraints.max_single_payout
                logger.info(f"Capped payout at max single payout: ${proposed_amount}")

        # Check if below minimum threshold
        if proposed_amount < budget_constraints.min_payout_threshold:
            proposed_amount = budget_constraints.min_payout_threshold
            logger.info(f"Raised payout to minimum threshold: ${proposed_amount}")

        # Check remaining budget
        if proposed_amount > budget_constraints.remaining_budget:
            # Budget critical - need to reduce
            if budget_constraints.remaining_budget >= budget_constraints.min_payout_threshold:
                proposed_amount = min(proposed_amount, budget_constraints.remaining_budget)
                logger.warning(f"Reduced payout to remaining budget: ${proposed_amount}")
            else:
                # Not enough budget even for minimum
                logger.error("Insufficient budget for payout")
                proposed_amount = 0.0

        # Check monthly budget (but don't override max_single_payout)
        monthly_remaining = budget_constraints.monthly_budget - budget_constraints.monthly_spent
        if proposed_amount > monthly_remaining:
            # Exceeds monthly budget
            if monthly_remaining >= budget_constraints.min_payout_threshold:
                # Can still pay something this month, but respect max_single_payout
                proposed_amount = min(proposed_amount, monthly_remaining)
                logger.warning(f"Adjusted payout to monthly budget: ${proposed_amount}")
            else:
                # Monthly budget exhausted
                logger.warning("Monthly budget exhausted - deferring payout")
                # Could implement deferral logic here

        # Apply budget pressure adjustment
        if budget_constraints.budget_warning or budget_constraints.budget_critical:
            pressure_factor = self._calculate_budget_pressure_factor(budget_constraints)
            proposed_amount *= pressure_factor
            logger.info(f"Applied budget pressure factor: {pressure_factor:.2f}")

        adjustment = proposed_amount - original_amount

        return round(proposed_amount, 2), round(adjustment, 2)
    
    def _calculate_budget_pressure_factor(self, budget_constraints: BudgetConstraints) -> float:
        """Calculate factor to reduce payouts under budget pressure."""
        if budget_constraints.budget_critical:
            # Critical: reduce by 20%
            return 0.80
        elif budget_constraints.budget_warning:
            # Warning: reduce by 10%
            return 0.90
        else:
            return 1.0
    
    def analyze_budget_health(
        self,
        budget_constraints: BudgetConstraints
    ) -> Dict[str, Any]:
        """
        Analyze budget health and spending patterns.
        
        Args:
            budget_constraints: Current budget constraints
            
        Returns:
            Budget health analysis
        """
        # Calculate utilization rates
        total_utilization = (budget_constraints.spent_to_date / budget_constraints.total_budget * 100) if budget_constraints.total_budget > 0 else 0
        monthly_utilization = (budget_constraints.monthly_spent / budget_constraints.monthly_budget * 100) if budget_constraints.monthly_budget > 0 else 0
        
        # Determine health status
        if total_utilization >= 90:
            health_status = 'critical'
            health_color = 'red'
        elif total_utilization >= 75:
            health_status = 'warning'
            health_color = 'yellow'
        elif total_utilization >= 50:
            health_status = 'healthy'
            health_color = 'green'
        else:
            health_status = 'excellent'
            health_color = 'green'
        
        # Calculate runway (months remaining at current rate)
        if budget_constraints.monthly_spent > 0:
            months_remaining = budget_constraints.remaining_budget / budget_constraints.monthly_spent
        else:
            months_remaining = float('inf')
        
        return {
            'health_status': health_status,
            'health_color': health_color,
            'total_utilization_percent': round(total_utilization, 2),
            'monthly_utilization_percent': round(monthly_utilization, 2),
            'remaining_budget': budget_constraints.remaining_budget,
            'months_remaining': round(months_remaining, 1) if months_remaining != float('inf') else 'unlimited',
            'recommendations': self._get_budget_recommendations(budget_constraints, total_utilization)
        }
    
    def _get_budget_recommendations(
        self,
        budget_constraints: BudgetConstraints,
        utilization: float
    ) -> List[str]:
        """Get budget management recommendations."""
        recommendations = []
        
        if utilization >= 90:
            recommendations.append("URGENT: Budget nearly exhausted. Consider increasing budget or reducing payout amounts.")
            recommendations.append("Implement strict approval process for all payouts.")
        elif utilization >= 75:
            recommendations.append("WARNING: Budget utilization high. Monitor spending closely.")
            recommendations.append("Consider prioritizing critical vulnerabilities only.")
        elif utilization >= 50:
            recommendations.append("Budget utilization healthy. Continue monitoring.")
        else:
            recommendations.append("Budget utilization excellent. Consider competitive payout strategy.")
        
        # Monthly budget recommendations
        monthly_util = (budget_constraints.monthly_spent / budget_constraints.monthly_budget * 100) if budget_constraints.monthly_budget > 0 else 0
        if monthly_util >= 80:
            recommendations.append("Monthly budget nearly exhausted. Defer non-critical payouts to next month.")
        
        return recommendations
    
    def forecast_budget(
        self,
        budget_constraints: BudgetConstraints,
        months_ahead: int = 3
    ) -> Dict[str, Any]:
        """
        Forecast budget utilization.
        
        Args:
            budget_constraints: Current budget constraints
            months_ahead: Number of months to forecast
            
        Returns:
            Budget forecast
        """
        # Calculate current monthly burn rate
        if budget_constraints.monthly_spent > 0:
            monthly_burn = budget_constraints.monthly_spent
        else:
            # Estimate from total spent (assume 1 month)
            monthly_burn = budget_constraints.spent_to_date
        
        # Forecast
        forecast = []
        remaining = budget_constraints.remaining_budget
        
        for month in range(1, months_ahead + 1):
            projected_spend = monthly_burn
            remaining -= projected_spend
            
            forecast.append({
                'month': month,
                'projected_spend': round(projected_spend, 2),
                'projected_remaining': round(max(0, remaining), 2),
                'budget_exhausted': remaining <= 0
            })
        
        # Determine when budget will be exhausted
        months_until_exhausted = None
        for entry in forecast:
            if entry['budget_exhausted']:
                months_until_exhausted = entry['month']
                break
        
        return {
            'monthly_burn_rate': round(monthly_burn, 2),
            'months_until_exhausted': months_until_exhausted,
            'forecast': forecast,
            'recommendation': self._get_forecast_recommendation(months_until_exhausted)
        }
    
    def _get_forecast_recommendation(self, months_until_exhausted: Optional[int]) -> str:
        """Get recommendation based on forecast."""
        if months_until_exhausted is None:
            return "Budget sustainable at current rate."
        elif months_until_exhausted <= 1:
            return "CRITICAL: Budget will be exhausted within 1 month. Immediate action required."
        elif months_until_exhausted <= 3:
            return "WARNING: Budget will be exhausted within 3 months. Plan budget increase or reduce spending."
        elif months_until_exhausted <= 6:
            return "CAUTION: Budget will be exhausted within 6 months. Start planning for next budget cycle."
        else:
            return "Budget healthy for foreseeable future."
    
    def calculate_optimal_allocation(
        self,
        budget_constraints: BudgetConstraints,
        pending_payouts: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate optimal allocation for pending payouts.
        
        Args:
            budget_constraints: Budget constraints
            pending_payouts: List of pending payout requests
            
        Returns:
            Optimal allocation plan
        """
        # Sort by priority (severity * reputation)
        sorted_payouts = sorted(
            pending_payouts,
            key=lambda p: p.get('priority_score', 0),
            reverse=True
        )
        
        # Allocate budget
        allocated = []
        deferred = []
        total_allocated = 0.0
        remaining = budget_constraints.remaining_budget
        
        for payout in sorted_payouts:
            amount = payout.get('amount', 0)
            
            if total_allocated + amount <= remaining:
                # Can afford this payout
                allocated.append({
                    **payout,
                    'status': 'approved',
                    'allocated_amount': amount
                })
                total_allocated += amount
            else:
                # Cannot afford - defer
                deferred.append({
                    **payout,
                    'status': 'deferred',
                    'reason': 'insufficient_budget'
                })
        
        return {
            'total_requested': sum(p.get('amount', 0) for p in pending_payouts),
            'total_allocated': round(total_allocated, 2),
            'allocated_count': len(allocated),
            'deferred_count': len(deferred),
            'allocated_payouts': allocated,
            'deferred_payouts': deferred,
            'remaining_after_allocation': round(remaining - total_allocated, 2)
        }
    
    def add_payout_history(self, payout: PayoutHistory):
        """Add payout to history for analysis."""
        self.payout_history.append(payout)
        logger.debug(f"Added payout history: ${payout.payout_amount}")

