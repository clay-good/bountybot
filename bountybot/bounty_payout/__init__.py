"""
Bounty Payout Recommendation Engine

Intelligent bounty payout recommendations based on:
- Vulnerability severity (CVSS score)
- Market rates and industry standards
- Historical payout data
- Researcher reputation
- Budget constraints and optimization
- Impact assessment
- Competitive analysis

Features:
- Smart payout calculation with multiple factors
- Market rate analysis and benchmarking
- Budget optimization and allocation
- Historical trend analysis
- Researcher-specific adjustments
- Payout range recommendations
- Justification and reasoning
- Competitive intelligence

Example:
    >>> from bountybot.bounty_payout import PayoutEngine
    >>> 
    >>> engine = PayoutEngine()
    >>> 
    >>> # Get payout recommendation
    >>> recommendation = engine.calculate_payout(
    ...     validation_result=result,
    ...     researcher_reputation=reputation
    ... )
    >>> 
    >>> print(f"Recommended payout: ${recommendation.recommended_amount}")
    >>> print(f"Range: ${recommendation.min_amount} - ${recommendation.max_amount}")
    >>> print(f"Reasoning: {recommendation.reasoning}")
"""

from .models import (
    PayoutRecommendation,
    PayoutRange,
    MarketRate,
    PayoutJustification,
    BudgetConstraints,
    PayoutHistory,
    SeverityTier,
    PayoutStrategy
)

from .payout_engine import PayoutEngine
from .market_analyzer import MarketRateAnalyzer
from .budget_optimizer import BudgetOptimizer

__all__ = [
    # Models
    'PayoutRecommendation',
    'PayoutRange',
    'MarketRate',
    'PayoutJustification',
    'BudgetConstraints',
    'PayoutHistory',
    'SeverityTier',
    'PayoutStrategy',

    # Core Components
    'PayoutEngine',
    'MarketRateAnalyzer',
    'BudgetOptimizer',
]

