"""
Data models for bounty payout system.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Dict, Any, Optional


class SeverityTier(Enum):
    """Severity tiers for payout calculation."""
    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"  # CVSS 7.0-8.9
    MEDIUM = "medium"  # CVSS 4.0-6.9
    LOW = "low"  # CVSS 0.1-3.9
    INFO = "info"  # CVSS 0.0


class PayoutStrategy(Enum):
    """Payout calculation strategy."""
    CONSERVATIVE = "conservative"  # Lower end of range
    BALANCED = "balanced"  # Middle of range
    COMPETITIVE = "competitive"  # Higher end of range
    PREMIUM = "premium"  # Top of range for elite researchers


@dataclass
class PayoutRange:
    """Payout range for a severity tier."""
    
    severity_tier: SeverityTier
    min_amount: float
    max_amount: float
    typical_amount: float
    currency: str = "USD"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'severity_tier': self.severity_tier.value,
            'min_amount': self.min_amount,
            'max_amount': self.max_amount,
            'typical_amount': self.typical_amount,
            'currency': self.currency
        }


@dataclass
class MarketRate:
    """Market rate data for vulnerability types."""
    
    vulnerability_type: str
    severity_tier: SeverityTier
    average_payout: float
    median_payout: float
    percentile_25: float
    percentile_75: float
    percentile_90: float
    sample_size: int
    last_updated: datetime
    source: str = "industry_data"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'vulnerability_type': self.vulnerability_type,
            'severity_tier': self.severity_tier.value,
            'average_payout': self.average_payout,
            'median_payout': self.median_payout,
            'percentiles': {
                '25': self.percentile_25,
                '75': self.percentile_75,
                '90': self.percentile_90
            },
            'sample_size': self.sample_size,
            'last_updated': self.last_updated.isoformat(),
            'source': self.source
        }


@dataclass
class PayoutJustification:
    """Justification for payout recommendation."""
    
    base_amount: float
    severity_multiplier: float
    impact_multiplier: float
    reputation_multiplier: float
    market_adjustment: float
    budget_adjustment: float
    
    factors: List[str] = field(default_factory=list)
    reasoning: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'base_amount': self.base_amount,
            'multipliers': {
                'severity': self.severity_multiplier,
                'impact': self.impact_multiplier,
                'reputation': self.reputation_multiplier
            },
            'adjustments': {
                'market': self.market_adjustment,
                'budget': self.budget_adjustment
            },
            'factors': self.factors,
            'reasoning': self.reasoning
        }


@dataclass
class BudgetConstraints:
    """Budget constraints for payout calculations."""
    
    total_budget: float
    spent_to_date: float
    remaining_budget: float
    monthly_budget: float
    monthly_spent: float
    
    # Limits
    max_single_payout: Optional[float] = None
    min_payout_threshold: float = 50.0
    
    # Flags
    budget_warning: bool = False
    budget_critical: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'total_budget': self.total_budget,
            'spent_to_date': self.spent_to_date,
            'remaining_budget': self.remaining_budget,
            'monthly_budget': self.monthly_budget,
            'monthly_spent': self.monthly_spent,
            'limits': {
                'max_single_payout': self.max_single_payout,
                'min_payout_threshold': self.min_payout_threshold
            },
            'status': {
                'budget_warning': self.budget_warning,
                'budget_critical': self.budget_critical
            }
        }


@dataclass
class PayoutHistory:
    """Historical payout record."""
    
    report_id: str
    researcher_id: str
    vulnerability_type: str
    severity_tier: SeverityTier
    cvss_score: float
    payout_amount: float
    paid_at: datetime
    
    # Context
    researcher_reputation_at_time: Optional[float] = None
    market_rate_at_time: Optional[float] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'report_id': self.report_id,
            'researcher_id': self.researcher_id,
            'vulnerability_type': self.vulnerability_type,
            'severity_tier': self.severity_tier.value,
            'cvss_score': self.cvss_score,
            'payout_amount': self.payout_amount,
            'paid_at': self.paid_at.isoformat(),
            'context': {
                'researcher_reputation': self.researcher_reputation_at_time,
                'market_rate': self.market_rate_at_time
            }
        }


@dataclass
class PayoutRecommendation:
    """Complete payout recommendation."""
    
    # Amounts
    recommended_amount: float
    min_amount: float
    max_amount: float
    currency: str = "USD"
    
    # Classification
    severity_tier: SeverityTier = SeverityTier.MEDIUM
    strategy: PayoutStrategy = PayoutStrategy.BALANCED
    
    # Analysis
    justification: Optional[PayoutJustification] = None
    market_comparison: Optional[Dict[str, Any]] = None
    
    # Context
    cvss_score: float = 0.0
    vulnerability_type: str = ""
    researcher_reputation_score: Optional[float] = None
    
    # Confidence
    confidence: float = 0.0  # 0-1
    
    # Metadata
    calculated_at: datetime = field(default_factory=datetime.utcnow)
    
    @property
    def reasoning(self) -> str:
        """Get reasoning for recommendation."""
        if self.justification:
            return self.justification.reasoning
        return "No reasoning provided"
    
    @property
    def is_premium(self) -> bool:
        """Check if this is a premium payout."""
        return self.strategy == PayoutStrategy.PREMIUM
    
    @property
    def is_above_market(self) -> bool:
        """Check if recommendation is above market rate."""
        if self.market_comparison and 'average' in self.market_comparison:
            return self.recommended_amount > self.market_comparison['average']
        return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'recommended_amount': self.recommended_amount,
            'range': {
                'min': self.min_amount,
                'max': self.max_amount,
                'currency': self.currency
            },
            'classification': {
                'severity_tier': self.severity_tier.value,
                'strategy': self.strategy.value,
                'cvss_score': self.cvss_score,
                'vulnerability_type': self.vulnerability_type
            },
            'justification': self.justification.to_dict() if self.justification else None,
            'market_comparison': self.market_comparison,
            'researcher_reputation_score': self.researcher_reputation_score,
            'confidence': self.confidence,
            'is_premium': self.is_premium,
            'is_above_market': self.is_above_market,
            'reasoning': self.reasoning,
            'calculated_at': self.calculated_at.isoformat()
        }

