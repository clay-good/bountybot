"""
Core bounty payout calculation engine.
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime

from .models import (
    PayoutRecommendation,
    PayoutRange,
    PayoutJustification,
    SeverityTier,
    PayoutStrategy
)
from .market_analyzer import MarketRateAnalyzer
from .budget_optimizer import BudgetOptimizer

logger = logging.getLogger(__name__)


class PayoutEngine:
    """
    Intelligent bounty payout recommendation engine.
    
    Calculates optimal payout amounts based on:
    - Vulnerability severity (CVSS score)
    - Market rates and industry standards
    - Researcher reputation
    - Historical data
    - Budget constraints
    - Impact assessment
    
    Example:
        >>> engine = PayoutEngine()
        >>> recommendation = engine.calculate_payout(
        ...     validation_result=result,
        ...     researcher_reputation=reputation
        ... )
        >>> print(f"Pay: ${recommendation.recommended_amount}")
    """
    
    # Default payout ranges by severity (USD)
    DEFAULT_RANGES = {
        SeverityTier.CRITICAL: PayoutRange(
            severity_tier=SeverityTier.CRITICAL,
            min_amount=5000.0,
            max_amount=50000.0,
            typical_amount=15000.0
        ),
        SeverityTier.HIGH: PayoutRange(
            severity_tier=SeverityTier.HIGH,
            min_amount=2000.0,
            max_amount=15000.0,
            typical_amount=5000.0
        ),
        SeverityTier.MEDIUM: PayoutRange(
            severity_tier=SeverityTier.MEDIUM,
            min_amount=500.0,
            max_amount=5000.0,
            typical_amount=1500.0
        ),
        SeverityTier.LOW: PayoutRange(
            severity_tier=SeverityTier.LOW,
            min_amount=100.0,
            max_amount=1000.0,
            typical_amount=300.0
        ),
        SeverityTier.INFO: PayoutRange(
            severity_tier=SeverityTier.INFO,
            min_amount=0.0,
            max_amount=200.0,
            typical_amount=50.0
        ),
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize payout engine.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.market_analyzer = MarketRateAnalyzer()
        self.budget_optimizer = BudgetOptimizer()
        
        # Load custom ranges if provided
        self.payout_ranges = self._load_payout_ranges()
        
        logger.info("PayoutEngine initialized")
    
    def calculate_payout(
        self,
        validation_result: Any,
        researcher_reputation: Optional[Any] = None,
        budget_constraints: Optional[Any] = None,
        strategy: PayoutStrategy = PayoutStrategy.BALANCED
    ) -> PayoutRecommendation:
        """
        Calculate recommended payout for a vulnerability report.

        Args:
            validation_result: ValidationResult object
            researcher_reputation: Optional ResearcherReputation object
            budget_constraints: Optional BudgetConstraints object
            strategy: Payout strategy to use

        Returns:
            PayoutRecommendation with amount and justification
        """
        # CRITICAL: Check for duplicate reports to prevent double-payment
        if hasattr(validation_result, 'duplicate_check') and validation_result.duplicate_check:
            duplicate_check = validation_result.duplicate_check
            if duplicate_check.is_duplicate and duplicate_check.confidence > 0.75:
                logger.warning(
                    f"⚠️ DUPLICATE DETECTED: Blocking payout (confidence: {duplicate_check.confidence:.0%})"
                )
                justification_obj = PayoutJustification(
                    base_amount=0.0,
                    severity_multiplier=0.0,
                    impact_multiplier=0.0,
                    reputation_multiplier=0.0,
                    market_adjustment=0.0,
                    budget_adjustment=0.0,
                    factors=[],
                    reasoning=(
                        f"Payout blocked: Duplicate of report {duplicate_check.matched_report_id} "
                        f"(confidence: {duplicate_check.confidence:.0%}). "
                        f"Reasoning: {', '.join(duplicate_check.reasoning)}"
                    )
                )
                return PayoutRecommendation(
                    recommended_amount=0.0,
                    min_amount=0.0,
                    max_amount=0.0,
                    severity_tier=SeverityTier.LOW,  # Use LOW instead of NONE
                    confidence=0.0,
                    justification=justification_obj
                )
            elif duplicate_check.is_duplicate and duplicate_check.confidence > 0.50:
                logger.warning(
                    f"⚠️ POSSIBLE DUPLICATE: Reducing payout (confidence: {duplicate_check.confidence:.0%})"
                )
                # Will apply reduction multiplier later

        # Extract key metrics
        cvss_score = self._extract_cvss_score(validation_result)
        vulnerability_type = self._extract_vulnerability_type(validation_result)
        
        # Determine severity tier
        severity_tier = self._determine_severity_tier(cvss_score)
        
        # Get base payout range
        payout_range = self.payout_ranges.get(severity_tier, self.DEFAULT_RANGES[SeverityTier.MEDIUM])
        
        # Calculate base amount based on strategy
        base_amount = self._calculate_base_amount(payout_range, strategy, cvss_score)
        
        # Apply multipliers
        severity_multiplier = self._calculate_severity_multiplier(cvss_score, severity_tier)
        impact_multiplier = self._calculate_impact_multiplier(validation_result)
        reputation_multiplier = self._calculate_reputation_multiplier(researcher_reputation)

        # Apply duplicate reduction multiplier if possible duplicate
        duplicate_multiplier = 1.0
        if hasattr(validation_result, 'duplicate_check') and validation_result.duplicate_check:
            duplicate_check = validation_result.duplicate_check
            if duplicate_check.is_duplicate and 0.50 < duplicate_check.confidence <= 0.75:
                # Reduce payout for possible duplicates
                duplicate_multiplier = 1.0 - (duplicate_check.confidence * 0.5)  # Up to 37.5% reduction
                logger.info(f"Applying duplicate reduction: {duplicate_multiplier:.2f}x")

        # Calculate adjusted amount
        adjusted_amount = base_amount * severity_multiplier * impact_multiplier * reputation_multiplier * duplicate_multiplier
        
        # Get market adjustment
        market_rate = self.market_analyzer.get_market_rate(vulnerability_type, severity_tier)
        market_adjustment = self._calculate_market_adjustment(adjusted_amount, market_rate)
        adjusted_amount += market_adjustment
        
        # Clamp to range first
        adjusted_amount = max(payout_range.min_amount, min(payout_range.max_amount, adjusted_amount))

        # Apply budget constraints (may reduce below range minimum if necessary)
        budget_adjustment = 0.0
        if budget_constraints:
            adjusted_amount, budget_adjustment = self.budget_optimizer.optimize_payout(
                adjusted_amount,
                budget_constraints
            )

        final_amount = adjusted_amount
        
        # Build justification
        justification = PayoutJustification(
            base_amount=base_amount,
            severity_multiplier=severity_multiplier,
            impact_multiplier=impact_multiplier,
            reputation_multiplier=reputation_multiplier,
            market_adjustment=market_adjustment,
            budget_adjustment=budget_adjustment,
            factors=self._build_factors_list(
                severity_tier, cvss_score, researcher_reputation, market_rate
            ),
            reasoning=self._build_reasoning(
                severity_tier, cvss_score, researcher_reputation, strategy, final_amount
            )
        )
        
        # Build market comparison
        market_comparison = None
        if market_rate:
            market_comparison = {
                'average': market_rate.average_payout,
                'median': market_rate.median_payout,
                'percentile_75': market_rate.percentile_75,
                'percentile_90': market_rate.percentile_90,
                'position': 'above' if final_amount > market_rate.average_payout else 'below'
            }
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            cvss_score, researcher_reputation, market_rate
        )
        
        # Build recommendation
        recommendation = PayoutRecommendation(
            recommended_amount=round(final_amount, 2),
            min_amount=payout_range.min_amount,
            max_amount=payout_range.max_amount,
            severity_tier=severity_tier,
            strategy=strategy,
            justification=justification,
            market_comparison=market_comparison,
            cvss_score=cvss_score,
            vulnerability_type=vulnerability_type,
            researcher_reputation_score=researcher_reputation.reputation_score.overall if researcher_reputation else None,
            confidence=confidence
        )
        
        logger.info(
            f"Payout calculated: ${recommendation.recommended_amount:.2f} "
            f"({severity_tier.value}, CVSS {cvss_score:.1f})"
        )
        
        return recommendation
    
    def _load_payout_ranges(self) -> Dict[SeverityTier, PayoutRange]:
        """Load payout ranges from config or use defaults."""
        ranges = self.DEFAULT_RANGES.copy()

        # Override with config if provided
        if 'payout_ranges' in self.config:
            custom_ranges = self.config['payout_ranges']
            for severity_name, range_config in custom_ranges.items():
                try:
                    severity_tier = SeverityTier[severity_name.upper()]
                    ranges[severity_tier] = PayoutRange(
                        severity_tier=severity_tier,
                        min_amount=float(range_config.get('min_amount', ranges[severity_tier].min_amount)),
                        max_amount=float(range_config.get('max_amount', ranges[severity_tier].max_amount)),
                        typical_amount=float(range_config.get('typical_amount', ranges[severity_tier].typical_amount))
                    )
                    logger.info(f"Loaded custom payout range for {severity_name}: ${ranges[severity_tier].min_amount}-${ranges[severity_tier].max_amount}")
                except (KeyError, ValueError) as e:
                    logger.warning(f"Invalid payout range config for {severity_name}: {e}")

        return ranges
    
    def _extract_cvss_score(self, validation_result: Any) -> float:
        """Extract CVSS score from validation result."""
        if hasattr(validation_result, 'cvss_score'):
            if hasattr(validation_result.cvss_score, 'base_score'):
                return float(validation_result.cvss_score.base_score)
            elif isinstance(validation_result.cvss_score, (int, float)):
                return float(validation_result.cvss_score)
        return 5.0  # Default medium severity
    
    def _extract_vulnerability_type(self, validation_result: Any) -> str:
        """Extract vulnerability type from validation result."""
        if hasattr(validation_result, 'report'):
            if hasattr(validation_result.report, 'vulnerability_type'):
                return validation_result.report.vulnerability_type
        return "unknown"
    
    def _determine_severity_tier(self, cvss_score: float) -> SeverityTier:
        """Determine severity tier from CVSS score."""
        if cvss_score >= 9.0:
            return SeverityTier.CRITICAL
        elif cvss_score >= 7.0:
            return SeverityTier.HIGH
        elif cvss_score >= 4.0:
            return SeverityTier.MEDIUM
        elif cvss_score > 0.0:
            return SeverityTier.LOW
        else:
            return SeverityTier.INFO
    
    def _calculate_base_amount(
        self,
        payout_range: PayoutRange,
        strategy: PayoutStrategy,
        cvss_score: float
    ) -> float:
        """Calculate base payout amount based on strategy."""
        if strategy == PayoutStrategy.CONSERVATIVE:
            # Lower end of range
            return payout_range.min_amount + (payout_range.typical_amount - payout_range.min_amount) * 0.5
        elif strategy == PayoutStrategy.BALANCED:
            # Typical amount
            return payout_range.typical_amount
        elif strategy == PayoutStrategy.COMPETITIVE:
            # Higher end of range
            return payout_range.typical_amount + (payout_range.max_amount - payout_range.typical_amount) * 0.5
        elif strategy == PayoutStrategy.PREMIUM:
            # Top of range
            return payout_range.max_amount * 0.9
        else:
            return payout_range.typical_amount
    
    def _calculate_severity_multiplier(self, cvss_score: float, severity_tier: SeverityTier) -> float:
        """Calculate multiplier based on exact CVSS score within tier."""
        # Fine-tune within tier based on exact score
        if severity_tier == SeverityTier.CRITICAL:
            # 9.0-10.0 -> 1.0-1.2
            return 1.0 + (cvss_score - 9.0) * 0.2
        elif severity_tier == SeverityTier.HIGH:
            # 7.0-8.9 -> 1.0-1.15
            return 1.0 + (cvss_score - 7.0) / 1.9 * 0.15
        elif severity_tier == SeverityTier.MEDIUM:
            # 4.0-6.9 -> 1.0-1.1
            return 1.0 + (cvss_score - 4.0) / 2.9 * 0.1
        else:
            return 1.0
    
    def _calculate_impact_multiplier(self, validation_result: Any) -> float:
        """Calculate multiplier based on business impact."""
        multiplier = 1.0
        
        # Check for high-impact indicators
        if hasattr(validation_result, 'priority_score'):
            priority = validation_result.priority_score
            if hasattr(priority, 'business_impact_score'):
                # High business impact increases payout
                if priority.business_impact_score > 80:
                    multiplier *= 1.3
                elif priority.business_impact_score > 60:
                    multiplier *= 1.15
        
        return multiplier
    
    def _calculate_reputation_multiplier(self, researcher_reputation: Optional[Any]) -> float:
        """Calculate multiplier based on researcher reputation."""
        if not researcher_reputation:
            return 1.0
        
        reputation_score = researcher_reputation.reputation_score.overall
        
        # Elite researchers get premium
        if reputation_score >= 90:
            return 1.25
        elif reputation_score >= 80:
            return 1.15
        elif reputation_score >= 70:
            return 1.1
        elif reputation_score >= 50:
            return 1.0
        else:
            # New/low reputation researchers get reduced payout
            return 0.9
    
    def _calculate_market_adjustment(self, current_amount: float, market_rate: Optional[Any]) -> float:
        """Calculate adjustment to align with market rates."""
        if not market_rate:
            return 0.0
        
        # If significantly below market, adjust upward
        if current_amount < market_rate.percentile_25:
            return (market_rate.median_payout - current_amount) * 0.3
        
        return 0.0
    
    def _build_factors_list(
        self,
        severity_tier: SeverityTier,
        cvss_score: float,
        researcher_reputation: Optional[Any],
        market_rate: Optional[Any]
    ) -> list:
        """Build list of factors affecting payout."""
        factors = [
            f"Severity: {severity_tier.value.upper()} (CVSS {cvss_score:.1f})"
        ]
        
        if researcher_reputation:
            rep_score = researcher_reputation.reputation_score.overall
            factors.append(f"Researcher reputation: {rep_score:.1f}/100")
            
            if researcher_reputation.trust_level.value == 'elite':
                factors.append("Elite researcher bonus applied")
        
        if market_rate:
            factors.append(f"Market rate: ${market_rate.median_payout:.2f} median")
        
        return factors
    
    def _build_reasoning(
        self,
        severity_tier: SeverityTier,
        cvss_score: float,
        researcher_reputation: Optional[Any],
        strategy: PayoutStrategy,
        final_amount: float
    ) -> str:
        """Build human-readable reasoning for payout."""
        reasoning_parts = [
            f"This {severity_tier.value} severity vulnerability (CVSS {cvss_score:.1f}) "
            f"warrants a ${final_amount:.2f} payout."
        ]
        
        if researcher_reputation:
            rep_score = researcher_reputation.reputation_score.overall
            if rep_score >= 80:
                reasoning_parts.append(
                    f"The researcher has an excellent reputation ({rep_score:.1f}/100), "
                    "justifying a premium payout."
                )
            elif rep_score < 50:
                reasoning_parts.append(
                    f"The researcher has limited track record ({rep_score:.1f}/100), "
                    "resulting in a conservative payout."
                )
        
        if strategy == PayoutStrategy.PREMIUM:
            reasoning_parts.append("Premium strategy applied for competitive positioning.")
        elif strategy == PayoutStrategy.CONSERVATIVE:
            reasoning_parts.append("Conservative strategy applied due to budget constraints.")
        
        return " ".join(reasoning_parts)
    
    def _calculate_confidence(
        self,
        cvss_score: float,
        researcher_reputation: Optional[Any],
        market_rate: Optional[Any]
    ) -> float:
        """Calculate confidence in payout recommendation."""
        confidence = 0.7  # Base confidence
        
        # Higher confidence with clear CVSS score
        if cvss_score > 0:
            confidence += 0.1
        
        # Higher confidence with researcher reputation data
        if researcher_reputation and researcher_reputation.total_reports >= 10:
            confidence += 0.1
        
        # Higher confidence with market data
        if market_rate and market_rate.sample_size >= 50:
            confidence += 0.1
        
        return min(1.0, confidence)

