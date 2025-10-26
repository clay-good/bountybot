"""
Market rate analysis for bounty payouts.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from collections import defaultdict
import statistics

from .models import MarketRate, SeverityTier, PayoutHistory

logger = logging.getLogger(__name__)


class MarketRateAnalyzer:
    """
    Analyzes market rates for vulnerability bounties.
    
    Features:
    - Industry benchmark tracking
    - Historical trend analysis
    - Competitive positioning
    - Market rate recommendations
    
    Example:
        >>> analyzer = MarketRateAnalyzer()
        >>> rate = analyzer.get_market_rate("sql_injection", SeverityTier.HIGH)
        >>> print(f"Market median: ${rate.median_payout}")
    """
    
    # Industry benchmark data (based on public bug bounty programs)
    INDUSTRY_BENCHMARKS = {
        ('sql_injection', SeverityTier.CRITICAL): {
            'average': 12000, 'median': 10000, 'p25': 7000, 'p75': 15000, 'p90': 20000
        },
        ('sql_injection', SeverityTier.HIGH): {
            'average': 5000, 'median': 4000, 'p25': 2500, 'p75': 7000, 'p90': 10000
        },
        ('xss', SeverityTier.HIGH): {
            'average': 3000, 'median': 2500, 'p25': 1500, 'p75': 4000, 'p90': 6000
        },
        ('xss', SeverityTier.MEDIUM): {
            'average': 1000, 'median': 800, 'p25': 500, 'p75': 1500, 'p90': 2000
        },
        ('rce', SeverityTier.CRITICAL): {
            'average': 25000, 'median': 20000, 'p25': 15000, 'p75': 30000, 'p90': 40000
        },
        ('rce', SeverityTier.HIGH): {
            'average': 10000, 'median': 8000, 'p25': 5000, 'p75': 12000, 'p90': 15000
        },
        ('authentication_bypass', SeverityTier.CRITICAL): {
            'average': 15000, 'median': 12000, 'p25': 8000, 'p75': 18000, 'p90': 25000
        },
        ('authentication_bypass', SeverityTier.HIGH): {
            'average': 6000, 'median': 5000, 'p25': 3000, 'p75': 8000, 'p90': 10000
        },
        ('idor', SeverityTier.HIGH): {
            'average': 4000, 'median': 3500, 'p25': 2000, 'p75': 5000, 'p90': 7000
        },
        ('idor', SeverityTier.MEDIUM): {
            'average': 1500, 'median': 1200, 'p25': 800, 'p75': 2000, 'p90': 2500
        },
        ('ssrf', SeverityTier.HIGH): {
            'average': 5000, 'median': 4000, 'p25': 2500, 'p75': 6000, 'p90': 8000
        },
        ('csrf', SeverityTier.MEDIUM): {
            'average': 1000, 'median': 800, 'p25': 500, 'p75': 1200, 'p90': 1500
        },
    }
    
    def __init__(self):
        """Initialize market rate analyzer."""
        self.payout_history: List[PayoutHistory] = []
        logger.info("MarketRateAnalyzer initialized")
    
    def get_market_rate(
        self,
        vulnerability_type: str,
        severity_tier: SeverityTier
    ) -> Optional[MarketRate]:
        """
        Get market rate for vulnerability type and severity.
        
        Args:
            vulnerability_type: Type of vulnerability
            severity_tier: Severity tier
            
        Returns:
            MarketRate object or None if no data available
        """
        # Normalize vulnerability type
        vuln_type = vulnerability_type.lower().replace(' ', '_')
        
        # Check if we have historical data
        historical_rate = self._calculate_historical_rate(vuln_type, severity_tier)
        if historical_rate:
            return historical_rate
        
        # Fall back to industry benchmarks
        benchmark_key = (vuln_type, severity_tier)
        if benchmark_key in self.INDUSTRY_BENCHMARKS:
            benchmark = self.INDUSTRY_BENCHMARKS[benchmark_key]
            return MarketRate(
                vulnerability_type=vuln_type,
                severity_tier=severity_tier,
                average_payout=benchmark['average'],
                median_payout=benchmark['median'],
                percentile_25=benchmark['p25'],
                percentile_75=benchmark['p75'],
                percentile_90=benchmark['p90'],
                sample_size=100,  # Estimated from industry data
                last_updated=datetime.utcnow(),
                source="industry_benchmarks"
            )
        
        # No data available
        logger.warning(f"No market rate data for {vuln_type} / {severity_tier.value}")
        return None
    
    def _calculate_historical_rate(
        self,
        vulnerability_type: str,
        severity_tier: SeverityTier
    ) -> Optional[MarketRate]:
        """Calculate market rate from historical payout data."""
        # Filter relevant payouts
        relevant_payouts = [
            p.payout_amount for p in self.payout_history
            if p.vulnerability_type.lower() == vulnerability_type.lower()
            and p.severity_tier == severity_tier
        ]
        
        if len(relevant_payouts) < 10:  # Need minimum sample size
            return None
        
        # Calculate statistics
        relevant_payouts.sort()
        n = len(relevant_payouts)
        
        return MarketRate(
            vulnerability_type=vulnerability_type,
            severity_tier=severity_tier,
            average_payout=statistics.mean(relevant_payouts),
            median_payout=statistics.median(relevant_payouts),
            percentile_25=relevant_payouts[n // 4],
            percentile_75=relevant_payouts[3 * n // 4],
            percentile_90=relevant_payouts[9 * n // 10],
            sample_size=n,
            last_updated=datetime.utcnow(),
            source="historical_data"
        )
    
    def add_payout_history(self, payout: PayoutHistory):
        """Add payout to historical data."""
        self.payout_history.append(payout)
        logger.debug(f"Added payout history: {payout.vulnerability_type} ${payout.payout_amount}")
    
    def get_trend_analysis(
        self,
        vulnerability_type: str,
        days: int = 90
    ) -> Dict[str, Any]:
        """
        Analyze payout trends over time.
        
        Args:
            vulnerability_type: Type of vulnerability
            days: Number of days to analyze
            
        Returns:
            Trend analysis results
        """
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        
        # Filter relevant payouts
        relevant_payouts = [
            p for p in self.payout_history
            if p.vulnerability_type.lower() == vulnerability_type.lower()
            and p.paid_at >= cutoff_date
        ]
        
        if not relevant_payouts:
            return {
                'vulnerability_type': vulnerability_type,
                'period_days': days,
                'sample_size': 0,
                'trend': 'insufficient_data'
            }
        
        # Sort by date
        relevant_payouts.sort(key=lambda p: p.paid_at)
        
        # Split into first half and second half
        mid_point = len(relevant_payouts) // 2
        first_half = relevant_payouts[:mid_point]
        second_half = relevant_payouts[mid_point:]
        
        # Calculate averages
        first_avg = statistics.mean([p.payout_amount for p in first_half])
        second_avg = statistics.mean([p.payout_amount for p in second_half])
        
        # Determine trend
        change_pct = ((second_avg - first_avg) / first_avg) * 100 if first_avg > 0 else 0
        
        if change_pct > 10:
            trend = 'increasing'
        elif change_pct < -10:
            trend = 'decreasing'
        else:
            trend = 'stable'
        
        return {
            'vulnerability_type': vulnerability_type,
            'period_days': days,
            'sample_size': len(relevant_payouts),
            'first_half_average': round(first_avg, 2),
            'second_half_average': round(second_avg, 2),
            'change_percent': round(change_pct, 2),
            'trend': trend
        }
    
    def get_competitive_position(
        self,
        payout_amount: float,
        vulnerability_type: str,
        severity_tier: SeverityTier
    ) -> Dict[str, Any]:
        """
        Determine competitive position of a payout amount.
        
        Args:
            payout_amount: Proposed payout amount
            vulnerability_type: Type of vulnerability
            severity_tier: Severity tier
            
        Returns:
            Competitive position analysis
        """
        market_rate = self.get_market_rate(vulnerability_type, severity_tier)
        
        if not market_rate:
            return {
                'position': 'unknown',
                'percentile': None,
                'recommendation': 'No market data available'
            }
        
        # Determine position
        if payout_amount >= market_rate.percentile_90:
            position = 'top_tier'
            percentile = 90
            recommendation = "Highly competitive - attracts top researchers"
        elif payout_amount >= market_rate.percentile_75:
            position = 'above_average'
            percentile = 75
            recommendation = "Above market average - competitive"
        elif payout_amount >= market_rate.median_payout:
            position = 'average'
            percentile = 50
            recommendation = "Market average - adequate"
        elif payout_amount >= market_rate.percentile_25:
            position = 'below_average'
            percentile = 25
            recommendation = "Below market average - may struggle to attract researchers"
        else:
            position = 'low'
            percentile = 10
            recommendation = "Significantly below market - unlikely to attract quality researchers"
        
        return {
            'position': position,
            'percentile': percentile,
            'market_median': market_rate.median_payout,
            'market_average': market_rate.average_payout,
            'difference_from_median': payout_amount - market_rate.median_payout,
            'difference_percent': ((payout_amount - market_rate.median_payout) / market_rate.median_payout * 100) if market_rate.median_payout > 0 else 0,
            'recommendation': recommendation
        }
    
    def get_all_market_rates(self) -> List[MarketRate]:
        """Get all available market rates."""
        rates = []
        
        for (vuln_type, severity_tier), benchmark in self.INDUSTRY_BENCHMARKS.items():
            rates.append(MarketRate(
                vulnerability_type=vuln_type,
                severity_tier=severity_tier,
                average_payout=benchmark['average'],
                median_payout=benchmark['median'],
                percentile_25=benchmark['p25'],
                percentile_75=benchmark['p75'],
                percentile_90=benchmark['p90'],
                sample_size=100,
                last_updated=datetime.utcnow(),
                source="industry_benchmarks"
            ))
        
        return rates

