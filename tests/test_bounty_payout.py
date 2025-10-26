"""
Tests for bounty payout system.
"""

import pytest
from datetime import datetime
from bountybot.bounty_payout import (
    PayoutEngine,
    MarketRateAnalyzer,
    BudgetOptimizer,
    PayoutRecommendation,
    SeverityTier,
    PayoutStrategy,
    BudgetConstraints,
    PayoutHistory,
)


class MockValidationResult:
    """Mock validation result for testing."""
    def __init__(self, cvss_score=7.5, vulnerability_type="sql_injection"):
        self.cvss_score = MockCVSS(cvss_score)
        self.report = MockReport(vulnerability_type)
        self.priority_score = MockPriorityScore()


class MockCVSS:
    """Mock CVSS score."""
    def __init__(self, score):
        self.base_score = score


class MockReport:
    """Mock report."""
    def __init__(self, vulnerability_type):
        self.vulnerability_type = vulnerability_type


class MockPriorityScore:
    """Mock priority score."""
    def __init__(self):
        self.business_impact_score = 70


class MockResearcherReputation:
    """Mock researcher reputation."""
    def __init__(self, score=75.0, trust_level='trusted'):
        self.reputation_score = MockReputationScore(score)
        self.trust_level = MockTrustLevel(trust_level)
        self.total_reports = 15


class MockReputationScore:
    """Mock reputation score."""
    def __init__(self, overall):
        self.overall = overall


class MockTrustLevel:
    """Mock trust level."""
    def __init__(self, value):
        self.value = value


class TestPayoutEngine:
    """Test payout engine."""
    
    def test_calculate_payout_basic(self):
        """Test basic payout calculation."""
        engine = PayoutEngine()
        result = MockValidationResult(cvss_score=7.5, vulnerability_type="sql_injection")
        
        recommendation = engine.calculate_payout(result)
        
        assert recommendation.recommended_amount > 0
        assert recommendation.min_amount < recommendation.recommended_amount < recommendation.max_amount
        assert recommendation.severity_tier == SeverityTier.HIGH
        assert recommendation.confidence > 0
    
    def test_payout_critical_severity(self):
        """Test payout for critical severity."""
        engine = PayoutEngine()
        result = MockValidationResult(cvss_score=9.5, vulnerability_type="rce")
        
        recommendation = engine.calculate_payout(result)
        
        assert recommendation.severity_tier == SeverityTier.CRITICAL
        assert recommendation.recommended_amount >= 5000  # Critical minimum
    
    def test_payout_with_reputation_bonus(self):
        """Test payout with researcher reputation bonus."""
        engine = PayoutEngine()
        result = MockValidationResult(cvss_score=7.5)
        reputation = MockResearcherReputation(score=90.0, trust_level='elite')
        
        recommendation = engine.calculate_payout(result, researcher_reputation=reputation)
        
        # Elite researchers should get premium
        assert recommendation.researcher_reputation_score == 90.0
        # Should have reputation multiplier applied
        assert 'reputation' in recommendation.reasoning.lower() or 'elite' in recommendation.reasoning.lower()
    
    def test_payout_strategies(self):
        """Test different payout strategies."""
        engine = PayoutEngine()
        result = MockValidationResult(cvss_score=7.5)
        
        # Conservative strategy
        conservative = engine.calculate_payout(result, strategy=PayoutStrategy.CONSERVATIVE)
        
        # Competitive strategy
        competitive = engine.calculate_payout(result, strategy=PayoutStrategy.COMPETITIVE)
        
        # Premium strategy
        premium = engine.calculate_payout(result, strategy=PayoutStrategy.PREMIUM)
        
        # Premium should be highest
        assert premium.recommended_amount > competitive.recommended_amount
        assert competitive.recommended_amount > conservative.recommended_amount
    
    def test_payout_with_budget_constraints(self):
        """Test payout with budget constraints."""
        engine = PayoutEngine()
        result = MockValidationResult(cvss_score=7.5)
        
        # Tight budget constraints
        constraints = BudgetConstraints(
            total_budget=10000,
            spent_to_date=8000,
            remaining_budget=2000,
            monthly_budget=5000,
            monthly_spent=4000,
            max_single_payout=1500,
            budget_warning=True
        )
        
        recommendation = engine.calculate_payout(result, budget_constraints=constraints)
        
        # Should respect max single payout
        assert recommendation.recommended_amount <= constraints.max_single_payout


class TestMarketRateAnalyzer:
    """Test market rate analyzer."""
    
    def test_get_market_rate_sql_injection(self):
        """Test getting market rate for SQL injection."""
        analyzer = MarketRateAnalyzer()
        
        rate = analyzer.get_market_rate("sql_injection", SeverityTier.HIGH)
        
        assert rate is not None
        assert rate.median_payout > 0
        assert rate.average_payout > 0
        assert rate.percentile_75 > rate.median_payout
    
    def test_get_market_rate_rce(self):
        """Test getting market rate for RCE."""
        analyzer = MarketRateAnalyzer()
        
        rate = analyzer.get_market_rate("rce", SeverityTier.CRITICAL)
        
        assert rate is not None
        # RCE should have high payouts
        assert rate.median_payout >= 15000
    
    def test_get_market_rate_unknown(self):
        """Test getting market rate for unknown vulnerability."""
        analyzer = MarketRateAnalyzer()
        
        rate = analyzer.get_market_rate("unknown_vuln", SeverityTier.MEDIUM)
        
        # Should return None for unknown types
        assert rate is None
    
    def test_competitive_position_top_tier(self):
        """Test competitive position analysis - top tier."""
        analyzer = MarketRateAnalyzer()
        
        position = analyzer.get_competitive_position(
            payout_amount=15000,
            vulnerability_type="sql_injection",
            severity_tier=SeverityTier.HIGH
        )
        
        assert position['position'] in ['top_tier', 'above_average']
        assert position['percentile'] >= 75
    
    def test_competitive_position_below_average(self):
        """Test competitive position analysis - below average."""
        analyzer = MarketRateAnalyzer()
        
        position = analyzer.get_competitive_position(
            payout_amount=1000,
            vulnerability_type="sql_injection",
            severity_tier=SeverityTier.HIGH
        )
        
        assert position['position'] in ['below_average', 'low']
        assert 'below' in position['recommendation'].lower()
    
    def test_add_payout_history(self):
        """Test adding payout history."""
        analyzer = MarketRateAnalyzer()
        
        payout = PayoutHistory(
            report_id="report-1",
            researcher_id="researcher-1",
            vulnerability_type="xss",
            severity_tier=SeverityTier.MEDIUM,
            cvss_score=5.5,
            payout_amount=1000,
            paid_at=datetime.utcnow()
        )
        
        analyzer.add_payout_history(payout)
        
        assert len(analyzer.payout_history) == 1


class TestBudgetOptimizer:
    """Test budget optimizer."""
    
    def test_optimize_payout_within_budget(self):
        """Test optimizing payout within budget."""
        optimizer = BudgetOptimizer()
        
        constraints = BudgetConstraints(
            total_budget=100000,
            spent_to_date=50000,
            remaining_budget=50000,
            monthly_budget=20000,
            monthly_spent=10000,
            max_single_payout=10000
        )
        
        optimized, adjustment = optimizer.optimize_payout(5000, constraints)
        
        # Should not need adjustment
        assert optimized == 5000
        assert adjustment == 0
    
    def test_optimize_payout_exceeds_max(self):
        """Test optimizing payout that exceeds max single payout."""
        optimizer = BudgetOptimizer()
        
        constraints = BudgetConstraints(
            total_budget=100000,
            spent_to_date=50000,
            remaining_budget=50000,
            monthly_budget=20000,
            monthly_spent=10000,
            max_single_payout=5000
        )
        
        optimized, adjustment = optimizer.optimize_payout(8000, constraints)
        
        # Should be capped at max
        assert optimized == 5000
        assert adjustment < 0
    
    def test_optimize_payout_exceeds_remaining(self):
        """Test optimizing payout that exceeds remaining budget."""
        optimizer = BudgetOptimizer()
        
        constraints = BudgetConstraints(
            total_budget=100000,
            spent_to_date=98000,
            remaining_budget=2000,
            monthly_budget=20000,
            monthly_spent=10000
        )
        
        optimized, adjustment = optimizer.optimize_payout(5000, constraints)
        
        # Should be reduced to remaining budget
        assert optimized == 2000
        assert adjustment < 0
    
    def test_analyze_budget_health_critical(self):
        """Test budget health analysis - critical."""
        optimizer = BudgetOptimizer()
        
        constraints = BudgetConstraints(
            total_budget=100000,
            spent_to_date=95000,
            remaining_budget=5000,
            monthly_budget=20000,
            monthly_spent=18000,
            budget_critical=True
        )
        
        health = optimizer.analyze_budget_health(constraints)
        
        assert health['health_status'] == 'critical'
        assert health['total_utilization_percent'] >= 90
        assert len(health['recommendations']) > 0
    
    def test_analyze_budget_health_healthy(self):
        """Test budget health analysis - healthy."""
        optimizer = BudgetOptimizer()
        
        constraints = BudgetConstraints(
            total_budget=100000,
            spent_to_date=40000,
            remaining_budget=60000,
            monthly_budget=20000,
            monthly_spent=8000
        )
        
        health = optimizer.analyze_budget_health(constraints)
        
        assert health['health_status'] in ['healthy', 'excellent']
        assert health['total_utilization_percent'] < 75
    
    def test_forecast_budget(self):
        """Test budget forecasting."""
        optimizer = BudgetOptimizer()
        
        constraints = BudgetConstraints(
            total_budget=100000,
            spent_to_date=50000,
            remaining_budget=50000,
            monthly_budget=20000,
            monthly_spent=15000
        )
        
        forecast = optimizer.forecast_budget(constraints, months_ahead=3)
        
        assert 'monthly_burn_rate' in forecast
        assert len(forecast['forecast']) == 3
        assert 'recommendation' in forecast


class TestPayoutIntegration:
    """Integration tests for payout system."""
    
    def test_end_to_end_payout_calculation(self):
        """Test end-to-end payout calculation."""
        engine = PayoutEngine()
        
        # High severity SQL injection from elite researcher
        result = MockValidationResult(cvss_score=8.5, vulnerability_type="sql_injection")
        reputation = MockResearcherReputation(score=92.0, trust_level='elite')
        
        recommendation = engine.calculate_payout(
            result,
            researcher_reputation=reputation,
            strategy=PayoutStrategy.COMPETITIVE
        )
        
        # Verify all components
        assert recommendation.recommended_amount > 0
        assert recommendation.severity_tier == SeverityTier.HIGH
        assert recommendation.justification is not None
        assert recommendation.market_comparison is not None
        assert recommendation.confidence > 0.7
        
        # Verify justification has all multipliers
        assert recommendation.justification.severity_multiplier > 0
        assert recommendation.justification.reputation_multiplier > 1.0  # Elite bonus
        
        # Verify reasoning is present
        assert len(recommendation.reasoning) > 0

