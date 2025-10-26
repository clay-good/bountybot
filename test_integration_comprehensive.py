#!/usr/bin/env python3
"""
Comprehensive integration test to verify all major modules work together.
"""

import sys
from pathlib import Path

def test_core_imports():
    """Test that all core modules can be imported."""
    print("=" * 70)
    print("TEST 1: Core Module Imports")
    print("=" * 70)
    
    modules = [
        'bountybot.orchestrator',
        'bountybot.async_orchestrator',
        'bountybot.models',
        'bountybot.config_loader',
    ]
    
    for module in modules:
        try:
            __import__(module)
            print(f"✓ {module}")
        except Exception as e:
            print(f"✗ {module}: {e}")
            return False
    
    print()
    return True


def test_ai_providers():
    """Test AI provider integration."""
    print("=" * 70)
    print("TEST 2: AI Provider Integration")
    print("=" * 70)

    try:
        from bountybot.ai_providers import AnthropicProvider, OpenAIProvider, GeminiProvider
        from bountybot.ai_providers.async_anthropic_provider import AsyncAnthropicProvider

        # Test provider initialization (providers require config dict)
        test_config = {
            'api_key': 'test-key',
            'model': 'claude-3-5-sonnet-20241022',
            'max_tokens': 4096
        }

        anthropic = AnthropicProvider(config=test_config)
        print(f"✓ AnthropicProvider initialized")

        openai = OpenAIProvider(config=test_config)
        print(f"✓ OpenAIProvider initialized")

        gemini = GeminiProvider(config=test_config)
        print(f"✓ GeminiProvider initialized")

        async_anthropic = AsyncAnthropicProvider(config=test_config)
        print(f"✓ AsyncAnthropicProvider initialized")

        print()
        return True
    except Exception as e:
        print(f"✗ AI Provider test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_collaboration_workflow():
    """Test collaboration and workflow integration."""
    print("=" * 70)
    print("TEST 3: Collaboration & Workflow Integration")
    print("=" * 70)

    try:
        from bountybot.collaboration import (
            WorkflowEngine,
            CollaborationManager,
            ActivityFeedManager,
            SLAManager,
            EscalationEngine
        )

        # Test workflow engine
        engine = WorkflowEngine()
        print(f"✓ WorkflowEngine initialized")

        # Test collaboration manager
        collab = CollaborationManager()
        print(f"✓ CollaborationManager initialized")

        # Test activity feed
        activity = ActivityFeedManager()
        print(f"✓ ActivityFeedManager initialized")

        # Test SLA manager
        sla = SLAManager()
        print(f"✓ SLAManager initialized")

        # Test escalation engine (requires sla_manager parameter)
        escalation = EscalationEngine(sla_manager=sla)
        print(f"✓ EscalationEngine initialized")

        print()
        return True
    except Exception as e:
        print(f"✗ Collaboration test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_reporting_analytics():
    """Test reporting and analytics integration."""
    print("=" * 70)
    print("TEST 4: Reporting & Analytics Integration")
    print("=" * 70)
    
    try:
        from bountybot.reporting import (
            ReportGenerator,
            AnalyticsEngine,
            DashboardManager,
            TrendAnalyzer,
            ROICalculator,
            BenchmarkAnalyzer
        )
        
        # Test report generator
        generator = ReportGenerator()
        print(f"✓ ReportGenerator initialized")
        
        # Test analytics engine
        analytics = AnalyticsEngine()
        print(f"✓ AnalyticsEngine initialized")
        
        # Test dashboard manager
        dashboard = DashboardManager()
        print(f"✓ DashboardManager initialized")
        
        # Test trend analyzer
        trend = TrendAnalyzer()
        print(f"✓ TrendAnalyzer initialized")
        
        # Test ROI calculator
        roi = ROICalculator()
        print(f"✓ ROICalculator initialized")
        
        # Test benchmark analyzer
        benchmark = BenchmarkAnalyzer()
        print(f"✓ BenchmarkAnalyzer initialized")
        
        print()
        return True
    except Exception as e:
        print(f"✗ Reporting test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_continuous_validation():
    """Test continuous validation integration."""
    print("=" * 70)
    print("TEST 5: Continuous Validation Integration")
    print("=" * 70)

    try:
        from bountybot.continuous_validation import (
            VulnerabilityLifecycleManager,
            RegressionTestingEngine,
            SecurityPostureTracker,
            ContinuousValidationScheduler
        )

        # Test lifecycle manager
        lifecycle = VulnerabilityLifecycleManager()
        print(f"✓ VulnerabilityLifecycleManager initialized")

        # Test regression engine
        regression = RegressionTestingEngine()
        print(f"✓ RegressionTestingEngine initialized")

        # Test posture tracker
        posture = SecurityPostureTracker()
        print(f"✓ SecurityPostureTracker initialized")

        # Test scheduler (requires regression_engine parameter)
        scheduler = ContinuousValidationScheduler(regression_engine=regression)
        print(f"✓ ContinuousValidationScheduler initialized")

        print()
        return True
    except Exception as e:
        print(f"✗ Continuous validation test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_threat_intelligence():
    """Test threat intelligence integration."""
    print("=" * 70)
    print("TEST 6: Threat Intelligence Integration")
    print("=" * 70)

    try:
        from bountybot.threat_intel import (
            ThreatCorrelationEngine,
            ExploitPredictor,
            ThreatHunter,
            ThreatIntelligenceEnrichmentPipeline  # Correct name
        )

        # Test correlation engine
        correlation = ThreatCorrelationEngine()
        print(f"✓ ThreatCorrelationEngine initialized")

        # Test exploit predictor
        predictor = ExploitPredictor()
        print(f"✓ ExploitPredictor initialized")

        # Test threat hunter
        hunter = ThreatHunter()
        print(f"✓ ThreatHunter initialized")

        # Test enrichment pipeline
        enrichment = ThreatIntelligenceEnrichmentPipeline()
        print(f"✓ ThreatIntelligenceEnrichmentPipeline initialized")

        print()
        return True
    except Exception as e:
        print(f"✗ Threat intelligence test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_autoscaling():
    """Test autoscaling integration."""
    print("=" * 70)
    print("TEST 7: Autoscaling Integration")
    print("=" * 70)

    try:
        from bountybot.autoscaling import (
            WorkloadPredictor,
            ScalingEngine,
            CostOptimizer,
            AutoScalingMetricsCollector  # Correct name
        )

        # Test workload predictor
        predictor = WorkloadPredictor()
        print(f"✓ WorkloadPredictor initialized")

        # Test scaling engine (requires config)
        scaling_config = {
            'min_workers': 1,
            'max_workers': 10,
            'target_queue_depth': 100,
            'scale_up_threshold': 0.8,
            'scale_down_threshold': 0.3
        }
        engine = ScalingEngine(config=scaling_config)
        print(f"✓ ScalingEngine initialized")

        # Test cost optimizer (requires config)
        cost_config = {
            'hourly_budget': 10.0,
            'daily_budget': 200.0,
            'monthly_budget': 5000.0,
            'cost_per_worker_hour': 2.0
        }
        optimizer = CostOptimizer(config=cost_config)
        print(f"✓ CostOptimizer initialized")

        # Test metrics collector
        collector = AutoScalingMetricsCollector()
        print(f"✓ AutoScalingMetricsCollector initialized")

        print()
        return True
    except Exception as e:
        print(f"✗ Autoscaling test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def main():
    """Run all integration tests."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 15 + "COMPREHENSIVE INTEGRATION TEST" + " " * 23 + "║")
    print("╚" + "=" * 68 + "╝")
    print()
    
    tests = [
        test_core_imports,
        test_ai_providers,
        test_collaboration_workflow,
        test_reporting_analytics,
        test_continuous_validation,
        test_threat_intelligence,
        test_autoscaling,
    ]
    
    results = []
    for test in tests:
        results.append(test())
    
    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    passed = sum(results)
    total = len(results)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("\n✅ ALL INTEGRATION TESTS PASSED!")
        return 0
    else:
        print(f"\n❌ {total - passed} INTEGRATION TEST(S) FAILED!")
        return 1


if __name__ == '__main__':
    sys.exit(main())

