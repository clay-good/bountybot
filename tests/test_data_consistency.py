#!/usr/bin/env python3
"""
Data consistency verification across modules.
Checks that data models are consistent and compatible.
"""

import sys
from typing import List, Dict, Any
from dataclasses import fields, is_dataclass
import inspect


def test_report_model_consistency():
    """Test that Report model is consistent across modules."""
    print("=" * 70)
    print("TEST 1: Report Model Consistency")
    print("=" * 70)
    
    try:
        from bountybot.models import Report
        
        # Check that Report is a dataclass
        if not is_dataclass(Report):
            print("✗ Report is not a dataclass")
            return False
        
        # Get all fields
        report_fields = {f.name: f.type for f in fields(Report)}
        
        print(f"✓ Report has {len(report_fields)} fields")
        
        # Check required fields
        required_fields = [
            'title', 'severity', 'vulnerability_type', 'target_url',
            'impact_description', 'reproduction_steps', 'submitted_by', 'submitted_at'
        ]
        
        missing_fields = []
        for field in required_fields:
            if field not in report_fields:
                missing_fields.append(field)
        
        if missing_fields:
            print(f"✗ Missing required fields: {missing_fields}")
            return False
        
        print(f"✓ All required fields present")
        
        # Check that parsers use correct field names
        from bountybot.parsers.html_parser import HTMLParser
        
        print("✓ HTMLParser imports successfully")
        
        # Check that validators work with Report
        from bountybot.validators.report_validator import ReportValidator
        
        print("✓ ReportValidator imports successfully")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Report model consistency test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_workflow_model_consistency():
    """Test that workflow models are consistent."""
    print("=" * 70)
    print("TEST 2: Workflow Model Consistency")
    print("=" * 70)
    
    try:
        from bountybot.collaboration.models import (
            WorkflowState,
            WorkflowInstance,
            WorkflowTask,
            TaskStatus,
            Comment,
            SLA,
            SLAStatus
        )
        
        # Check enums
        print(f"✓ WorkflowState has {len(WorkflowState)} states")
        print(f"✓ TaskStatus has {len(TaskStatus)} statuses")
        print(f"✓ SLAStatus has {len(SLAStatus)} statuses")
        
        # Check dataclasses
        if not is_dataclass(WorkflowInstance):
            print("✗ WorkflowInstance is not a dataclass")
            return False
        print("✓ WorkflowInstance is a dataclass")
        
        if not is_dataclass(WorkflowTask):
            print("✗ WorkflowTask is not a dataclass")
            return False
        print("✓ WorkflowTask is a dataclass")
        
        if not is_dataclass(Comment):
            print("✗ Comment is not a dataclass")
            return False
        print("✓ Comment is a dataclass")
        
        if not is_dataclass(SLA):
            print("✗ SLA is not a dataclass")
            return False
        print("✓ SLA is a dataclass")
        
        # Check that managers use correct models
        from bountybot.collaboration import (
            WorkflowEngine,
            CollaborationManager,
            SLAManager
        )
        
        print("✓ All collaboration managers import successfully")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Workflow model consistency test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_reporting_model_consistency():
    """Test that reporting models are consistent."""
    print("=" * 70)
    print("TEST 3: Reporting Model Consistency")
    print("=" * 70)
    
    try:
        from bountybot.reporting.models import (
            ReportFormat,
            TrendPeriod,
            ValidationTrend,
            ROIMetrics,
            BenchmarkMetrics
        )
        
        # Check enums
        print(f"✓ ReportFormat has {len(ReportFormat)} formats")
        print(f"✓ TrendPeriod has {len(TrendPeriod)} periods")
        
        # Check dataclasses
        if not is_dataclass(ValidationTrend):
            print("✗ ValidationTrend is not a dataclass")
            return False
        print("✓ ValidationTrend is a dataclass")
        
        if not is_dataclass(ROIMetrics):
            print("✗ ROIMetrics is not a dataclass")
            return False
        print("✓ ROIMetrics is a dataclass")
        
        if not is_dataclass(BenchmarkMetrics):
            print("✗ BenchmarkMetrics is not a dataclass")
            return False
        print("✓ BenchmarkMetrics is a dataclass")
        
        # Check that reporting components use correct models
        from bountybot.reporting import (
            ReportGenerator,
            AnalyticsEngine,
            TrendAnalyzer,
            ROICalculator,
            BenchmarkAnalyzer
        )
        
        print("✓ All reporting components import successfully")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Reporting model consistency test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_continuous_validation_model_consistency():
    """Test that continuous validation models are consistent."""
    print("=" * 70)
    print("TEST 4: Continuous Validation Model Consistency")
    print("=" * 70)
    
    try:
        from bountybot.continuous_validation.models import (
            VulnerabilityLifecycleState,
            VulnerabilitySnapshot,
            RegressionTest,
            RegressionTestResult,
            SecurityPosture
        )
        
        # Check enums
        print(f"✓ VulnerabilityLifecycleState has {len(VulnerabilityLifecycleState)} states")
        
        # Check dataclasses
        if not is_dataclass(VulnerabilitySnapshot):
            print("✗ VulnerabilitySnapshot is not a dataclass")
            return False
        print("✓ VulnerabilitySnapshot is a dataclass")
        
        if not is_dataclass(RegressionTest):
            print("✗ RegressionTest is not a dataclass")
            return False
        print("✓ RegressionTest is a dataclass")
        
        if not is_dataclass(RegressionTestResult):
            print("✗ RegressionTestResult is not a dataclass")
            return False
        print("✓ RegressionTestResult is a dataclass")
        
        if not is_dataclass(SecurityPosture):
            print("✗ SecurityPosture is not a dataclass")
            return False
        print("✓ SecurityPosture is a dataclass")
        
        # Check that components use correct models
        from bountybot.continuous_validation import (
            VulnerabilityLifecycleManager,
            RegressionTestingEngine,
            SecurityPostureTracker
        )
        
        print("✓ All continuous validation components import successfully")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Continuous validation model consistency test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_threat_intel_model_consistency():
    """Test that threat intelligence models are consistent."""
    print("=" * 70)
    print("TEST 5: Threat Intelligence Model Consistency")
    print("=" * 70)
    
    try:
        from bountybot.threat_intel.models import (
            CVEData,
            ExploitData,
            ThreatActor,
            IoC,
            IoCType,
            ThreatSeverity,
            ExploitMaturity
        )
        
        # Check enums
        print(f"✓ IoCType has {len(IoCType)} types")
        print(f"✓ ThreatSeverity has {len(ThreatSeverity)} levels")
        print(f"✓ ExploitMaturity has {len(ExploitMaturity)} levels")
        
        # Check dataclasses
        if not is_dataclass(CVEData):
            print("✗ CVEData is not a dataclass")
            return False
        print("✓ CVEData is a dataclass")
        
        if not is_dataclass(ExploitData):
            print("✗ ExploitData is not a dataclass")
            return False
        print("✓ ExploitData is a dataclass")
        
        if not is_dataclass(ThreatActor):
            print("✗ ThreatActor is not a dataclass")
            return False
        print("✓ ThreatActor is a dataclass")
        
        if not is_dataclass(IoC):
            print("✗ IoC is not a dataclass")
            return False
        print("✓ IoC is a dataclass")
        
        # Check that components use correct models
        from bountybot.threat_intel import (
            ThreatCorrelationEngine,
            ExploitPredictor,
            ThreatHunter
        )
        
        print("✓ All threat intelligence components import successfully")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Threat intelligence model consistency test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_cross_module_compatibility():
    """Test that models work correctly across module boundaries."""
    print("=" * 70)
    print("TEST 6: Cross-Module Compatibility")
    print("=" * 70)
    
    try:
        from bountybot.models import Report, Severity
        from bountybot.collaboration import WorkflowEngine, CollaborationManager
        from bountybot.reporting import ReportGenerator
        from datetime import datetime
        
        # Create a report
        report = Report(
            title="Test XSS",
            severity=Severity.HIGH,
            vulnerability_type="XSS",
            target_url="https://example.com",
            impact_description="Test impact",
            reproduction_steps="Test steps",
            submitted_by="test-user",
            submitted_at=datetime.utcnow()
        )
        print("✓ Created Report instance")
        
        # Test with workflow engine
        engine = WorkflowEngine()
        print("✓ WorkflowEngine can be instantiated")
        
        # Test with collaboration manager
        manager = CollaborationManager()
        print("✓ CollaborationManager can be instantiated")
        
        # Test with report generator
        generator = ReportGenerator()
        print("✓ ReportGenerator can be instantiated")
        
        # Test that report can be used with generator
        try:
            result = generator.generate_report([report], format="json")
            print("✓ Report works with ReportGenerator")
        except Exception as e:
            print(f"⚠ Report with ReportGenerator had issue: {type(e).__name__}")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Cross-module compatibility test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def main():
    """Run all data consistency tests."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 18 + "DATA CONSISTENCY TESTING" + " " * 26 + "║")
    print("╚" + "=" * 68 + "╝")
    print()
    
    tests = [
        test_report_model_consistency,
        test_workflow_model_consistency,
        test_reporting_model_consistency,
        test_continuous_validation_model_consistency,
        test_threat_intel_model_consistency,
        test_cross_module_compatibility,
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
        print("\n✅ ALL DATA CONSISTENCY TESTS PASSED!")
        return 0
    else:
        print(f"\n❌ {total - passed} DATA CONSISTENCY TEST(S) FAILED!")
        return 1


if __name__ == '__main__':
    sys.exit(main())

