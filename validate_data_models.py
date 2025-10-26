#!/usr/bin/env python3
"""
Validate data model consistency across the bountybot package.
"""

import sys
from dataclasses import is_dataclass, fields
from typing import get_type_hints

def test_core_models():
    """Test core data models."""
    print("Testing core models...")
    
    try:
        from bountybot.models import Report, ValidationResult, Severity
        
        # Check Report is a dataclass
        assert is_dataclass(Report), "Report should be a dataclass"
        print(f"✅ Report is a dataclass with {len(fields(Report))} fields")
        
        # Check ValidationResult is a dataclass
        assert is_dataclass(ValidationResult), "ValidationResult should be a dataclass"
        print(f"✅ ValidationResult is a dataclass with {len(fields(ValidationResult))} fields")
        
        # Test instantiation
        report = Report(title="Test SQL Injection")
        print(f"✅ Report instantiation works: {report.title}")
        
        from bountybot.models import Verdict
        result = ValidationResult(report=report, verdict=Verdict.VALID, confidence=95)
        print(f"✅ ValidationResult instantiation works: {result.verdict}")
        
        return True
    except Exception as e:
        print(f"❌ Core models error: {e}")
        return False

def test_ml_models():
    """Test ML data models."""
    print("\nTesting ML models...")
    
    try:
        from bountybot.ml.models import VulnerabilityPattern, PredictionResult
        
        assert is_dataclass(VulnerabilityPattern), "VulnerabilityPattern should be a dataclass"
        print(f"✅ VulnerabilityPattern is a dataclass with {len(fields(VulnerabilityPattern))} fields")
        
        assert is_dataclass(PredictionResult), "PredictionResult should be a dataclass"
        print(f"✅ PredictionResult is a dataclass with {len(fields(PredictionResult))} fields")
        
        return True
    except Exception as e:
        print(f"❌ ML models error: {e}")
        return False

def test_training_models():
    """Test training data models."""
    print("\nTesting training models...")
    
    try:
        from bountybot.ml.training.models import (
            TrainingDataset, TrainingExample, ModelVersion, TrainingExperiment
        )
        
        assert is_dataclass(TrainingDataset), "TrainingDataset should be a dataclass"
        print(f"✅ TrainingDataset is a dataclass with {len(fields(TrainingDataset))} fields")
        
        assert is_dataclass(TrainingExample), "TrainingExample should be a dataclass"
        print(f"✅ TrainingExample is a dataclass with {len(fields(TrainingExample))} fields")
        
        assert is_dataclass(ModelVersion), "ModelVersion should be a dataclass"
        print(f"✅ ModelVersion is a dataclass with {len(fields(ModelVersion))} fields")
        
        assert is_dataclass(TrainingExperiment), "TrainingExperiment should be a dataclass"
        print(f"✅ TrainingExperiment is a dataclass with {len(fields(TrainingExperiment))} fields")
        
        return True
    except Exception as e:
        print(f"❌ Training models error: {e}")
        return False

def test_collaboration_models():
    """Test collaboration data models."""
    print("\nTesting collaboration models...")
    
    try:
        from bountybot.collaboration.models import (
            WorkflowInstance, WorkflowTask, Comment, SLA
        )
        
        assert is_dataclass(WorkflowInstance), "WorkflowInstance should be a dataclass"
        print(f"✅ WorkflowInstance is a dataclass with {len(fields(WorkflowInstance))} fields")
        
        assert is_dataclass(WorkflowTask), "WorkflowTask should be a dataclass"
        print(f"✅ WorkflowTask is a dataclass with {len(fields(WorkflowTask))} fields")
        
        assert is_dataclass(Comment), "Comment should be a dataclass"
        print(f"✅ Comment is a dataclass with {len(fields(Comment))} fields")
        
        assert is_dataclass(SLA), "SLA should be a dataclass"
        print(f"✅ SLA is a dataclass with {len(fields(SLA))} fields")
        
        return True
    except Exception as e:
        print(f"❌ Collaboration models error: {e}")
        return False

def test_threat_intel_models():
    """Test threat intelligence data models."""
    print("\nTesting threat intelligence models...")
    
    try:
        from bountybot.threat_intel.models import (
            CVEData, ExploitData, ThreatFeed, ThreatIndicator
        )
        
        assert is_dataclass(CVEData), "CVEData should be a dataclass"
        print(f"✅ CVEData is a dataclass with {len(fields(CVEData))} fields")
        
        assert is_dataclass(ExploitData), "ExploitData should be a dataclass"
        print(f"✅ ExploitData is a dataclass with {len(fields(ExploitData))} fields")
        
        assert is_dataclass(ThreatFeed), "ThreatFeed should be a dataclass"
        print(f"✅ ThreatFeed is a dataclass with {len(fields(ThreatFeed))} fields")
        
        assert is_dataclass(ThreatIndicator), "ThreatIndicator should be a dataclass"
        print(f"✅ ThreatIndicator is a dataclass with {len(fields(ThreatIndicator))} fields")
        
        return True
    except Exception as e:
        print(f"❌ Threat intel models error: {e}")
        return False

def test_tenancy_models():
    """Test tenancy data models."""
    print("\nTesting tenancy models...")

    try:
        from bountybot.tenancy.models import Organization, UsageQuota, Subscription

        assert is_dataclass(Organization), "Organization should be a dataclass"
        print(f"✅ Organization is a dataclass with {len(fields(Organization))} fields")

        assert is_dataclass(UsageQuota), "UsageQuota should be a dataclass"
        print(f"✅ UsageQuota is a dataclass with {len(fields(UsageQuota))} fields")

        assert is_dataclass(Subscription), "Subscription should be a dataclass"
        print(f"✅ Subscription is a dataclass with {len(fields(Subscription))} fields")
        
        return True
    except Exception as e:
        print(f"❌ Tenancy models error: {e}")
        return False

def test_recommendations_models():
    """Test recommendations data models."""
    print("\nTesting recommendations models...")

    try:
        from bountybot.recommendations.models import (
            Recommendation, RecommendationFeedback, KnowledgeNode
        )

        assert is_dataclass(Recommendation), "Recommendation should be a dataclass"
        print(f"✅ Recommendation is a dataclass with {len(fields(Recommendation))} fields")

        assert is_dataclass(RecommendationFeedback), "RecommendationFeedback should be a dataclass"
        print(f"✅ RecommendationFeedback is a dataclass with {len(fields(RecommendationFeedback))} fields")
        
        assert is_dataclass(KnowledgeNode), "KnowledgeNode should be a dataclass"
        print(f"✅ KnowledgeNode is a dataclass with {len(fields(KnowledgeNode))} fields")
        
        return True
    except Exception as e:
        print(f"❌ Recommendations models error: {e}")
        return False

def test_reporting_models():
    """Test reporting data models."""
    print("\nTesting reporting models...")

    try:
        from bountybot.reporting.models import (
            ReportConfig, TrendData, ROIMetrics
        )

        assert is_dataclass(ReportConfig), "ReportConfig should be a dataclass"
        print(f"✅ ReportConfig is a dataclass with {len(fields(ReportConfig))} fields")
        
        assert is_dataclass(TrendData), "TrendData should be a dataclass"
        print(f"✅ TrendData is a dataclass with {len(fields(TrendData))} fields")
        
        assert is_dataclass(ROIMetrics), "ROIMetrics should be a dataclass"
        print(f"✅ ROIMetrics is a dataclass with {len(fields(ROIMetrics))} fields")
        
        return True
    except Exception as e:
        print(f"❌ Reporting models error: {e}")
        return False

def main():
    """Run all data model validation tests."""
    print("="*80)
    print("Data Model Consistency Validation")
    print("="*80)
    
    tests = [
        ("Core Models", test_core_models),
        ("ML Models", test_ml_models),
        ("Training Models", test_training_models),
        ("Collaboration Models", test_collaboration_models),
        ("Threat Intel Models", test_threat_intel_models),
        ("Tenancy Models", test_tenancy_models),
        ("Recommendations Models", test_recommendations_models),
        ("Reporting Models", test_reporting_models),
    ]
    
    results = {}
    for name, test_func in tests:
        try:
            results[name] = test_func()
        except Exception as e:
            print(f"\n❌ {name} test failed with exception: {e}")
            results[name] = False
    
    # Summary
    print("\n" + "="*80)
    print("SUMMARY")
    print("="*80)
    
    passed = sum(1 for v in results.values() if v)
    failed = len(results) - passed
    
    print(f"\nTotal test groups: {len(results)}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    
    if failed > 0:
        print(f"\nFailed test groups:")
        for name, success in results.items():
            if not success:
                print(f"  - {name}")
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())

