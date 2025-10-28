#!/usr/bin/env python3
"""
Validate all imports in the bountybot package.
"""

import sys
import importlib
from pathlib import Path

def test_import(module_name):
    """Test importing a module."""
    try:
        importlib.import_module(module_name)
        return True, None
    except Exception as e:
        return False, str(e)

def main():
    """Test all major module imports."""
    modules_to_test = [
        # Core modules
        "bountybot",
        "bountybot.ai_providers",
        "bountybot.orchestrator",
        "bountybot.validators",
        "bountybot.parsers",

        # Analysis features
        "bountybot.analysis",
        "bountybot.scanners",
        "bountybot.scoring",
        "bountybot.prioritization",

        # ML modules
        "bountybot.ml",
        "bountybot.ml.deep_learning",
        "bountybot.ml.transformers",
        "bountybot.ml.exploit_generation",
        "bountybot.ml.zero_day",
        "bountybot.ml.training",

        # Infrastructure
        "bountybot.api",
        "bountybot.database",
        "bountybot.cache",
        "bountybot.tasks",
        "bountybot.webhooks",
        "bountybot.websocket",

        # Security & Auth
        "bountybot.auth",
        "bountybot.secrets",
        "bountybot.compliance",
        "bountybot.audit",

        # Monitoring & Observability
        "bountybot.monitoring",
        "bountybot.autoscaling",

        # Analytics & Reporting
        "bountybot.analytics",
        "bountybot.reporting",
        "bountybot.dashboard",

        # Collaboration
        "bountybot.collaboration",
        "bountybot.continuous_validation",
        "bountybot.recommendations",

        # Tenancy
        "bountybot.tenancy",
        "bountybot.tenant_analytics",

        # Threat Intelligence
        "bountybot.threat_intel",

        # Utilities
        "bountybot.backup",
        "bountybot.integrations",
        "bountybot.generators",
        "bountybot.extractors",
        "bountybot.outputs",
        "bountybot.debug",
        "bountybot.dev_tools",
        "bountybot.logging",
        "bountybot.deduplication",
        "bountybot.remediation",
        "bountybot.knowledge",
        "bountybot.graphql",
    ]
    
    print(f"Testing {len(modules_to_test)} module imports...\n")
    
    results = {}
    for module in modules_to_test:
        success, error = test_import(module)
        results[module] = (success, error)
        
        if success:
            print(f"✅ {module}")
        else:
            print(f"❌ {module}")
            print(f"   Error: {error[:100]}")
    
    # Summary
    print(f"\n{'='*80}")
    print("SUMMARY")
    print('='*80)
    
    passed = sum(1 for success, _ in results.values() if success)
    failed = len(results) - passed
    
    print(f"\nTotal modules: {len(results)}")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    
    if failed > 0:
        print(f"\nFailed imports:")
        for module, (success, error) in results.items():
            if not success:
                print(f"  - {module}: {error[:80]}")
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())

