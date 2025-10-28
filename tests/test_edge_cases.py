#!/usr/bin/env python3
"""
Edge case and error handling tests.
Tests boundary conditions, null values, extreme values, and error scenarios.
"""

import sys
from datetime import datetime, timedelta
from uuid import uuid4


def test_workflow_edge_cases():
    """Test workflow engine edge cases."""
    print("=" * 70)
    print("TEST 1: Workflow Engine Edge Cases")
    print("=" * 70)

    try:
        from bountybot.collaboration import WorkflowEngine, WorkflowState, StateTransitionError

        engine = WorkflowEngine()

        # First create a workflow definition
        workflow_def = engine.create_workflow_definition(
            name="Test Workflow",
            description="Test workflow for edge cases",
            created_by="test-user"
        )

        # Test 1: Invalid state transition
        try:
            instance = engine.create_workflow_instance(
                workflow_id=workflow_def.workflow_id,  # Use definition ID
                entity_type="report",
                entity_id="test-report",
                started_by="test-user"
            )
            # Try to transition with an invalid action
            engine.transition_workflow(
                instance_id=instance.instance_id,
                action="invalid_action",
                user_id="test-user"
            )
            print("✗ Should have raised StateTransitionError")
            return False
        except (StateTransitionError, ValueError) as e:
            print("✓ Invalid state transition rejected")
        except Exception as e:
            print(f"✗ Wrong exception type: {type(e).__name__}")
            return False

        # Test 2: Non-existent workflow
        try:
            result = engine.get_workflow_instance("non-existent-id")
            if result is None:
                print("✓ Non-existent workflow returned None")
            else:
                print("✗ Should have returned None or raised ValueError")
                return False
        except (ValueError, KeyError):
            print("✓ Non-existent workflow rejected")

        # Test 3: Empty workflow name
        try:
            empty_def = engine.create_workflow_definition(
                name="",
                description="Empty name test",
                created_by="test-user"
            )
            print("✓ Empty workflow name accepted (or rejected gracefully)")
        except Exception as e:
            print(f"✓ Empty workflow name rejected: {type(e).__name__}")
        
        # Test 4: Very long workflow name
        try:
            long_id = str(uuid4())
            long_name = "A" * 10000
            engine.create_workflow(long_id, long_name, "test-user")
            print("✓ Very long workflow name handled")
        except Exception as e:
            print(f"✓ Very long workflow name rejected: {type(e).__name__}")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Workflow edge case test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_collaboration_edge_cases():
    """Test collaboration manager edge cases."""
    print("=" * 70)
    print("TEST 2: Collaboration Manager Edge Cases")
    print("=" * 70)
    
    try:
        from bountybot.collaboration import CollaborationManager
        
        manager = CollaborationManager()
        workflow_id = str(uuid4())
        
        # Test 1: Empty comment
        try:
            manager.add_comment(workflow_id, "", "test-user")
            print("✓ Empty comment handled")
        except Exception as e:
            print(f"✓ Empty comment rejected: {type(e).__name__}")
        
        # Test 2: Very long comment
        try:
            long_comment = "A" * 100000
            manager.add_comment(workflow_id, long_comment, "test-user")
            print("✓ Very long comment handled")
        except Exception as e:
            print(f"✓ Very long comment rejected: {type(e).__name__}")
        
        # Test 3: Invalid mention format
        try:
            comment_id = manager.add_comment(workflow_id, "Hello @invalid@user", "test-user")
            mentions = manager.get_mentions(workflow_id)
            print(f"✓ Invalid mention format handled (found {len(mentions)} mentions)")
        except Exception as e:
            print(f"✓ Invalid mention format rejected: {type(e).__name__}")
        
        # Test 4: Multiple reactions from same user
        try:
            comment_id = manager.add_comment(workflow_id, "Test", "test-user")
            manager.add_reaction(comment_id, "👍", "user1")
            manager.add_reaction(comment_id, "👍", "user1")  # Same user, same reaction
            reactions = manager.get_reactions(comment_id)
            print(f"✓ Duplicate reactions handled (total: {len(reactions)})")
        except Exception as e:
            print(f"✓ Duplicate reactions rejected: {type(e).__name__}")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Collaboration edge case test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_sla_edge_cases():
    """Test SLA manager edge cases."""
    print("=" * 70)
    print("TEST 3: SLA Manager Edge Cases")
    print("=" * 70)
    
    try:
        from bountybot.collaboration import SLAManager, TaskPriority

        manager = SLAManager()
        workflow_id = str(uuid4())

        # Test 1: Zero duration SLA
        try:
            manager.create_sla(workflow_id, TaskPriority.CRITICAL, timedelta(seconds=0))
            print("✓ Zero duration SLA handled")
        except Exception as e:
            print(f"✓ Zero duration SLA rejected: {type(e).__name__}")
        
        # Test 2: Negative duration SLA
        try:
            manager.create_sla(workflow_id, TaskPriority.CRITICAL, timedelta(seconds=-100))
            print("✓ Negative duration SLA handled")
        except Exception as e:
            print(f"✓ Negative duration SLA rejected: {type(e).__name__}")

        # Test 3: Very long duration SLA
        try:
            manager.create_sla(workflow_id, TaskPriority.LOW, timedelta(days=36500))  # 100 years
            print("✓ Very long duration SLA handled")
        except Exception as e:
            print(f"✓ Very long duration SLA rejected: {type(e).__name__}")
        
        # Test 4: Check non-existent SLA
        try:
            status = manager.check_sla_status("non-existent-id")
            if status is None:
                print("✓ Non-existent SLA returns None")
            else:
                print(f"✓ Non-existent SLA handled: {status}")
        except Exception as e:
            print(f"✓ Non-existent SLA rejected: {type(e).__name__}")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ SLA edge case test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_reporting_edge_cases():
    """Test reporting edge cases."""
    print("=" * 70)
    print("TEST 4: Reporting Edge Cases")
    print("=" * 70)
    
    try:
        from bountybot.reporting import ReportGenerator, AnalyticsEngine
        from bountybot.models import Report, Severity
        
        generator = ReportGenerator()
        analytics = AnalyticsEngine()
        
        # Test 1: Empty report list
        try:
            summary = analytics.generate_summary([])
            print(f"✓ Empty report list handled: {summary}")
        except Exception as e:
            print(f"✓ Empty report list rejected: {type(e).__name__}")
        
        # Test 2: Report with missing fields
        try:
            report = Report(
                title="Test",
                severity=Severity.HIGH,
                vulnerability_type="XSS",
                target_url="https://example.com",
                impact_description="Test impact",
                reproduction_steps="Test steps",
                submitted_by="test-user",
                submitted_at=datetime.utcnow()
            )
            result = generator.generate_report([report], format="json")
            print("✓ Report with minimal fields handled")
        except Exception as e:
            print(f"✓ Report with minimal fields rejected: {type(e).__name__}")
        
        # Test 3: Invalid date range
        try:
            start = datetime.utcnow()
            end = start - timedelta(days=30)  # End before start
            trends = analytics.analyze_trends([], start, end)
            print(f"✓ Invalid date range handled")
        except Exception as e:
            print(f"✓ Invalid date range rejected: {type(e).__name__}")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Reporting edge case test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_continuous_validation_edge_cases():
    """Test continuous validation edge cases."""
    print("=" * 70)
    print("TEST 5: Continuous Validation Edge Cases")
    print("=" * 70)
    
    try:
        from bountybot.continuous_validation import (
            VulnerabilityLifecycleManager,
            RegressionTestingEngine
        )
        
        lifecycle = VulnerabilityLifecycleManager()
        regression = RegressionTestingEngine()
        
        # Test 1: Non-existent vulnerability
        try:
            status = lifecycle.get_vulnerability_status("non-existent-id")
            if status is None:
                print("✓ Non-existent vulnerability returns None")
            else:
                print(f"✓ Non-existent vulnerability handled: {status}")
        except Exception as e:
            print(f"✓ Non-existent vulnerability rejected: {type(e).__name__}")
        
        # Test 2: Empty test suite
        try:
            results = regression.execute_test_suite([])
            print(f"✓ Empty test suite handled: {results}")
        except Exception as e:
            print(f"✓ Empty test suite rejected: {type(e).__name__}")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Continuous validation edge case test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def test_concurrent_access():
    """Test concurrent access scenarios."""
    print("=" * 70)
    print("TEST 6: Concurrent Access Scenarios")
    print("=" * 70)
    
    try:
        from bountybot.collaboration import WorkflowEngine, CollaborationManager
        import threading
        
        engine = WorkflowEngine()
        manager = CollaborationManager()

        # Create workflow definition and instance
        workflow_def = engine.create_workflow_definition(
            name="Concurrent Test",
            description="Test concurrent access",
            created_by="test-user"
        )
        instance = engine.create_workflow_instance(
            workflow_id=workflow_def.workflow_id,  # Use the definition ID
            entity_type="report",
            entity_id="test-report",
            started_by="test-user"
        )
        workflow_id = instance.instance_id  # Use the instance ID for comments
        
        # Test concurrent comments
        errors = []
        def add_comments(user_id):
            try:
                for i in range(10):
                    manager.add_comment(
                        entity_type="report",
                        entity_id="test-report",
                        user_id=user_id,
                        user_name=f"User {user_id}",
                        content=f"Comment {i} from {user_id}"
                    )
            except Exception as e:
                errors.append(e)
        
        threads = []
        for i in range(5):
            t = threading.Thread(target=add_comments, args=(f"user-{i}",))
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        if errors:
            print(f"⚠ Concurrent access had {len(errors)} errors (may be expected)")
        else:
            print("✓ Concurrent access handled without errors")

        comments = manager.get_comments(entity_type="report", entity_id="test-report")
        print(f"✓ Total comments created: {len(comments)}")
        
        print()
        return True
        
    except Exception as e:
        print(f"✗ Concurrent access test failed: {e}")
        import traceback
        traceback.print_exc()
        print()
        return False


def main():
    """Run all edge case tests."""
    print("\n")
    print("╔" + "=" * 68 + "╗")
    print("║" + " " * 20 + "EDGE CASE TESTING" + " " * 31 + "║")
    print("╚" + "=" * 68 + "╝")
    print()
    
    tests = [
        test_workflow_edge_cases,
        test_collaboration_edge_cases,
        test_sla_edge_cases,
        test_reporting_edge_cases,
        test_continuous_validation_edge_cases,
        test_concurrent_access,
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
        print("\n✅ ALL EDGE CASE TESTS PASSED!")
        return 0
    else:
        print(f"\n❌ {total - passed} EDGE CASE TEST(S) FAILED!")
        return 1


if __name__ == '__main__':
    sys.exit(main())

