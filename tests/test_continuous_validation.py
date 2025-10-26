"""
Tests for continuous validation and regression testing system.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from uuid import uuid4

from bountybot.continuous_validation import (
    VulnerabilityLifecycleManager,
    RegressionTestingEngine,
    SecurityPostureTracker,
    ContinuousValidationScheduler,
    VulnerabilityLifecycleState,
    VerificationStatus,
    RegressionStatus,
    ScheduleFrequency
)


class TestVulnerabilityLifecycleManager:
    """Tests for VulnerabilityLifecycleManager."""
    
    def test_create_lifecycle(self):
        """Test creating vulnerability lifecycle."""
        manager = VulnerabilityLifecycleManager()
        
        lifecycle = manager.create_lifecycle(
            vulnerability_id="vuln-001",
            report_id="report-001",
            vulnerability_type="SQL Injection",
            severity="high",
            discovered_by="researcher@example.com",
            discovery_source="bug_bounty"
        )
        
        assert lifecycle.vulnerability_id == "vuln-001"
        assert lifecycle.report_id == "report-001"
        assert lifecycle.vulnerability_type == "SQL Injection"
        assert lifecycle.severity == "high"
        assert lifecycle.current_state == VulnerabilityLifecycleState.DISCOVERED
        assert lifecycle.discovered_by == "researcher@example.com"
        assert len(lifecycle.state_history) == 1
    
    def test_mark_validated(self):
        """Test marking vulnerability as validated."""
        # Disable auto-triage for this test
        manager = VulnerabilityLifecycleManager(config={'auto_triage_enabled': False})

        lifecycle = manager.create_lifecycle(
            vulnerability_id="vuln-001",
            report_id="report-001",
            vulnerability_type="XSS",
            severity="medium"
        )

        validation_result = {"verdict": "valid", "confidence": 0.95}
        manager.mark_validated("vuln-001", validation_result, 0.95)

        updated = manager.get_lifecycle("vuln-001")
        assert updated.current_state == VulnerabilityLifecycleState.VALIDATED
        assert updated.validation_result == validation_result
        assert updated.confidence_score == 0.95
        assert updated.validated_at is not None
        assert len(updated.state_history) == 2
    
    def test_mark_triaged(self):
        """Test marking vulnerability as triaged."""
        manager = VulnerabilityLifecycleManager()
        
        lifecycle = manager.create_lifecycle(
            vulnerability_id="vuln-001",
            report_id="report-001",
            vulnerability_type="RCE",
            severity="critical"
        )
        
        target_date = datetime.utcnow() + timedelta(days=1)
        manager.mark_triaged(
            "vuln-001",
            assigned_to="dev@example.com",
            priority_score=0.95,
            target_fix_date=target_date
        )
        
        updated = manager.get_lifecycle("vuln-001")
        assert updated.current_state == VulnerabilityLifecycleState.TRIAGED
        assert updated.assigned_to == "dev@example.com"
        assert updated.priority_score == 0.95
        assert updated.target_fix_date == target_date
    
    def test_mark_fix_ready(self):
        """Test marking fix as ready."""
        manager = VulnerabilityLifecycleManager()
        
        lifecycle = manager.create_lifecycle(
            vulnerability_id="vuln-001",
            report_id="report-001",
            vulnerability_type="CSRF",
            severity="medium"
        )
        
        manager.mark_fix_in_progress("vuln-001")
        manager.mark_fix_ready(
            "vuln-001",
            fix_commit_hash="abc123",
            fix_pull_request="https://github.com/org/repo/pull/123",
            fix_description="Added CSRF token validation"
        )
        
        updated = manager.get_lifecycle("vuln-001")
        assert updated.current_state == VulnerabilityLifecycleState.FIX_READY
        assert updated.fix_commit_hash == "abc123"
        assert updated.fix_pull_request == "https://github.com/org/repo/pull/123"
        assert updated.fix_completed_at is not None
    
    def test_get_lifecycles_by_state(self):
        """Test getting lifecycles by state."""
        # Disable auto-triage for this test
        manager = VulnerabilityLifecycleManager(config={'auto_triage_enabled': False})

        # Create multiple lifecycles in different states
        manager.create_lifecycle("vuln-001", "report-001", "SQL Injection", "high")
        manager.create_lifecycle("vuln-002", "report-002", "XSS", "medium")
        manager.create_lifecycle("vuln-003", "report-003", "RCE", "critical")

        manager.mark_validated("vuln-001", {}, 0.9)
        manager.mark_validated("vuln-002", {}, 0.8)

        discovered = manager.get_lifecycles_by_state(VulnerabilityLifecycleState.DISCOVERED)
        validated = manager.get_lifecycles_by_state(VulnerabilityLifecycleState.VALIDATED)

        assert len(discovered) == 1
        assert len(validated) == 2


class TestRegressionTestingEngine:
    """Tests for RegressionTestingEngine."""
    
    @pytest.mark.asyncio
    async def test_create_regression_test(self):
        """Test creating regression test."""
        engine = RegressionTestingEngine()
        
        test = await engine.create_regression_test(
            vulnerability_id="vuln-001",
            test_type="poc_replay",
            test_config={"poc_id": "poc-001"}
        )
        
        assert test.vulnerability_id == "vuln-001"
        assert test.test_type == "poc_replay"
        assert test.status == RegressionStatus.SCHEDULED
        assert test.test_config["poc_id"] == "poc-001"
    
    @pytest.mark.asyncio
    async def test_execute_poc_replay(self):
        """Test executing PoC replay test."""
        engine = RegressionTestingEngine()
        
        test = await engine.create_regression_test(
            vulnerability_id="vuln-001",
            test_type="poc_replay",
            test_config={"poc_config": {"method": "POST", "url": "/api/test"}}
        )
        
        result = await engine.execute_regression_test(test.test_id)
        
        assert result.status in [RegressionStatus.PASSED, RegressionStatus.FAILED]
        assert result.started_at is not None
        assert result.completed_at is not None
        assert result.confidence_score > 0
        assert len(result.findings) > 0
    
    @pytest.mark.asyncio
    async def test_execute_automated_scan(self):
        """Test executing automated scan."""
        engine = RegressionTestingEngine()
        
        test = await engine.create_regression_test(
            vulnerability_id="vuln-001",
            test_type="automated_scan",
            test_config={"scan_config": {"vulnerability_type": "SQL Injection"}}
        )
        
        result = await engine.execute_regression_test(test.test_id)
        
        assert result.status in [RegressionStatus.PASSED, RegressionStatus.FAILED]
        assert result.confidence_score > 0
    
    @pytest.mark.asyncio
    async def test_execute_batch_regression_tests(self):
        """Test executing multiple regression tests in parallel."""
        engine = RegressionTestingEngine()
        
        # Create multiple tests
        test_ids = []
        for i in range(5):
            test = await engine.create_regression_test(
                vulnerability_id=f"vuln-{i:03d}",
                test_type="automated_scan",
                test_config={}
            )
            test_ids.append(test.test_id)
        
        # Execute in batch
        results = await engine.execute_batch_regression_tests(test_ids)
        
        assert len(results) == 5
        for result in results:
            assert result.status in [RegressionStatus.PASSED, RegressionStatus.FAILED, RegressionStatus.ERROR]
    
    @pytest.mark.asyncio
    async def test_verify_fix(self):
        """Test fix verification."""
        engine = RegressionTestingEngine()
        
        verification = await engine.verify_fix(
            vulnerability_id="vuln-001",
            test_method="automated_scan",
            test_config={"scan_type": "full"}
        )
        
        assert verification.vulnerability_id == "vuln-001"
        assert verification.test_method == "automated_scan"
        assert verification.status in [VerificationStatus.PASSED, VerificationStatus.FAILED]
        assert verification.completed_at is not None
        assert len(verification.recommendations) > 0
    
    @pytest.mark.asyncio
    async def test_get_regression_rate(self):
        """Test calculating regression rate."""
        engine = RegressionTestingEngine()
        
        # Create and execute multiple tests
        for i in range(10):
            test = await engine.create_regression_test(
                vulnerability_id=f"vuln-{i:03d}",
                test_type="automated_scan"
            )
            await engine.execute_regression_test(test.test_id)
        
        regression_rate = engine.get_regression_rate()
        
        assert 0.0 <= regression_rate <= 1.0


class TestSecurityPostureTracker:
    """Tests for SecurityPostureTracker."""
    
    def test_create_posture_snapshot(self):
        """Test creating security posture snapshot."""
        tracker = SecurityPostureTracker()
        # Disable auto-triage for this test
        manager = VulnerabilityLifecycleManager(config={'auto_triage_enabled': False})

        # Create some lifecycles
        lifecycles = []
        for i in range(10):
            lifecycle = manager.create_lifecycle(
                vulnerability_id=f"vuln-{i:03d}",
                report_id=f"report-{i:03d}",
                vulnerability_type="SQL Injection",
                severity="high" if i < 5 else "medium"
            )
            lifecycles.append(lifecycle)

        # Mark some as validated
        for i in range(5):
            manager.mark_validated(f"vuln-{i:03d}", {}, 0.9)

        # Create snapshot
        posture = tracker.create_posture_snapshot(list(manager.lifecycles.values()))

        assert posture.discovered_count == 5
        assert posture.validated_count == 5
        assert posture.high_count == 5
        assert posture.medium_count == 5
        assert posture.metrics is not None
    
    def test_calculate_metrics(self):
        """Test calculating posture metrics."""
        tracker = SecurityPostureTracker()
        manager = VulnerabilityLifecycleManager()
        
        # Create lifecycle with complete data
        lifecycle = manager.create_lifecycle(
            vulnerability_id="vuln-001",
            report_id="report-001",
            vulnerability_type="XSS",
            severity="high"
        )
        
        # Simulate complete lifecycle
        manager.mark_validated("vuln-001", {}, 0.95)
        manager.mark_triaged("vuln-001", priority_score=0.9)
        manager.mark_fix_in_progress("vuln-001")
        manager.mark_fix_ready("vuln-001")
        
        # Create snapshot
        posture = tracker.create_posture_snapshot([lifecycle])
        
        assert posture.metrics.avg_confidence_score is not None
        assert posture.metrics.avg_priority_score is not None
    
    def test_analyze_trends(self):
        """Test trend analysis."""
        tracker = SecurityPostureTracker()
        manager = VulnerabilityLifecycleManager()
        
        # Create initial snapshot
        lifecycles1 = []
        for i in range(10):
            lifecycle = manager.create_lifecycle(
                vulnerability_id=f"vuln-{i:03d}",
                report_id=f"report-{i:03d}",
                vulnerability_type="SQL Injection",
                severity="high"
            )
            lifecycles1.append(lifecycle)
        
        posture1 = tracker.create_posture_snapshot(lifecycles1)
        
        # Fix some vulnerabilities
        for i in range(5):
            manager.mark_validated(f"vuln-{i:03d}", {}, 0.9)
            manager.mark_triaged(f"vuln-{i:03d}")
            manager.mark_fix_in_progress(f"vuln-{i:03d}")
            manager.mark_fix_ready(f"vuln-{i:03d}")
            manager.mark_closed(f"vuln-{i:03d}", "Fixed and verified")
        
        # Create second snapshot
        posture2 = tracker.create_posture_snapshot(list(manager.lifecycles.values()))
        
        assert posture2.trend_direction in ["improving", "stable", "degrading"]
        assert posture2.trend_details is not None
    
    def test_generate_trend_report(self):
        """Test generating trend report."""
        tracker = SecurityPostureTracker()
        manager = VulnerabilityLifecycleManager()
        
        # Create multiple snapshots
        for snapshot_num in range(3):
            lifecycles = []
            for i in range(5):
                lifecycle = manager.create_lifecycle(
                    vulnerability_id=f"vuln-{snapshot_num}-{i:03d}",
                    report_id=f"report-{snapshot_num}-{i:03d}",
                    vulnerability_type="XSS",
                    severity="medium"
                )
                lifecycles.append(lifecycle)
            
            tracker.create_posture_snapshot(lifecycles)
        
        # Generate report
        report = tracker.generate_trend_report(days=30)
        
        assert 'analysis_period' in report
        assert 'vulnerability_trends' in report
        assert 'severity_trends' in report
        assert 'metrics_trends' in report


class TestContinuousValidationScheduler:
    """Tests for ContinuousValidationScheduler."""
    
    def test_create_schedule(self):
        """Test creating validation schedule."""
        engine = RegressionTestingEngine()
        scheduler = ContinuousValidationScheduler(engine)
        
        schedule = scheduler.create_schedule(
            vulnerability_id="vuln-001",
            frequency=ScheduleFrequency.DAILY,
            test_config={"test_type": "automated_scan"}
        )
        
        assert schedule.vulnerability_id == "vuln-001"
        assert schedule.frequency == ScheduleFrequency.DAILY
        assert schedule.enabled is True
        assert schedule.next_run is not None
    
    def test_update_schedule(self):
        """Test updating validation schedule."""
        engine = RegressionTestingEngine()
        scheduler = ContinuousValidationScheduler(engine)
        
        schedule = scheduler.create_schedule(
            vulnerability_id="vuln-001",
            frequency=ScheduleFrequency.DAILY
        )
        
        updated = scheduler.update_schedule(
            schedule.schedule_id,
            frequency=ScheduleFrequency.WEEKLY,
            enabled=False
        )
        
        assert updated.frequency == ScheduleFrequency.WEEKLY
        assert updated.enabled is False
    
    def test_delete_schedule(self):
        """Test deleting validation schedule."""
        engine = RegressionTestingEngine()
        scheduler = ContinuousValidationScheduler(engine)
        
        schedule = scheduler.create_schedule(
            vulnerability_id="vuln-001",
            frequency=ScheduleFrequency.DAILY
        )
        
        scheduler.delete_schedule(schedule.schedule_id)
        
        assert scheduler.get_schedule(schedule.schedule_id) is None
    
    @pytest.mark.asyncio
    async def test_scheduler_start_stop(self):
        """Test starting and stopping scheduler."""
        engine = RegressionTestingEngine()
        scheduler = ContinuousValidationScheduler(engine)
        
        await scheduler.start()
        assert scheduler.running is True
        
        await scheduler.stop()
        assert scheduler.running is False
    
    def test_get_schedule_statistics(self):
        """Test getting scheduler statistics."""
        engine = RegressionTestingEngine()
        scheduler = ContinuousValidationScheduler(engine)
        
        # Create multiple schedules
        for i in range(5):
            scheduler.create_schedule(
                vulnerability_id=f"vuln-{i:03d}",
                frequency=ScheduleFrequency.DAILY if i < 3 else ScheduleFrequency.WEEKLY
            )
        
        stats = scheduler.get_schedule_statistics()
        
        assert stats['total_schedules'] == 5
        assert stats['enabled_schedules'] == 5
        assert 'frequency_distribution' in stats
        assert stats['frequency_distribution']['daily'] == 3
        assert stats['frequency_distribution']['weekly'] == 2


class TestIntegration:
    """Integration tests for continuous validation system."""
    
    @pytest.mark.asyncio
    async def test_complete_lifecycle_workflow(self):
        """Test complete vulnerability lifecycle workflow."""
        # Initialize components (auto-triage enabled by default)
        lifecycle_manager = VulnerabilityLifecycleManager()
        regression_engine = RegressionTestingEngine()
        posture_tracker = SecurityPostureTracker()

        # 1. Create vulnerability lifecycle
        lifecycle = lifecycle_manager.create_lifecycle(
            vulnerability_id="vuln-001",
            report_id="report-001",
            vulnerability_type="SQL Injection",
            severity="critical",
            discovered_by="researcher@example.com"
        )

        assert lifecycle.current_state == VulnerabilityLifecycleState.DISCOVERED

        # 2. Mark as validated (will auto-triage to TRIAGED)
        lifecycle_manager.mark_validated("vuln-001", {"verdict": "valid"}, 0.95)

        # 3. Should be auto-triaged
        assert lifecycle.current_state == VulnerabilityLifecycleState.TRIAGED
        
        # 4. Mark fix in progress
        lifecycle_manager.mark_fix_in_progress("vuln-001")
        assert lifecycle.current_state == VulnerabilityLifecycleState.FIX_IN_PROGRESS
        
        # 5. Mark fix ready
        lifecycle_manager.mark_fix_ready("vuln-001", fix_commit_hash="abc123")
        assert lifecycle.current_state == VulnerabilityLifecycleState.FIX_READY
        
        # 6. Verify fix
        verification = await regression_engine.verify_fix(
            vulnerability_id="vuln-001",
            test_method="automated_scan"
        )
        
        # 7. Add verification result
        lifecycle_manager.add_verification_result("vuln-001", verification)
        
        # 8. Create posture snapshot
        posture = posture_tracker.create_posture_snapshot([lifecycle])
        
        assert posture.metrics is not None
        assert lifecycle.verification_count > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

