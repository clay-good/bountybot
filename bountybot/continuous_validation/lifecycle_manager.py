"""
Vulnerability Lifecycle Manager

Manages the complete lifecycle of vulnerabilities from discovery to closure.
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import uuid4

from .models import (
    VulnerabilityLifecycle,
    VulnerabilityLifecycleState,
    FixVerification,
    VerificationStatus
)

logger = logging.getLogger(__name__)


class VulnerabilityLifecycleManager:
    """
    Manages vulnerability lifecycle from discovery through fix verification and monitoring.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize lifecycle manager.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.lifecycles: Dict[str, VulnerabilityLifecycle] = {}
        
        # Configuration
        self.auto_triage_enabled = self.config.get('auto_triage_enabled', True)
        self.auto_monitoring_enabled = self.config.get('auto_monitoring_enabled', True)
        self.default_monitoring_frequency = self.config.get('default_monitoring_frequency', 'weekly')
        
        logger.info("VulnerabilityLifecycleManager initialized")
    
    def create_lifecycle(
        self,
        vulnerability_id: str,
        report_id: str,
        vulnerability_type: str,
        severity: str,
        discovered_by: Optional[str] = None,
        discovery_source: Optional[str] = None,
        metadata: Optional[Dict] = None
    ) -> VulnerabilityLifecycle:
        """
        Create new vulnerability lifecycle.
        
        Args:
            vulnerability_id: Unique vulnerability identifier
            report_id: Associated report ID
            vulnerability_type: Type of vulnerability
            severity: Severity level
            discovered_by: Who discovered it
            discovery_source: Source of discovery
            metadata: Additional metadata
            
        Returns:
            VulnerabilityLifecycle object
        """
        lifecycle = VulnerabilityLifecycle(
            vulnerability_id=vulnerability_id,
            report_id=report_id,
            vulnerability_type=vulnerability_type,
            severity=severity,
            current_state=VulnerabilityLifecycleState.DISCOVERED,
            discovered_by=discovered_by,
            discovery_source=discovery_source
        )
        
        # Add initial state to history
        lifecycle.state_history.append({
            'from_state': None,
            'to_state': VulnerabilityLifecycleState.DISCOVERED.value,
            'timestamp': datetime.utcnow().isoformat(),
            'reason': 'Initial discovery',
            'metadata': metadata or {}
        })
        
        self.lifecycles[vulnerability_id] = lifecycle
        logger.info(f"Created lifecycle for vulnerability {vulnerability_id}")
        
        return lifecycle
    
    def mark_validated(
        self,
        vulnerability_id: str,
        validation_result: Dict[str, Any],
        confidence_score: float,
        reason: Optional[str] = None
    ) -> VulnerabilityLifecycle:
        """
        Mark vulnerability as validated.
        
        Args:
            vulnerability_id: Vulnerability ID
            validation_result: Validation result data
            confidence_score: Confidence score (0-1)
            reason: Reason for validation
            
        Returns:
            Updated VulnerabilityLifecycle
        """
        lifecycle = self.lifecycles.get(vulnerability_id)
        if not lifecycle:
            raise ValueError(f"Lifecycle not found for vulnerability {vulnerability_id}")
        
        lifecycle.validated_at = datetime.utcnow()
        lifecycle.validation_result = validation_result
        lifecycle.confidence_score = confidence_score
        lifecycle.add_state_change(
            VulnerabilityLifecycleState.VALIDATED,
            reason or "Validation completed",
            {'confidence_score': confidence_score}
        )
        
        # Calculate time to validate
        lifecycle.calculate_metrics()
        
        # Auto-triage if enabled
        if self.auto_triage_enabled:
            self._auto_triage(lifecycle)
        
        logger.info(f"Marked vulnerability {vulnerability_id} as validated")
        return lifecycle
    
    def mark_triaged(
        self,
        vulnerability_id: str,
        assigned_to: Optional[str] = None,
        priority_score: Optional[float] = None,
        target_fix_date: Optional[datetime] = None,
        reason: Optional[str] = None
    ) -> VulnerabilityLifecycle:
        """
        Mark vulnerability as triaged.
        
        Args:
            vulnerability_id: Vulnerability ID
            assigned_to: Who it's assigned to
            priority_score: Priority score (0-1)
            target_fix_date: Target fix date
            reason: Reason for triage
            
        Returns:
            Updated VulnerabilityLifecycle
        """
        lifecycle = self.lifecycles.get(vulnerability_id)
        if not lifecycle:
            raise ValueError(f"Lifecycle not found for vulnerability {vulnerability_id}")
        
        lifecycle.triaged_at = datetime.utcnow()
        lifecycle.assigned_to = assigned_to
        lifecycle.priority_score = priority_score
        lifecycle.target_fix_date = target_fix_date
        lifecycle.add_state_change(
            VulnerabilityLifecycleState.TRIAGED,
            reason or "Triage completed",
            {
                'assigned_to': assigned_to,
                'priority_score': priority_score,
                'target_fix_date': target_fix_date.isoformat() if target_fix_date else None
            }
        )
        
        # Calculate metrics
        lifecycle.calculate_metrics()
        
        logger.info(f"Marked vulnerability {vulnerability_id} as triaged")
        return lifecycle
    
    def mark_fix_in_progress(
        self,
        vulnerability_id: str,
        reason: Optional[str] = None
    ) -> VulnerabilityLifecycle:
        """
        Mark vulnerability fix as in progress.
        
        Args:
            vulnerability_id: Vulnerability ID
            reason: Reason for starting fix
            
        Returns:
            Updated VulnerabilityLifecycle
        """
        lifecycle = self.lifecycles.get(vulnerability_id)
        if not lifecycle:
            raise ValueError(f"Lifecycle not found for vulnerability {vulnerability_id}")
        
        lifecycle.fix_started_at = datetime.utcnow()
        lifecycle.add_state_change(
            VulnerabilityLifecycleState.FIX_IN_PROGRESS,
            reason or "Fix started"
        )
        
        logger.info(f"Marked vulnerability {vulnerability_id} fix as in progress")
        return lifecycle
    
    def mark_fix_ready(
        self,
        vulnerability_id: str,
        fix_commit_hash: Optional[str] = None,
        fix_pull_request: Optional[str] = None,
        fix_description: Optional[str] = None,
        reason: Optional[str] = None
    ) -> VulnerabilityLifecycle:
        """
        Mark vulnerability fix as ready for verification.
        
        Args:
            vulnerability_id: Vulnerability ID
            fix_commit_hash: Git commit hash
            fix_pull_request: Pull request URL
            fix_description: Description of fix
            reason: Reason for marking ready
            
        Returns:
            Updated VulnerabilityLifecycle
        """
        lifecycle = self.lifecycles.get(vulnerability_id)
        if not lifecycle:
            raise ValueError(f"Lifecycle not found for vulnerability {vulnerability_id}")
        
        lifecycle.fix_completed_at = datetime.utcnow()
        lifecycle.fix_commit_hash = fix_commit_hash
        lifecycle.fix_pull_request = fix_pull_request
        lifecycle.fix_description = fix_description
        lifecycle.add_state_change(
            VulnerabilityLifecycleState.FIX_READY,
            reason or "Fix ready for verification",
            {
                'commit_hash': fix_commit_hash,
                'pull_request': fix_pull_request
            }
        )
        
        # Calculate metrics
        lifecycle.calculate_metrics()
        
        logger.info(f"Marked vulnerability {vulnerability_id} fix as ready")
        return lifecycle
    
    def add_verification_result(
        self,
        vulnerability_id: str,
        verification: FixVerification
    ) -> VulnerabilityLifecycle:
        """
        Add fix verification result.
        
        Args:
            vulnerability_id: Vulnerability ID
            verification: FixVerification object
            
        Returns:
            Updated VulnerabilityLifecycle
        """
        lifecycle = self.lifecycles.get(vulnerability_id)
        if not lifecycle:
            raise ValueError(f"Lifecycle not found for vulnerability {vulnerability_id}")
        
        lifecycle.verification_results.append(verification)
        lifecycle.verification_count += 1
        lifecycle.last_verification = datetime.utcnow()
        
        # Update state based on verification result
        if verification.status == VerificationStatus.PASSED:
            lifecycle.add_state_change(
                VulnerabilityLifecycleState.FIX_VERIFIED,
                "Fix verification passed",
                {'verification_id': verification.verification_id}
            )
            
            # Enable monitoring if configured
            if self.auto_monitoring_enabled:
                self._enable_monitoring(lifecycle)
        
        elif verification.status == VerificationStatus.FAILED:
            lifecycle.add_state_change(
                VulnerabilityLifecycleState.FIX_IN_PROGRESS,
                "Fix verification failed - needs rework",
                {'verification_id': verification.verification_id}
            )
        
        # Calculate metrics
        lifecycle.calculate_metrics()
        
        logger.info(f"Added verification result for vulnerability {vulnerability_id}: {verification.status.value}")
        return lifecycle
    
    def mark_regression_detected(
        self,
        vulnerability_id: str,
        regression_test_id: str,
        reason: Optional[str] = None
    ) -> VulnerabilityLifecycle:
        """
        Mark regression detected for vulnerability.
        
        Args:
            vulnerability_id: Vulnerability ID
            regression_test_id: Regression test ID
            reason: Reason for regression
            
        Returns:
            Updated VulnerabilityLifecycle
        """
        lifecycle = self.lifecycles.get(vulnerability_id)
        if not lifecycle:
            raise ValueError(f"Lifecycle not found for vulnerability {vulnerability_id}")
        
        lifecycle.regression_detected_count += 1
        lifecycle.add_state_change(
            VulnerabilityLifecycleState.REGRESSION_DETECTED,
            reason or "Regression detected in testing",
            {'regression_test_id': regression_test_id}
        )
        
        logger.warning(f"Regression detected for vulnerability {vulnerability_id}")
        return lifecycle
    
    def mark_closed(
        self,
        vulnerability_id: str,
        closure_reason: str,
        reason: Optional[str] = None
    ) -> VulnerabilityLifecycle:
        """
        Mark vulnerability as closed.
        
        Args:
            vulnerability_id: Vulnerability ID
            closure_reason: Reason for closure
            reason: Additional reason details
            
        Returns:
            Updated VulnerabilityLifecycle
        """
        lifecycle = self.lifecycles.get(vulnerability_id)
        if not lifecycle:
            raise ValueError(f"Lifecycle not found for vulnerability {vulnerability_id}")
        
        lifecycle.closed_at = datetime.utcnow()
        lifecycle.closure_reason = closure_reason
        lifecycle.add_state_change(
            VulnerabilityLifecycleState.CLOSED,
            reason or f"Closed: {closure_reason}"
        )
        
        # Calculate final metrics
        lifecycle.calculate_metrics()
        
        logger.info(f"Closed vulnerability {vulnerability_id}: {closure_reason}")
        return lifecycle
    
    def get_lifecycle(self, vulnerability_id: str) -> Optional[VulnerabilityLifecycle]:
        """Get lifecycle for vulnerability."""
        return self.lifecycles.get(vulnerability_id)
    
    def get_lifecycles_by_state(self, state: VulnerabilityLifecycleState) -> List[VulnerabilityLifecycle]:
        """Get all lifecycles in a specific state."""
        return [lc for lc in self.lifecycles.values() if lc.current_state == state]
    
    def get_lifecycles_by_severity(self, severity: str) -> List[VulnerabilityLifecycle]:
        """Get all lifecycles with specific severity."""
        return [lc for lc in self.lifecycles.values() if lc.severity.lower() == severity.lower()]
    
    def _auto_triage(self, lifecycle: VulnerabilityLifecycle):
        """Automatically triage vulnerability based on severity and confidence."""
        # Simple auto-triage logic
        severity_scores = {
            'critical': 1.0,
            'high': 0.8,
            'medium': 0.5,
            'low': 0.3,
            'info': 0.1
        }
        
        priority_score = severity_scores.get(lifecycle.severity.lower(), 0.5)
        if lifecycle.confidence_score:
            priority_score = (priority_score + lifecycle.confidence_score) / 2
        
        # Set target fix date based on severity
        days_to_fix = {
            'critical': 1,
            'high': 7,
            'medium': 30,
            'low': 90,
            'info': 180
        }
        target_days = days_to_fix.get(lifecycle.severity.lower(), 30)
        target_fix_date = datetime.utcnow() + timedelta(days=target_days)
        
        self.mark_triaged(
            lifecycle.vulnerability_id,
            priority_score=priority_score,
            target_fix_date=target_fix_date,
            reason="Auto-triaged based on severity and confidence"
        )
    
    def _enable_monitoring(self, lifecycle: VulnerabilityLifecycle):
        """Enable continuous monitoring for fixed vulnerability."""
        from .models import ScheduleFrequency
        
        lifecycle.monitoring_enabled = True
        lifecycle.monitoring_frequency = ScheduleFrequency(self.default_monitoring_frequency)
        lifecycle.next_scheduled_test = self._calculate_next_test_time(lifecycle.monitoring_frequency)
        
        logger.info(f"Enabled monitoring for vulnerability {lifecycle.vulnerability_id}")
    
    def _calculate_next_test_time(self, frequency: 'ScheduleFrequency') -> datetime:
        """Calculate next test time based on frequency."""
        from .models import ScheduleFrequency
        
        now = datetime.utcnow()
        if frequency == ScheduleFrequency.HOURLY:
            return now + timedelta(hours=1)
        elif frequency == ScheduleFrequency.DAILY:
            return now + timedelta(days=1)
        elif frequency == ScheduleFrequency.WEEKLY:
            return now + timedelta(weeks=1)
        elif frequency == ScheduleFrequency.MONTHLY:
            return now + timedelta(days=30)
        else:
            return now + timedelta(days=7)  # Default to weekly

