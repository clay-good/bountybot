"""
Data models for continuous security validation and regression testing.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any


class VulnerabilityLifecycleState(Enum):
    """Vulnerability lifecycle states."""
    DISCOVERED = "discovered"  # Initial discovery
    VALIDATED = "validated"  # Validation complete
    TRIAGED = "triaged"  # Prioritized and assigned
    FIX_IN_PROGRESS = "fix_in_progress"  # Being fixed
    FIX_READY = "fix_ready"  # Fix ready for verification
    FIX_VERIFIED = "fix_verified"  # Fix verified successful
    MONITORING = "monitoring"  # Continuous monitoring
    REGRESSION_DETECTED = "regression_detected"  # Regression found
    CLOSED = "closed"  # Permanently closed
    FALSE_POSITIVE = "false_positive"  # Marked as false positive


class VerificationStatus(Enum):
    """Fix verification status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    PASSED = "passed"
    FAILED = "failed"
    PARTIAL = "partial"  # Partially fixed
    INCONCLUSIVE = "inconclusive"


class RegressionStatus(Enum):
    """Regression test status."""
    SCHEDULED = "scheduled"
    RUNNING = "running"
    PASSED = "passed"  # No regression
    FAILED = "failed"  # Regression detected
    ERROR = "error"  # Test error
    SKIPPED = "skipped"


class ScheduleFrequency(Enum):
    """Validation schedule frequency."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


@dataclass
class VulnerabilityLifecycle:
    """
    Tracks complete lifecycle of a vulnerability from discovery to closure.
    """
    vulnerability_id: str
    report_id: str
    vulnerability_type: str
    severity: str
    
    # Lifecycle tracking
    current_state: VulnerabilityLifecycleState
    state_history: List[Dict[str, Any]] = field(default_factory=list)
    
    # Discovery information
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    discovered_by: Optional[str] = None
    discovery_source: Optional[str] = None  # e.g., "bug_bounty", "internal_scan"
    
    # Validation information
    validated_at: Optional[datetime] = None
    validation_result: Optional[Dict[str, Any]] = None
    confidence_score: Optional[float] = None
    
    # Triage information
    triaged_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    priority_score: Optional[float] = None
    target_fix_date: Optional[datetime] = None
    
    # Fix information
    fix_started_at: Optional[datetime] = None
    fix_completed_at: Optional[datetime] = None
    fix_commit_hash: Optional[str] = None
    fix_pull_request: Optional[str] = None
    fix_description: Optional[str] = None
    
    # Verification information
    verification_count: int = 0
    last_verification: Optional[datetime] = None
    verification_results: List['FixVerification'] = field(default_factory=list)
    
    # Regression tracking
    regression_test_count: int = 0
    last_regression_test: Optional[datetime] = None
    regression_detected_count: int = 0
    regression_tests: List['RegressionTest'] = field(default_factory=list)
    
    # Monitoring
    monitoring_enabled: bool = False
    monitoring_frequency: Optional[ScheduleFrequency] = None
    next_scheduled_test: Optional[datetime] = None
    
    # Closure information
    closed_at: Optional[datetime] = None
    closure_reason: Optional[str] = None
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    notes: List[Dict[str, Any]] = field(default_factory=list)
    related_vulnerabilities: List[str] = field(default_factory=list)
    
    # Metrics
    time_to_validate: Optional[float] = None  # Hours
    time_to_triage: Optional[float] = None  # Hours
    time_to_fix: Optional[float] = None  # Hours
    time_to_verify: Optional[float] = None  # Hours
    total_lifecycle_time: Optional[float] = None  # Hours
    
    def add_state_change(self, new_state: VulnerabilityLifecycleState, reason: Optional[str] = None, metadata: Optional[Dict] = None):
        """Add state change to history."""
        self.state_history.append({
            'from_state': self.current_state.value,
            'to_state': new_state.value,
            'timestamp': datetime.utcnow().isoformat(),
            'reason': reason,
            'metadata': metadata or {}
        })
        self.current_state = new_state
    
    def add_note(self, note: str, author: Optional[str] = None):
        """Add note to vulnerability."""
        self.notes.append({
            'note': note,
            'author': author,
            'timestamp': datetime.utcnow().isoformat()
        })
    
    def calculate_metrics(self):
        """Calculate lifecycle timing metrics."""
        if self.validated_at and self.discovered_at:
            self.time_to_validate = (self.validated_at - self.discovered_at).total_seconds() / 3600
        
        if self.triaged_at and self.validated_at:
            self.time_to_triage = (self.triaged_at - self.validated_at).total_seconds() / 3600
        
        if self.fix_completed_at and self.fix_started_at:
            self.time_to_fix = (self.fix_completed_at - self.fix_started_at).total_seconds() / 3600
        
        if self.last_verification and self.fix_completed_at:
            self.time_to_verify = (self.last_verification - self.fix_completed_at).total_seconds() / 3600
        
        if self.closed_at and self.discovered_at:
            self.total_lifecycle_time = (self.closed_at - self.discovered_at).total_seconds() / 3600


@dataclass
class FixVerification:
    """
    Results of fix verification testing.
    """
    verification_id: str
    vulnerability_id: str
    test_method: str  # e.g., "automated_scan", "manual_test", "poc_replay"

    # Verification details
    status: VerificationStatus = VerificationStatus.PENDING
    started_at: datetime = field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None

    # Test information
    test_details: Dict[str, Any] = field(default_factory=dict)
    
    # Results
    vulnerability_still_present: bool = False
    confidence_score: float = 0.0  # 0-1
    findings: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    
    # Fix assessment
    fix_effectiveness: Optional[float] = None  # 0-1 (0=ineffective, 1=fully effective)
    partial_fix_details: Optional[str] = None
    recommendations: List[str] = field(default_factory=list)
    
    # Metadata
    verified_by: Optional[str] = None
    verification_environment: Optional[str] = None
    notes: Optional[str] = None


@dataclass
class RegressionTest:
    """
    Regression test execution and results.
    """
    test_id: str
    vulnerability_id: str
    test_type: str  # e.g., "poc_replay", "automated_scan", "security_check"
    scheduled_at: datetime

    # Test details
    status: RegressionStatus = RegressionStatus.SCHEDULED
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Test configuration
    test_config: Dict[str, Any] = field(default_factory=dict)
    
    # Results
    regression_detected: bool = False
    confidence_score: float = 0.0  # 0-1
    findings: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    
    # Comparison with original
    original_validation_id: Optional[str] = None
    changes_detected: List[str] = field(default_factory=list)
    severity_change: Optional[str] = None  # e.g., "increased", "decreased", "unchanged"
    
    # Metadata
    test_environment: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0


@dataclass
class SecurityPosture:
    """
    Overall security posture snapshot.
    """
    snapshot_id: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Vulnerability counts by state
    discovered_count: int = 0
    validated_count: int = 0
    triaged_count: int = 0
    fix_in_progress_count: int = 0
    fix_verified_count: int = 0
    monitoring_count: int = 0
    regression_detected_count: int = 0
    closed_count: int = 0
    
    # Vulnerability counts by severity
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # Metrics
    metrics: 'PostureMetrics' = field(default_factory=lambda: PostureMetrics())
    
    # Trends (compared to previous snapshot)
    trend_direction: Optional[str] = None  # "improving", "degrading", "stable"
    trend_details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PostureMetrics:
    """
    Security posture metrics.
    """
    # Time metrics (in hours)
    avg_time_to_validate: Optional[float] = None
    avg_time_to_triage: Optional[float] = None
    avg_time_to_fix: Optional[float] = None
    avg_time_to_verify: Optional[float] = None
    avg_total_lifecycle_time: Optional[float] = None
    
    # Fix metrics
    fix_success_rate: Optional[float] = None  # 0-1
    regression_rate: Optional[float] = None  # 0-1
    false_positive_rate: Optional[float] = None  # 0-1
    
    # Velocity metrics
    vulnerabilities_discovered_per_day: Optional[float] = None
    vulnerabilities_fixed_per_day: Optional[float] = None
    vulnerabilities_verified_per_day: Optional[float] = None
    
    # Quality metrics
    avg_confidence_score: Optional[float] = None  # 0-1
    avg_priority_score: Optional[float] = None  # 0-1
    
    # Coverage metrics
    monitoring_coverage: Optional[float] = None  # 0-1 (% of fixed vulns being monitored)
    verification_coverage: Optional[float] = None  # 0-1 (% of fixes verified)


@dataclass
class ValidationSchedule:
    """
    Schedule for continuous validation.
    """
    schedule_id: str
    vulnerability_id: str
    
    # Schedule configuration
    frequency: ScheduleFrequency
    custom_cron: Optional[str] = None  # For CUSTOM frequency
    enabled: bool = True
    
    # Schedule details
    created_at: datetime = field(default_factory=datetime.utcnow)
    next_run: Optional[datetime] = None
    last_run: Optional[datetime] = None
    
    # Execution tracking
    total_runs: int = 0
    successful_runs: int = 0
    failed_runs: int = 0
    last_status: Optional[RegressionStatus] = None
    
    # Configuration
    test_config: Dict[str, Any] = field(default_factory=dict)
    notification_config: Dict[str, Any] = field(default_factory=dict)
    
    # Metadata
    created_by: Optional[str] = None
    notes: Optional[str] = None

