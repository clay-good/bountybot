"""
Continuous Security Validation & Regression Testing System

Provides comprehensive continuous validation capabilities:
- Vulnerability lifecycle management (discovery → fix → verification → monitoring)
- Automated regression testing for fixed vulnerabilities
- Security posture tracking and metrics
- Continuous validation scheduling
- Fix verification and validation
- Security trend analysis and reporting
"""

from .models import (
    VulnerabilityLifecycleState,
    VulnerabilityLifecycle,
    FixVerification,
    VerificationStatus,
    RegressionTest,
    RegressionStatus,
    SecurityPosture,
    PostureMetrics,
    ValidationSchedule,
    ScheduleFrequency
)

from .lifecycle_manager import VulnerabilityLifecycleManager
from .regression_engine import RegressionTestingEngine
from .posture_tracker import SecurityPostureTracker
from .validation_scheduler import ContinuousValidationScheduler

__all__ = [
    # Models
    'VulnerabilityLifecycleState',
    'VulnerabilityLifecycle',
    'FixVerification',
    'VerificationStatus',
    'RegressionTest',
    'RegressionStatus',
    'SecurityPosture',
    'PostureMetrics',
    'ValidationSchedule',
    'ScheduleFrequency',
    
    # Core Components
    'VulnerabilityLifecycleManager',
    'RegressionTestingEngine',
    'SecurityPostureTracker',
    'ContinuousValidationScheduler',
]

