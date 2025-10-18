"""
Policy Enforcement Engine

Enforces compliance policies and detects violations.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional
from .models import (
    ComplianceFramework,
    DataClassification,
    DataRetentionPolicy,
    PIIType
)
from .pii_detector import PIIDetector

logger = logging.getLogger(__name__)


@dataclass
class PolicyViolation:
    """Policy violation record."""
    violation_id: str
    policy_id: str
    policy_name: str
    severity: str  # critical, high, medium, low
    description: str
    
    # Context
    resource_type: str
    resource_id: Optional[str] = None
    
    # Details
    violation_details: Dict[str, Any] = field(default_factory=dict)
    
    # Remediation
    remediation_steps: List[str] = field(default_factory=list)
    auto_remediate: bool = False
    
    # Status
    is_resolved: bool = False
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    
    # Metadata
    detected_at: datetime = field(default_factory=datetime.utcnow)
    framework: Optional[ComplianceFramework] = None


class PolicyEngine:
    """Enforces compliance policies."""
    
    def __init__(self, pii_detector: Optional[PIIDetector] = None):
        """
        Initialize policy engine.
        
        Args:
            pii_detector: PII detector instance
        """
        self.pii_detector = pii_detector or PIIDetector()
        self.violations: List[PolicyViolation] = []
        self.policies: Dict[str, Any] = {}
    
    def check_data_classification(
        self,
        data: Dict[str, Any],
        expected_classification: DataClassification,
        resource_type: str,
        resource_id: Optional[str] = None
    ) -> List[PolicyViolation]:
        """
        Check if data meets classification requirements.
        
        Args:
            data: Data to check
            expected_classification: Expected classification level
            resource_type: Type of resource
            resource_id: Resource identifier
            
        Returns:
            List of violations
        """
        violations = []
        
        # Check for PII in data that shouldn't have it
        if expected_classification in [DataClassification.PUBLIC, DataClassification.INTERNAL]:
            pii_results = self.pii_detector.scan_dict(data)
            
            if pii_results:
                violation = PolicyViolation(
                    violation_id=f"pol_class_{datetime.utcnow().timestamp()}",
                    policy_id="data_classification",
                    policy_name="Data Classification Policy",
                    severity="high",
                    description=f"PII found in {expected_classification.value} data",
                    resource_type=resource_type,
                    resource_id=resource_id,
                    violation_details={
                        'expected_classification': expected_classification.value,
                        'pii_found': len(pii_results),
                        'pii_types': list(set(match.pii_type.value for _, match in pii_results))
                    },
                    remediation_steps=[
                        "Review data classification",
                        "Remove or anonymize PII",
                        "Update access controls"
                    ],
                    auto_remediate=False
                )
                violations.append(violation)
                self.violations.append(violation)
        
        return violations
    
    def check_retention_policy(
        self,
        data_age_days: int,
        policy: DataRetentionPolicy,
        resource_type: str,
        resource_id: Optional[str] = None
    ) -> List[PolicyViolation]:
        """
        Check if data exceeds retention policy.
        
        Args:
            data_age_days: Age of data in days
            policy: Retention policy to check
            resource_type: Type of resource
            resource_id: Resource identifier
            
        Returns:
            List of violations
        """
        violations = []
        
        if data_age_days > policy.retention_period_days:
            violation = PolicyViolation(
                violation_id=f"pol_ret_{datetime.utcnow().timestamp()}",
                policy_id=policy.policy_id,
                policy_name=policy.name,
                severity="medium",
                description=f"Data exceeds retention period ({policy.retention_period_days} days)",
                resource_type=resource_type,
                resource_id=resource_id,
                violation_details={
                    'data_age_days': data_age_days,
                    'retention_period_days': policy.retention_period_days,
                    'days_overdue': data_age_days - policy.retention_period_days
                },
                remediation_steps=[
                    f"Delete or archive data using {policy.deletion_method}",
                    "Update retention policy if needed"
                ],
                auto_remediate=policy.auto_delete
            )
            violations.append(violation)
            self.violations.append(violation)
        
        return violations
    
    def check_data_residency(
        self,
        data_location: str,
        allowed_locations: List[str],
        resource_type: str,
        resource_id: Optional[str] = None,
        framework: Optional[ComplianceFramework] = None
    ) -> List[PolicyViolation]:
        """
        Check if data is stored in allowed locations.
        
        Args:
            data_location: Current data location
            allowed_locations: List of allowed locations
            resource_type: Type of resource
            resource_id: Resource identifier
            framework: Compliance framework requiring this
            
        Returns:
            List of violations
        """
        violations = []
        
        if data_location not in allowed_locations:
            severity = "critical" if framework == ComplianceFramework.GDPR else "high"
            
            violation = PolicyViolation(
                violation_id=f"pol_res_{datetime.utcnow().timestamp()}",
                policy_id="data_residency",
                policy_name="Data Residency Policy",
                severity=severity,
                description=f"Data stored in unauthorized location: {data_location}",
                resource_type=resource_type,
                resource_id=resource_id,
                violation_details={
                    'current_location': data_location,
                    'allowed_locations': allowed_locations
                },
                remediation_steps=[
                    f"Migrate data to allowed location: {', '.join(allowed_locations)}",
                    "Update data storage configuration"
                ],
                auto_remediate=False,
                framework=framework
            )
            violations.append(violation)
            self.violations.append(violation)
        
        return violations
    
    def check_encryption_requirements(
        self,
        is_encrypted: bool,
        data_classification: DataClassification,
        resource_type: str,
        resource_id: Optional[str] = None
    ) -> List[PolicyViolation]:
        """
        Check if data meets encryption requirements.
        
        Args:
            is_encrypted: Whether data is encrypted
            data_classification: Data classification level
            resource_type: Type of resource
            resource_id: Resource identifier
            
        Returns:
            List of violations
        """
        violations = []
        
        # Require encryption for sensitive data
        requires_encryption = data_classification in [
            DataClassification.CONFIDENTIAL,
            DataClassification.RESTRICTED,
            DataClassification.PII,
            DataClassification.PHI,
            DataClassification.PCI
        ]
        
        if requires_encryption and not is_encrypted:
            violation = PolicyViolation(
                violation_id=f"pol_enc_{datetime.utcnow().timestamp()}",
                policy_id="encryption_policy",
                policy_name="Encryption Policy",
                severity="critical",
                description=f"Unencrypted {data_classification.value} data",
                resource_type=resource_type,
                resource_id=resource_id,
                violation_details={
                    'data_classification': data_classification.value,
                    'is_encrypted': is_encrypted
                },
                remediation_steps=[
                    "Enable encryption at rest",
                    "Enable encryption in transit",
                    "Rotate encryption keys"
                ],
                auto_remediate=False
            )
            violations.append(violation)
            self.violations.append(violation)
        
        return violations
    
    def check_access_controls(
        self,
        has_access_controls: bool,
        data_classification: DataClassification,
        resource_type: str,
        resource_id: Optional[str] = None
    ) -> List[PolicyViolation]:
        """
        Check if appropriate access controls are in place.
        
        Args:
            has_access_controls: Whether access controls exist
            data_classification: Data classification level
            resource_type: Type of resource
            resource_id: Resource identifier
            
        Returns:
            List of violations
        """
        violations = []
        
        # Require access controls for non-public data
        requires_controls = data_classification != DataClassification.PUBLIC
        
        if requires_controls and not has_access_controls:
            violation = PolicyViolation(
                violation_id=f"pol_acc_{datetime.utcnow().timestamp()}",
                policy_id="access_control_policy",
                policy_name="Access Control Policy",
                severity="high",
                description=f"Missing access controls for {data_classification.value} data",
                resource_type=resource_type,
                resource_id=resource_id,
                violation_details={
                    'data_classification': data_classification.value,
                    'has_access_controls': has_access_controls
                },
                remediation_steps=[
                    "Implement role-based access control (RBAC)",
                    "Configure authentication requirements",
                    "Enable audit logging"
                ],
                auto_remediate=False
            )
            violations.append(violation)
            self.violations.append(violation)
        
        return violations
    
    def get_violations(
        self,
        severity: Optional[str] = None,
        resolved: Optional[bool] = None,
        framework: Optional[ComplianceFramework] = None
    ) -> List[PolicyViolation]:
        """
        Get policy violations with optional filters.
        
        Args:
            severity: Filter by severity
            resolved: Filter by resolution status
            framework: Filter by compliance framework
            
        Returns:
            Filtered list of violations
        """
        violations = self.violations
        
        if severity:
            violations = [v for v in violations if v.severity == severity]
        
        if resolved is not None:
            violations = [v for v in violations if v.is_resolved == resolved]
        
        if framework:
            violations = [v for v in violations if v.framework == framework]
        
        return violations
    
    def resolve_violation(self, violation_id: str, resolved_by: str):
        """Mark violation as resolved."""
        for violation in self.violations:
            if violation.violation_id == violation_id:
                violation.is_resolved = True
                violation.resolved_at = datetime.utcnow()
                violation.resolved_by = resolved_by
                logger.info(f"Resolved violation: {violation_id}")
                break

