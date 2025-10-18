"""
Compliance & Regulatory Framework Module

Provides enterprise-grade compliance management:
- Compliance framework definitions (SOC 2, GDPR, HIPAA, PCI-DSS, ISO 27001)
- Data classification and labeling
- PII detection and anonymization
- Data retention policies and enforcement
- Compliance reporting and dashboards
- Policy enforcement engine
- Regulatory audit trails
- Data residency controls
- Consent management
- Evidence collection for audits
- Compliance scoring and gap analysis
"""

from .models import (
    ComplianceFramework,
    ComplianceControl,
    ComplianceRequirement,
    DataClassification,
    DataRetentionPolicy,
    PIIType,
    ConsentRecord,
    ComplianceReport,
    ComplianceStatus,
    ControlStatus,
    DataResidency,
    DataProcessingActivity
)
from .compliance_manager import ComplianceManager
from .pii_detector import PIIDetector, PIIMatch
from .data_anonymizer import DataAnonymizer, AnonymizationStrategy
from .policy_engine import PolicyEngine, PolicyViolation
from .retention_manager import RetentionManager
from .consent_manager import ConsentManager

__all__ = [
    # Models
    'ComplianceFramework',
    'ComplianceControl',
    'ComplianceRequirement',
    'DataClassification',
    'DataRetentionPolicy',
    'PIIType',
    'ConsentRecord',
    'ComplianceReport',
    'ComplianceStatus',
    'ControlStatus',
    'DataResidency',
    'DataProcessingActivity',

    # Core managers
    'ComplianceManager',
    'PIIDetector',
    'PIIMatch',
    'DataAnonymizer',
    'AnonymizationStrategy',
    'PolicyEngine',
    'PolicyViolation',
    'RetentionManager',
    'ConsentManager'
]

__version__ = '1.0.0'

