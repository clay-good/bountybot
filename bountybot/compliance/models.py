"""
Compliance Data Models

Defines compliance frameworks, controls, requirements, and policies.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Set
from enum import Enum
import uuid


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    SOC2_TYPE1 = "soc2_type1"
    SOC2_TYPE2 = "soc2_type2"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    ISO_27001 = "iso_27001"
    CCPA = "ccpa"
    NIST_CSF = "nist_csf"
    FedRAMP = "fedramp"


class ControlStatus(str, Enum):
    """Control implementation status."""
    NOT_IMPLEMENTED = "not_implemented"
    PARTIALLY_IMPLEMENTED = "partially_implemented"
    IMPLEMENTED = "implemented"
    VERIFIED = "verified"
    NON_COMPLIANT = "non_compliant"


class ComplianceStatus(str, Enum):
    """Overall compliance status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    UNDER_REVIEW = "under_review"
    NOT_ASSESSED = "not_assessed"


class DataClassification(str, Enum):
    """Data classification levels."""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    PII = "pii"
    PHI = "phi"  # Protected Health Information
    PCI = "pci"  # Payment Card Information


class PIIType(str, Enum):
    """Types of Personally Identifiable Information."""
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    NAME = "name"
    ADDRESS = "address"
    DATE_OF_BIRTH = "date_of_birth"
    PASSPORT = "passport"
    DRIVERS_LICENSE = "drivers_license"
    MEDICAL_RECORD = "medical_record"
    FINANCIAL_ACCOUNT = "financial_account"


class DataResidency(str, Enum):
    """Data residency regions."""
    US = "us"
    EU = "eu"
    UK = "uk"
    CANADA = "canada"
    AUSTRALIA = "australia"
    JAPAN = "japan"
    SINGAPORE = "singapore"
    GLOBAL = "global"


@dataclass
class ComplianceControl:
    """Individual compliance control."""
    control_id: str
    framework: ComplianceFramework
    control_number: str  # e.g., "CC6.1" for SOC 2
    title: str
    description: str
    
    # Implementation
    status: ControlStatus = ControlStatus.NOT_IMPLEMENTED
    implementation_notes: Optional[str] = None
    evidence: List[str] = field(default_factory=list)  # Evidence file paths/URLs
    
    # Testing
    last_tested: Optional[datetime] = None
    test_results: Optional[str] = None
    test_frequency_days: int = 90
    
    # Ownership
    owner: Optional[str] = None
    responsible_team: Optional[str] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    
    def needs_testing(self) -> bool:
        """Check if control needs testing."""
        if not self.last_tested:
            return True
        next_test = self.last_tested + timedelta(days=self.test_frequency_days)
        return datetime.utcnow() > next_test


@dataclass
class ComplianceRequirement:
    """Compliance requirement mapping."""
    requirement_id: str
    framework: ComplianceFramework
    requirement_text: str
    controls: List[str] = field(default_factory=list)  # Control IDs
    
    # Assessment
    is_applicable: bool = True
    assessment_notes: Optional[str] = None
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class DataRetentionPolicy:
    """Data retention policy."""
    policy_id: str
    name: str
    description: str
    
    # Scope
    data_types: List[str] = field(default_factory=list)
    data_classification: Optional[DataClassification] = None
    
    # Retention
    retention_period_days: int = 365
    archive_after_days: Optional[int] = None
    
    # Deletion
    auto_delete: bool = True
    deletion_method: str = "soft_delete"  # soft_delete, hard_delete, anonymize
    
    # Legal hold
    legal_hold_exempt: bool = False
    
    # Compliance
    frameworks: List[ComplianceFramework] = field(default_factory=list)
    
    # Metadata
    is_active: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None


@dataclass
class ConsentRecord:
    """User consent record for data processing."""
    consent_id: str
    user_id: str
    purpose: str  # e.g., "marketing", "analytics", "data_processing"
    consent_text: str

    # Optional fields
    org_id: Optional[str] = None
    consent_given: bool = False
    
    # Timestamps
    consent_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    withdrawn_date: Optional[datetime] = None
    
    # Audit
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def is_valid(self) -> bool:
        """Check if consent is currently valid."""
        if not self.consent_given:
            return False
        if self.withdrawn_date:
            return False
        if self.expiry_date and datetime.utcnow() > self.expiry_date:
            return False
        return True


@dataclass
class ComplianceReport:
    """Compliance assessment report."""
    report_id: str
    framework: ComplianceFramework
    
    # Assessment
    status: ComplianceStatus
    assessment_date: datetime
    assessor: Optional[str] = None
    
    # Scores
    total_controls: int = 0
    implemented_controls: int = 0
    compliant_controls: int = 0
    compliance_score: float = 0.0  # 0-100
    
    # Findings
    gaps: List[Dict[str, Any]] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    # Evidence
    evidence_collected: List[str] = field(default_factory=list)
    
    # Next steps
    next_assessment_date: Optional[datetime] = None
    remediation_deadline: Optional[datetime] = None
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def calculate_score(self):
        """Calculate compliance score."""
        if self.total_controls == 0:
            self.compliance_score = 0.0
        else:
            self.compliance_score = (self.compliant_controls / self.total_controls) * 100


@dataclass
class DataProcessingActivity:
    """GDPR Article 30 - Record of Processing Activities."""
    activity_id: str
    name: str
    description: str
    
    # Data controller/processor
    controller_name: str
    controller_contact: str
    is_processor: bool = False
    
    # Data subjects
    data_subject_categories: List[str] = field(default_factory=list)
    
    # Personal data
    personal_data_categories: List[PIIType] = field(default_factory=list)
    special_categories: List[str] = field(default_factory=list)
    
    # Recipients
    recipient_categories: List[str] = field(default_factory=list)
    
    # Transfers
    third_country_transfers: List[str] = field(default_factory=list)
    transfer_safeguards: Optional[str] = None
    
    # Retention
    retention_period: str = ""
    
    # Security
    security_measures: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

