"""
Database Models

SQLAlchemy ORM models for persistent storage.
"""

import json
from datetime import datetime
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column, Integer, String, Text, Float, Boolean, DateTime,
    ForeignKey, JSON, Index, Enum as SQLEnum
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import enum

Base = declarative_base()


class VerdictEnum(enum.Enum):
    """Validation verdict."""
    VALID = "VALID"
    INVALID = "INVALID"
    UNCERTAIN = "UNCERTAIN"


class SeverityEnum(enum.Enum):
    """Vulnerability severity."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PriorityEnum(enum.Enum):
    """Priority level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class StatusEnum(enum.Enum):
    """Report status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    RESOLVED = "resolved"
    REJECTED = "rejected"
    DUPLICATE = "duplicate"


class Report(Base):
    """Bug bounty report."""
    __tablename__ = 'reports'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Report metadata
    external_id = Column(String(255), unique=True, index=True)  # ID from bug bounty platform
    title = Column(String(500), nullable=False, index=True)
    submission_date = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Researcher information
    researcher_id = Column(Integer, ForeignKey('researchers.id'), index=True)
    researcher = relationship("Researcher", back_populates="reports")
    
    # Vulnerability details
    vulnerability_type = Column(String(100), index=True)
    severity = Column(SQLEnum(SeverityEnum), index=True)
    severity_justification = Column(Text)
    
    # Technical details
    affected_components = Column(JSON)  # List of affected components
    reproduction_steps = Column(JSON)   # List of steps
    proof_of_concept = Column(Text)
    impact_description = Column(Text)
    
    # Status and workflow
    status = Column(SQLEnum(StatusEnum), default=StatusEnum.PENDING, index=True)
    assigned_to = Column(String(255))
    resolution_date = Column(DateTime, nullable=True)
    
    # Raw content
    raw_content = Column(Text)
    attachments = Column(JSON)  # List of attachment URLs/paths
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    validation_results = relationship(
        "ValidationResult",
        back_populates="report",
        foreign_keys="[ValidationResult.report_id]",
        cascade="all, delete-orphan"
    )
    
    # Indexes for common queries
    __table_args__ = (
        Index('idx_report_status_priority', 'status', 'severity'),
        Index('idx_report_researcher_date', 'researcher_id', 'submission_date'),
        Index('idx_report_vuln_type_severity', 'vulnerability_type', 'severity'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'external_id': self.external_id,
            'title': self.title,
            'submission_date': self.submission_date.isoformat() if self.submission_date else None,
            'researcher_id': self.researcher_id,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity.value if self.severity else None,
            'affected_components': self.affected_components,
            'status': self.status.value if self.status else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


class ValidationResult(Base):
    """Validation result for a report."""
    __tablename__ = 'validation_results'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Foreign key to report
    report_id = Column(Integer, ForeignKey('reports.id'), nullable=False, index=True)
    report = relationship("Report", back_populates="validation_results", foreign_keys=[report_id])
    
    # Validation verdict
    verdict = Column(SQLEnum(VerdictEnum), nullable=False, index=True)
    confidence = Column(Integer)  # 0-100
    
    # CVSS scoring
    cvss_base_score = Column(Float)
    cvss_temporal_score = Column(Float)
    cvss_vector_string = Column(String(200))
    cvss_severity_rating = Column(String(50))
    
    # Advanced analysis
    exploit_complexity_score = Column(Float)  # 0-100
    exploit_skill_level = Column(String(50))
    exploit_time_estimate = Column(String(50))
    
    false_positive_confidence = Column(Float)  # 0-100
    false_positive_indicators = Column(JSON)  # List of indicators
    
    is_attack_chain = Column(Boolean, default=False)
    attack_chain_length = Column(Integer)
    attack_chain_type = Column(String(50))
    attack_chain_multiplier = Column(Float)
    
    # Priority scoring
    priority_level = Column(SQLEnum(PriorityEnum), index=True)
    priority_score = Column(Float, index=True)  # 0-100
    priority_sla = Column(String(50))
    escalation_required = Column(Boolean, default=False)
    
    # Duplicate detection
    is_duplicate = Column(Boolean, default=False, index=True)
    duplicate_of_id = Column(Integer, ForeignKey('reports.id'), nullable=True)
    duplicate_confidence = Column(Float)
    
    # Performance metrics
    processing_time_seconds = Column(Float)
    ai_cost = Column(Float)
    cache_hits = Column(Integer)
    cache_misses = Column(Integer)
    
    # Detailed results (JSON)
    quality_assessment = Column(JSON)
    plausibility_analysis = Column(JSON)
    key_findings = Column(JSON)
    recommendations_security = Column(JSON)
    recommendations_researcher = Column(JSON)
    reasoning = Column(Text)
    
    # Timestamps
    validated_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_validation_verdict_priority', 'verdict', 'priority_level'),
        Index('idx_validation_duplicate', 'is_duplicate', 'duplicate_confidence'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'report_id': self.report_id,
            'verdict': self.verdict.value if self.verdict else None,
            'confidence': self.confidence,
            'cvss_base_score': self.cvss_base_score,
            'priority_level': self.priority_level.value if self.priority_level else None,
            'priority_score': self.priority_score,
            'is_duplicate': self.is_duplicate,
            'validated_at': self.validated_at.isoformat() if self.validated_at else None,
        }


class Researcher(Base):
    """Bug bounty researcher."""
    __tablename__ = 'researchers'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Researcher details
    external_id = Column(String(255), unique=True, index=True)  # ID from platform
    username = Column(String(255), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=True)
    
    # Statistics
    total_reports = Column(Integer, default=0)
    valid_reports = Column(Integer, default=0)
    invalid_reports = Column(Integer, default=0)
    duplicate_reports = Column(Integer, default=0)
    
    # Quality metrics
    average_confidence = Column(Float)  # Average confidence of valid reports
    false_positive_rate = Column(Float)  # Percentage of FP reports
    quality_score = Column(Float)  # Overall quality score 0-100
    
    # Reputation
    reputation_score = Column(Integer, default=0)
    rank = Column(String(50))  # e.g., "Novice", "Intermediate", "Expert"
    
    # Timestamps
    first_report_date = Column(DateTime)
    last_report_date = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    reports = relationship("Report", back_populates="researcher")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'total_reports': self.total_reports,
            'valid_reports': self.valid_reports,
            'quality_score': self.quality_score,
            'reputation_score': self.reputation_score,
            'rank': self.rank,
        }


class AuditLog(Base):
    """Audit log for compliance and tracking."""
    __tablename__ = 'audit_logs'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Audit details
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50), index=True)  # e.g., "report", "validation"
    resource_id = Column(Integer)
    
    # User/system information
    user = Column(String(255))
    ip_address = Column(String(50))
    user_agent = Column(String(500))
    
    # Details
    details = Column(JSON)
    result = Column(String(50))
    
    # Indexes
    __table_args__ = (
        Index('idx_audit_timestamp_action', 'timestamp', 'action'),
        Index('idx_audit_resource', 'resource_type', 'resource_id'),
    )


class Metric(Base):
    """Time-series metrics for analytics."""
    __tablename__ = 'metrics'
    
    # Primary key
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Metric details
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    metric_name = Column(String(100), nullable=False, index=True)
    metric_value = Column(Float, nullable=False)
    
    # Dimensions for grouping
    dimensions = Column(JSON)  # e.g., {"vulnerability_type": "xss", "severity": "high"}
    
    # Metadata
    unit = Column(String(50))  # e.g., "count", "seconds", "dollars"
    
    # Indexes
    __table_args__ = (
        Index('idx_metric_name_timestamp', 'metric_name', 'timestamp'),
    )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'metric_name': self.metric_name,
            'metric_value': self.metric_value,
            'dimensions': self.dimensions,
            'unit': self.unit,
        }

