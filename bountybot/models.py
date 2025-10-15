from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
from enum import Enum


class Verdict(Enum):
    """Validation verdict options."""
    VALID = "VALID"
    INVALID = "INVALID"
    UNCERTAIN = "UNCERTAIN"


class Severity(Enum):
    """Vulnerability severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Report:
    """
    Standardized bug bounty report structure.
    All parsers convert their input to this format.
    """
    title: str
    researcher: Optional[str] = None
    submission_date: Optional[datetime] = None
    vulnerability_type: Optional[str] = None
    severity: Optional[Severity] = None
    severity_justification: Optional[str] = None
    affected_components: List[str] = field(default_factory=list)
    reproduction_steps: List[str] = field(default_factory=list)
    proof_of_concept: Optional[str] = None
    impact_description: Optional[str] = None
    attachments: List[str] = field(default_factory=list)
    raw_content: Optional[str] = None
    
    # Parsing metadata
    parsing_confidence: Dict[str, float] = field(default_factory=dict)
    missing_fields: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            'title': self.title,
            'researcher': self.researcher,
            'submission_date': self.submission_date.isoformat() if self.submission_date else None,
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity.value if self.severity else None,
            'severity_justification': self.severity_justification,
            'affected_components': self.affected_components,
            'reproduction_steps': self.reproduction_steps,
            'proof_of_concept': self.proof_of_concept,
            'impact_description': self.impact_description,
            'attachments': self.attachments,
            'parsing_confidence': self.parsing_confidence,
            'missing_fields': self.missing_fields,
        }


@dataclass
class QualityAssessment:
    """Report quality assessment from AI."""
    quality_score: int  # 1-10
    completeness_score: int  # 1-10
    technical_accuracy: int  # 1-10
    missing_elements: List[str] = field(default_factory=list)
    concerns: List[str] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'quality_score': self.quality_score,
            'completeness_score': self.completeness_score,
            'technical_accuracy': self.technical_accuracy,
            'missing_elements': self.missing_elements,
            'concerns': self.concerns,
            'strengths': self.strengths,
        }


@dataclass
class PlausibilityAnalysis:
    """Technical plausibility analysis from AI."""
    plausibility_score: int  # 0-100
    preconditions_met: List[str] = field(default_factory=list)
    preconditions_missing: List[str] = field(default_factory=list)
    red_flags: List[str] = field(default_factory=list)
    additional_evidence_needed: List[str] = field(default_factory=list)
    reasoning: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'plausibility_score': self.plausibility_score,
            'preconditions_met': self.preconditions_met,
            'preconditions_missing': self.preconditions_missing,
            'red_flags': self.red_flags,
            'additional_evidence_needed': self.additional_evidence_needed,
            'reasoning': self.reasoning,
        }


@dataclass
class CodeAnalysisResult:
    """Results from static code analysis."""
    vulnerable_code_found: bool
    vulnerable_files: List[str] = field(default_factory=list)
    vulnerable_patterns: List[Dict[str, Any]] = field(default_factory=list)
    security_controls: Dict[str, bool] = field(default_factory=dict)
    confidence: int = 0  # 0-100
    analysis_notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerable_code_found': self.vulnerable_code_found,
            'vulnerable_files': self.vulnerable_files,
            'vulnerable_patterns': self.vulnerable_patterns,
            'security_controls': self.security_controls,
            'confidence': self.confidence,
            'analysis_notes': self.analysis_notes,
        }


@dataclass
class DynamicTestResult:
    """Results from dynamic testing."""
    vulnerability_confirmed: bool
    test_results: List[Dict[str, Any]] = field(default_factory=list)
    confidence: int = 0  # 0-100
    notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'vulnerability_confirmed': self.vulnerability_confirmed,
            'test_results': self.test_results,
            'confidence': self.confidence,
            'notes': self.notes,
        }


@dataclass
class ValidationResult:
    """
    Complete validation result combining all analysis passes.
    """
    report: Report
    verdict: Verdict
    confidence: int  # 0-100

    # Analysis components
    quality_assessment: Optional[QualityAssessment] = None
    plausibility_analysis: Optional[PlausibilityAnalysis] = None
    code_analysis: Optional[CodeAnalysisResult] = None
    dynamic_test: Optional[DynamicTestResult] = None

    # Enhanced features
    extracted_http_requests: List[Any] = field(default_factory=list)  # List of HTTPRequest objects
    generated_poc: Optional[Any] = None  # ProofOfConcept object
    http_validation_issues: List[str] = field(default_factory=list)

    # Final reasoning
    key_findings: List[str] = field(default_factory=list)
    reasoning: Optional[str] = None
    recommendations_security_team: List[str] = field(default_factory=list)
    recommendations_researcher: List[str] = field(default_factory=list)

    # New advanced features
    cvss_score: Optional[Any] = None  # CVSSv31Score object
    duplicate_check: Optional[Any] = None  # DuplicateMatch object
    exploit_complexity_score: Optional[float] = None  # 0-100
    false_positive_indicators: List[str] = field(default_factory=list)
    attack_chain: Optional[Any] = None  # AttackChain object
    priority_score: Optional[Any] = None  # PriorityScore object

    # Performance metrics
    stage_timings: Dict[str, float] = field(default_factory=dict)  # Stage name -> duration in seconds
    cache_hits: int = 0
    cache_misses: int = 0

    # Metadata
    validation_timestamp: datetime = field(default_factory=datetime.now)
    request_id: Optional[str] = None
    ai_provider: Optional[str] = None
    ai_model: Optional[str] = None
    total_cost: float = 0.0
    processing_time_seconds: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert validation result to dictionary."""
        return {
            'report': self.report.to_dict(),
            'verdict': self.verdict.value,
            'confidence': self.confidence,
            'quality_assessment': self.quality_assessment.to_dict() if self.quality_assessment else None,
            'plausibility_analysis': self.plausibility_analysis.to_dict() if self.plausibility_analysis else None,
            'code_analysis': self.code_analysis.to_dict() if self.code_analysis else None,
            'dynamic_test': self.dynamic_test.to_dict() if self.dynamic_test else None,
            'extracted_http_requests': [req.to_dict() for req in self.extracted_http_requests] if self.extracted_http_requests else [],
            'generated_poc': self.generated_poc.to_dict() if self.generated_poc else None,
            'http_validation_issues': self.http_validation_issues,
            'key_findings': self.key_findings,
            'reasoning': self.reasoning,
            'recommendations_security_team': self.recommendations_security_team,
            'recommendations_researcher': self.recommendations_researcher,
            'validation_timestamp': self.validation_timestamp.isoformat(),
            'ai_provider': self.ai_provider,
            'ai_model': self.ai_model,
            'total_cost': self.total_cost,
            'processing_time_seconds': self.processing_time_seconds,
        }


@dataclass
class CostTracking:
    """Track API costs during validation."""
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    total_cost: float = 0.0
    requests: int = 0
    
    def add_request(self, input_tokens: int, output_tokens: int, cost: float):
        """Add a request to cost tracking."""
        self.input_tokens += input_tokens
        self.output_tokens += output_tokens
        self.total_cost += cost
        self.requests += 1
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'provider': self.provider,
            'model': self.model,
            'input_tokens': self.input_tokens,
            'output_tokens': self.output_tokens,
            'total_cost': self.total_cost,
            'requests': self.requests,
        }

