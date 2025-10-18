"""
Data models for remediation recommendations.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class RemediationType(Enum):
    """Types of remediation actions."""
    CODE_FIX = "code_fix"
    CONFIGURATION = "configuration"
    WAF_RULE = "waf_rule"
    NETWORK_CONTROL = "network_control"
    MONITORING = "monitoring"
    PROCESS_CHANGE = "process_change"


class RemediationPriority(Enum):
    """Priority levels for remediation."""
    IMMEDIATE = "immediate"  # Deploy within hours
    HIGH = "high"  # Deploy within days
    MEDIUM = "medium"  # Deploy within weeks
    LOW = "low"  # Deploy when convenient


@dataclass
class CodeFix:
    """Represents a code-level fix."""
    file_path: str
    line_number: Optional[int]
    vulnerable_code: str
    fixed_code: str
    explanation: str
    language: str
    diff: Optional[str] = None
    confidence: float = 0.0


@dataclass
class WAFRule:
    """Represents a WAF rule for compensating control."""
    rule_type: str  # modsecurity, aws_waf, cloudflare, etc.
    rule_content: str
    description: str
    attack_pattern: str
    false_positive_risk: str  # low, medium, high
    testing_notes: str


@dataclass
class CompensatingControl:
    """Represents a compensating security control."""
    control_type: str  # waf, rate_limiting, input_validation, etc.
    description: str
    implementation_steps: List[str]
    effectiveness: str  # high, medium, low
    limitations: List[str]
    monitoring_requirements: List[str]


@dataclass
class RemediationPlan:
    """Complete remediation plan for a vulnerability."""
    vulnerability_type: str
    severity: str
    
    # Primary remediation
    code_fixes: List[CodeFix] = field(default_factory=list)
    configuration_changes: List[str] = field(default_factory=list)
    
    # Compensating controls
    waf_rules: List[WAFRule] = field(default_factory=list)
    compensating_controls: List[CompensatingControl] = field(default_factory=list)
    
    # Additional recommendations
    immediate_actions: List[str] = field(default_factory=list)
    short_term_actions: List[str] = field(default_factory=list)
    long_term_actions: List[str] = field(default_factory=list)
    
    # Monitoring and detection
    detection_rules: List[str] = field(default_factory=list)
    monitoring_queries: List[str] = field(default_factory=list)
    
    # Testing and validation
    testing_steps: List[str] = field(default_factory=list)
    validation_criteria: List[str] = field(default_factory=list)
    
    # Metadata
    estimated_effort: str = ""  # hours, days, weeks
    risk_if_not_fixed: str = ""
    dependencies: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity,
            'code_fixes': [
                {
                    'file_path': fix.file_path,
                    'line_number': fix.line_number,
                    'vulnerable_code': fix.vulnerable_code,
                    'fixed_code': fix.fixed_code,
                    'explanation': fix.explanation,
                    'language': fix.language,
                    'confidence': fix.confidence,
                }
                for fix in self.code_fixes
            ],
            'configuration_changes': self.configuration_changes,
            'waf_rules': [
                {
                    'rule_type': rule.rule_type,
                    'rule_content': rule.rule_content,
                    'description': rule.description,
                    'attack_pattern': rule.attack_pattern,
                    'false_positive_risk': rule.false_positive_risk,
                    'testing_notes': rule.testing_notes,
                }
                for rule in self.waf_rules
            ],
            'compensating_controls': [
                {
                    'control_type': ctrl.control_type,
                    'description': ctrl.description,
                    'implementation_steps': ctrl.implementation_steps,
                    'effectiveness': ctrl.effectiveness,
                    'limitations': ctrl.limitations,
                    'monitoring_requirements': ctrl.monitoring_requirements,
                }
                for ctrl in self.compensating_controls
            ],
            'immediate_actions': self.immediate_actions,
            'short_term_actions': self.short_term_actions,
            'long_term_actions': self.long_term_actions,
            'detection_rules': self.detection_rules,
            'monitoring_queries': self.monitoring_queries,
            'testing_steps': self.testing_steps,
            'validation_criteria': self.validation_criteria,
            'estimated_effort': self.estimated_effort,
            'risk_if_not_fixed': self.risk_if_not_fixed,
            'dependencies': self.dependencies,
        }

