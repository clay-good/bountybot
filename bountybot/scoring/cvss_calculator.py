import logging
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
import math

logger = logging.getLogger(__name__)


# CVSS v3.1 Metric Enums
class AttackVector(Enum):
    """Attack Vector (AV) - How the vulnerability is exploited."""
    NETWORK = ("N", 0.85, "Remotely exploitable")
    ADJACENT = ("A", 0.62, "Adjacent network access required")
    LOCAL = ("L", 0.55, "Local access required")
    PHYSICAL = ("P", 0.20, "Physical access required")


class AttackComplexity(Enum):
    """Attack Complexity (AC) - Complexity of the attack."""
    LOW = ("L", 0.77, "No special conditions")
    HIGH = ("H", 0.44, "Special conditions required")


class PrivilegesRequired(Enum):
    """Privileges Required (PR) - Level of privileges needed."""
    NONE = ("N", 0.85, "No privileges required")
    LOW = ("L", 0.62, "Low privileges required")  # 0.68 if scope changed
    HIGH = ("H", 0.27, "High privileges required")  # 0.50 if scope changed


class UserInteraction(Enum):
    """User Interaction (UI) - Whether user interaction is required."""
    NONE = ("N", 0.85, "No user interaction")
    REQUIRED = ("R", 0.62, "User interaction required")


class Scope(Enum):
    """Scope (S) - Whether the vulnerability affects other components."""
    UNCHANGED = ("U", "Impacts only the vulnerable component")
    CHANGED = ("C", "Impacts beyond the vulnerable component")


class ImpactMetric(Enum):
    """Impact metrics for Confidentiality, Integrity, Availability."""
    NONE = ("N", 0.0, "No impact")
    LOW = ("L", 0.22, "Limited impact")
    HIGH = ("H", 0.56, "Total impact")


class ExploitCodeMaturity(Enum):
    """Temporal: Exploit Code Maturity."""
    NOT_DEFINED = ("X", 1.0)
    UNPROVEN = ("U", 0.91)
    PROOF_OF_CONCEPT = ("P", 0.94)
    FUNCTIONAL = ("F", 0.97)
    HIGH = ("H", 1.0)


class RemediationLevel(Enum):
    """Temporal: Remediation Level."""
    NOT_DEFINED = ("X", 1.0)
    OFFICIAL_FIX = ("O", 0.95)
    TEMPORARY_FIX = ("T", 0.96)
    WORKAROUND = ("W", 0.97)
    UNAVAILABLE = ("U", 1.0)


class ReportConfidence(Enum):
    """Temporal: Report Confidence."""
    NOT_DEFINED = ("X", 1.0)
    UNKNOWN = ("U", 0.92)
    REASONABLE = ("R", 0.96)
    CONFIRMED = ("C", 1.0)


@dataclass
class CVSSv31Score:
    """CVSS v3.1 Score with detailed breakdown."""
    
    # Base Metrics
    attack_vector: AttackVector
    attack_complexity: AttackComplexity
    privileges_required: PrivilegesRequired
    user_interaction: UserInteraction
    scope: Scope
    confidentiality_impact: ImpactMetric
    integrity_impact: ImpactMetric
    availability_impact: ImpactMetric
    
    # Temporal Metrics (optional)
    exploit_code_maturity: ExploitCodeMaturity = ExploitCodeMaturity.NOT_DEFINED
    remediation_level: RemediationLevel = RemediationLevel.NOT_DEFINED
    report_confidence: ReportConfidence = ReportConfidence.NOT_DEFINED
    
    # Calculated scores
    base_score: float = 0.0
    temporal_score: float = 0.0
    severity_rating: str = ""
    vector_string: str = ""
    
    # Detailed breakdown
    exploitability_score: float = 0.0
    impact_score: float = 0.0
    
    def __post_init__(self):
        """Calculate scores after initialization."""
        self.calculate_scores()
    
    def calculate_scores(self):
        """Calculate CVSS v3.1 scores."""
        # Calculate Impact Sub-Score
        isc_base = 1 - (
            (1 - self.confidentiality_impact.value[1]) *
            (1 - self.integrity_impact.value[1]) *
            (1 - self.availability_impact.value[1])
        )
        
        if self.scope == Scope.UNCHANGED:
            self.impact_score = 6.42 * isc_base
        else:
            self.impact_score = 7.52 * (isc_base - 0.029) - 3.25 * math.pow(isc_base - 0.02, 15)
        
        # Calculate Exploitability Sub-Score
        pr_value = self.privileges_required.value[1]
        if self.scope == Scope.CHANGED and self.privileges_required != PrivilegesRequired.NONE:
            # Adjust PR value for scope change
            if self.privileges_required == PrivilegesRequired.LOW:
                pr_value = 0.68
            elif self.privileges_required == PrivilegesRequired.HIGH:
                pr_value = 0.50
        
        self.exploitability_score = (
            8.22 *
            self.attack_vector.value[1] *
            self.attack_complexity.value[1] *
            pr_value *
            self.user_interaction.value[1]
        )
        
        # Calculate Base Score
        if self.impact_score <= 0:
            self.base_score = 0.0
        else:
            if self.scope == Scope.UNCHANGED:
                self.base_score = min(self.impact_score + self.exploitability_score, 10.0)
            else:
                self.base_score = min(1.08 * (self.impact_score + self.exploitability_score), 10.0)
        
        # Round up to 1 decimal
        self.base_score = math.ceil(self.base_score * 10) / 10
        
        # Calculate Temporal Score
        temporal_multiplier = (
            self.exploit_code_maturity.value[1] *
            self.remediation_level.value[1] *
            self.report_confidence.value[1]
        )
        self.temporal_score = math.ceil(self.base_score * temporal_multiplier * 10) / 10
        
        # Determine severity rating
        if self.base_score == 0.0:
            self.severity_rating = "None"
        elif self.base_score < 4.0:
            self.severity_rating = "Low"
        elif self.base_score < 7.0:
            self.severity_rating = "Medium"
        elif self.base_score < 9.0:
            self.severity_rating = "High"
        else:
            self.severity_rating = "Critical"
        
        # Generate vector string
        self.vector_string = self._generate_vector_string()
    
    def _generate_vector_string(self) -> str:
        """Generate CVSS v3.1 vector string."""
        vector = f"CVSS:3.1/AV:{self.attack_vector.value[0]}"
        vector += f"/AC:{self.attack_complexity.value[0]}"
        vector += f"/PR:{self.privileges_required.value[0]}"
        vector += f"/UI:{self.user_interaction.value[0]}"
        vector += f"/S:{self.scope.value[0]}"
        vector += f"/C:{self.confidentiality_impact.value[0]}"
        vector += f"/I:{self.integrity_impact.value[0]}"
        vector += f"/A:{self.availability_impact.value[0]}"
        
        # Add temporal metrics if defined
        if self.exploit_code_maturity != ExploitCodeMaturity.NOT_DEFINED:
            vector += f"/E:{self.exploit_code_maturity.value[0]}"
        if self.remediation_level != RemediationLevel.NOT_DEFINED:
            vector += f"/RL:{self.remediation_level.value[0]}"
        if self.report_confidence != ReportConfidence.NOT_DEFINED:
            vector += f"/RC:{self.report_confidence.value[0]}"
        
        return vector
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "version": "3.1",
            "vector_string": self.vector_string,
            "base_score": self.base_score,
            "temporal_score": self.temporal_score,
            "severity_rating": self.severity_rating,
            "exploitability_score": round(self.exploitability_score, 2),
            "impact_score": round(self.impact_score, 2),
            "metrics": {
                "attack_vector": {
                    "value": self.attack_vector.value[0],
                    "description": self.attack_vector.value[2]
                },
                "attack_complexity": {
                    "value": self.attack_complexity.value[0],
                    "description": self.attack_complexity.value[2]
                },
                "privileges_required": {
                    "value": self.privileges_required.value[0],
                    "description": self.privileges_required.value[2]
                },
                "user_interaction": {
                    "value": self.user_interaction.value[0],
                    "description": self.user_interaction.value[2]
                },
                "scope": {
                    "value": self.scope.value[0],
                    "description": self.scope.value[1]
                },
                "confidentiality_impact": {
                    "value": self.confidentiality_impact.value[0],
                    "description": self.confidentiality_impact.value[2]
                },
                "integrity_impact": {
                    "value": self.integrity_impact.value[0],
                    "description": self.integrity_impact.value[2]
                },
                "availability_impact": {
                    "value": self.availability_impact.value[0],
                    "description": self.availability_impact.value[2]
                }
            }
        }


class CVSSCalculator:
    """
    Automatic CVSS calculator that analyzes vulnerability reports
    and generates CVSS scores.
    """
    
    def __init__(self):
        """Initialize CVSS calculator."""
        self.vulnerability_profiles = self._load_vulnerability_profiles()
    
    def _load_vulnerability_profiles(self) -> Dict[str, Dict[str, Any]]:
        """Load default CVSS profiles for common vulnerability types."""
        return {
            "sql injection": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality_impact": ImpactMetric.HIGH,
                "integrity_impact": ImpactMetric.HIGH,
                "availability_impact": ImpactMetric.HIGH,
            },
            "xss": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.REQUIRED,
                "scope": Scope.CHANGED,
                "confidentiality_impact": ImpactMetric.LOW,
                "integrity_impact": ImpactMetric.LOW,
                "availability_impact": ImpactMetric.NONE,
            },
            "ssrf": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.LOW,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.CHANGED,
                "confidentiality_impact": ImpactMetric.HIGH,
                "integrity_impact": ImpactMetric.LOW,
                "availability_impact": ImpactMetric.LOW,
            },
            "rce": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.CHANGED,
                "confidentiality_impact": ImpactMetric.HIGH,
                "integrity_impact": ImpactMetric.HIGH,
                "availability_impact": ImpactMetric.HIGH,
            },
            "command injection": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.LOW,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality_impact": ImpactMetric.HIGH,
                "integrity_impact": ImpactMetric.HIGH,
                "availability_impact": ImpactMetric.HIGH,
            },
            "idor": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.LOW,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality_impact": ImpactMetric.HIGH,
                "integrity_impact": ImpactMetric.LOW,
                "availability_impact": ImpactMetric.NONE,
            },
            "csrf": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.REQUIRED,
                "scope": Scope.UNCHANGED,
                "confidentiality_impact": ImpactMetric.NONE,
                "integrity_impact": ImpactMetric.HIGH,
                "availability_impact": ImpactMetric.NONE,
            },
            "authentication bypass": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.CHANGED,
                "confidentiality_impact": ImpactMetric.HIGH,
                "integrity_impact": ImpactMetric.HIGH,
                "availability_impact": ImpactMetric.HIGH,
            },
            "path traversal": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.LOW,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality_impact": ImpactMetric.HIGH,
                "integrity_impact": ImpactMetric.NONE,
                "availability_impact": ImpactMetric.NONE,
            },
            "xxe": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality_impact": ImpactMetric.HIGH,
                "integrity_impact": ImpactMetric.LOW,
                "availability_impact": ImpactMetric.LOW,
            },
            "deserialization": {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.LOW,
                "privileges_required": PrivilegesRequired.NONE,
                "user_interaction": UserInteraction.NONE,
                "scope": Scope.UNCHANGED,
                "confidentiality_impact": ImpactMetric.HIGH,
                "integrity_impact": ImpactMetric.HIGH,
                "availability_impact": ImpactMetric.HIGH,
            },
        }

    def calculate_from_report(self, report, validation_result=None) -> CVSSv31Score:
        """
        Calculate CVSS score from a vulnerability report.

        Args:
            report: Bug bounty report
            validation_result: Optional validation result for context

        Returns:
            CVSSv31Score with calculated metrics
        """
        vuln_type = (report.vulnerability_type or "").lower()

        # Start with default profile for vulnerability type
        profile = self.vulnerability_profiles.get(vuln_type, {})

        # If no profile, use conservative defaults
        if not profile:
            logger.warning(f"No CVSS profile for vulnerability type: {vuln_type}")
            profile = {
                "attack_vector": AttackVector.NETWORK,
                "attack_complexity": AttackComplexity.HIGH,
                "privileges_required": PrivilegesRequired.LOW,
                "user_interaction": UserInteraction.REQUIRED,
                "scope": Scope.UNCHANGED,
                "confidentiality_impact": ImpactMetric.LOW,
                "integrity_impact": ImpactMetric.LOW,
                "availability_impact": ImpactMetric.NONE,
            }

        # Adjust based on report details
        profile = self._adjust_metrics_from_report(profile, report, validation_result)

        # Set temporal metrics based on validation
        temporal_metrics = self._determine_temporal_metrics(report, validation_result)

        score = CVSSv31Score(
            **profile,
            **temporal_metrics
        )

        logger.info(f"Calculated CVSS score: {score.base_score} ({score.severity_rating}) for {report.title}")
        return score

    def _adjust_metrics_from_report(self, profile: Dict, report, validation_result) -> Dict:
        """Adjust CVSS metrics based on report details."""
        adjusted = profile.copy()

        # Analyze report description for clues
        description = (report.impact_description or "").lower()
        steps = " ".join(report.reproduction_steps or []).lower()
        combined_text = f"{description} {steps}"

        # Adjust Attack Complexity
        if any(word in combined_text for word in ["race condition", "timing", "complex", "multiple steps"]):
            adjusted["attack_complexity"] = AttackComplexity.HIGH

        # Adjust Privileges Required
        if any(word in combined_text for word in ["unauthenticated", "no auth", "anonymous"]):
            adjusted["privileges_required"] = PrivilegesRequired.NONE
        elif any(word in combined_text for word in ["admin", "administrator", "root"]):
            adjusted["privileges_required"] = PrivilegesRequired.HIGH

        # Adjust User Interaction
        if any(word in combined_text for word in ["click", "visit", "open", "social engineering"]):
            adjusted["user_interaction"] = UserInteraction.REQUIRED

        # Adjust Scope
        if any(word in combined_text for word in ["other users", "all users", "system-wide", "cross-tenant"]):
            adjusted["scope"] = Scope.CHANGED

        # Adjust Impact based on severity keywords
        if any(word in combined_text for word in ["complete", "full", "total", "all data"]):
            adjusted["confidentiality_impact"] = ImpactMetric.HIGH
            adjusted["integrity_impact"] = ImpactMetric.HIGH
        elif any(word in combined_text for word in ["limited", "partial", "some"]):
            if adjusted["confidentiality_impact"] == ImpactMetric.HIGH:
                adjusted["confidentiality_impact"] = ImpactMetric.LOW
            if adjusted["integrity_impact"] == ImpactMetric.HIGH:
                adjusted["integrity_impact"] = ImpactMetric.LOW

        # Adjust based on affected components
        if report.affected_components and len(report.affected_components) > 0:
            component = " ".join(report.affected_components).lower()
            if any(word in component for word in ["api", "endpoint", "service"]):
                adjusted["attack_vector"] = AttackVector.NETWORK
            elif any(word in component for word in ["local", "file", "desktop"]):
                adjusted["attack_vector"] = AttackVector.LOCAL

        return adjusted

    def _determine_temporal_metrics(self, report, validation_result) -> Dict:
        """Determine temporal metrics based on validation."""
        temporal = {
            "exploit_code_maturity": ExploitCodeMaturity.NOT_DEFINED,
            "remediation_level": RemediationLevel.UNAVAILABLE,
            "report_confidence": ReportConfidence.NOT_DEFINED,
        }

        # Exploit Code Maturity
        if report.proof_of_concept:
            poc_text = str(report.proof_of_concept).lower()
            if any(word in poc_text for word in ["exploit", "working", "functional"]):
                temporal["exploit_code_maturity"] = ExploitCodeMaturity.FUNCTIONAL
            else:
                temporal["exploit_code_maturity"] = ExploitCodeMaturity.PROOF_OF_CONCEPT

        # Report Confidence based on validation
        if validation_result:
            if validation_result.confidence >= 80:
                temporal["report_confidence"] = ReportConfidence.CONFIRMED
            elif validation_result.confidence >= 60:
                temporal["report_confidence"] = ReportConfidence.REASONABLE
            else:
                temporal["report_confidence"] = ReportConfidence.UNKNOWN

        return temporal

