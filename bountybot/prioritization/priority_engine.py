import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class PriorityLevel(Enum):
    """Priority levels for remediation."""
    CRITICAL = "critical"  # P0: Fix immediately (< 24 hours)
    HIGH = "high"          # P1: Fix within 1 week
    MEDIUM = "medium"      # P2: Fix within 1 month
    LOW = "low"            # P3: Fix when convenient
    INFO = "info"          # P4: No fix required


@dataclass
class PriorityScore:
    """Complete priority scoring for a vulnerability report."""
    overall_score: float  # 0-100
    priority_level: PriorityLevel
    
    # Component scores (0-100 each)
    cvss_score: float = 0.0
    exploitability_score: float = 0.0
    confidence_score: float = 0.0  # Inverse of FP likelihood
    chain_amplification_score: float = 0.0
    business_impact_score: float = 0.0
    
    # Weights used
    weights: Dict[str, float] = field(default_factory=dict)
    
    # Reasoning
    reasoning: str = ""
    risk_factors: List[str] = field(default_factory=list)
    mitigating_factors: List[str] = field(default_factory=list)
    
    # Recommendations
    recommended_sla: str = ""  # e.g., "24 hours", "1 week"
    recommended_assignee: Optional[str] = None
    escalation_required: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'overall_score': self.overall_score,
            'priority_level': self.priority_level.value,
            'cvss_score': self.cvss_score,
            'exploitability_score': self.exploitability_score,
            'confidence_score': self.confidence_score,
            'chain_amplification_score': self.chain_amplification_score,
            'business_impact_score': self.business_impact_score,
            'weights': self.weights,
            'reasoning': self.reasoning,
            'risk_factors': self.risk_factors,
            'mitigating_factors': self.mitigating_factors,
            'recommended_sla': self.recommended_sla,
            'recommended_assignee': self.recommended_assignee,
            'escalation_required': self.escalation_required
        }


@dataclass
class QueueItem:
    """Item in the remediation queue."""
    report_id: str
    report_title: str
    priority_score: PriorityScore
    submission_date: datetime
    age_days: int
    status: str = "pending"  # pending, in_progress, resolved, rejected
    assigned_to: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'report_id': self.report_id,
            'report_title': self.report_title,
            'priority_score': self.priority_score.to_dict(),
            'submission_date': self.submission_date.isoformat(),
            'age_days': self.age_days,
            'status': self.status,
            'assigned_to': self.assigned_to
        }


class RemediationQueue:
    """Manages prioritized queue of vulnerability reports."""
    
    def __init__(self):
        self.items: List[QueueItem] = []
    
    def add(self, item: QueueItem):
        """Add item to queue and sort by priority."""
        self.items.append(item)
        self._sort()
    
    def _sort(self):
        """Sort queue by priority score (descending) and age (ascending for ties)."""
        self.items.sort(key=lambda x: (-x.priority_score.overall_score, x.age_days), reverse=False)
    
    def get_by_priority(self, priority_level: PriorityLevel) -> List[QueueItem]:
        """Get all items of a specific priority level."""
        return [item for item in self.items if item.priority_score.priority_level == priority_level]
    
    def get_top_n(self, n: int) -> List[QueueItem]:
        """Get top N items by priority."""
        return self.items[:n]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get queue statistics."""
        total = len(self.items)
        by_priority = {}
        by_status = {}
        
        for item in self.items:
            priority = item.priority_score.priority_level.value
            status = item.status
            
            by_priority[priority] = by_priority.get(priority, 0) + 1
            by_status[status] = by_status.get(status, 0) + 1
        
        return {
            'total_items': total,
            'by_priority': by_priority,
            'by_status': by_status,
            'avg_score': sum(item.priority_score.overall_score for item in self.items) / total if total > 0 else 0
        }


class PriorityEngine:
    """
    Intelligent prioritization engine that combines multiple signals.
    
    Scoring Algorithm:
    - CVSS Score (30%): Base severity assessment
    - Exploitability (25%): How easy to exploit
    - Confidence (20%): Inverse of false positive likelihood
    - Chain Amplification (15%): Impact multiplier from attack chains
    - Business Impact (10%): Affected components and business criticality
    """
    
    # Default weights
    DEFAULT_WEIGHTS = {
        'cvss': 0.30,
        'exploitability': 0.25,
        'confidence': 0.20,
        'chain_amplification': 0.15,
        'business_impact': 0.10
    }
    
    # Priority thresholds
    PRIORITY_THRESHOLDS = {
        PriorityLevel.CRITICAL: 85,  # >= 85
        PriorityLevel.HIGH: 70,      # >= 70
        PriorityLevel.MEDIUM: 50,    # >= 50
        PriorityLevel.LOW: 30,       # >= 30
        PriorityLevel.INFO: 0        # < 30
    }
    
    # SLA recommendations by priority
    SLA_RECOMMENDATIONS = {
        PriorityLevel.CRITICAL: "24 hours",
        PriorityLevel.HIGH: "1 week",
        PriorityLevel.MEDIUM: "1 month",
        PriorityLevel.LOW: "3 months",
        PriorityLevel.INFO: "No SLA"
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize priority engine.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.weights = self.config.get('weights', self.DEFAULT_WEIGHTS)
        self.critical_components = self.config.get('critical_components', [
            'authentication', 'payment', 'database', 'api', 'admin'
        ])
        
        logger.info(f"Initialized PriorityEngine with weights: {self.weights}")
    
    def calculate_priority(self, validation_result) -> PriorityScore:
        """
        Calculate priority score for a validation result.
        
        Args:
            validation_result: ValidationResult object with all analysis
            
        Returns:
            PriorityScore with detailed breakdown
        """
        # Extract component scores
        cvss_score = self._extract_cvss_score(validation_result)
        exploitability_score = self._extract_exploitability_score(validation_result)
        confidence_score = self._extract_confidence_score(validation_result)
        chain_score = self._extract_chain_score(validation_result)
        business_score = self._calculate_business_impact(validation_result)
        
        # Calculate weighted overall score
        overall_score = (
            cvss_score * self.weights['cvss'] +
            exploitability_score * self.weights['exploitability'] +
            confidence_score * self.weights['confidence'] +
            chain_score * self.weights['chain_amplification'] +
            business_score * self.weights['business_impact']
        )
        
        # Determine priority level
        priority_level = self._determine_priority_level(overall_score)
        
        # Generate reasoning
        reasoning, risk_factors, mitigating_factors = self._generate_reasoning(
            cvss_score, exploitability_score, confidence_score, chain_score, business_score
        )
        
        # Determine if escalation needed
        escalation_required = self._should_escalate(
            priority_level, exploitability_score, chain_score
        )
        
        return PriorityScore(
            overall_score=round(overall_score, 1),
            priority_level=priority_level,
            cvss_score=cvss_score,
            exploitability_score=exploitability_score,
            confidence_score=confidence_score,
            chain_amplification_score=chain_score,
            business_impact_score=business_score,
            weights=self.weights,
            reasoning=reasoning,
            risk_factors=risk_factors,
            mitigating_factors=mitigating_factors,
            recommended_sla=self.SLA_RECOMMENDATIONS[priority_level],
            escalation_required=escalation_required
        )
    
    def _extract_cvss_score(self, result) -> float:
        """Extract and normalize CVSS score to 0-100."""
        if result.cvss_score and hasattr(result.cvss_score, 'base_score'):
            # CVSS is 0-10, normalize to 0-100
            return result.cvss_score.base_score * 10
        
        # Fallback to severity
        severity_map = {
            'CRITICAL': 95,
            'HIGH': 75,
            'MEDIUM': 50,
            'LOW': 25,
            'INFO': 10
        }
        severity = result.report.severity.value if result.report.severity else 'MEDIUM'
        return severity_map.get(severity, 50)
    
    def _extract_exploitability_score(self, result) -> float:
        """Extract exploitability score (0-100, higher = easier to exploit)."""
        if result.exploit_complexity_score is not None:
            return result.exploit_complexity_score
        return 50.0  # Default moderate complexity
    
    def _extract_confidence_score(self, result) -> float:
        """Extract confidence score (inverse of FP likelihood)."""
        # Check if we have FP indicators
        if hasattr(result, 'false_positive_indicators') and result.false_positive_indicators:
            # If it's a list of strings, count them
            if isinstance(result.false_positive_indicators, list):
                fp_count = len(result.false_positive_indicators)
                # More indicators = lower confidence
                confidence = max(0, 100 - (fp_count * 15))
                return confidence
        
        # Use validation confidence
        return result.confidence if result.confidence else 70.0
    
    def _extract_chain_score(self, result) -> float:
        """Extract attack chain amplification score."""
        # Check for attack chain in result
        if hasattr(result, 'attack_chain'):
            chain = result.attack_chain
            if chain and hasattr(chain, 'is_chain') and chain.is_chain:
                # Use impact multiplier: 1.0x = 0, 3.0x = 100
                multiplier = chain.impact_multiplier if hasattr(chain, 'impact_multiplier') else 1.0
                return min(100, (multiplier - 1.0) * 50)
        return 0.0  # No chain
    
    def _calculate_business_impact(self, result) -> float:
        """Calculate business impact based on affected components."""
        affected = result.report.affected_components
        if not affected:
            return 50.0  # Default moderate impact
        
        # Check if any critical components are affected
        critical_affected = any(
            any(crit in comp.lower() for crit in self.critical_components)
            for comp in affected
        )
        
        if critical_affected:
            return 90.0  # High business impact
        
        return 60.0  # Moderate business impact
    
    def _determine_priority_level(self, score: float) -> PriorityLevel:
        """Determine priority level from overall score."""
        if score >= self.PRIORITY_THRESHOLDS[PriorityLevel.CRITICAL]:
            return PriorityLevel.CRITICAL
        elif score >= self.PRIORITY_THRESHOLDS[PriorityLevel.HIGH]:
            return PriorityLevel.HIGH
        elif score >= self.PRIORITY_THRESHOLDS[PriorityLevel.MEDIUM]:
            return PriorityLevel.MEDIUM
        elif score >= self.PRIORITY_THRESHOLDS[PriorityLevel.LOW]:
            return PriorityLevel.LOW
        else:
            return PriorityLevel.INFO

    def _generate_reasoning(self, cvss: float, exploit: float, confidence: float,
                           chain: float, business: float) -> tuple:
        """Generate human-readable reasoning for priority score."""
        risk_factors = []
        mitigating_factors = []

        # Analyze CVSS
        if cvss >= 90:
            risk_factors.append(f"Critical CVSS score ({cvss/10:.1f}/10)")
        elif cvss >= 70:
            risk_factors.append(f"High CVSS score ({cvss/10:.1f}/10)")
        elif cvss < 40:
            mitigating_factors.append(f"Low CVSS score ({cvss/10:.1f}/10)")

        # Analyze exploitability
        if exploit >= 80:
            risk_factors.append(f"Very easy to exploit (score: {exploit:.0f}/100)")
        elif exploit >= 60:
            risk_factors.append(f"Moderately easy to exploit (score: {exploit:.0f}/100)")
        elif exploit < 40:
            mitigating_factors.append(f"Difficult to exploit (score: {exploit:.0f}/100)")

        # Analyze confidence
        if confidence < 50:
            mitigating_factors.append(f"Low confidence / possible false positive ({confidence:.0f}%)")
        elif confidence >= 80:
            risk_factors.append(f"High confidence report ({confidence:.0f}%)")

        # Analyze chain
        if chain > 50:
            risk_factors.append(f"Part of attack chain (amplification: {chain:.0f}%)")

        # Analyze business impact
        if business >= 80:
            risk_factors.append("Affects critical business components")

        # Generate reasoning text
        reasoning_parts = []
        if risk_factors:
            reasoning_parts.append(f"Risk factors: {'; '.join(risk_factors)}")
        if mitigating_factors:
            reasoning_parts.append(f"Mitigating factors: {'; '.join(mitigating_factors)}")

        reasoning = ". ".join(reasoning_parts) if reasoning_parts else "Standard priority assessment"

        return reasoning, risk_factors, mitigating_factors

    def _should_escalate(self, priority: PriorityLevel, exploit_score: float,
                        chain_score: float) -> bool:
        """Determine if issue should be escalated to security leadership."""
        # Escalate if critical priority with high exploitability
        if priority == PriorityLevel.CRITICAL and exploit_score >= 80:
            return True

        # Escalate if part of significant attack chain
        if chain_score >= 70:
            return True

        return False

