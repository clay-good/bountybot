import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from enum import Enum

logger = logging.getLogger(__name__)


class FPCategory(Enum):
    """Categories of false positive indicators."""
    MISSING_EVIDENCE = "missing_evidence"
    IMPOSSIBLE_CHAIN = "impossible_chain"
    MISUNDERSTOOD_FEATURE = "misunderstood_feature"
    CONFIGURATION_ISSUE = "configuration_issue"
    INSUFFICIENT_IMPACT = "insufficient_impact"
    INVALID_SCOPE = "invalid_scope"
    THEORETICAL_ONLY = "theoretical_only"


@dataclass
class FalsePositiveIndicators:
    """Results from false positive detection."""
    is_likely_false_positive: bool
    confidence: float  # 0-100
    indicators: List[Dict[str, Any]] = field(default_factory=list)
    categories: List[FPCategory] = field(default_factory=list)
    reasoning: str = ""
    risk_score: float = 0.0  # 0-100, lower = more likely FP
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_likely_false_positive': self.is_likely_false_positive,
            'confidence': self.confidence,
            'indicators': self.indicators,
            'categories': [c.value for c in self.categories],
            'reasoning': self.reasoning,
            'risk_score': self.risk_score,
        }


class FalsePositiveDetector:
    """
    Detects false positive vulnerability reports using multi-signal analysis.
    
    Detection Strategies:
    1. Evidence Quality Analysis - Check for concrete proof
    2. Attack Chain Feasibility - Verify logical attack flow
    3. Feature vs Vulnerability - Distinguish intended behavior
    4. Impact Assessment - Validate claimed impact
    5. Scope Validation - Check if in-scope
    6. Pattern Matching - Known FP signatures
    """
    
    # Known false positive patterns
    FP_PATTERNS = {
        'missing_evidence': [
            r'(?i)could\s+potentially',
            r'(?i)might\s+be\s+possible',
            r'(?i)theoretically',
            r'(?i)i\s+think\s+this\s+could',
            r'(?i)this\s+may\s+lead\s+to',
            r'(?i)possibly\s+vulnerable',
        ],
        'configuration': [
            r'(?i)default\s+configuration',
            r'(?i)not\s+configured\s+properly',
            r'(?i)missing\s+security\s+headers?',
            r'(?i)http\s+instead\s+of\s+https',
            r'(?i)no\s+rate\s+limiting',
            r'(?i)verbose\s+error\s+messages?',
        ],
        'feature': [
            r'(?i)by\s+design',
            r'(?i)intended\s+behavior',
            r'(?i)working\s+as\s+expected',
            r'(?i)documented\s+feature',
            r'(?i)admin\s+can\s+see',
            r'(?i)user\s+can\s+view\s+their\s+own',
        ],
        'insufficient_impact': [
            r'(?i)information\s+disclosure\s+of\s+public\s+data',
            r'(?i)self-xss',
            r'(?i)only\s+affects?\s+the\s+attacker',
            r'(?i)requires?\s+physical\s+access',
            r'(?i)social\s+engineering\s+required',
        ],
        'invalid_scope': [
            r'(?i)third[- ]party\s+service',
            r'(?i)external\s+dependency',
            r'(?i)cdn\s+vulnerability',
            r'(?i)browser\s+vulnerability',
            r'(?i)out[- ]of[- ]scope',
        ],
    }
    
    # Vulnerability types prone to false positives
    HIGH_FP_VULN_TYPES = {
        'information disclosure': 0.3,
        'missing security headers': 0.7,
        'clickjacking': 0.4,
        'csrf': 0.3,
        'open redirect': 0.5,
        'cors misconfiguration': 0.6,
    }
    
    # Required evidence by vulnerability type
    REQUIRED_EVIDENCE = {
        'sql injection': ['payload', 'error message', 'database response'],
        'xss': ['payload', 'execution proof', 'screenshot'],
        'rce': ['command', 'output', 'proof of execution'],
        'ssrf': ['internal endpoint', 'response', 'metadata access'],
        'authentication bypass': ['bypass method', 'unauthorized access proof'],
        'idor': ['object id', 'unauthorized access', 'different user data'],
        'lfi': ['file path', 'file contents', 'sensitive data'],
        'xxe': ['xml payload', 'file disclosure', 'ssrf proof'],
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize false positive detector.

        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.fp_threshold = self.config.get('fp_threshold', 0.5)  # 50% confidence (lowered for better detection)
        self.min_evidence_score = self.config.get('min_evidence_score', 40)
        logger.info(f"Initialized FalsePositiveDetector (threshold={self.fp_threshold})")
    
    def analyze(self, report, validation_result=None) -> FalsePositiveIndicators:
        """
        Analyze report for false positive indicators.
        
        Args:
            report: Bug bounty report
            validation_result: Optional validation result with additional context
            
        Returns:
            False positive indicators with confidence score
        """
        logger.debug(f"Analyzing report for false positives: {report.title}")
        
        indicators = []
        categories = set()
        
        # 1. Evidence Quality Analysis
        evidence_score, evidence_indicators = self._analyze_evidence_quality(report)
        indicators.extend(evidence_indicators)
        
        # 2. Pattern Matching
        pattern_indicators = self._match_fp_patterns(report)
        indicators.extend(pattern_indicators)
        for ind in pattern_indicators:
            if ind['category'] in FPCategory.__members__:
                categories.add(FPCategory[ind['category'].upper()])
        
        # 3. Attack Chain Feasibility
        chain_score, chain_indicators = self._analyze_attack_chain(report)
        indicators.extend(chain_indicators)
        
        # 4. Feature vs Vulnerability
        feature_indicators = self._check_feature_vs_vulnerability(report)
        indicators.extend(feature_indicators)
        
        # 5. Impact Assessment
        impact_score, impact_indicators = self._assess_impact_validity(report)
        indicators.extend(impact_indicators)
        
        # 6. Scope Validation
        scope_indicators = self._validate_scope(report)
        indicators.extend(scope_indicators)
        
        # 7. Vulnerability Type Analysis
        vuln_type_score = self._analyze_vulnerability_type(report)
        
        # Calculate overall FP confidence
        fp_confidence = self._calculate_fp_confidence(
            evidence_score=evidence_score,
            chain_score=chain_score,
            impact_score=impact_score,
            vuln_type_score=vuln_type_score,
            indicator_count=len(indicators)
        )
        
        # Calculate risk score (inverse of FP confidence)
        risk_score = 100 - fp_confidence
        
        # Determine if likely false positive
        is_likely_fp = fp_confidence >= (self.fp_threshold * 100)
        
        # Generate reasoning
        reasoning = self._generate_reasoning(
            is_likely_fp, fp_confidence, indicators, evidence_score, chain_score, impact_score
        )
        
        result = FalsePositiveIndicators(
            is_likely_false_positive=is_likely_fp,
            confidence=fp_confidence,
            indicators=indicators,
            categories=list(categories),
            reasoning=reasoning,
            risk_score=risk_score,
        )
        
        logger.info(f"FP Analysis: confidence={fp_confidence:.1f}%, risk_score={risk_score:.1f}, likely_fp={is_likely_fp}")
        return result
    
    def _analyze_evidence_quality(self, report) -> tuple:
        """Analyze quality and completeness of evidence."""
        score = 100.0
        indicators = []
        
        vuln_type = (report.vulnerability_type or '').lower()
        required = self.REQUIRED_EVIDENCE.get(vuln_type, [])
        
        # Check for proof of concept
        if not report.proof_of_concept or len(report.proof_of_concept.strip()) < 20:
            score -= 30
            indicators.append({
                'type': 'missing_evidence',
                'category': 'missing_evidence',
                'severity': 'high',
                'description': 'Missing or insufficient proof of concept',
                'weight': 0.3,
            })
        
        # Check for reproduction steps
        if not report.reproduction_steps or len(report.reproduction_steps) < 3:
            score -= 20
            indicators.append({
                'type': 'missing_evidence',
                'category': 'missing_evidence',
                'severity': 'medium',
                'description': 'Insufficient reproduction steps (need at least 3 detailed steps)',
                'weight': 0.2,
            })
        
        # Check for impact description
        if not report.impact_description or len(report.impact_description.strip()) < 50:
            score -= 15
            indicators.append({
                'type': 'missing_evidence',
                'category': 'missing_evidence',
                'severity': 'medium',
                'description': 'Weak or missing impact description',
                'weight': 0.15,
            })
        
        # Check for required evidence by vulnerability type
        if required:
            report_text = f"{report.title} {report.impact_description or ''} {report.proof_of_concept or ''}".lower()
            missing_evidence = [req for req in required if req not in report_text]
            
            if missing_evidence:
                score -= 10 * len(missing_evidence)
                indicators.append({
                    'type': 'missing_required_evidence',
                    'category': 'missing_evidence',
                    'severity': 'high',
                    'description': f'Missing required evidence for {vuln_type}: {", ".join(missing_evidence)}',
                    'weight': 0.1 * len(missing_evidence),
                })
        
        return max(0, score), indicators

    def _match_fp_patterns(self, report) -> List[Dict[str, Any]]:
        """Match report against known false positive patterns."""
        indicators = []

        # Combine all text for pattern matching
        report_text = f"{report.title} {report.impact_description or ''} {report.proof_of_concept or ''}"
        if report.reproduction_steps:
            report_text += " " + " ".join(report.reproduction_steps)

        # Check each pattern category
        for category, patterns in self.FP_PATTERNS.items():
            for pattern in patterns:
                matches = re.findall(pattern, report_text)
                if matches:
                    indicators.append({
                        'type': 'pattern_match',
                        'category': category,
                        'severity': 'medium',
                        'description': f'Found {category} pattern: "{matches[0][:50]}"',
                        'weight': 0.15,
                        'pattern': pattern,
                    })

        return indicators

    def _analyze_attack_chain(self, report) -> tuple:
        """Analyze feasibility of attack chain."""
        score = 100.0
        indicators = []

        # Check for logical flow in reproduction steps
        if report.reproduction_steps:
            steps_text = " ".join(report.reproduction_steps).lower()

            # Check for authentication requirements
            has_auth = any(word in steps_text for word in ['login', 'authenticate', 'credentials', 'token'])
            needs_auth = any(word in steps_text for word in ['authenticated', 'logged in', 'authorized'])

            if needs_auth and not has_auth:
                score -= 25
                indicators.append({
                    'type': 'broken_chain',
                    'category': 'impossible_chain',
                    'severity': 'high',
                    'description': 'Attack requires authentication but no auth steps provided',
                    'weight': 0.25,
                })

            # Check for prerequisite steps
            if 'then' in steps_text or 'after' in steps_text:
                # Has sequential steps (good)
                pass
            else:
                score -= 10
                indicators.append({
                    'type': 'unclear_sequence',
                    'category': 'impossible_chain',
                    'severity': 'low',
                    'description': 'Attack steps lack clear sequence',
                    'weight': 0.1,
                })

        return max(0, score), indicators

    def _check_feature_vs_vulnerability(self, report) -> List[Dict[str, Any]]:
        """Check if reported issue is actually a feature."""
        indicators = []

        report_text = f"{report.title} {report.impact_description or ''}".lower()

        # Check for feature-related keywords
        feature_keywords = [
            'admin can', 'administrator can', 'by design', 'intended behavior',
            'documented feature', 'working as expected', 'user can view their own'
        ]

        for keyword in feature_keywords:
            if keyword in report_text:
                indicators.append({
                    'type': 'feature_not_vulnerability',
                    'category': 'misunderstood_feature',
                    'severity': 'high',
                    'description': f'Report mentions "{keyword}" - may be intended functionality',
                    'weight': 0.3,
                })

        # Check for privilege-appropriate actions
        if 'admin' in report_text and 'can' in report_text:
            if not any(word in report_text for word in ['bypass', 'unauthorized', 'escalation', 'without']):
                indicators.append({
                    'type': 'appropriate_privilege',
                    'category': 'misunderstood_feature',
                    'severity': 'medium',
                    'description': 'Admin action without indication of privilege escalation',
                    'weight': 0.2,
                })

        return indicators

    def _assess_impact_validity(self, report) -> tuple:
        """Assess if claimed impact is valid and significant."""
        score = 100.0
        indicators = []

        impact_text = (report.impact_description or '').lower()
        title_text = report.title.lower()

        # Check for self-inflicted issues
        if 'self-xss' in title_text or 'self xss' in title_text:
            score -= 50
            indicators.append({
                'type': 'self_inflicted',
                'category': 'insufficient_impact',
                'severity': 'critical',
                'description': 'Self-XSS has no real security impact',
                'weight': 0.5,
            })

        # Check for public information disclosure
        if 'information disclosure' in title_text or 'information leak' in title_text:
            if any(word in impact_text for word in ['public', 'already visible', 'non-sensitive']):
                score -= 40
                indicators.append({
                    'type': 'public_information',
                    'category': 'insufficient_impact',
                    'severity': 'high',
                    'description': 'Information disclosure of public/non-sensitive data',
                    'weight': 0.4,
                })

        # Check for theoretical-only impact
        theoretical_keywords = ['could potentially', 'might be possible', 'theoretically', 'may lead to']
        if any(keyword in impact_text for keyword in theoretical_keywords):
            score -= 20
            indicators.append({
                'type': 'theoretical_impact',
                'category': 'theoretical_only',
                'severity': 'medium',
                'description': 'Impact is theoretical without concrete demonstration',
                'weight': 0.2,
            })

        return max(0, score), indicators

    def _validate_scope(self, report) -> List[Dict[str, Any]]:
        """Validate if vulnerability is in scope."""
        indicators = []

        report_text = f"{report.title} {report.impact_description or ''}".lower()
        affected = " ".join(report.affected_components).lower() if report.affected_components else ""

        # Check for out-of-scope indicators
        out_of_scope_keywords = [
            'third-party', 'third party', 'external service', 'cdn',
            'browser vulnerability', 'operating system', 'out-of-scope', 'out of scope'
        ]

        for keyword in out_of_scope_keywords:
            if keyword in report_text or keyword in affected:
                indicators.append({
                    'type': 'out_of_scope',
                    'category': 'invalid_scope',
                    'severity': 'critical',
                    'description': f'Vulnerability in {keyword} - likely out of scope',
                    'weight': 0.4,
                })

        return indicators

    def _analyze_vulnerability_type(self, report) -> float:
        """Analyze vulnerability type for FP likelihood."""
        vuln_type = (report.vulnerability_type or '').lower()

        # Return FP likelihood score for this vulnerability type
        for known_type, fp_likelihood in self.HIGH_FP_VULN_TYPES.items():
            if known_type in vuln_type:
                return fp_likelihood * 100

        return 0.0  # Unknown types have no inherent FP bias

    def _calculate_fp_confidence(self, evidence_score: float, chain_score: float,
                                 impact_score: float, vuln_type_score: float,
                                 indicator_count: int) -> float:
        """Calculate overall false positive confidence."""
        # Weighted average of scores (inverted so low score = high FP confidence)
        evidence_weight = 0.35
        chain_weight = 0.25
        impact_weight = 0.25
        vuln_type_weight = 0.15

        # Invert scores (low evidence = high FP confidence)
        fp_score = (
            (100 - evidence_score) * evidence_weight +
            (100 - chain_score) * chain_weight +
            (100 - impact_score) * impact_weight +
            vuln_type_score * vuln_type_weight
        )

        # Boost confidence based on number of indicators
        indicator_boost = min(indicator_count * 2, 20)  # Max 20% boost
        fp_score = min(100, fp_score + indicator_boost)

        return round(fp_score, 2)

    def _generate_reasoning(self, is_likely_fp: bool, confidence: float,
                           indicators: List[Dict], evidence_score: float,
                           chain_score: float, impact_score: float) -> str:
        """Generate human-readable reasoning for FP determination."""
        if not is_likely_fp:
            return (f"Report appears legitimate with {confidence:.1f}% confidence. "
                   f"Evidence quality: {evidence_score:.0f}/100, "
                   f"Attack chain: {chain_score:.0f}/100, "
                   f"Impact validity: {impact_score:.0f}/100.")

        reasons = []

        if evidence_score < 50:
            reasons.append(f"weak evidence (score: {evidence_score:.0f}/100)")

        if chain_score < 50:
            reasons.append(f"questionable attack chain (score: {chain_score:.0f}/100)")

        if impact_score < 50:
            reasons.append(f"insufficient impact (score: {impact_score:.0f}/100)")

        # Add top indicators
        high_severity_indicators = [ind for ind in indicators if ind.get('severity') == 'critical' or ind.get('severity') == 'high']
        if high_severity_indicators:
            reasons.append(f"{len(high_severity_indicators)} critical indicators found")

        reason_text = ", ".join(reasons) if reasons else "multiple indicators"

        return (f"Likely false positive with {confidence:.1f}% confidence due to: {reason_text}. "
               f"Found {len(indicators)} total indicators.")


