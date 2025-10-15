import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from enum import Enum

logger = logging.getLogger(__name__)


class ChainType(Enum):
    """Types of attack chains."""
    PRIVILEGE_ESCALATION = "privilege_escalation"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    DATA_EXFILTRATION = "data_exfiltration"
    DEFENSE_EVASION = "defense_evasion"
    LATERAL_MOVEMENT = "lateral_movement"
    PERSISTENCE = "persistence"
    IMPACT_AMPLIFICATION = "impact_amplification"


@dataclass
class ChainedVulnerability:
    """Individual vulnerability in a chain."""
    vulnerability_type: str
    description: str
    step_number: int
    enables: List[str] = field(default_factory=list)  # What this enables
    requires: List[str] = field(default_factory=list)  # What this requires
    impact_multiplier: float = 1.0  # How much this amplifies impact


@dataclass
class AttackChain:
    """Complete attack chain analysis."""
    is_chain: bool
    chain_type: Optional[ChainType] = None
    chain_length: int = 1
    vulnerabilities: List[ChainedVulnerability] = field(default_factory=list)
    combined_impact: str = ""
    impact_multiplier: float = 1.0  # Total impact amplification
    exploitation_path: List[str] = field(default_factory=list)
    reasoning: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_chain': self.is_chain,
            'chain_type': self.chain_type.value if self.chain_type else None,
            'chain_length': self.chain_length,
            'vulnerabilities': [
                {
                    'vulnerability_type': v.vulnerability_type,
                    'description': v.description,
                    'step_number': v.step_number,
                    'enables': v.enables,
                    'requires': v.requires,
                    'impact_multiplier': v.impact_multiplier,
                }
                for v in self.vulnerabilities
            ],
            'combined_impact': self.combined_impact,
            'impact_multiplier': self.impact_multiplier,
            'exploitation_path': self.exploitation_path,
            'reasoning': self.reasoning,
        }


class AttackChainDetector:
    """
    Detects attack chains in vulnerability reports.
    
    Chain Detection Strategies:
    1. Multi-step Analysis - Identify sequential vulnerabilities
    2. Dependency Mapping - Map prerequisites and enablers
    3. Impact Amplification - Detect combined impact
    4. Pattern Matching - Known chain patterns
    """
    
    # Known chain patterns
    CHAIN_PATTERNS = {
        'privilege_escalation': [
            (r'(?i)information\s+disclosure.*privilege', ChainType.PRIVILEGE_ESCALATION),
            (r'(?i)csrf.*admin', ChainType.PRIVILEGE_ESCALATION),
            (r'(?i)idor.*escalate', ChainType.PRIVILEGE_ESCALATION),
            (r'(?i)low.*privilege.*high', ChainType.PRIVILEGE_ESCALATION),
        ],
        'auth_bypass': [
            (r'(?i)password\s+reset.*account\s+takeover', ChainType.AUTHENTICATION_BYPASS),
            (r'(?i)session.*fixation.*hijack', ChainType.AUTHENTICATION_BYPASS),
            (r'(?i)bypass.*authentication.*access', ChainType.AUTHENTICATION_BYPASS),
        ],
        'data_exfiltration': [
            (r'(?i)sql\s+injection.*dump.*database', ChainType.DATA_EXFILTRATION),
            (r'(?i)lfi.*read.*sensitive', ChainType.DATA_EXFILTRATION),
            (r'(?i)ssrf.*internal.*data', ChainType.DATA_EXFILTRATION),
            (r'(?i)xxe.*file.*disclosure', ChainType.DATA_EXFILTRATION),
        ],
        'defense_evasion': [
            (r'(?i)bypass.*waf.*exploit', ChainType.DEFENSE_EVASION),
            (r'(?i)evade.*detection.*attack', ChainType.DEFENSE_EVASION),
            (r'(?i)disable.*logging.*exploit', ChainType.DEFENSE_EVASION),
        ],
    }
    
    # Vulnerability combinations that form chains
    CHAIN_COMBINATIONS = {
        ('information disclosure', 'privilege escalation'): (ChainType.PRIVILEGE_ESCALATION, 1.5),
        ('csrf', 'privilege escalation'): (ChainType.PRIVILEGE_ESCALATION, 1.8),
        ('xss', 'csrf'): (ChainType.IMPACT_AMPLIFICATION, 1.4),
        ('ssrf', 'rce'): (ChainType.IMPACT_AMPLIFICATION, 2.0),
        ('lfi', 'rce'): (ChainType.IMPACT_AMPLIFICATION, 1.8),
        ('sql injection', 'rce'): (ChainType.IMPACT_AMPLIFICATION, 1.7),
        ('authentication bypass', 'idor'): (ChainType.DATA_EXFILTRATION, 1.6),
        ('session fixation', 'xss'): (ChainType.AUTHENTICATION_BYPASS, 1.5),
    }
    
    # Keywords indicating chained attacks
    CHAIN_KEYWORDS = [
        'chain', 'combine', 'together with', 'along with', 'in combination',
        'leads to', 'enables', 'allows', 'then', 'after', 'subsequently',
        'escalate', 'leverage', 'exploit further', 'pivot',
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize attack chain detector.
        
        Args:
            config: Optional configuration dictionary
        """
        self.config = config or {}
        self.min_chain_length = self.config.get('min_chain_length', 2)
        logger.info(f"Initialized AttackChainDetector (min_chain_length={self.min_chain_length})")
    
    def detect(self, report, validation_result=None) -> AttackChain:
        """
        Detect attack chains in a vulnerability report.
        
        Args:
            report: Bug bounty report
            validation_result: Optional validation result
            
        Returns:
            Attack chain analysis
        """
        logger.debug(f"Detecting attack chains: {report.title}")
        
        # 1. Pattern Matching
        chain_type, pattern_confidence = self._match_chain_patterns(report)
        
        # 2. Multi-step Analysis
        vulnerabilities = self._analyze_steps(report)
        
        # 3. Dependency Mapping
        self._map_dependencies(vulnerabilities, report)
        
        # 4. Impact Amplification
        impact_multiplier = self._calculate_impact_multiplier(vulnerabilities, report)
        
        # 5. Determine if it's a chain
        # Must have multiple vulnerabilities AND (pattern match OR clear dependencies)
        has_dependencies = any(v.requires for v in vulnerabilities)
        is_chain = (len(vulnerabilities) >= self.min_chain_length and
                   (pattern_confidence > 0.7 or has_dependencies or impact_multiplier > 1.3))
        
        # 6. Build exploitation path
        exploitation_path = self._build_exploitation_path(vulnerabilities, report)
        
        # 7. Generate combined impact description
        combined_impact = self._describe_combined_impact(vulnerabilities, chain_type, report)
        
        # 8. Generate reasoning
        reasoning = self._generate_reasoning(is_chain, chain_type, vulnerabilities, impact_multiplier)
        
        result = AttackChain(
            is_chain=is_chain,
            chain_type=chain_type,
            chain_length=len(vulnerabilities),
            vulnerabilities=vulnerabilities,
            combined_impact=combined_impact,
            impact_multiplier=impact_multiplier,
            exploitation_path=exploitation_path,
            reasoning=reasoning,
        )
        
        logger.info(f"Chain Detection: is_chain={is_chain}, type={chain_type.value if chain_type else 'none'}, length={len(vulnerabilities)}")
        return result
    
    def _match_chain_patterns(self, report) -> tuple:
        """Match report against known chain patterns."""
        report_text = f"{report.title} {report.impact_description or ''}".lower()
        
        # Check for chain keywords
        has_chain_keywords = any(keyword in report_text for keyword in self.CHAIN_KEYWORDS)
        
        # Check pattern matches
        for category, patterns in self.CHAIN_PATTERNS.items():
            for pattern, chain_type in patterns:
                if re.search(pattern, report_text):
                    confidence = 0.9 if has_chain_keywords else 0.7
                    return chain_type, confidence
        
        # Check for vulnerability combinations
        vuln_type = (report.vulnerability_type or '').lower()
        for (vuln1, vuln2), (chain_type, multiplier) in self.CHAIN_COMBINATIONS.items():
            if vuln1 in report_text and vuln2 in report_text:
                return chain_type, 0.8
        
        return None, 0.0
    
    def _analyze_steps(self, report) -> List[ChainedVulnerability]:
        """Analyze reproduction steps for chained vulnerabilities."""
        vulnerabilities = []
        
        if not report.reproduction_steps or len(report.reproduction_steps) < 2:
            # Single vulnerability
            if report.vulnerability_type:
                vulnerabilities.append(ChainedVulnerability(
                    vulnerability_type=report.vulnerability_type,
                    description=report.title,
                    step_number=1,
                ))
            return vulnerabilities
        
        # Analyze each step for vulnerability indicators
        vuln_indicators = {
            'sql injection': ['sql', 'injection', 'query', 'database', "' or", 'union select'],
            'xss': ['xss', 'script', 'javascript', '<script>', 'alert('],
            'csrf': ['csrf', 'cross-site request', 'forged request'],
            'idor': ['idor', 'object reference', 'user id', 'change id'],
            'authentication bypass': ['bypass', 'authentication', 'login', 'without password'],
            'privilege escalation': ['escalate', 'privilege', 'admin', 'elevate'],
            'rce': ['rce', 'remote code', 'command execution', 'shell'],
            'ssrf': ['ssrf', 'server-side request', 'internal', 'localhost'],
            'lfi': ['lfi', 'file inclusion', 'path traversal', '../'],
        }
        
        for i, step in enumerate(report.reproduction_steps, 1):
            step_lower = step.lower()
            
            # Check for vulnerability indicators in this step
            for vuln_type, indicators in vuln_indicators.items():
                if any(indicator in step_lower for indicator in indicators):
                    vulnerabilities.append(ChainedVulnerability(
                        vulnerability_type=vuln_type,
                        description=step[:100],  # First 100 chars
                        step_number=i,
                    ))
                    break
        
        # If no specific vulnerabilities detected, use the reported type
        if not vulnerabilities and report.vulnerability_type:
            vulnerabilities.append(ChainedVulnerability(
                vulnerability_type=report.vulnerability_type,
                description=report.title,
                step_number=1,
            ))
        
        return vulnerabilities
    
    def _map_dependencies(self, vulnerabilities: List[ChainedVulnerability], report):
        """Map dependencies between vulnerabilities in the chain."""
        if len(vulnerabilities) < 2:
            return
        
        # Define what each vulnerability type enables
        enablement_map = {
            'information disclosure': ['privilege escalation', 'authentication bypass', 'idor'],
            'csrf': ['privilege escalation', 'data modification', 'account takeover'],
            'xss': ['session hijacking', 'csrf', 'phishing', 'credential theft'],
            'sql injection': ['data exfiltration', 'rce', 'authentication bypass'],
            'ssrf': ['internal network access', 'data exfiltration', 'rce'],
            'lfi': ['information disclosure', 'rce'],
            'authentication bypass': ['idor', 'privilege escalation', 'data access'],
            'idor': ['data exfiltration', 'privilege escalation'],
        }
        
        # Map dependencies
        for i, vuln in enumerate(vulnerabilities):
            vuln_type = vuln.vulnerability_type.lower()
            
            # What does this enable?
            if vuln_type in enablement_map:
                vuln.enables = enablement_map[vuln_type]
            
            # What does this require? (previous steps)
            if i > 0:
                vuln.requires = [v.vulnerability_type for v in vulnerabilities[:i]]

    def _calculate_impact_multiplier(self, vulnerabilities: List[ChainedVulnerability], report) -> float:
        """Calculate impact amplification from chaining."""
        if len(vulnerabilities) <= 1:
            return 1.0

        multiplier = 1.0

        # Base multiplier for chain length
        multiplier += (len(vulnerabilities) - 1) * 0.2  # +20% per additional vuln

        # Check for known high-impact combinations
        vuln_types = [v.vulnerability_type.lower() for v in vulnerabilities]

        for (vuln1, vuln2), (chain_type, combo_multiplier) in self.CHAIN_COMBINATIONS.items():
            if vuln1 in vuln_types and vuln2 in vuln_types:
                multiplier = max(multiplier, combo_multiplier)

        # Cap at 3x
        return min(3.0, multiplier)

    def _build_exploitation_path(self, vulnerabilities: List[ChainedVulnerability], report) -> List[str]:
        """Build step-by-step exploitation path."""
        if not vulnerabilities:
            return []

        path = []
        for i, vuln in enumerate(vulnerabilities, 1):
            step = f"Step {i}: Exploit {vuln.vulnerability_type}"
            if vuln.requires:
                step += f" (requires: {', '.join(vuln.requires)})"
            if vuln.enables:
                step += f" → enables: {', '.join(vuln.enables[:2])}"
            path.append(step)

        return path

    def _describe_combined_impact(self, vulnerabilities: List[ChainedVulnerability],
                                  chain_type: Optional[ChainType], report) -> str:
        """Describe the combined impact of the chain."""
        if not vulnerabilities:
            return report.impact_description or "No impact description available"

        if len(vulnerabilities) == 1:
            return report.impact_description or f"Single {vulnerabilities[0].vulnerability_type} vulnerability"

        vuln_types = [v.vulnerability_type for v in vulnerabilities]

        if chain_type == ChainType.PRIVILEGE_ESCALATION:
            return f"Chain of {len(vulnerabilities)} vulnerabilities ({', '.join(vuln_types)}) leading to privilege escalation"
        elif chain_type == ChainType.AUTHENTICATION_BYPASS:
            return f"Chain of {len(vulnerabilities)} vulnerabilities ({', '.join(vuln_types)}) enabling authentication bypass"
        elif chain_type == ChainType.DATA_EXFILTRATION:
            return f"Chain of {len(vulnerabilities)} vulnerabilities ({', '.join(vuln_types)}) enabling data exfiltration"
        elif chain_type == ChainType.IMPACT_AMPLIFICATION:
            return f"Chain of {len(vulnerabilities)} vulnerabilities ({', '.join(vuln_types)}) with amplified combined impact"
        else:
            return f"Chain of {len(vulnerabilities)} vulnerabilities: {' → '.join(vuln_types)}"

    def _generate_reasoning(self, is_chain: bool, chain_type: Optional[ChainType],
                           vulnerabilities: List[ChainedVulnerability], impact_multiplier: float) -> str:
        """Generate human-readable reasoning."""
        if not is_chain:
            return f"Single vulnerability detected ({vulnerabilities[0].vulnerability_type if vulnerabilities else 'unknown'}). No chaining identified."

        vuln_count = len(vulnerabilities)
        vuln_types = [v.vulnerability_type for v in vulnerabilities]

        reasoning = f"Attack chain detected with {vuln_count} vulnerabilities: {', '.join(vuln_types)}. "

        if chain_type:
            reasoning += f"Chain type: {chain_type.value.replace('_', ' ')}. "

        reasoning += f"Combined impact is {impact_multiplier:.1f}x the individual impact. "

        # Add dependency information
        dependent_vulns = [v for v in vulnerabilities if v.requires]
        if dependent_vulns:
            reasoning += f"{len(dependent_vulns)} vulnerabilities depend on previous steps in the chain."

        return reasoning


