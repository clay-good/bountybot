"""
WAF rule generator for creating compensating controls.
Supports ModSecurity, AWS WAF, Cloudflare, and other WAF platforms.
"""

import logging
import re
from typing import List, Dict, Any, Optional

from bountybot.remediation.models import WAFRule

logger = logging.getLogger(__name__)


class WAFRuleGenerator:
    """
    Generates WAF rules for various platforms as compensating controls.
    """
    
    # Vulnerability type to attack pattern mapping
    ATTACK_PATTERNS = {
        'sql injection': {
            'patterns': [
                r"(?i)(union.*select|select.*from|insert.*into|delete.*from|drop.*table)",
                r"(?i)(\bor\b.*=.*|and.*=.*|\bor\b.*1=1|and.*1=1)",
                r"(?i)(--|#|/\*|\*/|;)",
                r"(?i)(exec|execute|sp_|xp_)",
            ],
            'description': 'SQL injection attack patterns'
        },
        'xss': {
            'patterns': [
                r"(?i)(<script|</script|javascript:|onerror=|onload=)",
                r"(?i)(<iframe|<embed|<object|<applet)",
                r"(?i)(alert\(|prompt\(|confirm\()",
                r"(?i)(document\.cookie|document\.write)",
            ],
            'description': 'Cross-site scripting (XSS) attack patterns'
        },
        'path traversal': {
            'patterns': [
                r"(\.\./|\.\.\\)",
                r"(?i)(etc/passwd|windows/system32|boot\.ini)",
                r"(%2e%2e/|%2e%2e\\|%252e%252e)",
            ],
            'description': 'Path traversal attack patterns'
        },
        'command injection': {
            'patterns': [
                r"(?i)(;|\||&|`|\$\(|\${)",
                r"(?i)(bash|sh|cmd|powershell|wget|curl)",
                r"(?i)(nc|netcat|telnet|ssh)",
            ],
            'description': 'Command injection attack patterns'
        },
        'xxe': {
            'patterns': [
                r"(?i)(<!ENTITY|<!DOCTYPE|SYSTEM|PUBLIC)",
                r"(?i)(file://|http://|https://|ftp://)",
            ],
            'description': 'XML External Entity (XXE) attack patterns'
        },
        'ssrf': {
            'patterns': [
                r"(?i)(localhost|127\.0\.0\.1|0\.0\.0\.0)",
                r"(?i)(169\.254\.|192\.168\.|10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.)",
                r"(?i)(metadata\.google|169\.254\.169\.254)",
            ],
            'description': 'Server-Side Request Forgery (SSRF) attack patterns'
        },
    }
    
    def generate_rules(self,
                      vulnerability_type: str,
                      target_url: Optional[str] = None,
                      attack_payload: Optional[str] = None,
                      platforms: Optional[List[str]] = None) -> List[WAFRule]:
        """
        Generate WAF rules for a vulnerability.
        
        Args:
            vulnerability_type: Type of vulnerability
            target_url: Target URL/endpoint
            attack_payload: Specific attack payload to block
            platforms: List of WAF platforms (modsecurity, aws_waf, cloudflare)
            
        Returns:
            List of WAF rules
        """
        if platforms is None:
            platforms = ['modsecurity', 'aws_waf', 'cloudflare']
        
        logger.info(f"Generating WAF rules for {vulnerability_type}")
        
        rules = []
        
        for platform in platforms:
            if platform == 'modsecurity':
                rules.extend(self._generate_modsecurity_rules(
                    vulnerability_type, target_url, attack_payload
                ))
            elif platform == 'aws_waf':
                rules.extend(self._generate_aws_waf_rules(
                    vulnerability_type, target_url, attack_payload
                ))
            elif platform == 'cloudflare':
                rules.extend(self._generate_cloudflare_rules(
                    vulnerability_type, target_url, attack_payload
                ))
        
        return rules
    
    def _generate_modsecurity_rules(self,
                                   vulnerability_type: str,
                                   target_url: Optional[str],
                                   attack_payload: Optional[str]) -> List[WAFRule]:
        """Generate ModSecurity rules."""
        rules = []
        
        vuln_type_normalized = vulnerability_type.lower()
        attack_info = self.ATTACK_PATTERNS.get(vuln_type_normalized, {})
        patterns = attack_info.get('patterns', [])
        
        if not patterns:
            logger.warning(f"No patterns found for {vulnerability_type}")
            return rules
        
        # Generate rule for each pattern
        for i, pattern in enumerate(patterns):
            rule_id = 900000 + hash(vulnerability_type + str(i)) % 10000
            
            # Build ModSecurity rule
            rule_content = f'''# Block {vulnerability_type} attacks
SecRule REQUEST_URI|ARGS|REQUEST_BODY "@rx {pattern}" \\
    "id:{rule_id},\\
    phase:2,\\
    block,\\
    log,\\
    msg:'Potential {vulnerability_type} attack detected',\\
    severity:CRITICAL,\\
    tag:'attack-{vuln_type_normalized.replace(" ", "-")}',\\
    tag:'OWASP_CRS'"'''
            
            # Add URL-specific rule if target URL provided
            if target_url:
                path = self._extract_path(target_url)
                rule_content += f'''

# Specific protection for {path}
SecRule REQUEST_URI "@streq {path}" \\
    "id:{rule_id + 1},\\
    phase:1,\\
    chain,\\
    log,\\
    msg:'Protecting {path} from {vulnerability_type}'"
    SecRule ARGS|REQUEST_BODY "@rx {pattern}" \\
        "block,\\
        severity:CRITICAL"'''
            
            rule = WAFRule(
                rule_type='modsecurity',
                rule_content=rule_content,
                description=f'ModSecurity rule to block {vulnerability_type} attacks',
                attack_pattern=pattern,
                false_positive_risk='medium',
                testing_notes=f'Test with legitimate traffic to {target_url or "the application"} to ensure no false positives'
            )
            
            rules.append(rule)
        
        return rules
    
    def _generate_aws_waf_rules(self,
                               vulnerability_type: str,
                               target_url: Optional[str],
                               attack_payload: Optional[str]) -> List[WAFRule]:
        """Generate AWS WAF rules (JSON format)."""
        rules = []
        
        vuln_type_normalized = vulnerability_type.lower()
        attack_info = self.ATTACK_PATTERNS.get(vuln_type_normalized, {})
        patterns = attack_info.get('patterns', [])
        
        if not patterns:
            return rules
        
        # AWS WAF uses regex pattern sets
        rule_content = f'''{{
  "Name": "Block{vulnerability_type.replace(" ", "")}",
  "Priority": 1,
  "Statement": {{
    "OrStatement": {{
      "Statements": [
'''
        
        # Add pattern for each attack signature
        for i, pattern in enumerate(patterns):
            comma = "," if i < len(patterns) - 1 else ""
            rule_content += f'''        {{
          "RegexPatternSetReferenceStatement": {{
            "Arn": "arn:aws:wafv2:region:account:regional/regexpatternset/{vuln_type_normalized.replace(" ", "-")}-{i}",
            "FieldToMatch": {{
              "AllQueryArguments": {{}}
            }},
            "TextTransformations": [
              {{
                "Priority": 0,
                "Type": "URL_DECODE"
              }}
            ]
          }}
        }}{comma}
'''
        
        rule_content += '''      ]
    }
  },
  "Action": {{
    "Block": {{}}
  }},
  "VisibilityConfig": {{
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "''' + vulnerability_type.replace(" ", "") + '''"
  }}
}'''
        
        rule = WAFRule(
            rule_type='aws_waf',
            rule_content=rule_content,
            description=f'AWS WAF rule to block {vulnerability_type} attacks',
            attack_pattern=', '.join(patterns[:3]),
            false_positive_risk='low',
            testing_notes='Deploy in COUNT mode first, monitor CloudWatch metrics for false positives'
        )
        
        rules.append(rule)
        
        return rules
    
    def _generate_cloudflare_rules(self,
                                  vulnerability_type: str,
                                  target_url: Optional[str],
                                  attack_payload: Optional[str]) -> List[WAFRule]:
        """Generate Cloudflare WAF rules."""
        rules = []
        
        vuln_type_normalized = vulnerability_type.lower()
        attack_info = self.ATTACK_PATTERNS.get(vuln_type_normalized, {})
        patterns = attack_info.get('patterns', [])
        
        if not patterns:
            return rules
        
        # Cloudflare uses expression-based rules
        expressions = []
        for pattern in patterns:
            # Convert regex to Cloudflare expression
            expr = f'(http.request.uri.query contains "{pattern}" or http.request.body.raw contains "{pattern}")'
            expressions.append(expr)
        
        rule_content = f'''# Cloudflare WAF Rule for {vulnerability_type}
(
  {" or ".join(expressions)}
)'''
        
        if target_url:
            path = self._extract_path(target_url)
            rule_content = f'''# Cloudflare WAF Rule for {vulnerability_type} on {path}
(
  http.request.uri.path eq "{path}" and
  (
    {" or ".join(expressions)}
  )
)'''
        
        rule = WAFRule(
            rule_type='cloudflare',
            rule_content=rule_content,
            description=f'Cloudflare WAF rule to block {vulnerability_type} attacks',
            attack_pattern=', '.join(patterns[:3]),
            false_positive_risk='medium',
            testing_notes='Use "Log" action first to test, then switch to "Block" after validation'
        )
        
        rules.append(rule)
        
        return rules
    
    def _extract_path(self, url: str) -> str:
        """Extract path from URL."""
        match = re.search(r'https?://[^/]+(/[^\s?]*)', url)
        if match:
            return match.group(1)
        return '/'

