"""
Main remediation engine that orchestrates code fixes, WAF rules, and compensating controls.
"""

import logging
from typing import Optional, List, Dict, Any

from bountybot.models import Report, ValidationResult
from bountybot.ai_providers.base import BaseAIProvider
from bountybot.remediation.models import RemediationPlan, CompensatingControl
from bountybot.remediation.code_fixer import CodeFixer
from bountybot.remediation.waf_rule_generator import WAFRuleGenerator

logger = logging.getLogger(__name__)


class RemediationEngine:
    """
    Orchestrates generation of comprehensive remediation plans.
    Includes code fixes, WAF rules, compensating controls, and defense strategies.
    """
    
    def __init__(self, ai_provider: BaseAIProvider):
        """
        Initialize remediation engine.
        
        Args:
            ai_provider: AI provider for generating recommendations
        """
        self.ai_provider = ai_provider
        self.code_fixer = CodeFixer(ai_provider)
        self.waf_generator = WAFRuleGenerator()
    
    def generate_remediation_plan(self,
                                 report: Report,
                                 validation_result: ValidationResult,
                                 codebase_path: Optional[str] = None,
                                 vulnerable_code: Optional[str] = None) -> RemediationPlan:
        """
        Generate comprehensive remediation plan.
        
        Args:
            report: Vulnerability report
            validation_result: Validation result
            codebase_path: Path to codebase
            vulnerable_code: Vulnerable code snippet
            
        Returns:
            Complete remediation plan
        """
        logger.info(f"Generating remediation plan for {report.vulnerability_type}")
        
        plan = RemediationPlan(
            vulnerability_type=report.vulnerability_type or "Unknown",
            severity=report.severity.value if report.severity else "unknown"
        )
        
        # Generate code fixes if vulnerable code provided
        if vulnerable_code:
            plan.code_fixes = self.code_fixer.generate_fixes(
                vulnerability_type=report.vulnerability_type or "Unknown",
                vulnerable_code=vulnerable_code,
                file_path=report.affected_components[0] if report.affected_components else None,
                codebase_path=codebase_path
            )
        
        # Generate WAF rules
        plan.waf_rules = self.waf_generator.generate_rules(
            vulnerability_type=report.vulnerability_type or "Unknown",
            target_url=report.target_url,
            attack_payload=report.proof_of_concept
        )
        
        # Generate compensating controls
        plan.compensating_controls = self._generate_compensating_controls(
            report, validation_result
        )
        
        # Generate action items
        plan.immediate_actions = self._generate_immediate_actions(report)
        plan.short_term_actions = self._generate_short_term_actions(report)
        plan.long_term_actions = self._generate_long_term_actions(report)
        
        # Generate detection and monitoring
        plan.detection_rules = self._generate_detection_rules(report)
        plan.monitoring_queries = self._generate_monitoring_queries(report)
        
        # Generate testing steps
        plan.testing_steps = self._generate_testing_steps(report)
        plan.validation_criteria = self._generate_validation_criteria(report)
        
        # Add metadata
        plan.estimated_effort = self._estimate_effort(report)
        plan.risk_if_not_fixed = self._assess_risk(report)
        
        logger.info("Remediation plan generated successfully")
        return plan
    
    def _generate_compensating_controls(self,
                                       report: Report,
                                       validation_result: ValidationResult) -> List[CompensatingControl]:
        """Generate compensating security controls."""
        controls = []
        vuln_type = (report.vulnerability_type or "").lower()
        
        # WAF control (already generated separately)
        controls.append(CompensatingControl(
            control_type="waf",
            description="Deploy WAF rules to block attack patterns",
            implementation_steps=[
                "Review generated WAF rules for your platform",
                "Test rules in monitoring/log mode first",
                "Validate no false positives with legitimate traffic",
                "Deploy rules in blocking mode",
                "Monitor WAF logs for blocked requests"
            ],
            effectiveness="high",
            limitations=[
                "Can be bypassed with encoding/obfuscation",
                "May cause false positives",
                "Does not fix root cause"
            ],
            monitoring_requirements=[
                "Monitor WAF block rate",
                "Alert on high false positive rate",
                "Review blocked requests daily"
            ]
        ))
        
        # Input validation control
        if vuln_type in ['sql injection', 'xss', 'command injection', 'xxe']:
            controls.append(CompensatingControl(
                control_type="input_validation",
                description="Implement strict input validation and sanitization",
                implementation_steps=[
                    "Define allowlist of acceptable input patterns",
                    "Reject any input not matching allowlist",
                    "Sanitize all user input before processing",
                    "Use parameterized queries/prepared statements",
                    "Encode output based on context"
                ],
                effectiveness="high",
                limitations=[
                    "Requires careful implementation",
                    "May impact user experience if too strict"
                ],
                monitoring_requirements=[
                    "Log rejected inputs",
                    "Monitor validation failure rate"
                ]
            ))
        
        # Rate limiting control
        controls.append(CompensatingControl(
            control_type="rate_limiting",
            description="Implement rate limiting to slow down attacks",
            implementation_steps=[
                "Set rate limits per IP address",
                "Set rate limits per user account",
                "Implement progressive delays for repeated violations",
                "Use CAPTCHA for suspicious activity"
            ],
            effectiveness="medium",
            limitations=[
                "Can be bypassed with distributed attacks",
                "May impact legitimate users"
            ],
            monitoring_requirements=[
                "Monitor rate limit violations",
                "Alert on distributed attack patterns"
            ]
        ))
        
        # Network segmentation (for SSRF, RCE)
        if vuln_type in ['ssrf', 'rce', 'command injection']:
            controls.append(CompensatingControl(
                control_type="network_segmentation",
                description="Isolate vulnerable components with network controls",
                implementation_steps=[
                    "Place vulnerable service in isolated network segment",
                    "Restrict outbound connections to allowlist",
                    "Block access to internal/metadata endpoints",
                    "Use egress filtering"
                ],
                effectiveness="high",
                limitations=[
                    "Requires infrastructure changes",
                    "May break legitimate functionality"
                ],
                monitoring_requirements=[
                    "Monitor blocked connection attempts",
                    "Alert on unusual outbound traffic"
                ]
            ))
        
        return controls
    
    def _generate_immediate_actions(self, report: Report) -> List[str]:
        """Generate immediate action items."""
        actions = [
            "Verify the vulnerability is exploitable in production",
            "Assess current exposure and attack surface",
            "Deploy WAF rules as temporary mitigation",
            "Enable enhanced logging for affected endpoints",
            "Notify security team and stakeholders"
        ]
        
        if report.severity and report.severity.value in ['critical', 'high']:
            actions.insert(0, "Consider taking affected service offline if actively exploited")
        
        return actions
    
    def _generate_short_term_actions(self, report: Report) -> List[str]:
        """Generate short-term action items."""
        return [
            "Apply code fixes to vulnerable components",
            "Deploy fixes to staging environment",
            "Conduct thorough testing of fixes",
            "Perform security regression testing",
            "Deploy fixes to production",
            "Verify vulnerability is remediated"
        ]
    
    def _generate_long_term_actions(self, report: Report) -> List[str]:
        """Generate long-term action items."""
        return [
            "Review similar code patterns across codebase",
            "Implement automated security testing for this vulnerability class",
            "Add security training for development team",
            "Update secure coding guidelines",
            "Implement pre-commit security checks",
            "Schedule regular security audits"
        ]
    
    def _generate_detection_rules(self, report: Report) -> List[str]:
        """Generate detection rules for monitoring."""
        vuln_type = (report.vulnerability_type or "").lower()
        
        rules = [
            f"Alert on HTTP requests matching {vuln_type} attack patterns",
            "Alert on unusual error rates from affected endpoints",
            "Alert on suspicious user agent strings"
        ]
        
        if vuln_type == 'sql injection':
            rules.extend([
                "Alert on SQL errors in application logs",
                "Alert on unusual database query patterns",
                "Alert on database access from unexpected IPs"
            ])
        elif vuln_type == 'xss':
            rules.extend([
                "Alert on script tags in user input",
                "Alert on JavaScript execution errors",
                "Alert on CSP violations"
            ])
        elif vuln_type in ['ssrf', 'rce']:
            rules.extend([
                "Alert on outbound connections to internal IPs",
                "Alert on metadata endpoint access",
                "Alert on unusual process execution"
            ])
        
        return rules
    
    def _generate_monitoring_queries(self, report: Report) -> List[str]:
        """Generate monitoring queries."""
        queries = []
        
        if report.target_url:
            queries.append(f'http.url == "{report.target_url}" AND http.status >= 400')
        
        queries.extend([
            'waf.action == "block" AND waf.rule_id == "vulnerability_rule"',
            'app.error_rate > threshold',
            'security.alert.severity == "high"'
        ])
        
        return queries
    
    def _generate_testing_steps(self, report: Report) -> List[str]:
        """Generate testing steps."""
        return [
            "Test fix with original proof of concept",
            "Test with variations of the attack payload",
            "Test with legitimate use cases to ensure no breakage",
            "Perform automated security scan",
            "Conduct manual penetration test",
            "Verify WAF rules block attacks without false positives"
        ]
    
    def _generate_validation_criteria(self, report: Report) -> List[str]:
        """Generate validation criteria."""
        return [
            "Original attack payload is blocked/sanitized",
            "All variations of attack are prevented",
            "Legitimate functionality works correctly",
            "No new vulnerabilities introduced",
            "Security tests pass",
            "Performance impact is acceptable"
        ]
    
    def _estimate_effort(self, report: Report) -> str:
        """Estimate remediation effort."""
        if report.severity:
            if report.severity.value == 'critical':
                return "4-8 hours (immediate priority)"
            elif report.severity.value == 'high':
                return "1-2 days"
            elif report.severity.value == 'medium':
                return "3-5 days"
            else:
                return "1-2 weeks"
        return "Unknown"
    
    def _assess_risk(self, report: Report) -> str:
        """Assess risk if not fixed."""
        vuln_type = (report.vulnerability_type or "").lower()
        
        risk_descriptions = {
            'sql injection': "Complete database compromise, data theft, data manipulation, potential server takeover",
            'xss': "Account takeover, session hijacking, malware distribution, phishing attacks",
            'rce': "Complete server compromise, data theft, lateral movement, ransomware deployment",
            'ssrf': "Internal network scanning, cloud metadata access, potential RCE",
            'command injection': "Server compromise, data theft, malware installation",
            'xxe': "File disclosure, SSRF, denial of service",
            'idor': "Unauthorized data access, privacy violations, data manipulation",
        }
        
        return risk_descriptions.get(vuln_type, "Security breach, data exposure, reputational damage")

