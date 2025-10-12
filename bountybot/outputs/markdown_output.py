import logging
from pathlib import Path
from datetime import datetime

from bountybot.models import ValidationResult, Verdict

logger = logging.getLogger(__name__)


class MarkdownOutput:
    """
    Formats validation results as professional Markdown with enhanced sections.
    """

    @staticmethod
    def _get_severity_badge(severity: str) -> str:
        """Get severity badge for markdown."""
        badges = {
            "CRITICAL": "![CRITICAL](https://img.shields.io/badge/CRITICAL-red)",
            "HIGH": "![HIGH](https://img.shields.io/badge/HIGH-orange)",
            "MEDIUM": "![MEDIUM](https://img.shields.io/badge/MEDIUM-yellow)",
            "LOW": "![LOW](https://img.shields.io/badge/LOW-green)"
        }
        return badges.get(severity, "")

    @staticmethod
    def _calculate_cvss_estimate(result: ValidationResult) -> str:
        """Calculate estimated CVSS score."""
        if result.verdict.value == 'INVALID':
            return "0.0 (None)"

        severity_map = {
            'CRITICAL': 9.5,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.0
        }

        if result.report.severity:
            base_score = severity_map.get(result.report.severity.value, 5.0)
        else:
            base_score = 5.0

        confidence_factor = result.confidence / 100.0
        adjusted_score = base_score * confidence_factor

        severity_label = "None"
        if adjusted_score >= 9.0:
            severity_label = "Critical"
        elif adjusted_score >= 7.0:
            severity_label = "High"
        elif adjusted_score >= 4.0:
            severity_label = "Medium"
        elif adjusted_score > 0:
            severity_label = "Low"

        return f"{adjusted_score:.1f} ({severity_label})"

    @staticmethod
    def format(result: ValidationResult) -> str:
        """
        Format validation result as enhanced Markdown string with BLUF style.

        Args:
            result: Validation result

        Returns:
            Markdown string with BLUF (Bottom Line Up Front) formatting
        """
        md = []

        # ============================================================================
        # BLUF - BOTTOM LINE UP FRONT
        # ============================================================================
        md.append("# VULNERABILITY VALIDATION REPORT")
        md.append("")
        md.append("## BOTTOM LINE UP FRONT (BLUF)")
        md.append("")

        # Clear verdict box
        verdict_status = {
            Verdict.VALID: "✓ VALID VULNERABILITY",
            Verdict.INVALID: "✗ INVALID / FALSE POSITIVE",
            Verdict.UNCERTAIN: "? UNCERTAIN - MANUAL REVIEW REQUIRED",
        }
        verdict_action = {
            Verdict.VALID: "IMMEDIATE ACTION REQUIRED",
            Verdict.INVALID: "NO ACTION REQUIRED - CAN BE CLOSED",
            Verdict.UNCERTAIN: "SECURITY TEAM REVIEW REQUIRED",
        }

        md.append(f"### {verdict_status[result.verdict]}")
        md.append(f"**Action Required:** {verdict_action[result.verdict]}")
        md.append("")
        md.append(f"**Confidence Level:** {result.confidence}%")

        # Severity and CVSS
        if result.report.severity:
            md.append(f"**Severity:** {result.report.severity.value} {MarkdownOutput._get_severity_badge(result.report.severity.value)}")
        md.append(f"**Estimated CVSS 3.1 Score:** {MarkdownOutput._calculate_cvss_estimate(result)}")
        md.append("")

        # One-line summary
        if result.verdict == Verdict.VALID:
            md.append(f"**Summary:** This is a VALID {result.report.vulnerability_type or 'security'} vulnerability that poses a {result.report.severity.value if result.report.severity else 'MEDIUM'} risk to the application. Immediate remediation is recommended.")
        elif result.verdict == Verdict.INVALID:
            md.append(f"**Summary:** This report does NOT represent a valid security vulnerability. The reported issue is either a false positive, expected behavior, or does not pose a security risk.")
        else:
            md.append(f"**Summary:** The validity of this vulnerability cannot be determined with high confidence. Manual security review by an experienced analyst is required.")
        md.append("")
        md.append("---")
        md.append("")

        # Metadata
        md.append("**Report Generated:** " + result.validation_timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'))
        md.append(f"**Processing Time:** {result.processing_time_seconds:.2f} seconds")
        md.append(f"**Report Version:** 2.0.0")
        md.append("")
        md.append("---")
        md.append("")

        # Executive Summary
        md.append("## EXECUTIVE SUMMARY")
        md.append("")

        # Quick facts table
        md.append("| Metric | Value |")
        md.append("|--------|-------|")
        md.append(f"| Vulnerability Type | {result.report.vulnerability_type or 'Unknown'} |")
        md.append(f"| Processing Time | {result.processing_time_seconds:.2f}s |")
        md.append(f"| AI Cost | ${result.total_cost:.4f} |")
        md.append(f"| Code Analysis | {'Yes' if result.code_analysis else 'No'} |")
        md.append(f"| PoC Generated | {'Yes' if result.generated_poc else 'No'} |")
        md.append("")

        # Key findings highlight
        if result.key_findings:
            md.append("### Key Findings")
            md.append("")
            for i, finding in enumerate(result.key_findings[:5], 1):
                md.append(f"{i}. {finding}")
            md.append("")
        
        # Report Details
        md.append("## Report Details")
        md.append("")
        md.append(f"**Title:** {result.report.title}")
        if result.report.researcher:
            md.append(f"**Researcher:** {result.report.researcher}")
        if result.report.submission_date:
            md.append(f"**Submission Date:** {result.report.submission_date.strftime('%Y-%m-%d')}")
        if result.report.vulnerability_type:
            md.append(f"**Vulnerability Type:** {result.report.vulnerability_type}")
        if result.report.severity:
            md.append(f"**Severity:** {result.report.severity.value}")
        md.append("")
        
        # Quality Assessment
        if result.quality_assessment:
            qa = result.quality_assessment
            md.append("## Report Assessment")
            md.append("")
            md.append(f"**Quality Score:** {qa.quality_score}/10")
            md.append(f"**Completeness Score:** {qa.completeness_score}/10")
            md.append(f"**Technical Accuracy:** {qa.technical_accuracy}/10")
            md.append("")
            
            if qa.strengths:
                md.append("### Strengths")
                for strength in qa.strengths:
                    md.append(f"- {strength}")
                md.append("")
            
            if qa.concerns:
                md.append("### Concerns")
                for concern in qa.concerns:
                    md.append(f"- {concern}")
                md.append("")
        
        # Technical Analysis
        md.append("## Technical Analysis")
        md.append("")
        
        if result.plausibility_analysis:
            pa = result.plausibility_analysis
            md.append(f"**Plausibility Score:** {pa.plausibility_score}/100")
            md.append("")
            
            if pa.reasoning:
                md.append("### Analysis")
                md.append(pa.reasoning)
                md.append("")
            
            if pa.preconditions_met:
                md.append("### Preconditions Met")
                for precond in pa.preconditions_met:
                    md.append(f"- {precond}")
                md.append("")
            
            if pa.red_flags:
                md.append("### Red Flags")
                for flag in pa.red_flags:
                    md.append(f"- {flag}")
                md.append("")
        
        # Code Analysis
        if result.code_analysis:
            ca = result.code_analysis
            md.append("## Code Analysis")
            md.append("")
            md.append(f"**Vulnerable Code Found:** {'Yes' if ca.vulnerable_code_found else 'No'}")
            md.append(f"**Confidence:** {ca.confidence}/100")
            md.append("")

            if ca.vulnerable_files:
                md.append("### Vulnerable Files")
                for file in ca.vulnerable_files:
                    md.append(f"- {file}")
                md.append("")

            if ca.vulnerable_patterns:
                md.append("### Vulnerable Patterns")
                for pattern in ca.vulnerable_patterns[:5]:  # Limit to 5
                    md.append(f"- **{pattern['file']}:{pattern['line']}**")
                    md.append(f"  ```")
                    md.append(f"  {pattern['code']}")
                    md.append(f"  ```")
                md.append("")

            if ca.security_controls:
                md.append("### Security Controls")
                for control, present in ca.security_controls.items():
                    status = "Present" if present else "Not Found"
                    md.append(f"- {control}: {status}")
                md.append("")

        # HTTP Requests
        if result.extracted_http_requests:
            md.append("## Extracted HTTP Requests")
            md.append("")
            md.append(f"**Total Requests:** {len(result.extracted_http_requests)}")
            md.append("")

            for i, req in enumerate(result.extracted_http_requests, 1):
                md.append(f"### Request {i}")
                md.append("")
                md.append(f"**Method:** {req.method}")
                md.append(f"**URL:** {req.url}")
                md.append(f"**Extraction Confidence:** {req.extraction_confidence:.0%}")
                md.append("")

                if req.headers:
                    md.append("**Headers:**")
                    for key, value in req.headers.items():
                        md.append(f"- `{key}: {value}`")
                    md.append("")

                if req.body:
                    md.append("**Body:**")
                    md.append("```")
                    md.append(req.body)
                    md.append("```")
                    md.append("")

                if req.payload_locations:
                    md.append(f"**Payload Locations:** {', '.join(req.payload_locations)}")
                    md.append("")

                # Add curl command
                md.append("**cURL Command:**")
                md.append("```bash")
                md.append(req.to_curl())
                md.append("```")
                md.append("")

            if result.http_validation_issues:
                md.append("### HTTP Validation Issues")
                md.append("")
                for issue in result.http_validation_issues:
                    md.append(f"- ⚠️ {issue}")
                md.append("")

        # Generated PoC
        if result.generated_poc:
            poc = result.generated_poc
            md.append("## Generated Proof-of-Concept")
            md.append("")
            md.append(f"### {poc.title}")
            md.append("")
            md.append(poc.description)
            md.append("")

            if poc.prerequisites:
                md.append("**Prerequisites:**")
                for prereq in poc.prerequisites:
                    md.append(f"- {prereq}")
                md.append("")

            if poc.curl_command:
                md.append("#### cURL Command")
                md.append("```bash")
                md.append(poc.curl_command)
                md.append("```")
                md.append("")

            if poc.python_code:
                md.append("#### Python Code")
                md.append("```python")
                md.append(poc.python_code)
                md.append("```")
                md.append("")

            if poc.javascript_code:
                md.append("#### JavaScript/HTML Code")
                md.append("```javascript")
                md.append(poc.javascript_code)
                md.append("```")
                md.append("")

            if poc.expected_result:
                md.append("**Expected Result:**")
                md.append(poc.expected_result)
                md.append("")

            if poc.safety_notes:
                md.append("**⚠️ Safety Notes:**")
                for note in poc.safety_notes:
                    md.append(f"- {note}")
                md.append("")

        # Final Reasoning
        if result.reasoning:
            md.append("## Final Assessment")
            md.append("")
            md.append(result.reasoning)
            md.append("")

        # Compliance Mappings
        md.append("## Compliance and Standards")
        md.append("")
        vuln_type = result.report.vulnerability_type or "Unknown"

        if "SQL" in vuln_type or "Injection" in vuln_type:
            md.append("**OWASP Top 10 2021:** A03:2021 - Injection")
            md.append("")
            md.append("**CWE:** CWE-89 (SQL Injection)")
            md.append("")
            md.append("**NIST CSF:** PR.DS-5 (Protections against data leaks)")
            md.append("")
            md.append("**PCI DSS:** Requirement 6.5.1")
        elif "XSS" in vuln_type:
            md.append("**OWASP Top 10 2021:** A03:2021 - Injection")
            md.append("")
            md.append("**CWE:** CWE-79 (Cross-site Scripting)")
            md.append("")
            md.append("**NIST CSF:** PR.DS-5")
            md.append("")
            md.append("**PCI DSS:** Requirement 6.5.7")
        elif "Authentication" in vuln_type or "JWT" in vuln_type:
            md.append("**OWASP Top 10 2021:** A07:2021 - Identification and Authentication Failures")
            md.append("")
            md.append("**CWE:** CWE-287 (Improper Authentication)")
            md.append("")
            md.append("**NIST CSF:** PR.AC-1")
            md.append("")
            md.append("**PCI DSS:** Requirement 8.2")
        elif "IDOR" in vuln_type or "Access Control" in vuln_type:
            md.append("**OWASP Top 10 2021:** A01:2021 - Broken Access Control")
            md.append("")
            md.append("**CWE:** CWE-639 (Insecure Direct Object Reference)")
            md.append("")
            md.append("**NIST CSF:** PR.AC-4")
            md.append("")
            md.append("**PCI DSS:** Requirement 7.1")
        else:
            md.append("**OWASP Top 10 2021:** Multiple categories may apply")
            md.append("")
            md.append("**CWE:** Varies by vulnerability type")

        md.append("")

        # Remediation Guidance
        if result.verdict.value == 'VALID':
            md.append("## Remediation Guidance")
            md.append("")
            md.append("### Immediate Actions")
            md.append("")
            md.append("1. Verify the vulnerability in a controlled environment")
            md.append("2. Assess the scope and impact on production systems")
            md.append("3. Implement temporary mitigations if necessary")
            md.append("4. Develop and test a permanent fix")
            md.append("5. Deploy the fix following change management procedures")
            md.append("6. Verify the fix resolves the vulnerability")
            md.append("7. Update security controls and monitoring")
            md.append("")

            md.append("### Estimated Remediation Time")
            if result.report.severity and result.report.severity.value in ['CRITICAL', 'HIGH']:
                md.append("**Priority:** Immediate (within 24-48 hours)")
            elif result.report.severity and result.report.severity.value == 'MEDIUM':
                md.append("**Priority:** High (within 1 week)")
            else:
                md.append("**Priority:** Medium (within 2-4 weeks)")
            md.append("")
            md.append("")
        
        # Key Findings
        if result.key_findings:
            md.append("## Key Findings")
            md.append("")
            for finding in result.key_findings:
                md.append(f"- {finding}")
            md.append("")
        
        # Recommendations
        if result.recommendations_security_team:
            md.append("## Recommendations for Security Team")
            md.append("")
            for rec in result.recommendations_security_team:
                md.append(f"- {rec}")
            md.append("")
        
        if result.recommendations_researcher:
            md.append("## Recommendations for Researcher")
            md.append("")
            for rec in result.recommendations_researcher:
                md.append(f"- {rec}")
            md.append("")
        
        # Metadata
        md.append("## Validation Metadata")
        md.append("")
        md.append(f"**Timestamp:** {result.validation_timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        md.append(f"**AI Provider:** {result.ai_provider}")
        md.append(f"**AI Model:** {result.ai_model}")
        md.append(f"**Total Cost:** ${result.total_cost:.4f}")
        md.append(f"**Processing Time:** {result.processing_time_seconds:.2f}s")
        md.append("")
        
        return "\n".join(md)
    
    @staticmethod
    def save(result: ValidationResult, output_dir: str, include_timestamp: bool = True) -> str:
        """
        Save validation result as Markdown file.
        
        Args:
            result: Validation result
            output_dir: Output directory
            include_timestamp: Whether to include timestamp in filename
            
        Returns:
            Path to saved file
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)
        
        # Generate filename
        safe_title = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' 
                           for c in result.report.title)
        safe_title = safe_title[:50]
        
        if include_timestamp:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{safe_title}_{timestamp}.md"
        else:
            filename = f"{safe_title}.md"
        
        file_path = output_path / filename
        
        # Write Markdown
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(MarkdownOutput.format(result))
        
        logger.info(f"Saved Markdown output to: {file_path}")
        return str(file_path)

