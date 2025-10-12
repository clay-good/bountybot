import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

from bountybot.models import ValidationResult

logger = logging.getLogger(__name__)


class JSONOutput:
    """
    Formats validation results as professional JSON with enhanced metadata.
    """

    @staticmethod
    def _calculate_cvss_base(result: ValidationResult) -> Dict[str, Any]:
        """Calculate CVSS 3.1 base score estimation."""
        # Simplified CVSS calculation based on verdict and severity
        if result.verdict.value == 'INVALID':
            return {
                "score": 0.0,
                "severity": "None",
                "vector": "N/A"
            }

        severity_map = {
            'CRITICAL': (9.0, 10.0),
            'HIGH': (7.0, 8.9),
            'MEDIUM': (4.0, 6.9),
            'LOW': (0.1, 3.9)
        }

        if result.report.severity:
            score_range = severity_map.get(result.report.severity.value, (5.0, 5.0))
            base_score = (score_range[0] + score_range[1]) / 2
        else:
            base_score = 5.0

        # Adjust based on confidence
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

        return {
            "score": round(adjusted_score, 1),
            "severity": severity_label,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "note": "Estimated score based on report analysis"
        }

    @staticmethod
    def _get_compliance_mappings(result: ValidationResult) -> Dict[str, Any]:
        """Get compliance framework mappings."""
        vuln_type = result.report.vulnerability_type or "Unknown"

        # Common mappings for vulnerability types
        mappings = {
            "owasp_top_10_2021": [],
            "cwe": [],
            "nist_csf": [],
            "pci_dss": []
        }

        # Add mappings based on vulnerability type
        if "SQL" in vuln_type or "Injection" in vuln_type:
            mappings["owasp_top_10_2021"].append("A03:2021 - Injection")
            mappings["cwe"].append("CWE-89: SQL Injection")
            mappings["nist_csf"].append("PR.DS-5")
            mappings["pci_dss"].append("Requirement 6.5.1")
        elif "XSS" in vuln_type or "Cross-Site Scripting" in vuln_type:
            mappings["owasp_top_10_2021"].append("A03:2021 - Injection")
            mappings["cwe"].append("CWE-79: Cross-site Scripting")
            mappings["nist_csf"].append("PR.DS-5")
            mappings["pci_dss"].append("Requirement 6.5.7")
        elif "Authentication" in vuln_type or "JWT" in vuln_type:
            mappings["owasp_top_10_2021"].append("A07:2021 - Identification and Authentication Failures")
            mappings["cwe"].append("CWE-287: Improper Authentication")
            mappings["nist_csf"].append("PR.AC-1")
            mappings["pci_dss"].append("Requirement 8.2")
        elif "IDOR" in vuln_type or "Access Control" in vuln_type:
            mappings["owasp_top_10_2021"].append("A01:2021 - Broken Access Control")
            mappings["cwe"].append("CWE-639: Insecure Direct Object Reference")
            mappings["nist_csf"].append("PR.AC-4")
            mappings["pci_dss"].append("Requirement 7.1")

        return mappings

    @staticmethod
    def _create_bluf_summary(result: ValidationResult) -> Dict[str, Any]:
        """Create BLUF (Bottom Line Up Front) summary."""
        verdict_text = {
            'VALID': 'VALID VULNERABILITY - IMMEDIATE ACTION REQUIRED',
            'INVALID': 'INVALID / FALSE POSITIVE - NO ACTION REQUIRED',
            'UNCERTAIN': 'UNCERTAIN - MANUAL SECURITY REVIEW REQUIRED'
        }

        action_required = {
            'VALID': 'Immediate remediation required',
            'INVALID': 'No action required - can be closed',
            'UNCERTAIN': 'Security team review and manual testing required'
        }

        summary_text = ""
        if result.verdict.value == 'VALID':
            severity = result.report.severity.value if result.report.severity else 'MEDIUM'
            vuln_type = result.report.vulnerability_type or 'security'
            summary_text = f"This is a VALID {vuln_type} vulnerability that poses a {severity} risk to the application. Immediate remediation is recommended."
        elif result.verdict.value == 'INVALID':
            summary_text = "This report does NOT represent a valid security vulnerability. The reported issue is either a false positive, expected behavior, or does not pose a security risk."
        else:
            summary_text = "The validity of this vulnerability cannot be determined with high confidence. Manual security review by an experienced analyst is required."

        return {
            "verdict": result.verdict.value,
            "verdict_text": verdict_text[result.verdict.value],
            "action_required": action_required[result.verdict.value],
            "confidence_level": result.confidence,
            "summary": summary_text,
            "severity": result.report.severity.value if result.report.severity else "UNKNOWN",
            "vulnerability_type": result.report.vulnerability_type or "Unknown"
        }

    @staticmethod
    def _create_executive_summary(result: ValidationResult) -> Dict[str, Any]:
        """Create executive summary section."""
        return {
            "verdict": result.verdict.value,
            "confidence": result.confidence,
            "severity": result.report.severity.value if result.report.severity else "Unknown",
            "vulnerability_type": result.report.vulnerability_type or "Unknown",
            "requires_immediate_action": result.verdict.value == 'VALID' and result.confidence >= 70,
            "estimated_remediation_time": "2-4 hours" if result.verdict.value == 'VALID' else "N/A",
            "business_impact": "High" if result.verdict.value == 'VALID' and result.report.severity and result.report.severity.value in ['CRITICAL', 'HIGH'] else "Medium",
            "key_findings_count": len(result.key_findings),
            "code_analysis_performed": result.code_analysis is not None,
            "poc_generated": result.generated_poc is not None
        }

    @staticmethod
    def format(result: ValidationResult) -> str:
        """
        Format validation result as enhanced JSON string with BLUF style.

        Args:
            result: Validation result

        Returns:
            JSON string with BLUF (Bottom Line Up Front) formatting
        """
        # Create structured output with BLUF at top
        data = {
            "bluf": JSONOutput._create_bluf_summary(result),
            "metadata": {
                "report_version": "2.0.0",
                "validation_timestamp": result.validation_timestamp.isoformat(),
                "processing_time_seconds": result.processing_time_seconds,
                "ai_provider": result.ai_provider,
                "ai_model": result.ai_model,
                "total_cost_usd": result.total_cost
            },
            "cvss_assessment": JSONOutput._calculate_cvss_base(result),
            "compliance_mappings": JSONOutput._get_compliance_mappings(result),
            "executive_summary": JSONOutput._create_executive_summary(result),
            "detailed_analysis": result.to_dict()
        }

        return json.dumps(data, indent=2, default=str)
    
    @staticmethod
    def save(result: ValidationResult, output_dir: str, include_timestamp: bool = True) -> str:
        """
        Save validation result as JSON file.
        
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
        safe_title = safe_title[:50]  # Limit length
        
        if include_timestamp:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{safe_title}_{timestamp}.json"
        else:
            filename = f"{safe_title}.json"
        
        file_path = output_path / filename
        
        # Write JSON
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(JSONOutput.format(result))
        
        logger.info(f"Saved JSON output to: {file_path}")
        return str(file_path)

