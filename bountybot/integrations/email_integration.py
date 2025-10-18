"""
Email integration for BountyBot.

Sends email notifications for validated vulnerability reports.
"""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional, List

from bountybot.integrations.base import (
    BaseIntegration,
    IntegrationConfig,
    IntegrationResult,
    IntegrationStatus,
)

logger = logging.getLogger(__name__)


class EmailIntegration(BaseIntegration):
    """
    Email integration for sending notifications.
    
    Configuration:
        smtp_host: SMTP server hostname
        smtp_port: SMTP server port (default: 587)
        smtp_username: SMTP username
        smtp_password: SMTP password
        use_tls: Use TLS encryption (default: True)
        from_address: Sender email address
        to_addresses: List of recipient email addresses
        cc_addresses: List of CC email addresses (optional)
        subject_prefix: Email subject prefix (default: [BountyBot])
        include_html: Send HTML formatted emails (default: True)
    """
    
    def __init__(self, config: IntegrationConfig):
        """Initialize Email integration."""
        super().__init__(config)
        
        self.smtp_host = config.config.get('smtp_host', '')
        self.smtp_port = config.config.get('smtp_port', 587)
        self.smtp_username = config.config.get('smtp_username', '')
        self.smtp_password = config.config.get('smtp_password', '')
        self.use_tls = config.config.get('use_tls', True)
        
        self.from_address = config.config.get('from_address', '')
        self.to_addresses = config.config.get('to_addresses', [])
        self.cc_addresses = config.config.get('cc_addresses', [])
        
        self.subject_prefix = config.config.get('subject_prefix', '[BountyBot]')
        self.include_html = config.config.get('include_html', True)
    
    def test_connection(self) -> bool:
        """Test connection to SMTP server."""
        try:
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10)
            
            if self.smtp_username and self.smtp_password:
                server.login(self.smtp_username, self.smtp_password)
            
            server.quit()
            
            self.logger.info("Email connection test successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Email connection test error: {e}")
            return False
    
    def create_issue(self, validation_result: Any) -> IntegrationResult:
        """
        Send email notification for new validation.
        
        Args:
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with notification status
        """
        subject = f"{self.subject_prefix} New Vulnerability Report: {validation_result.report.title}"
        return self.send_notification(validation_result, subject)
    
    def update_issue(self, external_id: str, validation_result: Any) -> IntegrationResult:
        """
        Send email notification for updated validation.
        
        Args:
            external_id: Not used for email
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with notification status
        """
        subject = f"{self.subject_prefix} Re-validation: {validation_result.report.title}"
        return self.send_notification(validation_result, subject)
    
    def send_notification(self, validation_result: Any, subject: str) -> IntegrationResult:
        """
        Send an email notification.
        
        Args:
            validation_result: ValidationResult object
            subject: Email subject
            
        Returns:
            IntegrationResult with notification status
        """
        try:
            # Build email
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = self.from_address
            msg['To'] = ', '.join(self.to_addresses)
            
            if self.cc_addresses:
                msg['Cc'] = ', '.join(self.cc_addresses)
            
            # Build plain text version
            text_body = self._build_text_body(validation_result)
            msg.attach(MIMEText(text_body, 'plain'))
            
            # Build HTML version if enabled
            if self.include_html:
                html_body = self._build_html_body(validation_result)
                msg.attach(MIMEText(html_body, 'html'))
            
            # Send email
            recipients = self.to_addresses + self.cc_addresses
            
            if self.use_tls:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
                server.starttls()
            else:
                server = smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=30)
            
            if self.smtp_username and self.smtp_password:
                server.login(self.smtp_username, self.smtp_password)
            
            server.sendmail(self.from_address, recipients, msg.as_string())
            server.quit()
            
            self.logger.info(f"Sent email notification to {len(recipients)} recipients")
            
            return IntegrationResult(
                integration_name=self.config.name,
                status=IntegrationStatus.SUCCESS,
                message=f"Email sent to {len(recipients)} recipients"
            )
            
        except Exception as e:
            self.logger.exception("Error sending email notification")
            return IntegrationResult(
                integration_name=self.config.name,
                status=IntegrationStatus.FAILED,
                message="Exception sending email notification",
                error=str(e)
            )
    
    def _build_text_body(self, validation_result: Any) -> str:
        """Build plain text email body."""
        report = validation_result.report
        lines = []
        
        lines.append("=" * 70)
        lines.append("BOUNTYBOT VALIDATION REPORT")
        lines.append("=" * 70)
        lines.append("")
        
        # Validation results
        lines.append("VALIDATION RESULTS")
        lines.append("-" * 70)
        lines.append(f"Verdict:     {validation_result.verdict.value}")
        lines.append(f"Confidence:  {validation_result.confidence}%")
        
        if validation_result.cvss_score:
            cvss = validation_result.cvss_score
            lines.append(f"CVSS Score:  {cvss.base_score} ({cvss.severity})")
            lines.append(f"CVSS Vector: {cvss.vector_string}")
        
        if validation_result.priority_score:
            priority = validation_result.priority_score
            lines.append(f"Priority:    {priority.priority_level} (Score: {priority.total_score:.1f})")
        
        lines.append("")
        
        # Vulnerability details
        lines.append("VULNERABILITY DETAILS")
        lines.append("-" * 70)
        lines.append(f"Title:       {report.title}")
        lines.append(f"Type:        {report.vulnerability_type or 'Unknown'}")
        lines.append(f"Severity:    {report.severity or 'Unknown'}")
        lines.append(f"Researcher:  {report.researcher or 'Unknown'}")
        lines.append("")
        
        # Description
        if report.impact_description:
            lines.append("DESCRIPTION")
            lines.append("-" * 70)
            lines.append(report.impact_description)
            lines.append("")
        
        # Affected components
        if report.affected_components:
            lines.append("AFFECTED COMPONENTS")
            lines.append("-" * 70)
            for component in report.affected_components:
                lines.append(f"  - {component}")
            lines.append("")
        
        # Key findings
        if validation_result.key_findings:
            lines.append("KEY FINDINGS")
            lines.append("-" * 70)
            for finding in validation_result.key_findings:
                lines.append(f"  - {finding}")
            lines.append("")
        
        # Recommendations
        if validation_result.recommendations_security_team:
            lines.append("RECOMMENDATIONS")
            lines.append("-" * 70)
            for rec in validation_result.recommendations_security_team:
                lines.append(f"  - {rec}")
            lines.append("")
        
        # Footer
        lines.append("=" * 70)
        lines.append(f"Generated by BountyBot")
        lines.append(f"Processing time: {validation_result.processing_time_seconds:.2f}s")
        if validation_result.ai_provider:
            lines.append(f"AI Provider: {validation_result.ai_provider}")
        lines.append("=" * 70)
        
        return "\n".join(lines)
    
    def _build_html_body(self, validation_result: Any) -> str:
        """Build HTML email body."""
        report = validation_result.report
        
        # Determine color based on verdict
        verdict_colors = {
            'VALID': '#dc3545',
            'INVALID': '#28a745',
            'UNCERTAIN': '#ffc107',
        }
        verdict_color = verdict_colors.get(validation_result.verdict.value, '#6c757d')
        
        html = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
                .container {{ max-width: 800px; margin: 0 auto; padding: 20px; }}
                .header {{ background-color: #007bff; color: white; padding: 20px; text-align: center; }}
                .section {{ margin: 20px 0; padding: 15px; border-left: 4px solid #007bff; background-color: #f8f9fa; }}
                .verdict {{ background-color: {verdict_color}; color: white; padding: 10px; text-align: center; font-size: 18px; font-weight: bold; }}
                .metric {{ display: inline-block; margin: 10px 20px 10px 0; }}
                .metric-label {{ font-weight: bold; color: #666; }}
                .metric-value {{ color: #333; }}
                .list-item {{ margin: 5px 0; padding-left: 20px; }}
                .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #ddd; text-align: center; color: #666; font-size: 12px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🛡️ BountyBot Validation Report</h1>
                </div>
                
                <div class="verdict">
                    {validation_result.verdict.value}
                </div>
                
                <div class="section">
                    <h2>Validation Results</h2>
                    <div class="metric">
                        <span class="metric-label">Confidence:</span>
                        <span class="metric-value">{validation_result.confidence}%</span>
                    </div>
        """
        
        if validation_result.cvss_score:
            cvss = validation_result.cvss_score
            html += f"""
                    <div class="metric">
                        <span class="metric-label">CVSS Score:</span>
                        <span class="metric-value">{cvss.base_score} ({cvss.severity})</span>
                    </div>
            """
        
        if validation_result.priority_score:
            priority = validation_result.priority_score
            html += f"""
                    <div class="metric">
                        <span class="metric-label">Priority:</span>
                        <span class="metric-value">{priority.priority_level}</span>
                    </div>
            """
        
        html += """
                </div>
                
                <div class="section">
                    <h2>Vulnerability Details</h2>
        """
        
        html += f"""
                    <p><strong>Title:</strong> {report.title}</p>
                    <p><strong>Type:</strong> {report.vulnerability_type or 'Unknown'}</p>
                    <p><strong>Severity:</strong> {report.severity or 'Unknown'}</p>
                    <p><strong>Researcher:</strong> {report.researcher or 'Unknown'}</p>
        """
        
        if report.impact_description:
            html += f"""
                    <p><strong>Description:</strong></p>
                    <p>{report.impact_description}</p>
            """
        
        html += """
                </div>
        """
        
        if validation_result.key_findings:
            html += """
                <div class="section">
                    <h2>Key Findings</h2>
                    <ul>
            """
            for finding in validation_result.key_findings:
                html += f"<li class='list-item'>{finding}</li>"
            html += """
                    </ul>
                </div>
            """
        
        html += f"""
                <div class="footer">
                    <p>Generated by BountyBot | Processing time: {validation_result.processing_time_seconds:.2f}s</p>
        """
        
        if validation_result.ai_provider:
            html += f"<p>AI Provider: {validation_result.ai_provider}</p>"
        
        html += """
                </div>
            </div>
        </body>
        </html>
        """
        
        return html

