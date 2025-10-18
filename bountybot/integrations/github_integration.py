"""
GitHub integration for BountyBot.

Creates and updates GitHub issues for validated vulnerability reports.
"""

import logging
import requests
from typing import Dict, Any, Optional

from bountybot.integrations.base import (
    BaseIntegration,
    IntegrationConfig,
    IntegrationResult,
    IntegrationStatus,
)

logger = logging.getLogger(__name__)


class GitHubIntegration(BaseIntegration):
    """
    GitHub integration for creating and managing security issues.
    
    Configuration:
        token: GitHub personal access token
        owner: Repository owner (username or organization)
        repo: Repository name
        labels: Default labels for issues (default: ['security', 'bountybot'])
        assignees: Default assignees (list of usernames)
        milestone: Milestone number (optional)
        use_security_advisories: Use GitHub Security Advisories (default: False)
    """
    
    def __init__(self, config: IntegrationConfig):
        """Initialize GitHub integration."""
        super().__init__(config)
        
        self.token = config.config.get('token', '')
        self.owner = config.config.get('owner', '')
        self.repo = config.config.get('repo', '')
        self.labels = config.config.get('labels', ['security', 'bountybot'])
        self.assignees = config.config.get('assignees', [])
        self.milestone = config.config.get('milestone')
        self.use_security_advisories = config.config.get('use_security_advisories', False)
        
        # Setup headers
        self.headers = {
            'Authorization': f'token {self.token}',
            'Accept': 'application/vnd.github.v3+json',
            'Content-Type': 'application/json',
        }
        
        self.api_base = 'https://api.github.com'
    
    def test_connection(self) -> bool:
        """Test connection to GitHub."""
        try:
            response = requests.get(
                f"{self.api_base}/repos/{self.owner}/{self.repo}",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("GitHub connection test successful")
                return True
            else:
                self.logger.error(f"GitHub connection test failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"GitHub connection test error: {e}")
            return False
    
    def create_issue(self, validation_result: Any) -> IntegrationResult:
        """
        Create a GitHub issue for the validation result.
        
        Args:
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with issue details
        """
        try:
            # Build issue data
            issue_data = self._build_issue_data(validation_result)
            
            # Create issue
            response = requests.post(
                f"{self.api_base}/repos/{self.owner}/{self.repo}/issues",
                headers=self.headers,
                json=issue_data,
                timeout=30
            )
            
            if response.status_code == 201:
                result_data = response.json()
                issue_number = result_data.get('number')
                issue_url = result_data.get('html_url')
                
                self.logger.info(f"Created GitHub issue #{issue_number}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.SUCCESS,
                    message=f"Created GitHub issue #{issue_number}",
                    external_id=str(issue_number),
                    external_url=issue_url,
                    metadata={'issue_data': result_data}
                )
            else:
                error_msg = response.text
                self.logger.error(f"Failed to create GitHub issue: {error_msg}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.FAILED,
                    message="Failed to create GitHub issue",
                    error=error_msg
                )
                
        except Exception as e:
            self.logger.exception("Error creating GitHub issue")
            return IntegrationResult(
                integration_name=self.config.name,
                status=IntegrationStatus.FAILED,
                message="Exception creating GitHub issue",
                error=str(e)
            )
    
    def update_issue(self, external_id: str, validation_result: Any) -> IntegrationResult:
        """
        Update an existing GitHub issue.
        
        Args:
            external_id: GitHub issue number
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with update status
        """
        try:
            # Build comment
            comment = self._build_comment(validation_result)
            
            # Add comment to issue
            response = requests.post(
                f"{self.api_base}/repos/{self.owner}/{self.repo}/issues/{external_id}/comments",
                headers=self.headers,
                json={'body': comment},
                timeout=30
            )
            
            if response.status_code == 201:
                self.logger.info(f"Updated GitHub issue #{external_id}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.SUCCESS,
                    message=f"Updated GitHub issue #{external_id}",
                    external_id=external_id,
                    external_url=f"https://github.com/{self.owner}/{self.repo}/issues/{external_id}"
                )
            else:
                error_msg = response.text
                self.logger.error(f"Failed to update GitHub issue: {error_msg}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.FAILED,
                    message="Failed to update GitHub issue",
                    error=error_msg
                )
                
        except Exception as e:
            self.logger.exception("Error updating GitHub issue")
            return IntegrationResult(
                integration_name=self.config.name,
                status=IntegrationStatus.FAILED,
                message="Exception updating GitHub issue",
                error=str(e)
            )
    
    def send_notification(self, validation_result: Any, message: str) -> IntegrationResult:
        """
        Send notification (not applicable for GitHub).
        
        GitHub integration creates issues, not notifications.
        """
        return IntegrationResult(
            integration_name=self.config.name,
            status=IntegrationStatus.SKIPPED,
            message="Notifications not supported for GitHub integration"
        )
    
    def _build_issue_data(self, validation_result: Any) -> Dict[str, Any]:
        """Build GitHub issue data from validation result."""
        report = validation_result.report
        
        # Build title with severity prefix
        title = report.title
        if validation_result.cvss_score:
            severity = validation_result.cvss_score.severity.upper()
            title = f"[{severity}] {title}"
        
        # Build body
        body = self._build_body(validation_result)
        
        # Build issue data
        issue_data = {
            'title': title,
            'body': body,
            'labels': self.labels.copy(),
        }
        
        # Add vulnerability type as label
        if report.vulnerability_type:
            vuln_label = report.vulnerability_type.lower().replace(' ', '-')
            issue_data['labels'].append(vuln_label)
        
        # Add severity label
        if validation_result.cvss_score:
            severity = validation_result.cvss_score.severity.lower()
            issue_data['labels'].append(f"severity-{severity}")
        
        # Add assignees
        if self.assignees:
            issue_data['assignees'] = self.assignees
        
        # Add milestone
        if self.milestone:
            issue_data['milestone'] = self.milestone
        
        return issue_data
    
    def _build_body(self, validation_result: Any) -> str:
        """Build issue body."""
        report = validation_result.report
        lines = []
        
        # Warning banner for valid vulnerabilities
        if validation_result.verdict.value == 'VALID':
            lines.append("> **⚠️ SECURITY VULNERABILITY DETECTED**")
            lines.append("> This issue was automatically created by BountyBot after validating a security report.")
            lines.append("")
        
        # Validation summary
        lines.append("## Validation Results")
        lines.append("")
        lines.append(f"- **Verdict:** {validation_result.verdict.value}")
        lines.append(f"- **Confidence:** {validation_result.confidence}%")
        
        if validation_result.cvss_score:
            cvss = validation_result.cvss_score
            lines.append(f"- **CVSS Score:** {cvss.base_score} ({cvss.severity})")
            lines.append(f"- **CVSS Vector:** `{cvss.vector_string}`")
        
        if validation_result.priority_score:
            priority = validation_result.priority_score
            lines.append(f"- **Priority:** {priority.priority_level} (Score: {priority.total_score:.1f})")
        
        lines.append("")
        
        # Vulnerability details
        lines.append("## Vulnerability Details")
        lines.append("")
        lines.append(f"**Type:** {report.vulnerability_type or 'Unknown'}")
        lines.append(f"**Severity:** {report.severity or 'Unknown'}")
        lines.append(f"**Researcher:** {report.researcher or 'Unknown'}")
        lines.append("")
        
        # Description
        if report.impact_description:
            lines.append("### Description")
            lines.append("")
            lines.append(report.impact_description)
            lines.append("")
        
        # Affected components
        if report.affected_components:
            lines.append("### Affected Components")
            lines.append("")
            for component in report.affected_components:
                lines.append(f"- `{component}`")
            lines.append("")
        
        # Reproduction steps
        if report.reproduction_steps:
            lines.append("### Reproduction Steps")
            lines.append("")
            for i, step in enumerate(report.reproduction_steps, 1):
                lines.append(f"{i}. {step}")
            lines.append("")
        
        # Proof of Concept
        if report.proof_of_concept:
            lines.append("### Proof of Concept")
            lines.append("")
            lines.append("```")
            lines.append(report.proof_of_concept)
            lines.append("```")
            lines.append("")
        
        # Key findings
        if validation_result.key_findings:
            lines.append("### Key Findings")
            lines.append("")
            for finding in validation_result.key_findings:
                lines.append(f"- {finding}")
            lines.append("")
        
        # Recommendations
        if validation_result.recommendations_security_team:
            lines.append("### Recommendations")
            lines.append("")
            for rec in validation_result.recommendations_security_team:
                lines.append(f"- {rec}")
            lines.append("")
        
        # Footer
        lines.append("---")
        lines.append(f"*Generated by BountyBot | Processing time: {validation_result.processing_time_seconds:.2f}s*")
        
        return "\n".join(lines)
    
    def _build_comment(self, validation_result: Any) -> str:
        """Build comment for issue update."""
        lines = []
        lines.append("## Re-validation Results")
        lines.append("")
        lines.append(self._format_validation_summary(validation_result))
        lines.append("")
        lines.append("---")
        lines.append(f"*Updated by BountyBot*")
        return "\n".join(lines)

