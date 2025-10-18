"""
JIRA integration for BountyBot.

Creates and updates JIRA issues for validated vulnerability reports.
"""

import logging
import requests
from typing import Dict, Any, Optional
from base64 import b64encode

from bountybot.integrations.base import (
    BaseIntegration,
    IntegrationConfig,
    IntegrationResult,
    IntegrationStatus,
)

logger = logging.getLogger(__name__)


class JiraIntegration(BaseIntegration):
    """
    JIRA integration for creating and managing security issues.
    
    Configuration:
        url: JIRA instance URL (e.g., https://company.atlassian.net)
        username: JIRA username/email
        api_token: JIRA API token
        project_key: Project key (e.g., SEC, VULN)
        issue_type: Issue type (e.g., Bug, Security Issue)
        priority_mapping: Map severity to JIRA priority
        custom_fields: Additional custom fields
    """
    
    def __init__(self, config: IntegrationConfig):
        """Initialize JIRA integration."""
        super().__init__(config)
        
        self.url = config.config.get('url', '').rstrip('/')
        self.username = config.config.get('username', '')
        self.api_token = config.config.get('api_token', '')
        self.project_key = config.config.get('project_key', 'SEC')
        self.issue_type = config.config.get('issue_type', 'Bug')
        
        # Priority mapping: CVSS severity -> JIRA priority
        self.priority_mapping = config.config.get('priority_mapping', {
            'CRITICAL': 'Highest',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low',
            'INFO': 'Lowest',
        })
        
        # Custom fields
        self.custom_fields = config.config.get('custom_fields', {})
        
        # Setup authentication
        self._setup_auth()
    
    def _setup_auth(self):
        """Setup authentication headers."""
        if self.username and self.api_token:
            auth_str = f"{self.username}:{self.api_token}"
            auth_bytes = auth_str.encode('ascii')
            auth_b64 = b64encode(auth_bytes).decode('ascii')
            
            self.headers = {
                'Authorization': f'Basic {auth_b64}',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            }
        else:
            self.headers = {}
    
    def test_connection(self) -> bool:
        """Test connection to JIRA."""
        try:
            response = requests.get(
                f"{self.url}/rest/api/3/myself",
                headers=self.headers,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("JIRA connection test successful")
                return True
            else:
                self.logger.error(f"JIRA connection test failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"JIRA connection test error: {e}")
            return False
    
    def create_issue(self, validation_result: Any) -> IntegrationResult:
        """
        Create a JIRA issue for the validation result.
        
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
                f"{self.url}/rest/api/3/issue",
                headers=self.headers,
                json=issue_data,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                result_data = response.json()
                issue_key = result_data.get('key')
                issue_url = f"{self.url}/browse/{issue_key}"
                
                self.logger.info(f"Created JIRA issue: {issue_key}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.SUCCESS,
                    message=f"Created JIRA issue {issue_key}",
                    external_id=issue_key,
                    external_url=issue_url,
                    metadata={'issue_data': result_data}
                )
            else:
                error_msg = response.text
                self.logger.error(f"Failed to create JIRA issue: {error_msg}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.FAILED,
                    message="Failed to create JIRA issue",
                    error=error_msg
                )
                
        except Exception as e:
            self.logger.exception("Error creating JIRA issue")
            return IntegrationResult(
                integration_name=self.config.name,
                status=IntegrationStatus.FAILED,
                message="Exception creating JIRA issue",
                error=str(e)
            )
    
    def update_issue(self, external_id: str, validation_result: Any) -> IntegrationResult:
        """
        Update an existing JIRA issue.
        
        Args:
            external_id: JIRA issue key
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with update status
        """
        try:
            # Build update data
            update_data = {
                'fields': {}
            }
            
            # Add comment with new validation
            comment = self._build_comment(validation_result)
            comment_data = {
                'body': {
                    'type': 'doc',
                    'version': 1,
                    'content': [
                        {
                            'type': 'paragraph',
                            'content': [
                                {
                                    'type': 'text',
                                    'text': comment
                                }
                            ]
                        }
                    ]
                }
            }
            
            # Add comment
            response = requests.post(
                f"{self.url}/rest/api/3/issue/{external_id}/comment",
                headers=self.headers,
                json=comment_data,
                timeout=30
            )
            
            if response.status_code in [200, 201]:
                self.logger.info(f"Updated JIRA issue: {external_id}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.SUCCESS,
                    message=f"Updated JIRA issue {external_id}",
                    external_id=external_id,
                    external_url=f"{self.url}/browse/{external_id}"
                )
            else:
                error_msg = response.text
                self.logger.error(f"Failed to update JIRA issue: {error_msg}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.FAILED,
                    message="Failed to update JIRA issue",
                    error=error_msg
                )
                
        except Exception as e:
            self.logger.exception("Error updating JIRA issue")
            return IntegrationResult(
                integration_name=self.config.name,
                status=IntegrationStatus.FAILED,
                message="Exception updating JIRA issue",
                error=str(e)
            )
    
    def send_notification(self, validation_result: Any, message: str) -> IntegrationResult:
        """
        Send notification (not applicable for JIRA).
        
        JIRA integration creates issues, not notifications.
        """
        return IntegrationResult(
            integration_name=self.config.name,
            status=IntegrationStatus.SKIPPED,
            message="Notifications not supported for JIRA integration"
        )
    
    def _build_issue_data(self, validation_result: Any) -> Dict[str, Any]:
        """Build JIRA issue data from validation result."""
        report = validation_result.report
        
        # Determine priority
        priority = 'Medium'
        if validation_result.cvss_score:
            severity = validation_result.cvss_score.severity.upper()
            priority = self.priority_mapping.get(severity, 'Medium')
        
        # Build description
        description = self._build_description(validation_result)
        
        # Build issue data
        issue_data = {
            'fields': {
                'project': {
                    'key': self.project_key
                },
                'summary': report.title,
                'description': {
                    'type': 'doc',
                    'version': 1,
                    'content': [
                        {
                            'type': 'paragraph',
                            'content': [
                                {
                                    'type': 'text',
                                    'text': description
                                }
                            ]
                        }
                    ]
                },
                'issuetype': {
                    'name': self.issue_type
                },
                'priority': {
                    'name': priority
                },
            }
        }
        
        # Add custom fields
        if self.custom_fields:
            issue_data['fields'].update(self.custom_fields)
        
        # Add labels
        labels = ['bountybot', 'security']
        if report.vulnerability_type:
            labels.append(report.vulnerability_type.lower().replace(' ', '-'))
        issue_data['fields']['labels'] = labels
        
        return issue_data
    
    def _build_description(self, validation_result: Any) -> str:
        """Build issue description."""
        report = validation_result.report
        lines = []
        
        lines.append(f"Vulnerability Type: {report.vulnerability_type or 'Unknown'}")
        lines.append(f"Severity: {report.severity or 'Unknown'}")
        lines.append(f"Researcher: {report.researcher or 'Unknown'}")
        lines.append("")
        lines.append("=== Validation Results ===")
        lines.append(self._format_validation_summary(validation_result))
        lines.append("")
        lines.append("=== Description ===")
        lines.append(report.impact_description or "No description provided")
        
        return "\n".join(lines)
    
    def _build_comment(self, validation_result: Any) -> str:
        """Build comment for issue update."""
        lines = []
        lines.append("=== Re-validation Results ===")
        lines.append(self._format_validation_summary(validation_result))
        return "\n".join(lines)

