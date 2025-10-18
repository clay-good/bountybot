"""
Slack integration for BountyBot.

Sends notifications to Slack channels for validated vulnerability reports.
"""

import logging
import requests
from typing import Dict, Any, Optional, List

from bountybot.integrations.base import (
    BaseIntegration,
    IntegrationConfig,
    IntegrationResult,
    IntegrationStatus,
)

logger = logging.getLogger(__name__)


class SlackIntegration(BaseIntegration):
    """
    Slack integration for sending notifications.
    
    Configuration:
        webhook_url: Slack webhook URL
        channel: Default channel (optional, webhook has default)
        username: Bot username (default: BountyBot)
        icon_emoji: Bot icon (default: :shield:)
        mention_users: List of user IDs to mention for critical issues
        mention_channels: List of channels to mention
        include_details: Include detailed validation info (default: True)
    """
    
    def __init__(self, config: IntegrationConfig):
        """Initialize Slack integration."""
        super().__init__(config)
        
        self.webhook_url = config.config.get('webhook_url', '')
        self.channel = config.config.get('channel')
        self.username = config.config.get('username', 'BountyBot')
        self.icon_emoji = config.config.get('icon_emoji', ':shield:')
        self.mention_users = config.config.get('mention_users', [])
        self.mention_channels = config.config.get('mention_channels', [])
        self.include_details = config.config.get('include_details', True)
    
    def test_connection(self) -> bool:
        """Test connection to Slack."""
        try:
            payload = {
                'text': 'BountyBot connection test successful! :white_check_mark:',
                'username': self.username,
                'icon_emoji': self.icon_emoji,
            }
            
            if self.channel:
                payload['channel'] = self.channel
            
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                self.logger.info("Slack connection test successful")
                return True
            else:
                self.logger.error(f"Slack connection test failed: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Slack connection test error: {e}")
            return False
    
    def create_issue(self, validation_result: Any) -> IntegrationResult:
        """
        Send Slack notification for new validation.
        
        Args:
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with notification status
        """
        return self.send_notification(validation_result, "New vulnerability report validated")
    
    def update_issue(self, external_id: str, validation_result: Any) -> IntegrationResult:
        """
        Send Slack notification for updated validation.
        
        Args:
            external_id: Not used for Slack
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with notification status
        """
        return self.send_notification(validation_result, "Vulnerability report re-validated")
    
    def send_notification(self, validation_result: Any, message: str) -> IntegrationResult:
        """
        Send a Slack notification.
        
        Args:
            validation_result: ValidationResult object
            message: Notification message
            
        Returns:
            IntegrationResult with notification status
        """
        try:
            # Build Slack message
            payload = self._build_message(validation_result, message)
            
            # Send to Slack
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                self.logger.info("Sent Slack notification")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.SUCCESS,
                    message="Slack notification sent successfully"
                )
            else:
                error_msg = response.text
                self.logger.error(f"Failed to send Slack notification: {error_msg}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.FAILED,
                    message="Failed to send Slack notification",
                    error=error_msg
                )
                
        except Exception as e:
            self.logger.exception("Error sending Slack notification")
            return IntegrationResult(
                integration_name=self.config.name,
                status=IntegrationStatus.FAILED,
                message="Exception sending Slack notification",
                error=str(e)
            )
    
    def _build_message(self, validation_result: Any, header_message: str) -> Dict[str, Any]:
        """Build Slack message payload."""
        report = validation_result.report
        
        # Determine color based on verdict and severity
        color = self._get_color(validation_result)
        
        # Build message
        payload = {
            'username': self.username,
            'icon_emoji': self.icon_emoji,
        }
        
        if self.channel:
            payload['channel'] = self.channel
        
        # Build blocks for rich formatting
        blocks = []
        
        # Header
        header_text = f"*{header_message}*"
        
        # Add mentions for critical issues
        if self._is_critical(validation_result):
            mentions = []
            for user_id in self.mention_users:
                mentions.append(f"<@{user_id}>")
            for channel in self.mention_channels:
                mentions.append(f"<!{channel}>")
            
            if mentions:
                header_text += f" {' '.join(mentions)}"
        
        blocks.append({
            'type': 'section',
            'text': {
                'type': 'mrkdwn',
                'text': header_text
            }
        })
        
        # Title and basic info
        blocks.append({
            'type': 'section',
            'fields': [
                {
                    'type': 'mrkdwn',
                    'text': f"*Title:*\n{report.title}"
                },
                {
                    'type': 'mrkdwn',
                    'text': f"*Researcher:*\n{report.researcher or 'Unknown'}"
                }
            ]
        })
        
        # Validation results
        verdict_emoji = self._get_verdict_emoji(validation_result.verdict.value)
        blocks.append({
            'type': 'section',
            'fields': [
                {
                    'type': 'mrkdwn',
                    'text': f"*Verdict:*\n{verdict_emoji} {validation_result.verdict.value}"
                },
                {
                    'type': 'mrkdwn',
                    'text': f"*Confidence:*\n{validation_result.confidence}%"
                }
            ]
        })
        
        # CVSS and Priority
        if validation_result.cvss_score or validation_result.priority_score:
            fields = []
            
            if validation_result.cvss_score:
                cvss = validation_result.cvss_score
                fields.append({
                    'type': 'mrkdwn',
                    'text': f"*CVSS Score:*\n{cvss.base_score} ({cvss.severity})"
                })
            
            if validation_result.priority_score:
                priority = validation_result.priority_score
                fields.append({
                    'type': 'mrkdwn',
                    'text': f"*Priority:*\n{priority.priority_level} (Score: {priority.total_score:.1f})"
                })
            
            blocks.append({
                'type': 'section',
                'fields': fields
            })
        
        # Key findings (if enabled)
        if self.include_details and validation_result.key_findings:
            findings_text = "*Key Findings:*\n"
            for finding in validation_result.key_findings[:3]:
                findings_text += f"• {finding}\n"
            
            blocks.append({
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': findings_text
                }
            })
        
        # Divider
        blocks.append({'type': 'divider'})
        
        # Footer with metadata
        footer_text = f"Processed in {validation_result.processing_time_seconds:.2f}s"
        if validation_result.ai_provider:
            footer_text += f" | Provider: {validation_result.ai_provider}"
        
        blocks.append({
            'type': 'context',
            'elements': [
                {
                    'type': 'mrkdwn',
                    'text': footer_text
                }
            ]
        })
        
        payload['blocks'] = blocks
        
        # Fallback text for notifications
        payload['text'] = f"{header_message}: {report.title} - {validation_result.verdict.value}"
        
        return payload
    
    def _get_color(self, validation_result: Any) -> str:
        """Get color based on verdict and severity."""
        if validation_result.verdict.value == 'VALID':
            if validation_result.cvss_score:
                severity = validation_result.cvss_score.severity.upper()
                if severity == 'CRITICAL':
                    return 'danger'
                elif severity == 'HIGH':
                    return 'warning'
            return 'warning'
        elif validation_result.verdict.value == 'INVALID':
            return 'good'
        else:  # UNCERTAIN
            return '#808080'
    
    def _get_verdict_emoji(self, verdict: str) -> str:
        """Get emoji for verdict."""
        emoji_map = {
            'VALID': ':red_circle:',
            'INVALID': ':white_check_mark:',
            'UNCERTAIN': ':warning:',
        }
        return emoji_map.get(verdict, ':question:')
    
    def _is_critical(self, validation_result: Any) -> bool:
        """Check if issue is critical."""
        if validation_result.verdict.value != 'VALID':
            return False
        
        if validation_result.cvss_score:
            severity = validation_result.cvss_score.severity.upper()
            if severity in ['CRITICAL', 'HIGH']:
                return True
        
        if validation_result.priority_score:
            if validation_result.priority_score.priority_level in ['P0', 'P1']:
                return True
        
        return False

