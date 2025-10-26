"""
PagerDuty integration for BountyBot.

Creates incidents in PagerDuty for critical validated vulnerability reports.
"""

import logging
import requests
from typing import Dict, Any, Optional
from datetime import datetime

from bountybot.integrations.base import (
    BaseIntegration,
    IntegrationConfig,
    IntegrationResult,
    IntegrationStatus,
)

logger = logging.getLogger(__name__)


class PagerDutyIntegration(BaseIntegration):
    """
    PagerDuty integration for incident management.
    
    Configuration:
        integration_key: PagerDuty Events API v2 integration key
        routing_key: Alternative to integration_key
        severity_mapping: Map CVSS severity to PagerDuty severity
        auto_resolve: Auto-resolve incidents for invalid reports (default: False)
        dedup_key_prefix: Prefix for deduplication keys (default: bountybot)
    """
    
    def __init__(self, config: IntegrationConfig):
        """Initialize PagerDuty integration."""
        super().__init__(config)
        
        self.integration_key = config.config.get('integration_key', '') or config.config.get('routing_key', '')
        
        # Severity mapping: CVSS severity -> PagerDuty severity
        self.severity_mapping = config.config.get('severity_mapping', {
            'CRITICAL': 'critical',
            'HIGH': 'error',
            'MEDIUM': 'warning',
            'LOW': 'info',
            'INFO': 'info',
        })
        
        self.auto_resolve = config.config.get('auto_resolve', False)
        self.dedup_key_prefix = config.config.get('dedup_key_prefix', 'bountybot')
        
        self.api_url = 'https://events.pagerduty.com/v2/enqueue'
    
    def test_connection(self) -> bool:
        """
        Test connection to PagerDuty.
        
        Note: PagerDuty Events API doesn't have a test endpoint,
        so we'll just validate the integration key format.
        """
        if self.integration_key and len(self.integration_key) > 20:
            self.logger.info("PagerDuty integration key validated")
            return True
        else:
            self.logger.error("Invalid PagerDuty integration key")
            return False
    
    def create_issue(self, validation_result: Any) -> IntegrationResult:
        """
        Create a PagerDuty incident for the validation result.
        
        Args:
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with incident details
        """
        try:
            # Build event data
            event_data = self._build_event_data(validation_result, action='trigger')
            
            # Send event
            response = requests.post(
                self.api_url,
                json=event_data,
                timeout=30
            )
            
            if response.status_code == 202:
                result_data = response.json()
                dedup_key = result_data.get('dedup_key')
                
                self.logger.info(f"Created PagerDuty incident: {dedup_key}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.SUCCESS,
                    message=f"Created PagerDuty incident",
                    external_id=dedup_key,
                    metadata={'event_data': result_data}
                )
            else:
                error_msg = response.text
                self.logger.error(f"Failed to create PagerDuty incident: {error_msg}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.FAILED,
                    message="Failed to create PagerDuty incident",
                    error=error_msg
                )
                
        except Exception as e:
            self.logger.exception("Error creating PagerDuty incident")
            return IntegrationResult(
                integration_name=self.config.name,
                status=IntegrationStatus.FAILED,
                message="Exception creating PagerDuty incident",
                error=str(e)
            )
    
    def update_issue(self, external_id: str, validation_result: Any) -> IntegrationResult:
        """
        Update an existing PagerDuty incident.
        
        Args:
            external_id: PagerDuty deduplication key
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with update status
        """
        try:
            # Determine action based on verdict
            if validation_result.verdict.value == 'INVALID' and self.auto_resolve:
                action = 'resolve'
            else:
                action = 'trigger'  # Re-trigger with updated info
            
            # Build event data
            event_data = self._build_event_data(validation_result, action=action, dedup_key=external_id)
            
            # Send event
            response = requests.post(
                self.api_url,
                json=event_data,
                timeout=30
            )
            
            if response.status_code == 202:
                self.logger.info(f"Updated PagerDuty incident: {external_id}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.SUCCESS,
                    message=f"Updated PagerDuty incident ({action})",
                    external_id=external_id
                )
            else:
                error_msg = response.text
                self.logger.error(f"Failed to update PagerDuty incident: {error_msg}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.FAILED,
                    message="Failed to update PagerDuty incident",
                    error=error_msg
                )
                
        except Exception as e:
            self.logger.exception("Error updating PagerDuty incident")
            return IntegrationResult(
                integration_name=self.config.name,
                status=IntegrationStatus.FAILED,
                message="Exception updating PagerDuty incident",
                error=str(e)
            )
    
    def send_notification(self, validation_result: Any, message: str) -> IntegrationResult:
        """
        Send notification via PagerDuty.
        
        For PagerDuty, this is the same as creating an incident.
        """
        return self.create_issue(validation_result)
    
    def _build_event_data(self, validation_result: Any, action: str = 'trigger', 
                          dedup_key: Optional[str] = None) -> Dict[str, Any]:
        """Build PagerDuty event data."""
        report = validation_result.report
        
        # Generate deduplication key if not provided
        if not dedup_key:
            # Use report title hash for deduplication (SHA256 for security)
            import hashlib
            title_hash = hashlib.sha256(report.title.encode()).hexdigest()[:16]
            dedup_key = f"{self.dedup_key_prefix}-{title_hash}"
        
        # Determine severity
        severity = 'warning'
        if validation_result.cvss_score:
            cvss_severity = validation_result.cvss_score.severity.upper()
            severity = self.severity_mapping.get(cvss_severity, 'warning')
        
        # Build event
        event_data = {
            'routing_key': self.integration_key,
            'event_action': action,
            'dedup_key': dedup_key,
        }
        
        if action in ['trigger', 'acknowledge']:
            # Build payload for trigger/acknowledge
            payload = {
                'summary': f"Security Vulnerability: {report.title}",
                'source': 'BountyBot',
                'severity': severity,
                'timestamp': datetime.now().isoformat(),
                'component': 'Security',
                'group': 'Bug Bounty',
                'class': report.vulnerability_type or 'Unknown',
            }
            
            # Add custom details
            custom_details = {
                'verdict': validation_result.verdict.value,
                'confidence': f"{validation_result.confidence}%",
                'researcher': report.researcher or 'Unknown',
                'vulnerability_type': report.vulnerability_type or 'Unknown',
            }
            
            if validation_result.cvss_score:
                cvss = validation_result.cvss_score
                custom_details['cvss_score'] = f"{cvss.base_score} ({cvss.severity})"
                custom_details['cvss_vector'] = cvss.vector_string
            
            if validation_result.priority_score:
                priority = validation_result.priority_score
                custom_details['priority'] = f"{priority.priority_level} (Score: {priority.total_score:.1f})"
            
            if report.affected_components:
                custom_details['affected_components'] = ', '.join(report.affected_components)
            
            if validation_result.key_findings:
                custom_details['key_findings'] = validation_result.key_findings[:3]
            
            payload['custom_details'] = custom_details
            
            event_data['payload'] = payload
        
        return event_data
    
    def resolve_incident(self, dedup_key: str) -> IntegrationResult:
        """
        Resolve a PagerDuty incident.
        
        Args:
            dedup_key: PagerDuty deduplication key
            
        Returns:
            IntegrationResult with resolution status
        """
        try:
            event_data = {
                'routing_key': self.integration_key,
                'event_action': 'resolve',
                'dedup_key': dedup_key,
            }
            
            response = requests.post(
                self.api_url,
                json=event_data,
                timeout=30
            )
            
            if response.status_code == 202:
                self.logger.info(f"Resolved PagerDuty incident: {dedup_key}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.SUCCESS,
                    message=f"Resolved PagerDuty incident",
                    external_id=dedup_key
                )
            else:
                error_msg = response.text
                self.logger.error(f"Failed to resolve PagerDuty incident: {error_msg}")
                
                return IntegrationResult(
                    integration_name=self.config.name,
                    status=IntegrationStatus.FAILED,
                    message="Failed to resolve PagerDuty incident",
                    error=error_msg
                )
                
        except Exception as e:
            self.logger.exception("Error resolving PagerDuty incident")
            return IntegrationResult(
                integration_name=self.config.name,
                status=IntegrationStatus.FAILED,
                message="Exception resolving PagerDuty incident",
                error=str(e)
            )

