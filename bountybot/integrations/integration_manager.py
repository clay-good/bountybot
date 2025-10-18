"""
Integration Manager for BountyBot.

Manages and orchestrates all integrations.
"""

import logging
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from bountybot.integrations.base import (
    BaseIntegration,
    IntegrationConfig,
    IntegrationResult,
    IntegrationStatus,
    IntegrationType,
)
from bountybot.integrations.jira_integration import JiraIntegration
from bountybot.integrations.slack_integration import SlackIntegration
from bountybot.integrations.github_integration import GitHubIntegration
from bountybot.integrations.pagerduty_integration import PagerDutyIntegration
from bountybot.integrations.email_integration import EmailIntegration

logger = logging.getLogger(__name__)


class IntegrationManager:
    """
    Manages all integrations for BountyBot.
    
    Handles:
    - Loading and initializing integrations
    - Executing integrations based on triggers
    - Parallel execution of integrations
    - Result aggregation and reporting
    """
    
    # Integration type mapping
    INTEGRATION_CLASSES = {
        'jira': JiraIntegration,
        'slack': SlackIntegration,
        'github': GitHubIntegration,
        'pagerduty': PagerDutyIntegration,
        'email': EmailIntegration,
    }
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize integration manager.
        
        Args:
            config: Configuration dictionary with integrations section
        """
        self.config = config
        self.integrations: Dict[str, BaseIntegration] = {}
        self.enabled_integrations: List[str] = []
        
        # Load integrations from config
        self._load_integrations()
    
    def _load_integrations(self):
        """Load and initialize integrations from configuration."""
        integrations_config = self.config.get('integrations', {})
        
        if not integrations_config.get('enabled', False):
            logger.info("Integrations disabled in configuration")
            return
        
        # Load each integration
        for integration_name, integration_config in integrations_config.items():
            if integration_name == 'enabled':
                continue
            
            try:
                # Determine integration type
                integration_type_str = integration_config.get('type', integration_name)
                
                if integration_type_str not in self.INTEGRATION_CLASSES:
                    logger.warning(f"Unknown integration type: {integration_type_str}")
                    continue
                
                # Map type string to enum
                type_mapping = {
                    'jira': IntegrationType.ISSUE_TRACKER,
                    'slack': IntegrationType.NOTIFICATION,
                    'github': IntegrationType.VERSION_CONTROL,
                    'pagerduty': IntegrationType.INCIDENT_MANAGEMENT,
                    'email': IntegrationType.EMAIL,
                }
                
                integration_type = type_mapping.get(integration_type_str, IntegrationType.NOTIFICATION)
                
                # Create integration config
                config_obj = IntegrationConfig(
                    name=integration_name,
                    type=integration_type,
                    enabled=integration_config.get('enabled', True),
                    config=integration_config.get('config', {}),
                    trigger_on_valid=integration_config.get('trigger_on_valid', True),
                    trigger_on_invalid=integration_config.get('trigger_on_invalid', False),
                    trigger_on_uncertain=integration_config.get('trigger_on_uncertain', True),
                    min_severity=integration_config.get('min_severity'),
                    min_confidence=integration_config.get('min_confidence', 0),
                    rate_limit_enabled=integration_config.get('rate_limit_enabled', False),
                    max_calls_per_hour=integration_config.get('max_calls_per_hour', 100),
                )
                
                # Instantiate integration
                integration_class = self.INTEGRATION_CLASSES[integration_type_str]
                integration = integration_class(config_obj)
                
                self.integrations[integration_name] = integration
                
                if config_obj.enabled:
                    self.enabled_integrations.append(integration_name)
                    logger.info(f"Loaded integration: {integration_name} ({integration_type_str})")
                else:
                    logger.info(f"Loaded integration (disabled): {integration_name}")
                
            except Exception as e:
                logger.error(f"Failed to load integration {integration_name}: {e}")
    
    def test_all_connections(self) -> Dict[str, bool]:
        """
        Test connections for all enabled integrations.
        
        Returns:
            Dictionary mapping integration name to connection status
        """
        results = {}
        
        for name in self.enabled_integrations:
            integration = self.integrations[name]
            try:
                results[name] = integration.test_connection()
            except Exception as e:
                logger.error(f"Error testing {name}: {e}")
                results[name] = False
        
        return results
    
    def execute_integrations(self, validation_result: Any, 
                            parallel: bool = True) -> List[IntegrationResult]:
        """
        Execute all applicable integrations for a validation result.
        
        Args:
            validation_result: ValidationResult object
            parallel: Execute integrations in parallel (default: True)
            
        Returns:
            List of IntegrationResult objects
        """
        results = []
        
        # Filter integrations that should be triggered
        applicable_integrations = []
        for name in self.enabled_integrations:
            integration = self.integrations[name]
            if integration.should_trigger(validation_result):
                applicable_integrations.append((name, integration))
        
        if not applicable_integrations:
            logger.info("No integrations triggered for this validation result")
            return results
        
        logger.info(f"Executing {len(applicable_integrations)} integrations")
        
        if parallel and len(applicable_integrations) > 1:
            # Execute in parallel
            results = self._execute_parallel(applicable_integrations, validation_result)
        else:
            # Execute sequentially
            results = self._execute_sequential(applicable_integrations, validation_result)
        
        return results
    
    def _execute_sequential(self, integrations: List[tuple], 
                           validation_result: Any) -> List[IntegrationResult]:
        """Execute integrations sequentially."""
        results = []
        
        for name, integration in integrations:
            try:
                logger.info(f"Executing integration: {name}")
                result = integration.create_issue(validation_result)
                results.append(result)
                
                if result.status == IntegrationStatus.SUCCESS:
                    logger.info(f"Integration {name} succeeded: {result.message}")
                else:
                    logger.warning(f"Integration {name} failed: {result.message}")
                    
            except Exception as e:
                logger.exception(f"Error executing integration {name}")
                results.append(IntegrationResult(
                    integration_name=name,
                    status=IntegrationStatus.FAILED,
                    message="Exception during execution",
                    error=str(e)
                ))
        
        return results
    
    def _execute_parallel(self, integrations: List[tuple], 
                         validation_result: Any) -> List[IntegrationResult]:
        """Execute integrations in parallel."""
        results = []
        
        with ThreadPoolExecutor(max_workers=len(integrations)) as executor:
            # Submit all integration tasks
            future_to_integration = {}
            for name, integration in integrations:
                future = executor.submit(integration.create_issue, validation_result)
                future_to_integration[future] = name
            
            # Collect results as they complete
            for future in as_completed(future_to_integration):
                name = future_to_integration[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result.status == IntegrationStatus.SUCCESS:
                        logger.info(f"Integration {name} succeeded: {result.message}")
                    else:
                        logger.warning(f"Integration {name} failed: {result.message}")
                        
                except Exception as e:
                    logger.exception(f"Error executing integration {name}")
                    results.append(IntegrationResult(
                        integration_name=name,
                        status=IntegrationStatus.FAILED,
                        message="Exception during execution",
                        error=str(e)
                    ))
        
        return results
    
    def send_notification(self, validation_result: Any, message: str,
                         integration_names: Optional[List[str]] = None) -> List[IntegrationResult]:
        """
        Send notifications via specified integrations.
        
        Args:
            validation_result: ValidationResult object
            message: Notification message
            integration_names: List of integration names (None = all notification integrations)
            
        Returns:
            List of IntegrationResult objects
        """
        results = []
        
        # Determine which integrations to use
        if integration_names:
            targets = [name for name in integration_names if name in self.enabled_integrations]
        else:
            # Use all notification-type integrations
            targets = [
                name for name in self.enabled_integrations
                if self.integrations[name].config.type in [
                    IntegrationType.NOTIFICATION,
                    IntegrationType.EMAIL
                ]
            ]
        
        # Send notifications
        for name in targets:
            integration = self.integrations[name]
            try:
                result = integration.send_notification(validation_result, message)
                results.append(result)
            except Exception as e:
                logger.exception(f"Error sending notification via {name}")
                results.append(IntegrationResult(
                    integration_name=name,
                    status=IntegrationStatus.FAILED,
                    message="Exception sending notification",
                    error=str(e)
                ))
        
        return results
    
    def update_issue(self, integration_name: str, external_id: str,
                    validation_result: Any) -> IntegrationResult:
        """
        Update an existing issue in a specific integration.
        
        Args:
            integration_name: Name of the integration
            external_id: External ID (issue key, incident ID, etc.)
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult
        """
        if integration_name not in self.integrations:
            return IntegrationResult(
                integration_name=integration_name,
                status=IntegrationStatus.FAILED,
                message=f"Integration {integration_name} not found"
            )
        
        integration = self.integrations[integration_name]
        
        try:
            return integration.update_issue(external_id, validation_result)
        except Exception as e:
            logger.exception(f"Error updating issue in {integration_name}")
            return IntegrationResult(
                integration_name=integration_name,
                status=IntegrationStatus.FAILED,
                message="Exception updating issue",
                error=str(e)
            )
    
    def get_integration(self, name: str) -> Optional[BaseIntegration]:
        """
        Get a specific integration by name.
        
        Args:
            name: Integration name
            
        Returns:
            Integration instance or None
        """
        return self.integrations.get(name)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get statistics for all integrations.
        
        Returns:
            Dictionary with integration statistics
        """
        stats = {
            'total_integrations': len(self.integrations),
            'enabled_integrations': len(self.enabled_integrations),
            'integrations': {}
        }
        
        for name, integration in self.integrations.items():
            stats['integrations'][name] = integration.get_stats()
        
        return stats
    
    def list_integrations(self) -> List[Dict[str, Any]]:
        """
        List all integrations with their status.
        
        Returns:
            List of integration info dictionaries
        """
        integrations_list = []
        
        for name, integration in self.integrations.items():
            integrations_list.append({
                'name': name,
                'type': integration.config.type.value,
                'enabled': integration.config.enabled,
                'trigger_on_valid': integration.config.trigger_on_valid,
                'trigger_on_invalid': integration.config.trigger_on_invalid,
                'trigger_on_uncertain': integration.config.trigger_on_uncertain,
                'min_severity': integration.config.min_severity,
                'min_confidence': integration.config.min_confidence,
            })
        
        return integrations_list

