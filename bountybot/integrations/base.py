"""
Base classes for integrations.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class IntegrationStatus(Enum):
    """Integration execution status."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"


class IntegrationType(Enum):
    """Types of integrations."""
    ISSUE_TRACKER = "ISSUE_TRACKER"
    NOTIFICATION = "NOTIFICATION"
    INCIDENT_MANAGEMENT = "INCIDENT_MANAGEMENT"
    VERSION_CONTROL = "VERSION_CONTROL"
    EMAIL = "EMAIL"


@dataclass
class IntegrationConfig:
    """Configuration for an integration."""
    name: str
    type: IntegrationType
    enabled: bool = True
    config: Dict[str, Any] = field(default_factory=dict)
    
    # Trigger conditions
    trigger_on_valid: bool = True
    trigger_on_invalid: bool = False
    trigger_on_uncertain: bool = True
    min_severity: Optional[str] = None  # CRITICAL, HIGH, MEDIUM, LOW
    min_confidence: int = 0  # 0-100
    
    # Rate limiting
    rate_limit_enabled: bool = False
    max_calls_per_hour: int = 100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'name': self.name,
            'type': self.type.value,
            'enabled': self.enabled,
            'config': self.config,
            'trigger_on_valid': self.trigger_on_valid,
            'trigger_on_invalid': self.trigger_on_invalid,
            'trigger_on_uncertain': self.trigger_on_uncertain,
            'min_severity': self.min_severity,
            'min_confidence': self.min_confidence,
            'rate_limit_enabled': self.rate_limit_enabled,
            'max_calls_per_hour': self.max_calls_per_hour,
        }


@dataclass
class IntegrationResult:
    """Result of an integration execution."""
    integration_name: str
    status: IntegrationStatus
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    
    # Optional data
    external_id: Optional[str] = None  # ID in external system (JIRA issue key, etc.)
    external_url: Optional[str] = None  # URL to external resource
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'integration_name': self.integration_name,
            'status': self.status.value,
            'message': self.message,
            'timestamp': self.timestamp.isoformat(),
            'external_id': self.external_id,
            'external_url': self.external_url,
            'error': self.error,
            'metadata': self.metadata,
        }


class BaseIntegration(ABC):
    """
    Base class for all integrations.
    
    Provides common functionality for connecting BountyBot with external systems.
    """
    
    def __init__(self, config: IntegrationConfig):
        """
        Initialize integration.
        
        Args:
            config: Integration configuration
        """
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.{config.name}")
        self._call_count = 0
        self._last_reset = datetime.now()
    
    @abstractmethod
    def test_connection(self) -> bool:
        """
        Test connection to external system.
        
        Returns:
            True if connection successful, False otherwise
        """
        pass
    
    @abstractmethod
    def create_issue(self, validation_result: Any) -> IntegrationResult:
        """
        Create an issue/ticket in the external system.
        
        Args:
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with status and details
        """
        pass
    
    @abstractmethod
    def update_issue(self, external_id: str, validation_result: Any) -> IntegrationResult:
        """
        Update an existing issue/ticket.
        
        Args:
            external_id: ID in external system
            validation_result: ValidationResult object
            
        Returns:
            IntegrationResult with status and details
        """
        pass
    
    @abstractmethod
    def send_notification(self, validation_result: Any, message: str) -> IntegrationResult:
        """
        Send a notification.
        
        Args:
            validation_result: ValidationResult object
            message: Notification message
            
        Returns:
            IntegrationResult with status and details
        """
        pass
    
    def should_trigger(self, validation_result: Any) -> bool:
        """
        Check if integration should be triggered based on validation result.
        
        Args:
            validation_result: ValidationResult object
            
        Returns:
            True if integration should be triggered
        """
        # Check if enabled
        if not self.config.enabled:
            return False
        
        # Check rate limit
        if self.config.rate_limit_enabled:
            if not self._check_rate_limit():
                self.logger.warning(f"Rate limit exceeded for {self.config.name}")
                return False
        
        # Check verdict
        verdict = validation_result.verdict.value
        if verdict == 'VALID' and not self.config.trigger_on_valid:
            return False
        if verdict == 'INVALID' and not self.config.trigger_on_invalid:
            return False
        if verdict == 'UNCERTAIN' and not self.config.trigger_on_uncertain:
            return False
        
        # Check confidence
        if validation_result.confidence < self.config.min_confidence:
            return False
        
        # Check severity (if CVSS score available)
        if self.config.min_severity and validation_result.cvss_score:
            severity_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            min_severity_idx = severity_order.index(self.config.min_severity)
            current_severity = validation_result.cvss_score.severity.upper()
            
            if current_severity not in severity_order:
                return False
            
            current_severity_idx = severity_order.index(current_severity)
            if current_severity_idx < min_severity_idx:
                return False
        
        return True
    
    def _check_rate_limit(self) -> bool:
        """
        Check if rate limit allows another call.
        
        Returns:
            True if call is allowed
        """
        now = datetime.now()
        elapsed = (now - self._last_reset).total_seconds()
        
        # Reset counter every hour
        if elapsed >= 3600:
            self._call_count = 0
            self._last_reset = now
        
        if self._call_count >= self.config.max_calls_per_hour:
            return False
        
        self._call_count += 1
        return True
    
    def _format_validation_summary(self, validation_result: Any) -> str:
        """
        Format validation result into a summary string.
        
        Args:
            validation_result: ValidationResult object
            
        Returns:
            Formatted summary string
        """
        lines = []
        lines.append(f"**Verdict:** {validation_result.verdict.value}")
        lines.append(f"**Confidence:** {validation_result.confidence}%")
        
        if validation_result.cvss_score:
            lines.append(f"**CVSS Score:** {validation_result.cvss_score.base_score} ({validation_result.cvss_score.severity})")
        
        if validation_result.priority_score:
            lines.append(f"**Priority:** {validation_result.priority_score.priority_level}")
        
        if validation_result.key_findings:
            lines.append(f"\n**Key Findings:**")
            for finding in validation_result.key_findings[:3]:
                lines.append(f"- {finding}")
        
        return "\n".join(lines)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get integration statistics.
        
        Returns:
            Dictionary with stats
        """
        return {
            'name': self.config.name,
            'type': self.config.type.value,
            'enabled': self.config.enabled,
            'call_count': self._call_count,
            'rate_limit_enabled': self.config.rate_limit_enabled,
            'max_calls_per_hour': self.config.max_calls_per_hour,
        }

