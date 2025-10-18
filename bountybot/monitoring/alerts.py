"""
Alert Management

Manages alerts and notifications for system events.
"""

import logging
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
import threading

logger = logging.getLogger(__name__)


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class AlertChannel(str, Enum):
    """Alert notification channels."""
    LOG = "log"
    EMAIL = "email"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    WEBHOOK = "webhook"


@dataclass
class Alert:
    """Alert data."""
    alert_id: str
    severity: AlertSeverity
    title: str
    message: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    source: str = "bountybot"
    metadata: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolved_at: Optional[datetime] = None


@dataclass
class AlertRule:
    """Alert rule configuration."""
    rule_id: str
    name: str
    condition: Callable[[], bool]
    severity: AlertSeverity
    message_template: str
    channels: List[AlertChannel]
    cooldown_minutes: int = 15
    enabled: bool = True
    last_triggered: Optional[datetime] = None


class AlertManager:
    """
    Manages alerts and notifications.
    
    Features:
    - Alert rules with conditions
    - Multiple notification channels
    - Alert cooldown to prevent spam
    - Alert history and tracking
    - Alert resolution
    """
    
    def __init__(self):
        """Initialize alert manager."""
        self.alerts: Dict[str, Alert] = {}
        self.rules: Dict[str, AlertRule] = {}
        self.handlers: Dict[AlertChannel, Callable] = {}
        self.lock = threading.Lock()
        
        # Register default handlers
        self._register_default_handlers()
        
        # Initialize default rules
        self._initialize_default_rules()
        
        logger.info("Initialized AlertManager")
    
    def _register_default_handlers(self):
        """Register default alert handlers."""
        self.handlers[AlertChannel.LOG] = self._handle_log_alert
    
    def _handle_log_alert(self, alert: Alert):
        """Handle alert by logging."""
        log_level = {
            AlertSeverity.INFO: logging.INFO,
            AlertSeverity.WARNING: logging.WARNING,
            AlertSeverity.ERROR: logging.ERROR,
            AlertSeverity.CRITICAL: logging.CRITICAL
        }.get(alert.severity, logging.INFO)
        
        logger.log(log_level, f"[ALERT] {alert.title}: {alert.message}")
    
    def _initialize_default_rules(self):
        """Initialize default alert rules."""
        # High error rate alert
        self.add_rule(AlertRule(
            rule_id="high_error_rate",
            name="High Error Rate",
            condition=lambda: False,  # Will be set dynamically
            severity=AlertSeverity.ERROR,
            message_template="Error rate is above threshold",
            channels=[AlertChannel.LOG],
            cooldown_minutes=15
        ))
        
        # Low disk space alert
        self.add_rule(AlertRule(
            rule_id="low_disk_space",
            name="Low Disk Space",
            condition=lambda: False,
            severity=AlertSeverity.WARNING,
            message_template="Disk space is running low",
            channels=[AlertChannel.LOG],
            cooldown_minutes=60
        ))
        
        # High memory usage alert
        self.add_rule(AlertRule(
            rule_id="high_memory_usage",
            name="High Memory Usage",
            condition=lambda: False,
            severity=AlertSeverity.WARNING,
            message_template="Memory usage is high",
            channels=[AlertChannel.LOG],
            cooldown_minutes=30
        ))
        
        # Database connection failure
        self.add_rule(AlertRule(
            rule_id="database_connection_failure",
            name="Database Connection Failure",
            condition=lambda: False,
            severity=AlertSeverity.CRITICAL,
            message_template="Cannot connect to database",
            channels=[AlertChannel.LOG],
            cooldown_minutes=5
        ))
        
        # AI provider failure
        self.add_rule(AlertRule(
            rule_id="ai_provider_failure",
            name="AI Provider Failure",
            condition=lambda: False,
            severity=AlertSeverity.CRITICAL,
            message_template="AI provider is unavailable",
            channels=[AlertChannel.LOG],
            cooldown_minutes=5
        ))
    
    def add_rule(self, rule: AlertRule):
        """Add an alert rule."""
        with self.lock:
            self.rules[rule.rule_id] = rule
            logger.info(f"Added alert rule: {rule.name}")
    
    def remove_rule(self, rule_id: str):
        """Remove an alert rule."""
        with self.lock:
            if rule_id in self.rules:
                del self.rules[rule_id]
                logger.info(f"Removed alert rule: {rule_id}")
    
    def enable_rule(self, rule_id: str):
        """Enable an alert rule."""
        with self.lock:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = True
                logger.info(f"Enabled alert rule: {rule_id}")
    
    def disable_rule(self, rule_id: str):
        """Disable an alert rule."""
        with self.lock:
            if rule_id in self.rules:
                self.rules[rule_id].enabled = False
                logger.info(f"Disabled alert rule: {rule_id}")
    
    def register_handler(self, channel: AlertChannel, handler: Callable[[Alert], None]):
        """Register a custom alert handler."""
        self.handlers[channel] = handler
        logger.info(f"Registered handler for channel: {channel}")
    
    def create_alert(
        self,
        severity: AlertSeverity,
        title: str,
        message: str,
        source: str = "bountybot",
        metadata: Optional[Dict[str, Any]] = None
    ) -> Alert:
        """Create and send an alert."""
        import secrets
        
        alert_id = f"alert_{secrets.token_hex(8)}"
        
        alert = Alert(
            alert_id=alert_id,
            severity=severity,
            title=title,
            message=message,
            source=source,
            metadata=metadata or {}
        )
        
        with self.lock:
            self.alerts[alert_id] = alert
        
        # Send to all log channel by default
        self._send_alert(alert, [AlertChannel.LOG])
        
        logger.info(f"Created alert: {alert.title} ({alert.severity})")
        
        return alert
    
    def _send_alert(self, alert: Alert, channels: List[AlertChannel]):
        """Send alert to specified channels."""
        for channel in channels:
            handler = self.handlers.get(channel)
            if handler:
                try:
                    handler(alert)
                except Exception as e:
                    logger.error(f"Error sending alert to {channel}: {e}")
    
    def check_rules(self):
        """Check all alert rules and trigger alerts if conditions are met."""
        with self.lock:
            for rule in self.rules.values():
                if not rule.enabled:
                    continue
                
                # Check cooldown
                if rule.last_triggered:
                    cooldown_end = rule.last_triggered + timedelta(minutes=rule.cooldown_minutes)
                    if datetime.utcnow() < cooldown_end:
                        continue
                
                # Check condition
                try:
                    if rule.condition():
                        # Trigger alert
                        alert = Alert(
                            alert_id=f"alert_{rule.rule_id}_{int(datetime.utcnow().timestamp())}",
                            severity=rule.severity,
                            title=rule.name,
                            message=rule.message_template,
                            source="alert_rule"
                        )
                        
                        self.alerts[alert.alert_id] = alert
                        self._send_alert(alert, rule.channels)
                        
                        rule.last_triggered = datetime.utcnow()
                        
                        logger.info(f"Triggered alert rule: {rule.name}")
                        
                except Exception as e:
                    logger.error(f"Error checking rule {rule.name}: {e}")
    
    def resolve_alert(self, alert_id: str):
        """Mark an alert as resolved."""
        with self.lock:
            if alert_id in self.alerts:
                alert = self.alerts[alert_id]
                alert.resolved = True
                alert.resolved_at = datetime.utcnow()
                logger.info(f"Resolved alert: {alert.title}")
    
    def get_alert(self, alert_id: str) -> Optional[Alert]:
        """Get an alert by ID."""
        return self.alerts.get(alert_id)
    
    def get_active_alerts(self) -> List[Alert]:
        """Get all active (unresolved) alerts."""
        with self.lock:
            return [alert for alert in self.alerts.values() if not alert.resolved]
    
    def get_alerts_by_severity(self, severity: AlertSeverity) -> List[Alert]:
        """Get alerts by severity."""
        with self.lock:
            return [alert for alert in self.alerts.values() if alert.severity == severity]
    
    def get_recent_alerts(self, hours: int = 24) -> List[Alert]:
        """Get alerts from the last N hours."""
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        with self.lock:
            return [
                alert for alert in self.alerts.values()
                if alert.timestamp >= cutoff
            ]
    
    def clear_resolved_alerts(self, older_than_hours: int = 24):
        """Clear resolved alerts older than specified hours."""
        cutoff = datetime.utcnow() - timedelta(hours=older_than_hours)
        
        with self.lock:
            to_remove = [
                alert_id for alert_id, alert in self.alerts.items()
                if alert.resolved and alert.resolved_at and alert.resolved_at < cutoff
            ]
            
            for alert_id in to_remove:
                del self.alerts[alert_id]
            
            if to_remove:
                logger.info(f"Cleared {len(to_remove)} resolved alerts")
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """Get summary of alerts."""
        with self.lock:
            active_alerts = [a for a in self.alerts.values() if not a.resolved]
            
            summary = {
                "total_alerts": len(self.alerts),
                "active_alerts": len(active_alerts),
                "resolved_alerts": len(self.alerts) - len(active_alerts),
                "by_severity": {
                    "critical": len([a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]),
                    "error": len([a for a in active_alerts if a.severity == AlertSeverity.ERROR]),
                    "warning": len([a for a in active_alerts if a.severity == AlertSeverity.WARNING]),
                    "info": len([a for a in active_alerts if a.severity == AlertSeverity.INFO])
                },
                "rules_enabled": len([r for r in self.rules.values() if r.enabled]),
                "rules_total": len(self.rules)
            }
            
            return summary


# Global alert manager instance
alert_manager = AlertManager()

