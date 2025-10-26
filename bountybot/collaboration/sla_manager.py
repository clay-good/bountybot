"""
SLA manager for tracking service level agreements and automated escalation.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from bountybot.collaboration.models import (
    SLA,
    SLAStatus,
    SLABreach,
    EscalationLevel,
    EscalationRule,
    Notification,
    NotificationType,
)


class SLAManager:
    """
    Manage SLAs for reports, tasks, and vulnerabilities.
    
    Example:
        >>> manager = SLAManager()
        >>> 
        >>> # Create SLA
        >>> sla = manager.create_sla(
        ...     entity_type="report",
        ...     entity_id="report-123",
        ...     target_hours=24.0
        ... )
        >>> 
        >>> # Update SLA
        >>> manager.update_sla(sla.sla_id)
        >>> 
        >>> # Check if breached
        >>> if sla.breached:
        ...     print(f"SLA breached by {sla.breach_duration_hours:.1f} hours!")
        >>> 
        >>> # Complete SLA
        >>> manager.complete_sla(sla.sla_id)
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize SLA manager."""
        self.config = config or {}
        self.slas: Dict[str, SLA] = {}
        self.breaches: Dict[str, SLABreach] = {}
        self.notifications: Dict[str, Notification] = {}
        
        # Default SLA targets by entity type and severity
        self.default_targets = {
            'report': {
                'critical': 4.0,   # 4 hours
                'high': 24.0,      # 24 hours
                'medium': 72.0,    # 3 days
                'low': 168.0,      # 7 days
            },
            'task': {
                'critical': 2.0,
                'high': 8.0,
                'medium': 24.0,
                'low': 72.0,
            },
            'vulnerability': {
                'critical': 24.0,
                'high': 72.0,
                'medium': 168.0,
                'low': 720.0,  # 30 days
            }
        }
    
    def create_sla(
        self,
        entity_type: str,
        entity_id: str,
        target_hours: Optional[float] = None,
        severity: Optional[str] = None,
        warning_threshold_percent: float = 0.75
    ) -> SLA:
        """Create a new SLA."""
        # Use default target if not specified
        if target_hours is None:
            if severity and entity_type in self.default_targets:
                target_hours = self.default_targets[entity_type].get(severity, 24.0)
            else:
                target_hours = 24.0
        
        target_completion_time = datetime.utcnow() + timedelta(hours=target_hours)
        
        sla = SLA(
            entity_type=entity_type,
            entity_id=entity_id,
            target_hours=target_hours,
            warning_threshold_percent=warning_threshold_percent,
            target_completion_time=target_completion_time
        )
        
        if severity:
            sla.metadata['severity'] = severity
        
        self.slas[sla.sla_id] = sla
        return sla
    
    def update_sla(self, sla_id: str) -> SLA:
        """Update SLA status and check for breaches."""
        sla = self.slas.get(sla_id)
        if not sla:
            raise ValueError(f"SLA not found: {sla_id}")
        
        if sla.status in [SLAStatus.COMPLETED, SLAStatus.CANCELLED]:
            return sla
        
        now = datetime.utcnow()
        
        # Calculate elapsed time
        elapsed = now - sla.started_at
        sla.elapsed_hours = elapsed.total_seconds() / 3600
        
        # Calculate remaining time
        remaining = sla.target_completion_time - now
        sla.remaining_hours = max(0, remaining.total_seconds() / 3600)
        
        # Calculate percent elapsed
        sla.percent_elapsed = (sla.elapsed_hours / sla.target_hours) * 100
        
        # Check status
        if sla.elapsed_hours >= sla.target_hours:
            # Breached
            if not sla.breached:
                sla.breached = True
                sla.breach_time = now
                sla.status = SLAStatus.BREACHED
                self._record_breach(sla)
            else:
                # Update breach duration
                sla.breach_duration_hours = (now - sla.breach_time).total_seconds() / 3600
        elif sla.percent_elapsed >= (sla.warning_threshold_percent * 100):
            # Warning
            if sla.status == SLAStatus.ACTIVE:
                sla.status = SLAStatus.WARNING
                self._send_warning_notification(sla)
        
        return sla
    
    def complete_sla(self, sla_id: str) -> SLA:
        """Mark SLA as completed."""
        sla = self.slas.get(sla_id)
        if not sla:
            raise ValueError(f"SLA not found: {sla_id}")
        
        sla.status = SLAStatus.COMPLETED
        sla.completed_at = datetime.utcnow()
        
        # Update final metrics
        self.update_sla(sla_id)
        
        return sla
    
    def cancel_sla(self, sla_id: str) -> SLA:
        """Cancel an SLA."""
        sla = self.slas.get(sla_id)
        if not sla:
            raise ValueError(f"SLA not found: {sla_id}")
        
        sla.status = SLAStatus.CANCELLED
        return sla
    
    def get_sla(self, sla_id: str) -> Optional[SLA]:
        """Get SLA by ID."""
        return self.slas.get(sla_id)
    
    def get_entity_sla(self, entity_type: str, entity_id: str) -> Optional[SLA]:
        """Get SLA for an entity."""
        for sla in self.slas.values():
            if sla.entity_type == entity_type and sla.entity_id == entity_id:
                return sla
        return None
    
    def get_active_slas(self) -> List[SLA]:
        """Get all active SLAs."""
        return [
            sla for sla in self.slas.values()
            if sla.status in [SLAStatus.ACTIVE, SLAStatus.WARNING]
        ]
    
    def get_breached_slas(self) -> List[SLA]:
        """Get all breached SLAs."""
        return [
            sla for sla in self.slas.values()
            if sla.status == SLAStatus.BREACHED
        ]
    
    def get_sla_stats(self) -> Dict[str, Any]:
        """Get SLA statistics."""
        all_slas = list(self.slas.values())
        
        stats = {
            'total_slas': len(all_slas),
            'active': len([s for s in all_slas if s.status == SLAStatus.ACTIVE]),
            'warning': len([s for s in all_slas if s.status == SLAStatus.WARNING]),
            'breached': len([s for s in all_slas if s.status == SLAStatus.BREACHED]),
            'completed': len([s for s in all_slas if s.status == SLAStatus.COMPLETED]),
            'cancelled': len([s for s in all_slas if s.status == SLAStatus.CANCELLED]),
            'breach_rate': 0.0,
            'avg_completion_time_hours': 0.0,
            'avg_breach_duration_hours': 0.0,
        }
        
        # Calculate breach rate
        completed_or_breached = [
            s for s in all_slas
            if s.status in [SLAStatus.COMPLETED, SLAStatus.BREACHED]
        ]
        if completed_or_breached:
            breached_count = len([s for s in completed_or_breached if s.breached])
            stats['breach_rate'] = (breached_count / len(completed_or_breached)) * 100
        
        # Calculate average completion time
        completed = [s for s in all_slas if s.status == SLAStatus.COMPLETED]
        if completed:
            total_hours = sum(s.elapsed_hours for s in completed)
            stats['avg_completion_time_hours'] = total_hours / len(completed)
        
        # Calculate average breach duration
        breached = [s for s in all_slas if s.breached and s.breach_duration_hours > 0]
        if breached:
            total_breach_hours = sum(s.breach_duration_hours for s in breached)
            stats['avg_breach_duration_hours'] = total_breach_hours / len(breached)
        
        return stats
    
    def _record_breach(self, sla: SLA):
        """Record an SLA breach."""
        severity = sla.metadata.get('severity', 'medium')
        
        breach = SLABreach(
            sla_id=sla.sla_id,
            entity_type=sla.entity_type,
            entity_id=sla.entity_id,
            breach_time=sla.breach_time,
            target_hours=sla.target_hours,
            actual_hours=sla.elapsed_hours,
            breach_duration_hours=0.0,
            severity=severity
        )
        
        self.breaches[breach.breach_id] = breach
        
        # Send breach notification
        self._send_breach_notification(sla)
    
    def _send_warning_notification(self, sla: SLA):
        """Send warning notification for SLA approaching deadline."""
        notification = Notification(
            user_id="system",  # Would be assigned user in real implementation
            notification_type=NotificationType.SLA_WARNING,
            title=f"SLA Warning: {sla.entity_type} {sla.entity_id}",
            message=f"SLA is at {sla.percent_elapsed:.0f}% ({sla.remaining_hours:.1f}h remaining)",
            entity_type=sla.entity_type,
            entity_id=sla.entity_id
        )
        
        self.notifications[notification.notification_id] = notification
    
    def _send_breach_notification(self, sla: SLA):
        """Send breach notification for SLA."""
        notification = Notification(
            user_id="system",
            notification_type=NotificationType.SLA_BREACH,
            title=f"SLA BREACHED: {sla.entity_type} {sla.entity_id}",
            message=f"SLA breached! Target: {sla.target_hours:.1f}h, Actual: {sla.elapsed_hours:.1f}h",
            entity_type=sla.entity_type,
            entity_id=sla.entity_id
        )
        
        self.notifications[notification.notification_id] = notification


class SLAMonitor:
    """
    Monitor SLAs and trigger updates.
    
    Example:
        >>> manager = SLAManager()
        >>> monitor = SLAMonitor(manager)
        >>> 
        >>> # Monitor all active SLAs
        >>> monitor.monitor_slas()
    """
    
    def __init__(self, sla_manager: SLAManager):
        """Initialize SLA monitor."""
        self.sla_manager = sla_manager
    
    def monitor_slas(self) -> Dict[str, Any]:
        """Monitor all active SLAs and update their status."""
        active_slas = self.sla_manager.get_active_slas()
        
        results = {
            'monitored': len(active_slas),
            'warnings': 0,
            'breaches': 0,
            'updated': []
        }
        
        for sla in active_slas:
            old_status = sla.status
            self.sla_manager.update_sla(sla.sla_id)
            
            if sla.status != old_status:
                results['updated'].append(sla.sla_id)
                
                if sla.status == SLAStatus.WARNING:
                    results['warnings'] += 1
                elif sla.status == SLAStatus.BREACHED:
                    results['breaches'] += 1
        
        return results


class EscalationEngine:
    """
    Automated escalation engine for SLA breaches.
    
    Example:
        >>> manager = SLAManager()
        >>> engine = EscalationEngine(manager)
        >>> 
        >>> # Add escalation rule
        >>> rule = engine.add_escalation_rule(
        ...     name="Critical Report Escalation",
        ...     entity_type="report",
        ...     severity="critical",
        ...     breach_duration_hours=2.0,
        ...     escalation_level=EscalationLevel.LEVEL_2,
        ...     escalate_to=["manager@acme.com"]
        ... )
        >>> 
        >>> # Process escalations
        >>> engine.process_escalations()
    """
    
    def __init__(self, sla_manager: SLAManager):
        """Initialize escalation engine."""
        self.sla_manager = sla_manager
        self.escalation_rules: Dict[str, EscalationRule] = {}
    
    def add_escalation_rule(
        self,
        name: str,
        entity_type: str,
        breach_duration_hours: float,
        escalation_level: EscalationLevel,
        escalate_to: List[str],
        severity: Optional[str] = None,
        notification_template: str = ""
    ) -> EscalationRule:
        """Add an escalation rule."""
        rule = EscalationRule(
            name=name,
            entity_type=entity_type,
            severity=severity,
            breach_duration_hours=breach_duration_hours,
            escalation_level=escalation_level,
            escalate_to=escalate_to,
            notification_template=notification_template
        )
        
        self.escalation_rules[rule.rule_id] = rule
        return rule
    
    def process_escalations(self) -> Dict[str, Any]:
        """Process escalations for breached SLAs."""
        breached_slas = self.sla_manager.get_breached_slas()
        
        results = {
            'processed': len(breached_slas),
            'escalated': 0,
            'escalations': []
        }
        
        for sla in breached_slas:
            # Find matching escalation rules
            matching_rules = self._find_matching_rules(sla)
            
            for rule in matching_rules:
                # Check if already escalated to this level
                if sla.escalation_level and sla.escalation_level.value >= rule.escalation_level.value:
                    continue
                
                # Escalate
                sla.escalation_level = rule.escalation_level
                sla.escalated_to.extend(rule.escalate_to)
                
                results['escalated'] += 1
                results['escalations'].append({
                    'sla_id': sla.sla_id,
                    'rule_id': rule.rule_id,
                    'level': rule.escalation_level.value,
                    'escalated_to': rule.escalate_to
                })
        
        return results
    
    def _find_matching_rules(self, sla: SLA) -> List[EscalationRule]:
        """Find escalation rules matching an SLA."""
        matching_rules = []
        
        for rule in self.escalation_rules.values():
            if not rule.active:
                continue
            
            # Check entity type
            if rule.entity_type != sla.entity_type:
                continue
            
            # Check severity if specified
            if rule.severity:
                sla_severity = sla.metadata.get('severity')
                if sla_severity != rule.severity:
                    continue
            
            # Check breach duration
            if sla.breach_duration_hours >= rule.breach_duration_hours:
                matching_rules.append(rule)
        
        # Sort by escalation level
        matching_rules.sort(key=lambda r: r.escalation_level.value)
        
        return matching_rules

