"""
Forensic Analyzer

Tools for forensic investigation and timeline reconstruction.
"""

import secrets
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Set

from .models import (
    AuditEvent,
    AuditQuery,
    AuditEventType,
    AuditSeverity,
    ForensicTimeline,
    AnomalyDetection
)
from .audit_search import AuditSearch


class ForensicAnalyzer:
    """
    Forensic analysis tools for audit logs.
    
    Features:
    - Timeline reconstruction
    - Chain of custody tracking
    - Anomaly detection
    - Pattern analysis
    - Suspicious activity detection
    """
    
    def __init__(self, audit_search: AuditSearch):
        self.audit_search = audit_search
    
    def create_timeline(
        self,
        title: str,
        description: str,
        query: AuditQuery
    ) -> ForensicTimeline:
        """Create forensic timeline from query."""
        
        # Search for events
        events = self.audit_search.search(query)
        
        # Extract actors and resources
        actors = set()
        resources = set()
        
        for event in events:
            if event.user_id:
                actors.add(event.user_id)
            if event.username:
                actors.add(event.username)
            if event.resource_id:
                resources.add(f"{event.resource_type}:{event.resource_id}")
        
        # Generate key findings
        key_findings = self._analyze_timeline(events)
        
        # Build chain of custody
        chain_of_custody = self._build_chain_of_custody(events)
        
        timeline = ForensicTimeline(
            timeline_id=f"timeline_{secrets.token_hex(8)}",
            title=title,
            description=description,
            created_at=datetime.utcnow(),
            events=events,
            actors=list(actors),
            resources=list(resources),
            key_findings=key_findings,
            chain_of_custody=chain_of_custody
        )
        
        return timeline
    
    def detect_anomalies(
        self,
        query: AuditQuery,
        sensitivity: float = 0.7
    ) -> List[AnomalyDetection]:
        """Detect anomalies in audit logs."""
        
        events = self.audit_search.search(query)
        anomalies = []
        
        # Detect brute force attempts
        anomalies.extend(self._detect_brute_force(events))
        
        # Detect unusual access patterns
        anomalies.extend(self._detect_unusual_access(events, sensitivity))
        
        # Detect privilege escalation
        anomalies.extend(self._detect_privilege_escalation(events))
        
        # Detect data exfiltration
        anomalies.extend(self._detect_data_exfiltration(events))
        
        # Detect suspicious time patterns
        anomalies.extend(self._detect_suspicious_timing(events))
        
        return anomalies
    
    def analyze_user_activity(
        self,
        user_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """Analyze activity for specific user."""
        
        query = AuditQuery(
            start_time=start_time,
            end_time=end_time,
            user_ids=[user_id]
        )
        
        events = self.audit_search.search(query)
        
        # Analyze activity
        analysis = {
            'user_id': user_id,
            'total_events': len(events),
            'events_by_type': defaultdict(int),
            'events_by_category': defaultdict(int),
            'failed_attempts': 0,
            'resources_accessed': set(),
            'ip_addresses': set(),
            'suspicious_activities': [],
            'activity_timeline': []
        }
        
        for event in events:
            analysis['events_by_type'][event.event_type.value] += 1
            analysis['events_by_category'][event.category.value] += 1
            
            if not event.success:
                analysis['failed_attempts'] += 1
            
            if event.resource_id:
                analysis['resources_accessed'].add(f"{event.resource_type}:{event.resource_id}")
            
            if event.ip_address:
                analysis['ip_addresses'].add(event.ip_address)
            
            if event.severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL]:
                analysis['suspicious_activities'].append({
                    'timestamp': event.timestamp.isoformat(),
                    'event_type': event.event_type.value,
                    'action': event.action,
                    'severity': event.severity.value
                })
        
        # Convert sets to lists for JSON serialization
        analysis['resources_accessed'] = list(analysis['resources_accessed'])
        analysis['ip_addresses'] = list(analysis['ip_addresses'])
        analysis['events_by_type'] = dict(analysis['events_by_type'])
        analysis['events_by_category'] = dict(analysis['events_by_category'])
        
        return analysis
    
    def analyze_resource_access(
        self,
        resource_type: str,
        resource_id: str,
        start_time: datetime,
        end_time: datetime
    ) -> Dict[str, Any]:
        """Analyze access to specific resource."""
        
        query = AuditQuery(
            start_time=start_time,
            end_time=end_time,
            resource_types=[resource_type],
            resource_ids=[resource_id]
        )
        
        events = self.audit_search.search(query)
        
        analysis = {
            'resource_type': resource_type,
            'resource_id': resource_id,
            'total_accesses': len(events),
            'unique_users': set(),
            'access_by_type': defaultdict(int),
            'failed_accesses': 0,
            'access_timeline': []
        }
        
        for event in events:
            if event.user_id:
                analysis['unique_users'].add(event.user_id)
            
            analysis['access_by_type'][event.event_type.value] += 1
            
            if not event.success:
                analysis['failed_accesses'] += 1
            
            analysis['access_timeline'].append({
                'timestamp': event.timestamp.isoformat(),
                'user': event.username or event.user_id,
                'action': event.action,
                'success': event.success
            })
        
        analysis['unique_users'] = list(analysis['unique_users'])
        analysis['access_by_type'] = dict(analysis['access_by_type'])
        
        return analysis
    
    def _analyze_timeline(self, events: List[AuditEvent]) -> List[str]:
        """Analyze timeline and generate key findings."""
        findings = []
        
        if not events:
            return findings
        
        # Count security events
        security_events = [e for e in events if e.category.value == 'security']
        if security_events:
            findings.append(f"Found {len(security_events)} security-related events")
        
        # Count failed attempts
        failed_events = [e for e in events if not e.success]
        if failed_events:
            findings.append(f"Found {len(failed_events)} failed attempts")
        
        # Identify critical events
        critical_events = [e for e in events if e.severity == AuditSeverity.CRITICAL]
        if critical_events:
            findings.append(f"Found {len(critical_events)} critical severity events")
        
        # Identify unique actors
        actors = set(e.user_id for e in events if e.user_id)
        findings.append(f"Activity from {len(actors)} unique users")
        
        return findings
    
    def _build_chain_of_custody(self, events: List[AuditEvent]) -> List[Dict[str, Any]]:
        """Build chain of custody for events."""
        chain = []
        
        for event in events:
            chain.append({
                'timestamp': event.timestamp.isoformat(),
                'event_id': event.event_id,
                'actor': event.username or event.user_id,
                'action': event.action,
                'resource': f"{event.resource_type}:{event.resource_id}" if event.resource_id else None,
                'signature': event.signature,
                'previous_hash': event.previous_event_hash
            })
        
        return chain
    
    def _detect_brute_force(self, events: List[AuditEvent]) -> List[AnomalyDetection]:
        """Detect brute force attempts."""
        anomalies = []
        
        # Group failed login attempts by user and IP
        failed_logins = defaultdict(list)
        
        for event in events:
            if event.event_type == AuditEventType.LOGIN_FAILURE:
                key = (event.user_id or event.username, event.ip_address)
                failed_logins[key].append(event)
        
        # Check for excessive failures
        for (user, ip), login_events in failed_logins.items():
            if len(login_events) >= 5:
                anomaly = AnomalyDetection(
                    anomaly_id=f"anomaly_{secrets.token_hex(8)}",
                    detected_at=datetime.utcnow(),
                    anomaly_type="brute_force",
                    severity=AuditSeverity.HIGH,
                    description=f"Detected {len(login_events)} failed login attempts",
                    affected_user=user,
                    related_events=[e.event_id for e in login_events],
                    confidence_score=0.9,
                    recommended_actions=[
                        "Block IP address temporarily",
                        "Notify user of suspicious activity",
                        "Require password reset"
                    ]
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_unusual_access(
        self,
        events: List[AuditEvent],
        sensitivity: float
    ) -> List[AnomalyDetection]:
        """Detect unusual access patterns."""
        anomalies = []
        
        # Group events by user
        user_events = defaultdict(list)
        for event in events:
            if event.user_id:
                user_events[event.user_id].append(event)
        
        # Check for unusual activity volume
        for user_id, user_event_list in user_events.items():
            if len(user_event_list) > 100:  # Threshold
                anomaly = AnomalyDetection(
                    anomaly_id=f"anomaly_{secrets.token_hex(8)}",
                    detected_at=datetime.utcnow(),
                    anomaly_type="unusual_volume",
                    severity=AuditSeverity.MEDIUM,
                    description=f"User generated {len(user_event_list)} events (unusually high)",
                    affected_user=user_id,
                    confidence_score=0.7,
                    recommended_actions=["Review user activity", "Check for automation"]
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_privilege_escalation(self, events: List[AuditEvent]) -> List[AnomalyDetection]:
        """Detect privilege escalation attempts."""
        anomalies = []
        
        # Look for role assignment followed by suspicious activity
        role_assignments = [e for e in events if e.event_type == AuditEventType.ROLE_ASSIGNED]
        
        for assignment in role_assignments:
            # Check for suspicious activity shortly after
            suspicious_window = assignment.timestamp + timedelta(minutes=30)
            suspicious_events = [
                e for e in events
                if e.user_id == assignment.user_id
                and e.timestamp > assignment.timestamp
                and e.timestamp < suspicious_window
                and e.severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL]
            ]
            
            if suspicious_events:
                anomaly = AnomalyDetection(
                    anomaly_id=f"anomaly_{secrets.token_hex(8)}",
                    detected_at=datetime.utcnow(),
                    anomaly_type="privilege_escalation",
                    severity=AuditSeverity.HIGH,
                    description="Suspicious activity detected after role assignment",
                    affected_user=assignment.user_id,
                    related_events=[assignment.event_id] + [e.event_id for e in suspicious_events],
                    confidence_score=0.8,
                    recommended_actions=[
                        "Review role assignment",
                        "Investigate user activity",
                        "Consider revoking elevated privileges"
                    ]
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_data_exfiltration(self, events: List[AuditEvent]) -> List[AnomalyDetection]:
        """Detect potential data exfiltration."""
        anomalies = []
        
        # Look for excessive data exports
        export_events = [
            e for e in events
            if e.event_type in [AuditEventType.DATA_EXPORTED, AuditEventType.REPORT_DOWNLOADED]
        ]
        
        # Group by user
        user_exports = defaultdict(list)
        for event in export_events:
            if event.user_id:
                user_exports[event.user_id].append(event)
        
        # Check for excessive exports
        for user_id, exports in user_exports.items():
            if len(exports) >= 10:
                anomaly = AnomalyDetection(
                    anomaly_id=f"anomaly_{secrets.token_hex(8)}",
                    detected_at=datetime.utcnow(),
                    anomaly_type="data_exfiltration",
                    severity=AuditSeverity.CRITICAL,
                    description=f"User exported data {len(exports)} times (potential exfiltration)",
                    affected_user=user_id,
                    related_events=[e.event_id for e in exports],
                    confidence_score=0.85,
                    recommended_actions=[
                        "Immediately review user activity",
                        "Suspend user account if necessary",
                        "Investigate exported data",
                        "Notify security team"
                    ]
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_suspicious_timing(self, events: List[AuditEvent]) -> List[AnomalyDetection]:
        """Detect suspicious timing patterns (e.g., off-hours access)."""
        anomalies = []
        
        # Check for activity during off-hours (midnight to 6 AM)
        off_hours_events = [
            e for e in events
            if e.timestamp.hour >= 0 and e.timestamp.hour < 6
            and e.category.value in ['data_access', 'data_modification']
        ]
        
        if len(off_hours_events) >= 5:
            anomaly = AnomalyDetection(
                anomaly_id=f"anomaly_{secrets.token_hex(8)}",
                detected_at=datetime.utcnow(),
                anomaly_type="off_hours_access",
                severity=AuditSeverity.MEDIUM,
                description=f"Detected {len(off_hours_events)} events during off-hours (midnight-6AM)",
                related_events=[e.event_id for e in off_hours_events],
                confidence_score=0.6,
                recommended_actions=[
                    "Review off-hours activity",
                    "Verify legitimate business need",
                    "Consider implementing time-based access controls"
                ]
            )
            anomalies.append(anomaly)
        
        return anomalies

