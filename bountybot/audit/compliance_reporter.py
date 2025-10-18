"""
Compliance Reporter

Generate compliance reports from audit logs.
"""

import secrets
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .models import (
    AuditEvent,
    AuditQuery,
    AuditReport,
    AuditEventType,
    AuditSeverity
)
from .audit_search import AuditSearch


class ComplianceReporter:
    """
    Generate compliance reports for various frameworks.
    
    Supports:
    - SOC 2
    - GDPR
    - HIPAA
    - PCI-DSS
    - ISO 27001
    """
    
    def __init__(self, audit_search: AuditSearch):
        self.audit_search = audit_search
    
    def generate_soc2_report(
        self,
        start_time: datetime,
        end_time: datetime,
        org_id: Optional[str] = None
    ) -> AuditReport:
        """Generate SOC 2 compliance report."""
        
        query = AuditQuery(
            start_time=start_time,
            end_time=end_time,
            org_ids=[org_id] if org_id else []
        )
        
        # Get all events
        all_events = self.audit_search.search(query)
        
        # Filter SOC 2 relevant events
        soc2_events = [e for e in all_events if 'SOC2' in e.compliance_tags]
        
        # Analyze events
        events_by_category = self.audit_search.aggregate_by_category(query)
        events_by_severity = self.audit_search.aggregate_by_severity(query)
        events_by_user = self.audit_search.aggregate_by_user(query)
        
        # Count security incidents
        security_incidents = len([
            e for e in soc2_events
            if e.category.value == 'security'
            and e.severity in [AuditSeverity.HIGH, AuditSeverity.CRITICAL]
        ])
        
        # Generate summary
        summary = self._generate_soc2_summary(soc2_events, security_incidents)
        
        # Generate recommendations
        recommendations = self._generate_soc2_recommendations(soc2_events)
        
        report = AuditReport(
            report_id=f"report_{secrets.token_hex(8)}",
            title="SOC 2 Compliance Report",
            description="Audit trail report for SOC 2 compliance",
            generated_at=datetime.utcnow(),
            start_time=start_time,
            end_time=end_time,
            total_events=len(soc2_events),
            events_by_category=events_by_category,
            events_by_severity=events_by_severity,
            events_by_user=events_by_user,
            security_incidents=security_incidents,
            summary=summary,
            recommendations=recommendations
        )
        
        return report
    
    def generate_gdpr_report(
        self,
        start_time: datetime,
        end_time: datetime,
        org_id: Optional[str] = None
    ) -> AuditReport:
        """Generate GDPR compliance report."""
        
        query = AuditQuery(
            start_time=start_time,
            end_time=end_time,
            org_ids=[org_id] if org_id else []
        )
        
        all_events = self.audit_search.search(query)
        gdpr_events = [e for e in all_events if 'GDPR' in e.compliance_tags]
        
        events_by_category = self.audit_search.aggregate_by_category(query)
        events_by_severity = self.audit_search.aggregate_by_severity(query)
        events_by_user = self.audit_search.aggregate_by_user(query)
        
        # Count data subject requests
        dsr_events = len([
            e for e in gdpr_events
            if e.event_type == AuditEventType.GDPR_REQUEST
        ])
        
        # Count data exports
        export_events = len([
            e for e in gdpr_events
            if e.event_type == AuditEventType.DATA_EXPORTED
        ])
        
        # Count consent events
        consent_events = len([
            e for e in gdpr_events
            if e.event_type in [AuditEventType.CONSENT_GRANTED, AuditEventType.CONSENT_REVOKED]
        ])
        
        summary = f"""
GDPR Compliance Report Summary:
- Total GDPR-relevant events: {len(gdpr_events)}
- Data Subject Requests: {dsr_events}
- Data Exports: {export_events}
- Consent Management Events: {consent_events}
- Reporting Period: {start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}
        """.strip()
        
        recommendations = self._generate_gdpr_recommendations(gdpr_events)
        
        report = AuditReport(
            report_id=f"report_{secrets.token_hex(8)}",
            title="GDPR Compliance Report",
            description="Audit trail report for GDPR compliance",
            generated_at=datetime.utcnow(),
            start_time=start_time,
            end_time=end_time,
            total_events=len(gdpr_events),
            events_by_category=events_by_category,
            events_by_severity=events_by_severity,
            events_by_user=events_by_user,
            summary=summary,
            recommendations=recommendations
        )
        
        return report
    
    def generate_hipaa_report(
        self,
        start_time: datetime,
        end_time: datetime,
        org_id: Optional[str] = None
    ) -> AuditReport:
        """Generate HIPAA compliance report."""
        
        query = AuditQuery(
            start_time=start_time,
            end_time=end_time,
            org_ids=[org_id] if org_id else []
        )
        
        all_events = self.audit_search.search(query)
        hipaa_events = [e for e in all_events if 'HIPAA' in e.compliance_tags]
        
        events_by_category = self.audit_search.aggregate_by_category(query)
        events_by_severity = self.audit_search.aggregate_by_severity(query)
        events_by_user = self.audit_search.aggregate_by_user(query)
        
        # Count PHI access events
        phi_access = len([
            e for e in hipaa_events
            if e.category.value == 'data_access'
        ])
        
        # Count unauthorized access attempts
        unauthorized = len([
            e for e in hipaa_events
            if e.event_type == AuditEventType.PERMISSION_DENIED
        ])
        
        summary = f"""
HIPAA Compliance Report Summary:
- Total HIPAA-relevant events: {len(hipaa_events)}
- PHI Access Events: {phi_access}
- Unauthorized Access Attempts: {unauthorized}
- Reporting Period: {start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}
        """.strip()
        
        recommendations = self._generate_hipaa_recommendations(hipaa_events)
        
        report = AuditReport(
            report_id=f"report_{secrets.token_hex(8)}",
            title="HIPAA Compliance Report",
            description="Audit trail report for HIPAA compliance",
            generated_at=datetime.utcnow(),
            start_time=start_time,
            end_time=end_time,
            total_events=len(hipaa_events),
            events_by_category=events_by_category,
            events_by_severity=events_by_severity,
            events_by_user=events_by_user,
            summary=summary,
            recommendations=recommendations
        )
        
        return report
    
    def generate_access_report(
        self,
        start_time: datetime,
        end_time: datetime,
        org_id: Optional[str] = None
    ) -> AuditReport:
        """Generate access control report."""
        
        query = AuditQuery(
            start_time=start_time,
            end_time=end_time,
            org_ids=[org_id] if org_id else [],
            categories=[
                'authentication',
                'authorization',
                'data_access'
            ]
        )
        
        events = self.audit_search.search(query)
        
        events_by_category = self.audit_search.aggregate_by_category(query)
        events_by_severity = self.audit_search.aggregate_by_severity(query)
        events_by_user = self.audit_search.aggregate_by_user(query)
        
        # Count failed access attempts
        failed_attempts = len([e for e in events if not e.success])
        
        summary = f"""
Access Control Report Summary:
- Total Access Events: {len(events)}
- Failed Access Attempts: {failed_attempts}
- Unique Users: {len(events_by_user)}
- Reporting Period: {start_time.strftime('%Y-%m-%d')} to {end_time.strftime('%Y-%m-%d')}
        """.strip()
        
        report = AuditReport(
            report_id=f"report_{secrets.token_hex(8)}",
            title="Access Control Report",
            description="Comprehensive access control audit report",
            generated_at=datetime.utcnow(),
            start_time=start_time,
            end_time=end_time,
            total_events=len(events),
            events_by_category=events_by_category,
            events_by_severity=events_by_severity,
            events_by_user=events_by_user,
            summary=summary,
            recommendations=[]
        )
        
        return report
    
    def _generate_soc2_summary(
        self,
        events: List[AuditEvent],
        security_incidents: int
    ) -> str:
        """Generate SOC 2 summary."""
        
        auth_events = len([e for e in events if e.category.value == 'authentication'])
        config_events = len([e for e in events if e.category.value == 'configuration'])
        
        return f"""
SOC 2 Compliance Report Summary:
- Total SOC 2-relevant events: {len(events)}
- Authentication Events: {auth_events}
- Configuration Changes: {config_events}
- Security Incidents: {security_incidents}
- Compliance Status: {'PASS' if security_incidents == 0 else 'REVIEW REQUIRED'}
        """.strip()
    
    def _generate_soc2_recommendations(self, events: List[AuditEvent]) -> List[str]:
        """Generate SOC 2 recommendations."""
        recommendations = []
        
        failed_logins = len([
            e for e in events
            if e.event_type == AuditEventType.LOGIN_FAILURE
        ])
        
        if failed_logins > 10:
            recommendations.append("High number of failed login attempts detected. Consider implementing account lockout policies.")
        
        config_changes = len([
            e for e in events
            if e.event_type == AuditEventType.CONFIG_CHANGED
        ])
        
        if config_changes > 5:
            recommendations.append("Multiple configuration changes detected. Ensure all changes are documented and approved.")
        
        if not recommendations:
            recommendations.append("No significant issues detected. Continue monitoring.")
        
        return recommendations
    
    def _generate_gdpr_recommendations(self, events: List[AuditEvent]) -> List[str]:
        """Generate GDPR recommendations."""
        recommendations = []
        
        export_events = len([
            e for e in events
            if e.event_type == AuditEventType.DATA_EXPORTED
        ])
        
        if export_events > 20:
            recommendations.append("High volume of data exports detected. Review data minimization practices.")
        
        recommendations.append("Ensure all data subject requests are responded to within 30 days.")
        recommendations.append("Maintain audit logs for at least 7 years for compliance.")
        
        return recommendations
    
    def _generate_hipaa_recommendations(self, events: List[AuditEvent]) -> List[str]:
        """Generate HIPAA recommendations."""
        recommendations = []
        
        unauthorized = len([
            e for e in events
            if e.event_type == AuditEventType.PERMISSION_DENIED
        ])
        
        if unauthorized > 5:
            recommendations.append("Multiple unauthorized access attempts detected. Review access controls.")
        
        recommendations.append("Ensure all PHI access is logged and monitored.")
        recommendations.append("Conduct regular access reviews for users with PHI access.")
        
        return recommendations

