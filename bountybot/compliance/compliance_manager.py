"""
Compliance Manager

Central manager for compliance framework implementation and reporting.
"""

import logging
import secrets
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from .models import (
    ComplianceFramework,
    ComplianceControl,
    ComplianceRequirement,
    ComplianceReport,
    ComplianceStatus,
    ControlStatus,
    DataProcessingActivity
)
from .pii_detector import PIIDetector
from .data_anonymizer import DataAnonymizer, AnonymizationStrategy
from .policy_engine import PolicyEngine
from .retention_manager import RetentionManager
from .consent_manager import ConsentManager

logger = logging.getLogger(__name__)


class ComplianceManager:
    """Central compliance management system."""
    
    def __init__(self):
        """Initialize compliance manager."""
        self.controls: Dict[str, ComplianceControl] = {}
        self.requirements: Dict[str, ComplianceRequirement] = {}
        self.reports: Dict[str, ComplianceReport] = {}
        self.processing_activities: Dict[str, DataProcessingActivity] = {}
        
        # Initialize sub-managers
        self.pii_detector = PIIDetector()
        self.data_anonymizer = DataAnonymizer()
        self.policy_engine = PolicyEngine(self.pii_detector)
        self.retention_manager = RetentionManager()
        self.consent_manager = ConsentManager()
        
        # Initialize default frameworks
        self._initialize_frameworks()
    
    def _initialize_frameworks(self):
        """Initialize compliance framework controls."""
        # SOC 2 Type II controls
        self._add_soc2_controls()
        
        # GDPR requirements
        self._add_gdpr_requirements()
        
        # Create default retention policies
        self.retention_manager.create_default_policies()
    
    def _add_soc2_controls(self):
        """Add SOC 2 Type II controls."""
        soc2_controls = [
            {
                'control_number': 'CC6.1',
                'title': 'Logical and Physical Access Controls',
                'description': 'The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.'
            },
            {
                'control_number': 'CC6.6',
                'title': 'Encryption of Data',
                'description': 'The entity implements encryption to protect data at rest and in transit.'
            },
            {
                'control_number': 'CC7.2',
                'title': 'System Monitoring',
                'description': 'The entity monitors system components and the operation of those components for anomalies.'
            },
            {
                'control_number': 'CC8.1',
                'title': 'Change Management',
                'description': 'The entity authorizes, designs, develops or acquires, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.'
            }
        ]
        
        for control_data in soc2_controls:
            control = ComplianceControl(
                control_id=f"soc2_{control_data['control_number'].lower().replace('.', '_')}",
                framework=ComplianceFramework.SOC2_TYPE2,
                control_number=control_data['control_number'],
                title=control_data['title'],
                description=control_data['description'],
                status=ControlStatus.NOT_IMPLEMENTED
            )
            self.add_control(control)
    
    def _add_gdpr_requirements(self):
        """Add GDPR requirements."""
        gdpr_requirements = [
            {
                'requirement_text': 'Article 5 - Principles relating to processing of personal data',
                'controls': ['data_minimization', 'purpose_limitation', 'storage_limitation']
            },
            {
                'requirement_text': 'Article 6 - Lawfulness of processing',
                'controls': ['consent_management', 'legitimate_interest']
            },
            {
                'requirement_text': 'Article 17 - Right to erasure (right to be forgotten)',
                'controls': ['data_deletion', 'erasure_procedures']
            },
            {
                'requirement_text': 'Article 30 - Records of processing activities',
                'controls': ['processing_records', 'data_inventory']
            },
            {
                'requirement_text': 'Article 32 - Security of processing',
                'controls': ['encryption', 'access_controls', 'security_monitoring']
            }
        ]
        
        for req_data in gdpr_requirements:
            requirement = ComplianceRequirement(
                requirement_id=f"gdpr_{secrets.token_hex(4)}",
                framework=ComplianceFramework.GDPR,
                requirement_text=req_data['requirement_text'],
                controls=req_data['controls']
            )
            self.add_requirement(requirement)
    
    def add_control(self, control: ComplianceControl):
        """Add compliance control."""
        self.controls[control.control_id] = control
        logger.info(f"Added control: {control.control_id}")
    
    def add_requirement(self, requirement: ComplianceRequirement):
        """Add compliance requirement."""
        self.requirements[requirement.requirement_id] = requirement
        logger.info(f"Added requirement: {requirement.requirement_id}")
    
    def update_control_status(
        self,
        control_id: str,
        status: ControlStatus,
        implementation_notes: Optional[str] = None,
        evidence: Optional[List[str]] = None
    ) -> Optional[ComplianceControl]:
        """Update control implementation status."""
        control = self.controls.get(control_id)
        
        if not control:
            logger.error(f"Control not found: {control_id}")
            return None
        
        control.status = status
        control.updated_at = datetime.utcnow()
        
        if implementation_notes:
            control.implementation_notes = implementation_notes
        
        if evidence:
            control.evidence.extend(evidence)
        
        logger.info(f"Updated control {control_id} status to {status.value}")
        
        return control
    
    def test_control(
        self,
        control_id: str,
        test_results: str,
        tested_by: Optional[str] = None
    ) -> Optional[ComplianceControl]:
        """Record control testing results."""
        control = self.controls.get(control_id)
        
        if not control:
            return None
        
        control.last_tested = datetime.utcnow()
        control.test_results = test_results
        control.updated_at = datetime.utcnow()
        
        logger.info(f"Recorded test results for control {control_id}")
        
        return control
    
    def assess_framework(
        self,
        framework: ComplianceFramework,
        assessor: Optional[str] = None
    ) -> ComplianceReport:
        """
        Assess compliance with framework.
        
        Args:
            framework: Framework to assess
            assessor: Person conducting assessment
            
        Returns:
            Compliance report
        """
        # Get controls for framework
        framework_controls = [
            c for c in self.controls.values()
            if c.framework == framework
        ]
        
        total_controls = len(framework_controls)
        implemented_controls = sum(
            1 for c in framework_controls
            if c.status in [ControlStatus.IMPLEMENTED, ControlStatus.VERIFIED]
        )
        compliant_controls = sum(
            1 for c in framework_controls
            if c.status == ControlStatus.VERIFIED
        )
        
        # Determine overall status
        if compliant_controls == total_controls:
            status = ComplianceStatus.COMPLIANT
        elif compliant_controls == 0:
            status = ComplianceStatus.NON_COMPLIANT
        else:
            status = ComplianceStatus.PARTIALLY_COMPLIANT
        
        # Identify gaps
        gaps = []
        for control in framework_controls:
            if control.status != ControlStatus.VERIFIED:
                gaps.append({
                    'control_id': control.control_id,
                    'control_number': control.control_number,
                    'title': control.title,
                    'current_status': control.status.value,
                    'required_status': 'verified'
                })
        
        # Generate recommendations
        recommendations = self._generate_recommendations(framework, gaps)
        
        # Create report
        report = ComplianceReport(
            report_id=f"report_{secrets.token_hex(8)}",
            framework=framework,
            status=status,
            assessment_date=datetime.utcnow(),
            assessor=assessor,
            total_controls=total_controls,
            implemented_controls=implemented_controls,
            compliant_controls=compliant_controls,
            gaps=gaps,
            recommendations=recommendations,
            next_assessment_date=datetime.utcnow() + timedelta(days=90)
        )
        
        report.calculate_score()
        
        self.reports[report.report_id] = report
        
        logger.info(f"Completed {framework.value} assessment: {status.value} ({report.compliance_score:.1f}%)")
        
        return report
    
    def _generate_recommendations(
        self,
        framework: ComplianceFramework,
        gaps: List[Dict[str, Any]]
    ) -> List[str]:
        """Generate recommendations based on gaps."""
        recommendations = []
        
        if not gaps:
            recommendations.append("Maintain current compliance posture through regular testing and monitoring")
            return recommendations
        
        # Priority recommendations
        not_implemented = [g for g in gaps if g['current_status'] == 'not_implemented']
        if not_implemented:
            recommendations.append(
                f"Implement {len(not_implemented)} missing controls as priority"
            )
        
        partially_implemented = [g for g in gaps if g['current_status'] == 'partially_implemented']
        if partially_implemented:
            recommendations.append(
                f"Complete implementation of {len(partially_implemented)} partially implemented controls"
            )
        
        # Framework-specific recommendations
        if framework == ComplianceFramework.GDPR:
            recommendations.extend([
                "Ensure all data processing activities are documented (Article 30)",
                "Implement data subject rights procedures (Articles 15-22)",
                "Conduct Data Protection Impact Assessments for high-risk processing"
            ])
        
        elif framework == ComplianceFramework.SOC2_TYPE2:
            recommendations.extend([
                "Establish continuous monitoring for all controls",
                "Document control testing procedures and results",
                "Implement automated evidence collection where possible"
            ])
        
        return recommendations
    
    def add_processing_activity(self, activity: DataProcessingActivity):
        """Add GDPR Article 30 processing activity record."""
        self.processing_activities[activity.activity_id] = activity
        logger.info(f"Added processing activity: {activity.name}")
    
    def get_compliance_dashboard(self) -> Dict[str, Any]:
        """
        Get compliance dashboard data.
        
        Returns:
            Dashboard data dictionary
        """
        # Overall statistics
        total_controls = len(self.controls)
        implemented_controls = sum(
            1 for c in self.controls.values()
            if c.status in [ControlStatus.IMPLEMENTED, ControlStatus.VERIFIED]
        )
        
        # Controls by framework
        by_framework = {}
        for control in self.controls.values():
            framework = control.framework.value
            if framework not in by_framework:
                by_framework[framework] = {
                    'total': 0,
                    'implemented': 0,
                    'verified': 0
                }
            
            by_framework[framework]['total'] += 1
            if control.status in [ControlStatus.IMPLEMENTED, ControlStatus.VERIFIED]:
                by_framework[framework]['implemented'] += 1
            if control.status == ControlStatus.VERIFIED:
                by_framework[framework]['verified'] += 1
        
        # Recent reports
        recent_reports = sorted(
            self.reports.values(),
            key=lambda r: r.assessment_date,
            reverse=True
        )[:5]
        
        # Policy violations
        violations = self.policy_engine.get_violations(resolved=False)
        
        return {
            'total_controls': total_controls,
            'implemented_controls': implemented_controls,
            'implementation_rate': (implemented_controls / total_controls * 100) if total_controls > 0 else 0,
            'by_framework': by_framework,
            'recent_reports': [
                {
                    'report_id': r.report_id,
                    'framework': r.framework.value,
                    'status': r.status.value,
                    'score': r.compliance_score,
                    'date': r.assessment_date.isoformat()
                }
                for r in recent_reports
            ],
            'open_violations': len(violations),
            'critical_violations': len([v for v in violations if v.severity == 'critical']),
            'retention_policies': len(self.retention_manager.policies),
            'processing_activities': len(self.processing_activities),
            'consent_records': len(self.consent_manager.consents)
        }

