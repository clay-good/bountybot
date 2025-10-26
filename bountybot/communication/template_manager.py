"""
Template management for communications.
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime

from .models import ResponseTemplate, CommunicationScenario, Language, ToneType

logger = logging.getLogger(__name__)


class TemplateManager:
    """
    Manages communication templates.
    
    Features:
    - Template storage and retrieval
    - Multi-language support
    - Variable substitution
    - Template versioning
    
    Example:
        >>> manager = TemplateManager()
        >>> template = manager.get_template(
        ...     CommunicationScenario.REPORT_ACCEPTED,
        ...     Language.ENGLISH
        ... )
    """
    
    def __init__(self):
        """Initialize template manager."""
        self.templates: Dict[str, ResponseTemplate] = {}
        self._load_default_templates()
        logger.info("TemplateManager initialized")
    
    def _load_default_templates(self):
        """Load default templates."""
        # Report Accepted
        self.add_template(ResponseTemplate(
            template_id="report_accepted_en",
            scenario=CommunicationScenario.REPORT_ACCEPTED,
            language=Language.ENGLISH,
            subject="Your Security Report Has Been Accepted - ${report_id}",
            body="""Dear {researcher_name},

Thank you for your security report (ID: {report_id}). We are pleased to inform you that your report has been validated and accepted.

Vulnerability Details:
- Type: {vulnerability_type}
- Severity: {severity}
- CVSS Score: {cvss_score}

We will be awarding a bounty of ${payout} for this finding. The payment will be processed within 5-7 business days.

Thank you for helping us improve our security posture. We greatly appreciate your contribution to our bug bounty program.

Best regards,
Security Team""",
            variables=["researcher_name", "report_id", "vulnerability_type", "severity", "cvss_score", "payout"],
            tone=ToneType.PROFESSIONAL
        ))
        
        # Report Rejected
        self.add_template(ResponseTemplate(
            template_id="report_rejected_en",
            scenario=CommunicationScenario.REPORT_REJECTED,
            language=Language.ENGLISH,
            subject="Update on Your Security Report - ${report_id}",
            body="""Dear {researcher_name},

Thank you for submitting your security report (ID: {report_id}).

After careful review by our security team, we have determined that this report does not qualify for a bounty at this time.

Reason: {rejection_reason}

We appreciate your effort and encourage you to continue participating in our bug bounty program. Please review our program guidelines for information on qualifying vulnerabilities.

Best regards,
Security Team""",
            variables=["researcher_name", "report_id", "rejection_reason"],
            tone=ToneType.PROFESSIONAL
        ))
        
        # Needs More Info
        self.add_template(ResponseTemplate(
            template_id="needs_info_en",
            scenario=CommunicationScenario.NEEDS_MORE_INFO,
            language=Language.ENGLISH,
            subject="Additional Information Needed - ${report_id}",
            body="""Dear {researcher_name},

Thank you for your security report (ID: {report_id}).

To proceed with validation, we need some additional information:

{requested_info}

Please provide this information at your earliest convenience so we can continue our review.

Thank you for your cooperation.

Best regards,
Security Team""",
            variables=["researcher_name", "report_id", "requested_info"],
            tone=ToneType.PROFESSIONAL
        ))
        
        # Report Duplicate
        self.add_template(ResponseTemplate(
            template_id="duplicate_en",
            scenario=CommunicationScenario.REPORT_DUPLICATE,
            language=Language.ENGLISH,
            subject="Duplicate Report Notification - ${report_id}",
            body="""Dear {researcher_name},

Thank you for your security report (ID: {report_id}).

We have determined that this vulnerability was previously reported by another researcher on {original_report_date}.

While we cannot award a bounty for duplicate reports, we appreciate your diligence and encourage you to continue participating in our program.

Best regards,
Security Team""",
            variables=["researcher_name", "report_id", "original_report_date"],
            tone=ToneType.PROFESSIONAL
        ))
    
    def add_template(self, template: ResponseTemplate):
        """Add a template."""
        self.templates[template.template_id] = template
        logger.debug(f"Added template: {template.template_id}")
    
    def get_template(
        self,
        scenario: CommunicationScenario,
        language: Language = Language.ENGLISH
    ) -> Optional[ResponseTemplate]:
        """Get template for scenario and language."""
        # Find matching template
        for template in self.templates.values():
            if template.scenario == scenario and template.language == language:
                return template
        
        # Fallback to English if not found
        if language != Language.ENGLISH:
            for template in self.templates.values():
                if template.scenario == scenario and template.language == Language.ENGLISH:
                    return template
        
        return None
    
    def list_templates(
        self,
        scenario: Optional[CommunicationScenario] = None,
        language: Optional[Language] = None
    ) -> List[ResponseTemplate]:
        """List templates with optional filters."""
        templates = list(self.templates.values())
        
        if scenario:
            templates = [t for t in templates if t.scenario == scenario]
        
        if language:
            templates = [t for t in templates if t.language == language]
        
        return templates
    
    def delete_template(self, template_id: str) -> bool:
        """Delete a template."""
        if template_id in self.templates:
            del self.templates[template_id]
            logger.info(f"Deleted template: {template_id}")
            return True
        return False

