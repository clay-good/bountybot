import logging
from typing import List, Tuple
from bountybot.models import Report

logger = logging.getLogger(__name__)


class ReportValidator:
    """
    Validates bug reports for completeness and quality before AI validation.
    Provides early feedback on report quality issues.
    """
    
    # Minimum lengths for various fields
    MIN_TITLE_LENGTH = 10
    MIN_DESCRIPTION_LENGTH = 50
    MIN_STEPS_LENGTH = 30
    MIN_IMPACT_LENGTH = 20
    
    # Required fields for different severity levels
    CRITICAL_REQUIRED_FIELDS = [
        'title', 'description', 'steps_to_reproduce', 
        'proof_of_concept', 'impact', 'affected_component'
    ]
    
    HIGH_REQUIRED_FIELDS = [
        'title', 'description', 'steps_to_reproduce', 
        'impact', 'affected_component'
    ]
    
    MEDIUM_REQUIRED_FIELDS = [
        'title', 'description', 'steps_to_reproduce', 'impact'
    ]
    
    def __init__(self):
        """Initialize report validator."""
        pass
    
    def validate(self, report: Report) -> Tuple[bool, List[str], List[str]]:
        """
        Validate a bug report for completeness and quality.

        Args:
            report: Bug report to validate

        Returns:
            Tuple of (is_valid, errors, warnings)
        """
        errors = []
        warnings = []

        # Check required fields
        if not report.title or len(report.title.strip()) < self.MIN_TITLE_LENGTH:
            errors.append(f"Title must be at least {self.MIN_TITLE_LENGTH} characters")

        # Check impact description (equivalent to description)
        if not report.impact_description or len(report.impact_description.strip()) < self.MIN_DESCRIPTION_LENGTH:
            warnings.append(f"Impact description should be at least {self.MIN_DESCRIPTION_LENGTH} characters")

        # Check steps to reproduce
        if not report.reproduction_steps or len(report.reproduction_steps) == 0:
            warnings.append("Missing steps to reproduce - this significantly reduces report quality")
        else:
            steps_text = ' '.join(report.reproduction_steps)
            if len(steps_text.strip()) < self.MIN_STEPS_LENGTH:
                warnings.append("Steps to reproduce are too brief - provide detailed steps")

        # Check impact
        if not report.impact_description:
            warnings.append("Missing impact description - explain the security implications")
        elif len(report.impact_description.strip()) < self.MIN_IMPACT_LENGTH:
            warnings.append("Impact description is too brief - explain the full security impact")

        # Check proof of concept
        if not report.proof_of_concept:
            warnings.append("Missing proof of concept - include PoC code, payloads, or screenshots")

        # Check affected component
        if not report.affected_components or len(report.affected_components) == 0:
            warnings.append("Missing affected component - specify the vulnerable endpoint, file, or feature")

        # Check vulnerability type
        if not report.vulnerability_type:
            warnings.append("Missing vulnerability type - specify the type of vulnerability")

        # Check severity
        if not report.severity:
            warnings.append("Missing severity rating - specify CRITICAL, HIGH, MEDIUM, or LOW")

        # Severity-specific checks
        if report.severity:
            severity_value = report.severity.value if hasattr(report.severity, 'value') else str(report.severity)

            if severity_value in ['CRITICAL', 'HIGH']:
                if not report.proof_of_concept:
                    errors.append(f"{severity_value} severity reports must include proof of concept")

                if not report.affected_components or len(report.affected_components) == 0:
                    warnings.append(f"{severity_value} severity reports should specify affected component")
        
        # Check for common quality issues
        self._check_quality_issues(report, warnings)
        
        is_valid = len(errors) == 0
        
        if errors:
            logger.warning(f"Report validation failed with {len(errors)} errors")
        elif warnings:
            logger.info(f"Report validation passed with {len(warnings)} warnings")
        else:
            logger.info("Report validation passed with no issues")
        
        return is_valid, errors, warnings
    
    def _check_quality_issues(self, report: Report, warnings: List[str]):
        """
        Check for common quality issues in the report.

        Args:
            report: Bug report
            warnings: List to append warnings to
        """
        # Check for vague titles
        vague_words = ['bug', 'issue', 'problem', 'error', 'vulnerability']
        if report.title:
            title_lower = report.title.lower()
            if any(word in title_lower for word in vague_words) and len(report.title.split()) < 5:
                warnings.append("Title is too vague - be specific about the vulnerability")

        # Check for missing technical details
        if report.impact_description:
            desc_lower = report.impact_description.lower()

            # Check for HTTP details in web vulnerabilities
            if report.vulnerability_type and any(vuln in report.vulnerability_type.lower()
                                                 for vuln in ['xss', 'sql', 'injection', 'csrf']):
                if 'http' not in desc_lower and 'request' not in desc_lower:
                    warnings.append("Consider including HTTP request/response details")

            # Check for payload details
            if report.vulnerability_type and 'injection' in report.vulnerability_type.lower():
                if 'payload' not in desc_lower and 'input' not in desc_lower:
                    warnings.append("Include the specific payload or input used")

        # Check for reproduction steps quality
        if report.reproduction_steps and len(report.reproduction_steps) > 0:
            steps = ' '.join(report.reproduction_steps).lower()

            # Should have numbered steps or clear structure
            if not any(marker in steps for marker in ['1.', '2.', 'step 1', 'step 2', 'first', 'then']):
                warnings.append("Steps to reproduce should be numbered or clearly structured")

            # Should mention expected vs actual behavior
            if 'expect' not in steps and 'actual' not in steps and 'result' not in steps:
                warnings.append("Include expected vs actual behavior in reproduction steps")

        # Check for evidence
        if not report.proof_of_concept:
            warnings.append("Include evidence such as screenshots, logs, or network captures")
    
    def get_quality_score(self, report: Report) -> int:
        """
        Calculate a quality score for the report (0-100).

        Args:
            report: Bug report

        Returns:
            Quality score (0-100)
        """
        score = 0
        max_score = 100

        # Title (10 points)
        if report.title and len(report.title.strip()) >= self.MIN_TITLE_LENGTH:
            score += 10

        # Impact description (20 points)
        if report.impact_description:
            if len(report.impact_description.strip()) >= self.MIN_DESCRIPTION_LENGTH:
                score += 10
            if len(report.impact_description.strip()) >= 200:
                score += 10

        # Steps to reproduce (20 points)
        if report.reproduction_steps and len(report.reproduction_steps) > 0:
            steps_text = ' '.join(report.reproduction_steps)
            if len(steps_text.strip()) >= self.MIN_STEPS_LENGTH:
                score += 10
            if any(marker in steps_text.lower()
                  for marker in ['1.', '2.', 'step 1', 'step 2']):
                score += 10

        # Proof of concept (15 points)
        if report.proof_of_concept:
            score += 15

        # Impact (15 points)
        if report.impact_description:
            if len(report.impact_description.strip()) >= self.MIN_IMPACT_LENGTH:
                score += 15

        # Affected component (10 points)
        if report.affected_components and len(report.affected_components) > 0:
            score += 10

        # Vulnerability type (5 points)
        if report.vulnerability_type:
            score += 5

        # Severity (5 points)
        if report.severity:
            score += 5

        return min(score, max_score)

