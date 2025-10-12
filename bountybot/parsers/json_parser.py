import json
import logging
from pathlib import Path
from typing import Union
from datetime import datetime
from dateutil import parser as date_parser

from .base import BaseParser
from bountybot.models import Report, Severity

logger = logging.getLogger(__name__)


class JSONParser(BaseParser):
    """
    Parser for JSON-formatted bug bounty reports.
    Supports various JSON schemas including HackerOne exports.
    """
    
    def parse(self, content: Union[str, Path]) -> Report:
        """
        Parse JSON report into standardized Report object.
        
        Args:
            content: JSON string or path to JSON file
            
        Returns:
            Standardized Report object
        """
        # Read file if path provided
        if isinstance(content, Path):
            content = self._read_file(content)
        
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON: {e}")
            raise ValueError(f"Invalid JSON format: {e}")
        
        # Extract fields with various possible key names
        title = self._extract_field(data, ['title', 'name', 'summary', 'vulnerability_title'])
        researcher = self._extract_field(data, ['researcher', 'reporter', 'author', 'submitted_by'])
        
        # Parse submission date
        submission_date = None
        date_str = self._extract_field(data, ['submission_date', 'submitted_at', 'created_at', 'date'])
        if date_str:
            try:
                submission_date = date_parser.parse(date_str)
            except Exception as e:
                logger.warning(f"Could not parse date: {date_str}")
        
        # Extract vulnerability type
        vuln_type = self._extract_field(data, ['vulnerability_type', 'type', 'category', 'weakness'])
        vuln_type = self._normalize_vulnerability_type(vuln_type) if vuln_type else None
        
        # Extract severity
        severity = None
        severity_str = self._extract_field(data, ['severity', 'risk', 'priority'])
        if severity_str:
            severity = self._parse_severity(severity_str)
        
        severity_justification = self._extract_field(data, 
            ['severity_justification', 'severity_reason', 'impact_assessment'])
        
        # Extract affected components
        affected_components = self._extract_list(data, 
            ['affected_components', 'affected_urls', 'endpoints', 'targets', 'urls'])
        
        # Extract reproduction steps
        reproduction_steps = self._extract_list(data, 
            ['reproduction_steps', 'steps_to_reproduce', 'steps', 'reproduction'])
        
        # If steps is a string, split by newlines
        if not reproduction_steps:
            steps_str = self._extract_field(data, 
                ['reproduction_steps', 'steps_to_reproduce', 'steps'])
            if steps_str and isinstance(steps_str, str):
                reproduction_steps = [s.strip() for s in steps_str.split('\n') if s.strip()]
        
        # Extract proof of concept
        poc = self._extract_field(data, 
            ['proof_of_concept', 'poc', 'exploit', 'payload', 'code'])
        
        # Extract impact description
        impact = self._extract_field(data, 
            ['impact_description', 'impact', 'business_impact', 'description'])
        
        # Extract attachments
        attachments = self._extract_list(data, 
            ['attachments', 'files', 'screenshots', 'evidence'])
        
        # Calculate parsing confidence
        parsing_confidence = {}
        missing_fields = []
        
        fields_to_check = {
            'title': title,
            'researcher': researcher,
            'submission_date': submission_date,
            'vulnerability_type': vuln_type,
            'severity': severity,
            'affected_components': affected_components,
            'reproduction_steps': reproduction_steps,
            'proof_of_concept': poc,
            'impact_description': impact,
        }
        
        for field_name, field_value in fields_to_check.items():
            if field_value:
                if isinstance(field_value, list):
                    parsing_confidence[field_name] = 1.0 if len(field_value) > 0 else 0.5
                else:
                    parsing_confidence[field_name] = 1.0
            else:
                parsing_confidence[field_name] = 0.0
                missing_fields.append(field_name)
        
        # Create Report object
        report = Report(
            title=title or "Untitled Report",
            researcher=researcher,
            submission_date=submission_date,
            vulnerability_type=vuln_type,
            severity=severity,
            severity_justification=severity_justification,
            affected_components=affected_components,
            reproduction_steps=reproduction_steps,
            proof_of_concept=poc,
            impact_description=impact,
            attachments=attachments,
            raw_content=json.dumps(data, indent=2),
            parsing_confidence=parsing_confidence,
            missing_fields=missing_fields,
        )
        
        logger.info(f"Parsed JSON report: {report.title}")
        return report
    
    def _extract_field(self, data: dict, possible_keys: list) -> str:
        """
        Extract a field from data using multiple possible key names.
        
        Args:
            data: Dictionary to search
            possible_keys: List of possible key names
            
        Returns:
            Field value or None
        """
        for key in possible_keys:
            if key in data and data[key]:
                return str(data[key])
        return None
    
    def _extract_list(self, data: dict, possible_keys: list) -> list:
        """
        Extract a list field from data.
        
        Args:
            data: Dictionary to search
            possible_keys: List of possible key names
            
        Returns:
            List of values or empty list
        """
        for key in possible_keys:
            if key in data:
                value = data[key]
                if isinstance(value, list):
                    return [str(v) for v in value]
                elif value:
                    return [str(value)]
        return []
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """
        Parse severity string to Severity enum.
        
        Args:
            severity_str: Severity string
            
        Returns:
            Severity enum value
        """
        severity_lower = severity_str.lower()
        
        if 'critical' in severity_lower:
            return Severity.CRITICAL
        elif 'high' in severity_lower:
            return Severity.HIGH
        elif 'medium' in severity_lower or 'moderate' in severity_lower:
            return Severity.MEDIUM
        elif 'low' in severity_lower:
            return Severity.LOW
        else:
            return Severity.INFO

