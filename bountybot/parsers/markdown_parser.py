import re
import logging
from pathlib import Path
from typing import Union, Optional
from datetime import datetime
from dateutil import parser as date_parser

from .base import BaseParser
from bountybot.models import Report, Severity

logger = logging.getLogger(__name__)


class MarkdownParser(BaseParser):
    """
    Parser for Markdown-formatted bug bounty reports.
    Extracts structured information from markdown sections.
    """
    
    def parse(self, content: Union[str, Path]) -> Report:
        """
        Parse Markdown report into standardized Report object.

        Args:
            content: Markdown string or path to markdown file

        Returns:
            Standardized Report object
        """
        # Read file if path provided
        if isinstance(content, (Path, str)) and (isinstance(content, Path) or Path(content).exists()):
            content = self._read_file(Path(content) if isinstance(content, str) else content)
        
        # Extract title (first H1 or H2)
        title = self._extract_title(content)
        
        # Extract sections
        sections = self._extract_sections(content)
        
        # Parse fields from sections
        researcher = self._find_in_sections(sections, ['researcher', 'reporter', 'author', 'submitted by'])
        
        # Parse date
        submission_date = None
        date_str = self._find_in_sections(sections, ['date', 'submission date', 'submitted', 'created'])
        if date_str:
            try:
                submission_date = date_parser.parse(date_str)
            except Exception:
                pass
        
        # Extract vulnerability type
        vuln_type = self._find_in_sections(sections, ['vulnerability type', 'type', 'category', 'weakness'])
        vuln_type = self._normalize_vulnerability_type(vuln_type) if vuln_type else None
        
        # Extract severity
        severity = None
        severity_str = self._find_in_sections(sections, ['severity', 'risk', 'priority'])
        if severity_str:
            severity = self._parse_severity(severity_str)
        
        severity_justification = self._find_in_sections(sections, 
            ['severity justification', 'impact assessment', 'risk assessment'])
        
        # Extract affected components
        affected_str = self._find_in_sections(sections, 
            ['affected components', 'affected urls', 'endpoints', 'targets', 'affected'])
        affected_components = self._parse_list(affected_str) if affected_str else []
        
        # Extract reproduction steps
        steps_str = self._find_in_sections(sections, 
            ['reproduction steps', 'steps to reproduce', 'how to reproduce', 'steps'])
        reproduction_steps = self._parse_numbered_list(steps_str) if steps_str else []
        
        # Extract proof of concept
        poc = self._find_in_sections(sections, 
            ['proof of concept', 'poc', 'exploit', 'payload'])
        
        # Extract impact
        impact = self._find_in_sections(sections, 
            ['impact', 'business impact', 'description'])
        
        # Calculate parsing confidence
        parsing_confidence = {}
        missing_fields = []
        
        fields = {
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
        
        for field_name, field_value in fields.items():
            if field_value:
                if isinstance(field_value, list):
                    parsing_confidence[field_name] = 0.9 if len(field_value) > 0 else 0.5
                else:
                    parsing_confidence[field_name] = 0.9
            else:
                parsing_confidence[field_name] = 0.0
                missing_fields.append(field_name)
        
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
            raw_content=content,
            parsing_confidence=parsing_confidence,
            missing_fields=missing_fields,
        )
        
        logger.info(f"Parsed Markdown report: {report.title}")
        return report
    
    def _extract_title(self, content: str) -> Optional[str]:
        """Extract title from first heading."""
        match = re.search(r'^#+ (.+)$', content, re.MULTILINE)
        return match.group(1).strip() if match else None
    
    def _extract_sections(self, content: str) -> dict:
        """
        Extract sections from markdown content.
        Returns dict mapping section names to content.
        """
        sections = {}
        current_section = None
        current_content = []
        
        for line in content.split('\n'):
            # Check if line is a heading
            heading_match = re.match(r'^#+\s+(.+)$', line)
            if heading_match:
                # Save previous section
                if current_section:
                    sections[current_section.lower()] = '\n'.join(current_content).strip()
                
                # Start new section
                current_section = heading_match.group(1).strip()
                current_content = []
            else:
                if current_section:
                    current_content.append(line)
        
        # Save last section
        if current_section:
            sections[current_section.lower()] = '\n'.join(current_content).strip()
        
        return sections
    
    def _find_in_sections(self, sections: dict, possible_names: list) -> Optional[str]:
        """Find content in sections by trying multiple possible section names."""
        for name in possible_names:
            name_lower = name.lower()
            if name_lower in sections:
                content = sections[name_lower].strip()
                if content:
                    return content
        return None
    
    def _parse_list(self, content: str) -> list:
        """Parse a list from content (bullet points or newlines)."""
        if not content:
            return []
        
        items = []
        for line in content.split('\n'):
            line = line.strip()
            # Remove bullet points
            line = re.sub(r'^[-*+]\s+', '', line)
            # Remove numbered lists
            line = re.sub(r'^\d+\.\s+', '', line)
            if line:
                items.append(line)
        
        return items
    
    def _parse_numbered_list(self, content: str) -> list:
        """Parse a numbered or bulleted list."""
        return self._parse_list(content)
    
    def _parse_severity(self, severity_str: str) -> Severity:
        """Parse severity string to Severity enum."""
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

