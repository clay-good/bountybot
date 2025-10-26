import logging
from pathlib import Path
from typing import Union

from .base import BaseParser
from bountybot.models import Report

logger = logging.getLogger(__name__)


class TextParser(BaseParser):
    """
    Parser for plain text bug bounty reports.
    Uses simple heuristics to extract information.
    """
    
    def parse(self, content: Union[str, Path]) -> Report:
        """
        Parse plain text report into standardized Report object.

        Args:
            content: Text string or path to text file

        Returns:
            Standardized Report object
        """
        # Read file if path provided
        if isinstance(content, (Path, str)) and (isinstance(content, Path) or Path(content).exists()):
            content = self._read_file(Path(content) if isinstance(content, str) else content)

        # Validate content
        if not content or not content.strip():
            raise ValueError("Empty content provided")

        # For plain text, we extract minimal information
        # The title is the first non-empty line
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        title = lines[0] if lines else "Untitled Report"
        
        # Mark most fields as missing since plain text is unstructured
        parsing_confidence = {
            'title': 0.7,
            'researcher': 0.0,
            'submission_date': 0.0,
            'vulnerability_type': 0.0,
            'severity': 0.0,
            'affected_components': 0.0,
            'reproduction_steps': 0.0,
            'proof_of_concept': 0.0,
            'impact_description': 0.0,
        }
        
        missing_fields = [
            'researcher',
            'submission_date',
            'vulnerability_type',
            'severity',
            'affected_components',
            'reproduction_steps',
            'proof_of_concept',
            'impact_description',
        ]
        
        report = Report(
            title=title,
            raw_content=content,
            parsing_confidence=parsing_confidence,
            missing_fields=missing_fields,
        )
        
        logger.info(f"Parsed text report: {report.title}")
        logger.warning("Plain text format provides limited structured data. Consider using JSON or Markdown format.")
        
        return report

