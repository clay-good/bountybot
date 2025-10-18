"""
HTML parser for bug bounty reports.
Extracts structured data from HTML reports exported from bug bounty platforms.
"""

import logging
import re
from pathlib import Path
from typing import Union, Optional, Dict, Any
from html.parser import HTMLParser
from datetime import datetime

from bountybot.models import Report, Severity
from bountybot.parsers.base import BaseParser

logger = logging.getLogger(__name__)


class HTMLReportParser(HTMLParser):
    """HTML parser that extracts report data from HTML structure."""
    
    def __init__(self):
        super().__init__()
        self.data = {
            'title': '',
            'description': '',
            'steps': '',
            'impact': '',
            'severity': '',
            'vulnerability_type': '',
            'poc': '',
            'submitted_by': '',
            'submitted_at': '',
            'target_url': '',
            'affected_endpoints': [],
            'raw_html': ''
        }
        self.current_tag = None
        self.current_attrs = {}
        self.capture_text = False
        self.text_buffer = []
        
    def handle_starttag(self, tag, attrs):
        """Handle opening tags."""
        self.current_tag = tag
        self.current_attrs = dict(attrs)
        
        # Look for common patterns in bug bounty platform HTML
        class_name = self.current_attrs.get('class', '')
        id_name = self.current_attrs.get('id', '')
        
        # Title patterns
        if any(x in class_name.lower() or x in id_name.lower() 
               for x in ['title', 'heading', 'report-title', 'vulnerability-title']):
            self.capture_text = True
            self.text_buffer = []
            
        # Description patterns
        elif any(x in class_name.lower() or x in id_name.lower()
                 for x in ['description', 'summary', 'details', 'report-body']):
            self.capture_text = True
            self.text_buffer = []
            
        # Steps patterns
        elif any(x in class_name.lower() or x in id_name.lower()
                 for x in ['steps', 'reproduction', 'reproduce', 'how-to']):
            self.capture_text = True
            self.text_buffer = []
            
        # Impact patterns
        elif any(x in class_name.lower() or x in id_name.lower()
                 for x in ['impact', 'risk', 'consequence']):
            self.capture_text = True
            self.text_buffer = []
            
        # Severity patterns
        elif any(x in class_name.lower() or x in id_name.lower()
                 for x in ['severity', 'priority', 'criticality']):
            self.capture_text = True
            self.text_buffer = []
            
        # POC patterns
        elif any(x in class_name.lower() or x in id_name.lower()
                 for x in ['poc', 'proof', 'exploit', 'payload']):
            self.capture_text = True
            self.text_buffer = []
            
    def handle_endtag(self, tag):
        """Handle closing tags."""
        if self.capture_text and self.text_buffer:
            text = ' '.join(self.text_buffer).strip()
            
            # Determine which field to populate based on content
            if not self.data['title'] and len(text) < 200:
                self.data['title'] = text
            elif 'step' in text.lower() or 'reproduce' in text.lower():
                self.data['steps'] += text + '\n'
            elif 'impact' in text.lower() or 'risk' in text.lower():
                self.data['impact'] += text + '\n'
            elif any(x in text.lower() for x in ['critical', 'high', 'medium', 'low']):
                self.data['severity'] = text
            elif 'poc' in text.lower() or 'proof' in text.lower():
                self.data['poc'] += text + '\n'
            elif not self.data['description']:
                self.data['description'] = text
            else:
                self.data['description'] += '\n' + text
                
        self.capture_text = False
        self.text_buffer = []
        self.current_tag = None
        
    def handle_data(self, data):
        """Handle text data."""
        if self.capture_text:
            self.text_buffer.append(data.strip())


class BountyHTMLParser(BaseParser):
    """
    Parser for HTML bug bounty reports.
    Supports reports exported from HackerOne, Bugcrowd, Synack, etc.
    """
    
    def parse(self, content: Union[str, Path]) -> Report:
        """
        Parse HTML report into standardized Report object.
        
        Args:
            content: HTML content as string or path to HTML file
            
        Returns:
            Standardized Report object
        """
        # Read file if path provided
        if isinstance(content, (str, Path)) and Path(content).exists():
            html_content = self._read_file(Path(content))
            logger.info(f"Parsing HTML report from file: {content}")
        else:
            html_content = str(content)
            logger.info("Parsing HTML report from string")
        
        # Parse HTML
        parser = HTMLReportParser()
        parser.feed(html_content)
        data = parser.data
        
        # Extract additional data using regex patterns
        data = self._extract_with_regex(html_content, data)
        
        # Clean and normalize extracted data
        title = data.get('title', '').strip() or self._extract_title_fallback(html_content)
        description = data.get('description', '').strip()
        steps = data.get('steps', '').strip()
        impact = data.get('impact', '').strip()
        poc = data.get('poc', '').strip()
        
        # Combine all text for full description
        full_description = self._build_full_description(description, steps, impact, poc)
        
        # Extract vulnerability type
        vuln_type = self._extract_vulnerability_type(html_content, title, full_description)
        
        # Extract severity
        severity = self._extract_severity(html_content, data.get('severity', ''))
        
        # Extract metadata
        submitted_by = data.get('submitted_by', '') or self._extract_researcher(html_content)
        submitted_at = self._extract_date(html_content)
        target_url = data.get('target_url', '') or self._extract_target_url(html_content)
        
        # Create report object
        report = Report(
            title=title,
            description=full_description,
            vulnerability_type=self._normalize_vulnerability_type(vuln_type),
            severity=severity,
            steps_to_reproduce=steps or None,
            proof_of_concept=poc or None,
            impact=impact or None,
            submitted_by=submitted_by or None,
            submitted_at=submitted_at,
            target_url=target_url or None,
            raw_report=html_content[:5000]  # Store first 5000 chars
        )
        
        logger.info(f"Successfully parsed HTML report: {report.title}")
        return report
    
    def _extract_with_regex(self, html: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract data using regex patterns."""
        
        # Extract title if not found
        if not data['title']:
            title_match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
            if title_match:
                data['title'] = title_match.group(1).strip()
        
        # Extract URLs
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
        urls = url_pattern.findall(html)
        if urls and not data['target_url']:
            data['target_url'] = urls[0]
        
        return data
    
    def _extract_title_fallback(self, html: str) -> str:
        """Extract title using fallback methods."""
        # Try h1, h2, h3 tags
        for tag in ['h1', 'h2', 'h3']:
            match = re.search(f'<{tag}[^>]*>([^<]+)</{tag}>', html, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        # Try title tag
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        if match:
            return match.group(1).strip()
        
        return "Untitled Report"
    
    def _build_full_description(self, description: str, steps: str, 
                                 impact: str, poc: str) -> str:
        """Build comprehensive description from all parts."""
        parts = []
        
        if description:
            parts.append(description)
        
        if steps:
            parts.append(f"\n\n## Steps to Reproduce\n{steps}")
        
        if impact:
            parts.append(f"\n\n## Impact\n{impact}")
        
        if poc:
            parts.append(f"\n\n## Proof of Concept\n{poc}")
        
        return '\n'.join(parts).strip()
    
    def _extract_vulnerability_type(self, html: str, title: str, 
                                     description: str) -> str:
        """Extract vulnerability type from HTML content."""
        combined_text = f"{title} {description}".lower()
        
        # Common vulnerability type patterns
        patterns = {
            'sql injection': r'\b(sql\s*injection|sqli)\b',
            'xss': r'\b(xss|cross[- ]site\s*scripting)\b',
            'csrf': r'\b(csrf|cross[- ]site\s*request\s*forgery)\b',
            'rce': r'\b(rce|remote\s*code\s*execution)\b',
            'ssrf': r'\b(ssrf|server[- ]side\s*request\s*forgery)\b',
            'idor': r'\b(idor|insecure\s*direct\s*object\s*reference)\b',
            'authentication bypass': r'\b(auth(entication)?\s*bypass)\b',
            'authorization bypass': r'\b(authz|authorization\s*bypass)\b',
            'path traversal': r'\b(path\s*traversal|directory\s*traversal|lfi)\b',
            'xxe': r'\b(xxe|xml\s*external\s*entity)\b',
        }
        
        for vuln_type, pattern in patterns.items():
            if re.search(pattern, combined_text, re.IGNORECASE):
                return vuln_type
        
        return "Unknown"
    
    def _extract_severity(self, html: str, severity_text: str) -> Severity:
        """Extract severity from HTML content."""
        combined = f"{html} {severity_text}".lower()
        
        if any(x in combined for x in ['critical', 'p1', 'severity: 1']):
            return Severity.CRITICAL
        elif any(x in combined for x in ['high', 'p2', 'severity: 2']):
            return Severity.HIGH
        elif any(x in combined for x in ['medium', 'p3', 'severity: 3']):
            return Severity.MEDIUM
        elif any(x in combined for x in ['low', 'p4', 'severity: 4']):
            return Severity.LOW
        else:
            return Severity.MEDIUM  # Default
    
    def _extract_researcher(self, html: str) -> str:
        """Extract researcher name from HTML."""
        patterns = [
            r'submitted\s*by[:\s]+([^\n<]+)',
            r'reporter[:\s]+([^\n<]+)',
            r'researcher[:\s]+([^\n<]+)',
            r'author[:\s]+([^\n<]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return ""
    
    def _extract_date(self, html: str) -> Optional[datetime]:
        """Extract submission date from HTML."""
        # Common date patterns
        patterns = [
            r'(\d{4}-\d{2}-\d{2})',  # YYYY-MM-DD
            r'(\d{2}/\d{2}/\d{4})',  # MM/DD/YYYY
            r'(\d{2}-\d{2}-\d{4})',  # DD-MM-YYYY
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html)
            if match:
                try:
                    date_str = match.group(1)
                    # Try different formats
                    for fmt in ['%Y-%m-%d', '%m/%d/%Y', '%d-%m-%Y']:
                        try:
                            return datetime.strptime(date_str, fmt)
                        except ValueError:
                            continue
                except Exception:
                    pass
        
        return None
    
    def _extract_target_url(self, html: str) -> str:
        """Extract target URL from HTML."""
        # Look for URLs in common locations
        patterns = [
            r'target[:\s]+([^\n<]+)',
            r'url[:\s]+([^\n<]+)',
            r'endpoint[:\s]+([^\n<]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                url_text = match.group(1).strip()
                # Extract actual URL
                url_match = re.search(r'https?://[^\s<>"{}|\\^`\[\]]+', url_text)
                if url_match:
                    return url_match.group(0)
        
        # Fallback: find first URL in document
        url_match = re.search(r'https?://[^\s<>"{}|\\^`\[\]]+', html)
        if url_match:
            return url_match.group(0)
        
        return ""

