from abc import ABC, abstractmethod
from pathlib import Path
from typing import Union
import logging

from bountybot.models import Report

logger = logging.getLogger(__name__)


class BaseParser(ABC):
    """
    Abstract base class for report parsers.
    All parsers convert their input format to a standardized Report object.
    """
    
    @abstractmethod
    def parse(self, content: Union[str, Path]) -> Report:
        """
        Parse report content into standardized Report object.
        
        Args:
            content: Report content as string or path to file
            
        Returns:
            Standardized Report object
        """
        pass
    
    def _read_file(self, path: Path) -> str:
        """
        Read content from file.
        
        Args:
            path: Path to file
            
        Returns:
            File content as string
        """
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file {path}: {e}")
            raise
    
    def _normalize_vulnerability_type(self, vuln_type: str) -> str:
        """
        Normalize vulnerability type to standard categories.
        
        Args:
            vuln_type: Raw vulnerability type string
            
        Returns:
            Normalized vulnerability type
        """
        if not vuln_type:
            return "Unknown"
        
        vuln_type_lower = vuln_type.lower()
        
        # Map common variations to standard types
        mappings = {
            'sql injection': ['sql', 'sqli', 'sql injection'],
            'xss': ['xss', 'cross-site scripting', 'cross site scripting'],
            'csrf': ['csrf', 'cross-site request forgery', 'xsrf'],
            'rce': ['rce', 'remote code execution', 'code execution'],
            'ssrf': ['ssrf', 'server-side request forgery'],
            'idor': ['idor', 'insecure direct object reference'],
            'authentication bypass': ['auth bypass', 'authentication bypass', 'broken authentication'],
            'authorization bypass': ['authz bypass', 'authorization bypass', 'broken access control'],
            'path traversal': ['path traversal', 'directory traversal', 'lfi', 'local file inclusion'],
            'xxe': ['xxe', 'xml external entity'],
            'deserialization': ['deserialization', 'insecure deserialization'],
            'open redirect': ['open redirect', 'unvalidated redirect'],
        }
        
        for standard_type, variations in mappings.items():
            if any(var in vuln_type_lower for var in variations):
                return standard_type
        
        return vuln_type

