import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class KnowledgeBaseLoader:
    """
    Loads vulnerability knowledge from YAML files.
    Provides context for AI validation.
    """
    
    def __init__(self):
        """Initialize knowledge base loader."""
        self.knowledge_dir = Path(__file__).parent / "vulnerabilities"
        self.cache: Dict[str, Dict[str, Any]] = {}
    
    def load_vulnerability_info(self, vuln_type: str) -> Optional[Dict[str, Any]]:
        """
        Load vulnerability information from knowledge base.
        
        Args:
            vuln_type: Vulnerability type (e.g., 'sql injection', 'xss')
            
        Returns:
            Dictionary with vulnerability information or None
        """
        # Normalize vulnerability type
        vuln_type_normalized = vuln_type.lower().replace(' ', '_').replace('-', '_')
        
        # Check cache
        if vuln_type_normalized in self.cache:
            return self.cache[vuln_type_normalized]
        
        # Try to load from file
        file_path = self.knowledge_dir / f"{vuln_type_normalized}.yaml"
        
        if not file_path.exists():
            logger.debug(f"No knowledge base file found for: {vuln_type}")
            return None
        
        try:
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
                self.cache[vuln_type_normalized] = data
                logger.info(f"Loaded knowledge base for: {vuln_type}")
                return data
        except Exception as e:
            logger.error(f"Error loading knowledge base for {vuln_type}: {e}")
            return None
    
    def get_context_for_validation(self, vuln_type: str) -> str:
        """
        Get formatted context string for AI validation.
        
        Args:
            vuln_type: Vulnerability type
            
        Returns:
            Formatted context string
        """
        info = self.load_vulnerability_info(vuln_type)
        
        if not info:
            return ""
        
        context_parts = []
        
        if 'definition' in info:
            context_parts.append(f"Definition: {info['definition']}")
        
        if 'common_patterns' in info:
            patterns = ', '.join(info['common_patterns'])
            context_parts.append(f"Common Patterns: {patterns}")
        
        if 'preconditions' in info:
            preconditions = ', '.join(info['preconditions'])
            context_parts.append(f"Preconditions: {preconditions}")
        
        if 'false_positive_indicators' in info:
            indicators = ', '.join(info['false_positive_indicators'])
            context_parts.append(f"False Positive Indicators: {indicators}")
        
        if 'exploitation_requirements' in info:
            requirements = ', '.join(info['exploitation_requirements'])
            context_parts.append(f"Exploitation Requirements: {requirements}")
        
        return "\n".join(context_parts)
    
    def list_available_vulnerabilities(self) -> list:
        """
        List all available vulnerability types in knowledge base.
        
        Returns:
            List of vulnerability type names
        """
        if not self.knowledge_dir.exists():
            return []
        
        vulns = []
        for file_path in self.knowledge_dir.glob("*.yaml"):
            vuln_name = file_path.stem.replace('_', ' ')
            vulns.append(vuln_name)
        
        return sorted(vulns)

