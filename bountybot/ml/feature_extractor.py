"""
Feature extraction for ML models.
"""

import logging
import re
from typing import Dict, List, Any, Optional
from collections import Counter
from datetime import datetime

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Extract features from vulnerability reports for ML models.
    
    Features include:
    - Text features (keywords, length, complexity)
    - Structural features (sections, formatting)
    - Metadata features (timestamps, researcher info)
    - Technical features (endpoints, parameters, payloads)
    """
    
    def __init__(self):
        """Initialize feature extractor."""
        self.vulnerability_keywords = {
            'sql injection': ['sql', 'injection', 'query', 'database', 'union', 'select'],
            'xss': ['xss', 'script', 'javascript', 'alert', 'dom', 'reflected'],
            'csrf': ['csrf', 'token', 'cross-site', 'request', 'forgery'],
            'ssrf': ['ssrf', 'server-side', 'request', 'internal', 'localhost'],
            'rce': ['rce', 'remote', 'code', 'execution', 'command', 'shell'],
            'idor': ['idor', 'insecure', 'direct', 'object', 'reference', 'authorization'],
            'auth': ['authentication', 'authorization', 'bypass', 'privilege', 'escalation'],
            'xxe': ['xxe', 'xml', 'external', 'entity', 'injection'],
        }
        
        logger.info("FeatureExtractor initialized")
    
    def extract_from_report(self, report: Any) -> Dict[str, Any]:
        """
        Extract features from a vulnerability report.
        
        Args:
            report: Report object with title, description, etc.
            
        Returns:
            Dictionary of extracted features
        """
        features = {}
        
        # Text features
        features.update(self._extract_text_features(report))
        
        # Structural features
        features.update(self._extract_structural_features(report))
        
        # Technical features
        features.update(self._extract_technical_features(report))
        
        # Metadata features
        features.update(self._extract_metadata_features(report))
        
        logger.debug(f"Extracted {len(features)} features from report")
        
        return features
    
    def _extract_text_features(self, report: Any) -> Dict[str, Any]:
        """Extract text-based features."""
        text = f"{report.title} {report.description}".lower()
        
        features = {
            # Length features
            'title_length': len(report.title),
            'description_length': len(report.description),
            'total_length': len(text),
            'word_count': len(text.split()),
            
            # Complexity features
            'avg_word_length': sum(len(w) for w in text.split()) / max(len(text.split()), 1),
            'sentence_count': text.count('.') + text.count('!') + text.count('?'),
            'paragraph_count': text.count('\n\n') + 1,
            
            # Technical indicators
            'has_code_blocks': '```' in report.description or '`' in report.description,
            'has_urls': bool(re.search(r'https?://', text)),
            'has_payloads': bool(re.search(r'[<>{}[\]()]', text)),
            
            # Keyword presence
            'keyword_density': self._calculate_keyword_density(text),
        }
        
        # Vulnerability type indicators
        for vuln_type, keywords in self.vulnerability_keywords.items():
            features[f'vuln_indicator_{vuln_type}'] = sum(
                1 for kw in keywords if kw in text
            ) / len(keywords)
        
        return features
    
    def _extract_structural_features(self, report: Any) -> Dict[str, Any]:
        """Extract structural features."""
        desc = report.description
        
        features = {
            # Section presence
            'has_steps': any(marker in desc.lower() for marker in ['steps', 'reproduce', 'reproduction']),
            'has_impact': 'impact' in desc.lower(),
            'has_poc': any(marker in desc.lower() for marker in ['poc', 'proof of concept', 'demonstration']),
            'has_remediation': any(marker in desc.lower() for marker in ['fix', 'remediation', 'mitigation', 'recommendation']),
            
            # Formatting quality
            'has_headers': bool(re.search(r'^#+\s', desc, re.MULTILINE)),
            'has_lists': bool(re.search(r'^\s*[-*]\s', desc, re.MULTILINE)),
            'has_numbered_lists': bool(re.search(r'^\s*\d+\.\s', desc, re.MULTILINE)),
            
            # Code/technical content
            'code_block_count': desc.count('```'),
            'inline_code_count': desc.count('`') - desc.count('```') * 6,
        }
        
        return features
    
    def _extract_technical_features(self, report: Any) -> Dict[str, Any]:
        """Extract technical features."""
        text = f"{report.title} {report.description}"
        
        # Extract URLs and endpoints
        urls = re.findall(r'https?://[^\s<>"{}|\\^`\[\]]+', text)
        endpoints = re.findall(r'/[a-zA-Z0-9/_-]+', text)
        
        # Extract parameters
        params = re.findall(r'[?&]([a-zA-Z0-9_]+)=', text)
        
        # Extract HTTP methods
        http_methods = re.findall(r'\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b', text, re.IGNORECASE)
        
        features = {
            # URL/endpoint features
            'url_count': len(urls),
            'endpoint_count': len(endpoints),
            'unique_endpoints': len(set(endpoints)),
            
            # Parameter features
            'parameter_count': len(params),
            'unique_parameters': len(set(params)),
            
            # HTTP features
            'http_method_count': len(http_methods),
            'uses_post': 'POST' in [m.upper() for m in http_methods],
            'uses_get': 'GET' in [m.upper() for m in http_methods],
            
            # Payload indicators
            'has_sql_syntax': bool(re.search(r'\b(SELECT|UNION|INSERT|UPDATE|DELETE|DROP)\b', text, re.IGNORECASE)),
            'has_js_syntax': bool(re.search(r'\b(alert|console|document|window)\b', text, re.IGNORECASE)),
            'has_xml_syntax': bool(re.search(r'<\?xml|<!DOCTYPE|<!ENTITY', text, re.IGNORECASE)),
            'has_shell_syntax': bool(re.search(r'\b(bash|sh|cmd|powershell|exec)\b', text, re.IGNORECASE)),
        }
        
        return features
    
    def _extract_metadata_features(self, report: Any) -> Dict[str, Any]:
        """Extract metadata features."""
        features = {
            # Vulnerability type
            'vulnerability_type': report.vulnerability_type if hasattr(report, 'vulnerability_type') else 'unknown',
            
            # Severity (if available)
            'has_severity': hasattr(report, 'severity') and report.severity is not None,
            
            # Researcher info (if available)
            'has_researcher_id': hasattr(report, 'researcher_id') and report.researcher_id is not None,
        }
        
        # Timestamp features (if available)
        if hasattr(report, 'submitted_at') and report.submitted_at:
            if isinstance(report.submitted_at, datetime):
                features['submission_hour'] = report.submitted_at.hour
                features['submission_day_of_week'] = report.submitted_at.weekday()
                features['submission_is_weekend'] = report.submitted_at.weekday() >= 5
        
        return features
    
    def _calculate_keyword_density(self, text: str) -> float:
        """Calculate density of security-related keywords."""
        words = text.split()
        if not words:
            return 0.0
        
        all_keywords = set()
        for keywords in self.vulnerability_keywords.values():
            all_keywords.update(keywords)
        
        keyword_count = sum(1 for word in words if word in all_keywords)
        return keyword_count / len(words)
    
    def extract_from_validation_result(self, validation_result: Any) -> Dict[str, Any]:
        """
        Extract features from a validation result.
        
        Args:
            validation_result: ValidationResult object
            
        Returns:
            Dictionary of extracted features
        """
        features = {
            # Verdict features
            'verdict': validation_result.verdict,
            'confidence': validation_result.confidence,
            
            # CVSS features
            'cvss_score': validation_result.cvss_score if hasattr(validation_result, 'cvss_score') else 0.0,
            'severity': validation_result.severity if hasattr(validation_result, 'severity') else 'unknown',
            
            # Analysis features
            'is_duplicate': validation_result.is_duplicate if hasattr(validation_result, 'is_duplicate') else False,
            'is_false_positive': validation_result.is_false_positive if hasattr(validation_result, 'is_false_positive') else False,
            
            # Priority features
            'priority_score': validation_result.priority_score if hasattr(validation_result, 'priority_score') else 0.0,
        }
        
        # Exploit complexity (if available)
        if hasattr(validation_result, 'exploit_complexity'):
            features['exploit_complexity'] = validation_result.exploit_complexity
        
        # Attack chain (if available)
        if hasattr(validation_result, 'attack_chain_length'):
            features['attack_chain_length'] = validation_result.attack_chain_length
        
        return features
    
    def extract_time_series_features(self, reports: List[Any], window_days: int = 30) -> Dict[str, Any]:
        """
        Extract time-series features from multiple reports.
        
        Args:
            reports: List of reports
            window_days: Time window in days
            
        Returns:
            Dictionary of time-series features
        """
        if not reports:
            return {}
        
        features = {
            'report_count': len(reports),
            'reports_per_day': len(reports) / max(window_days, 1),
        }
        
        # Vulnerability type distribution
        vuln_types = [r.vulnerability_type for r in reports if hasattr(r, 'vulnerability_type')]
        if vuln_types:
            type_counts = Counter(vuln_types)
            features['most_common_vuln_type'] = type_counts.most_common(1)[0][0]
            features['vuln_type_diversity'] = len(type_counts) / len(vuln_types)
        
        # Severity distribution
        severities = [r.severity for r in reports if hasattr(r, 'severity') and r.severity]
        if severities:
            severity_counts = Counter(severities)
            features['critical_rate'] = severity_counts.get('critical', 0) / len(severities)
            features['high_rate'] = severity_counts.get('high', 0) / len(severities)
        
        return features

