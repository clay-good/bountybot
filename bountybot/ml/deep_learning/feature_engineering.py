"""
Feature engineering for vulnerability classification.

Extracts and transforms features from vulnerability reports for ML models.
"""

import re
import logging
from typing import List, Dict, Set
from collections import Counter

from bountybot.ml.deep_learning.models import FeatureVector

logger = logging.getLogger(__name__)


class FeatureEngineering:
    """Feature engineering for vulnerability data."""
    
    # Security-related keywords for different vulnerability types
    VULNERABILITY_KEYWORDS = {
        'sql_injection': ['sql', 'injection', 'query', 'database', 'union', 'select', 'drop', 'insert'],
        'xss': ['xss', 'script', 'javascript', 'alert', 'dom', 'reflected', 'stored'],
        'csrf': ['csrf', 'token', 'session', 'cookie', 'cross-site', 'request', 'forgery'],
        'ssrf': ['ssrf', 'server-side', 'request', 'forgery', 'internal', 'localhost'],
        'rce': ['rce', 'remote', 'code', 'execution', 'command', 'shell', 'exec'],
        'lfi': ['lfi', 'local', 'file', 'inclusion', 'path', 'traversal', '../'],
        'xxe': ['xxe', 'xml', 'external', 'entity', 'dtd', 'parser'],
        'idor': ['idor', 'insecure', 'direct', 'object', 'reference', 'authorization'],
        'auth': ['auth', 'authentication', 'bypass', 'login', 'password', 'credential'],
    }
    
    def __init__(self):
        """Initialize feature engineering."""
        self.keyword_set = self._build_keyword_set()
        logger.info(f"Initialized feature engineering with {len(self.keyword_set)} keywords")
    
    def _build_keyword_set(self) -> Set[str]:
        """Build set of all security keywords."""
        keywords = set()
        for keyword_list in self.VULNERABILITY_KEYWORDS.values():
            keywords.update(keyword_list)
        return keywords
    
    def extract_features(self, title: str, description: str, metadata: Dict = None) -> FeatureVector:
        """
        Extract features from vulnerability report.
        
        Args:
            title: Vulnerability title
            description: Vulnerability description
            metadata: Optional metadata
        
        Returns:
            Feature vector
        """
        metadata = metadata or {}
        
        # Tokenize text
        title_tokens = self._tokenize(title)
        description_tokens = self._tokenize(description)
        
        # Extract numerical features
        title_length = len(title)
        description_length = len(description)
        num_urls = self._count_urls(description)
        num_code_blocks = self._count_code_blocks(description)
        num_special_chars = self._count_special_chars(description)
        
        # Extract categorical features
        has_poc = self._has_proof_of_concept(description)
        has_exploit = self._has_exploit(description)
        has_cve = self._has_cve_reference(description)
        
        # Count security keywords
        keyword_counts = self._count_keywords(title_tokens + description_tokens)
        
        # Generate text embedding (simplified - in production use word2vec/BERT)
        text_embedding = self._generate_embedding(title_tokens + description_tokens)
        
        return FeatureVector(
            title_tokens=title_tokens,
            description_tokens=description_tokens,
            title_length=title_length,
            description_length=description_length,
            num_urls=num_urls,
            num_code_blocks=num_code_blocks,
            num_special_chars=num_special_chars,
            has_poc=has_poc,
            has_exploit=has_exploit,
            has_cve=has_cve,
            keyword_counts=keyword_counts,
            text_embedding=text_embedding
        )
    
    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text into words."""
        # Convert to lowercase and split on non-alphanumeric
        tokens = re.findall(r'\b\w+\b', text.lower())
        return tokens
    
    def _count_urls(self, text: str) -> int:
        """Count URLs in text."""
        url_pattern = r'https?://[^\s]+'
        return len(re.findall(url_pattern, text))
    
    def _count_code_blocks(self, text: str) -> int:
        """Count code blocks in text."""
        # Count markdown code blocks
        code_block_pattern = r'```[\s\S]*?```|`[^`]+`'
        return len(re.findall(code_block_pattern, text))
    
    def _count_special_chars(self, text: str) -> int:
        """Count special characters."""
        special_chars = set('!@#$%^&*()[]{}|\\:;"\'<>,.?/')
        return sum(1 for char in text if char in special_chars)
    
    def _has_proof_of_concept(self, text: str) -> bool:
        """Check if text contains proof of concept."""
        poc_keywords = ['poc', 'proof of concept', 'proof-of-concept', 'demonstration', 'reproduce']
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in poc_keywords)
    
    def _has_exploit(self, text: str) -> bool:
        """Check if text contains exploit information."""
        exploit_keywords = ['exploit', 'payload', 'attack', 'malicious']
        text_lower = text.lower()
        return any(keyword in text_lower for keyword in exploit_keywords)
    
    def _has_cve_reference(self, text: str) -> bool:
        """Check if text contains CVE reference."""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return bool(re.search(cve_pattern, text, re.IGNORECASE))
    
    def _count_keywords(self, tokens: List[str]) -> Dict[str, int]:
        """Count security-related keywords."""
        keyword_counts = {}
        token_counter = Counter(tokens)
        
        for keyword in self.keyword_set:
            keyword_counts[keyword] = token_counter.get(keyword, 0)
        
        return keyword_counts
    
    def _generate_embedding(self, tokens: List[str], embedding_size: int = 50) -> List[float]:
        """
        Generate text embedding.
        
        This is a simplified implementation using TF-IDF-like approach.
        In production, use word2vec, GloVe, or BERT embeddings.
        """
        # Create a simple embedding based on keyword presence
        embedding = [0.0] * embedding_size
        
        # Map keywords to embedding dimensions
        for i, keyword in enumerate(list(self.keyword_set)[:embedding_size]):
            if keyword in tokens:
                # TF-IDF-like score
                tf = tokens.count(keyword) / len(tokens) if tokens else 0
                embedding[i] = tf
        
        return embedding
    
    def extract_batch(self, reports: List[Dict]) -> List[FeatureVector]:
        """
        Extract features from multiple reports.
        
        Args:
            reports: List of vulnerability reports with 'title' and 'description'
        
        Returns:
            List of feature vectors
        """
        return [
            self.extract_features(
                report.get('title', ''),
                report.get('description', ''),
                report.get('metadata', {})
            )
            for report in reports
        ]
    
    def get_feature_names(self) -> List[str]:
        """Get names of all features."""
        feature_names = [
            'title_length',
            'description_length',
            'num_urls',
            'num_code_blocks',
            'num_special_chars',
            'has_poc',
            'has_exploit',
            'has_cve',
        ]
        
        # Add keyword features
        for keyword in sorted(self.keyword_set):
            feature_names.append(f'keyword_{keyword}')
        
        # Add embedding features
        for i in range(50):
            feature_names.append(f'embedding_{i}')
        
        return feature_names
    
    def get_feature_importance(self, feature_vector: FeatureVector) -> Dict[str, float]:
        """
        Calculate feature importance for a given vector.
        
        Returns normalized importance scores.
        """
        importance = {}
        
        # Numerical features
        total = (
            feature_vector.title_length +
            feature_vector.description_length +
            feature_vector.num_urls +
            feature_vector.num_code_blocks +
            feature_vector.num_special_chars
        )
        
        if total > 0:
            importance['title_length'] = feature_vector.title_length / total
            importance['description_length'] = feature_vector.description_length / total
            importance['num_urls'] = feature_vector.num_urls / total
            importance['num_code_blocks'] = feature_vector.num_code_blocks / total
            importance['num_special_chars'] = feature_vector.num_special_chars / total
        
        # Categorical features
        importance['has_poc'] = 1.0 if feature_vector.has_poc else 0.0
        importance['has_exploit'] = 1.0 if feature_vector.has_exploit else 0.0
        importance['has_cve'] = 1.0 if feature_vector.has_cve else 0.0
        
        # Keyword features (top 5)
        if feature_vector.keyword_counts:
            top_keywords = sorted(
                feature_vector.keyword_counts.items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            for keyword, count in top_keywords:
                importance[f'keyword_{keyword}'] = float(count)
        
        return importance

