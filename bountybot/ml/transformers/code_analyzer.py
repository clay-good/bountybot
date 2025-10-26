"""
Transformer-based code analyzer for vulnerability detection.

Uses pre-trained transformer models (CodeBERT, GraphCodeBERT) for semantic code analysis.
"""

import logging
import time
import re
from typing import List, Optional, Dict

from bountybot.ml.transformers.models import (
    ProgrammingLanguage,
    CodeAnalysisResult,
    VulnerabilityPattern,
    VulnerabilityPatternType,
    TransformerConfig,
    CodeContext
)
from bountybot.ml.transformers.code_tokenizer import CodeTokenizer
from bountybot.ml.transformers.vulnerability_detector import VulnerabilityDetector
from bountybot.ml.transformers.code_embeddings import CodeEmbeddings

logger = logging.getLogger(__name__)


class CodeAnalyzer:
    """
    Transformer-based code analyzer.
    
    Provides semantic code analysis using pre-trained transformer models
    for vulnerability detection and code understanding.
    """
    
    def __init__(self, config: Optional[TransformerConfig] = None):
        """
        Initialize code analyzer.
        
        Args:
            config: Transformer configuration
        """
        self.config = config or TransformerConfig()
        self.tokenizer = CodeTokenizer(self.config)
        self.vulnerability_detector = VulnerabilityDetector(self.config)
        self.embeddings = CodeEmbeddings(self.config)
        
        logger.info(f"Initialized CodeAnalyzer with model: {self.config.model_name}")
    
    def analyze(
        self,
        code: str,
        language: ProgrammingLanguage = ProgrammingLanguage.PYTHON,
        context: Optional[CodeContext] = None
    ) -> CodeAnalysisResult:
        """
        Analyze code for vulnerabilities and quality.
        
        Args:
            code: Source code to analyze
            language: Programming language
            context: Optional code context
        
        Returns:
            Code analysis result
        """
        start_time = time.time()
        
        logger.info(f"Analyzing {language.value} code ({len(code)} chars)...")
        
        # Tokenize code
        tokens = self.tokenizer.tokenize(code, language)
        
        # Generate embeddings
        embedding = self.embeddings.generate_embedding(code, language)
        
        # Detect vulnerabilities
        vulnerabilities = self.vulnerability_detector.detect(code, language, context)
        
        # Calculate code quality metrics
        quality_score = self._calculate_quality_score(code, vulnerabilities)
        complexity_score = self._calculate_complexity(code, language)
        
        analysis_time = (time.time() - start_time) * 1000
        
        result = CodeAnalysisResult(
            language=language,
            vulnerabilities=vulnerabilities,
            code_quality_score=quality_score,
            complexity_score=complexity_score,
            embedding=embedding,
            analysis_time_ms=analysis_time
        )
        
        logger.info(
            f"Analysis complete: {len(vulnerabilities)} vulnerabilities found, "
            f"quality={quality_score:.2f}, complexity={complexity_score:.2f}"
        )
        
        return result
    
    def analyze_batch(
        self,
        code_samples: List[Dict]
    ) -> List[CodeAnalysisResult]:
        """
        Analyze multiple code samples.
        
        Args:
            code_samples: List of dicts with 'code', 'language', 'context'
        
        Returns:
            List of analysis results
        """
        results = []
        
        for sample in code_samples:
            result = self.analyze(
                sample['code'],
                sample.get('language', ProgrammingLanguage.PYTHON),
                sample.get('context')
            )
            results.append(result)
        
        return results
    
    def compare_code(
        self,
        code1: str,
        code2: str,
        language: ProgrammingLanguage = ProgrammingLanguage.PYTHON
    ) -> float:
        """
        Compare two code snippets for similarity.
        
        Args:
            code1: First code snippet
            code2: Second code snippet
            language: Programming language
        
        Returns:
            Similarity score (0-1)
        """
        return self.embeddings.calculate_similarity(code1, code2, language)
    
    def _calculate_quality_score(
        self,
        code: str,
        vulnerabilities: List[VulnerabilityPattern]
    ) -> float:
        """Calculate code quality score (0-100)."""
        # Start with perfect score
        score = 100.0
        
        # Deduct points for vulnerabilities
        for vuln in vulnerabilities:
            if vuln.severity == "critical":
                score -= 20
            elif vuln.severity == "high":
                score -= 10
            elif vuln.severity == "medium":
                score -= 5
            else:
                score -= 2
        
        # Deduct points for code smells
        if len(code) > 10000:  # Very long file
            score -= 5
        
        if code.count('\n') > 500:  # Too many lines
            score -= 5
        
        # Ensure score is in valid range
        return max(0.0, min(100.0, score))
    
    def _calculate_complexity(
        self,
        code: str,
        language: ProgrammingLanguage
    ) -> float:
        """Calculate code complexity score."""
        # Simplified cyclomatic complexity
        complexity = 1  # Base complexity
        
        # Count decision points
        decision_keywords = ['if', 'elif', 'else', 'for', 'while', 'case', 'catch', '&&', '||']
        for keyword in decision_keywords:
            complexity += code.lower().count(keyword)
        
        # Normalize by lines of code
        lines = code.count('\n') + 1
        normalized_complexity = complexity / lines if lines > 0 else 0
        
        return min(100.0, normalized_complexity * 10)
    
    def get_vulnerability_summary(
        self,
        result: CodeAnalysisResult
    ) -> Dict:
        """Get summary of vulnerabilities."""
        summary = {
            'total': len(result.vulnerabilities),
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
            'by_type': {},
            'high_confidence': 0
        }
        
        for vuln in result.vulnerabilities:
            summary['by_severity'][vuln.severity] += 1
            
            vuln_type = vuln.pattern_type.value
            summary['by_type'][vuln_type] = summary['by_type'].get(vuln_type, 0) + 1
            
            if vuln.is_high_confidence():
                summary['high_confidence'] += 1
        
        return summary

