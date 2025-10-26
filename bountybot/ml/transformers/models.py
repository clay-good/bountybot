"""
Data models for transformer-based code analysis.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Tuple
from datetime import datetime


class ProgrammingLanguage(Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    JAVA = "java"
    CPP = "cpp"
    C = "c"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"
    CSHARP = "csharp"
    TYPESCRIPT = "typescript"
    UNKNOWN = "unknown"


class VulnerabilityPatternType(Enum):
    """Types of vulnerability patterns."""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    WEAK_CRYPTO = "weak_crypto"
    RACE_CONDITION = "race_condition"
    BUFFER_OVERFLOW = "buffer_overflow"
    USE_AFTER_FREE = "use_after_free"


@dataclass
class TransformerConfig:
    """Configuration for transformer models."""
    model_name: str = "microsoft/codebert-base"
    max_sequence_length: int = 512
    embedding_dim: int = 768
    num_attention_heads: int = 12
    num_layers: int = 12
    dropout: float = 0.1
    use_gpu: bool = False
    batch_size: int = 8


@dataclass
class CodeEmbedding:
    """Code embedding from transformer model."""
    embedding_vector: List[float]
    tokens: List[str]
    attention_weights: Optional[List[List[float]]] = None
    model_name: str = "codebert"
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class VulnerabilityPattern:
    """Detected vulnerability pattern in code."""
    pattern_type: VulnerabilityPatternType
    confidence: float
    line_numbers: List[int]
    code_snippet: str
    description: str
    severity: str  # "critical", "high", "medium", "low"
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None
    
    def is_high_confidence(self, threshold: float = 0.8) -> bool:
        """Check if detection is high confidence."""
        return self.confidence >= threshold


@dataclass
class CodeAnalysisResult:
    """Result of code analysis."""
    language: ProgrammingLanguage
    vulnerabilities: List[VulnerabilityPattern] = field(default_factory=list)
    code_quality_score: float = 0.0
    complexity_score: float = 0.0
    embedding: Optional[CodeEmbedding] = None
    analysis_time_ms: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def get_critical_vulnerabilities(self) -> List[VulnerabilityPattern]:
        """Get critical severity vulnerabilities."""
        return [v for v in self.vulnerabilities if v.severity == "critical"]
    
    def get_high_confidence_vulnerabilities(self, threshold: float = 0.8) -> List[VulnerabilityPattern]:
        """Get high confidence vulnerabilities."""
        return [v for v in self.vulnerabilities if v.confidence >= threshold]


@dataclass
class SimilarityScore:
    """Code similarity score."""
    code1_id: str
    code2_id: str
    similarity: float
    method: str  # "cosine", "euclidean", "semantic"
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def is_similar(self, threshold: float = 0.8) -> bool:
        """Check if codes are similar."""
        return self.similarity >= threshold


@dataclass
class CodeContext:
    """Context information for code analysis."""
    file_path: str
    function_name: Optional[str] = None
    class_name: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)

