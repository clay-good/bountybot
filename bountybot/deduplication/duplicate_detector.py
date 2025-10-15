import logging
import hashlib
import json
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime
from difflib import SequenceMatcher
import re

logger = logging.getLogger(__name__)


@dataclass
class ReportFingerprint:
    """Fingerprint of a bug bounty report for duplicate detection."""
    
    report_id: str
    title: str
    vulnerability_type: Optional[str]
    affected_component: Optional[str]
    
    # Fingerprints
    title_hash: str = ""
    description_hash: str = ""
    http_request_fingerprints: List[str] = field(default_factory=list)
    payload_fingerprints: List[str] = field(default_factory=list)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.now)
    severity: Optional[str] = None
    
    # Normalized text for fuzzy matching
    normalized_title: str = ""
    normalized_description: str = ""
    
    def __post_init__(self):
        """Generate fingerprints after initialization."""
        if not self.title_hash:
            self.title_hash = self._hash_text(self.title)
        if not self.normalized_title:
            self.normalized_title = self._normalize_text(self.title)
    
    @staticmethod
    def _hash_text(text: str) -> str:
        """Generate SHA-256 hash of text."""
        if not text:
            return ""
        return hashlib.sha256(text.encode('utf-8')).hexdigest()
    
    @staticmethod
    def _normalize_text(text: str) -> str:
        """Normalize text for fuzzy matching."""
        if not text:
            return ""
        # Convert to lowercase
        text = text.lower()
        # Remove special characters but keep spaces
        text = re.sub(r'[^a-z0-9\s]', '', text)
        # Collapse multiple spaces
        text = re.sub(r'\s+', ' ', text)
        return text.strip()


@dataclass
class DuplicateMatch:
    """Result of duplicate detection."""
    
    is_duplicate: bool
    confidence: float  # 0.0 to 1.0
    matched_report_id: Optional[str] = None
    similarity_scores: Dict[str, float] = field(default_factory=dict)
    reasoning: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_duplicate": self.is_duplicate,
            "confidence": round(self.confidence, 3),
            "matched_report_id": self.matched_report_id,
            "similarity_scores": {k: round(v, 3) for k, v in self.similarity_scores.items()},
            "reasoning": self.reasoning,
        }


class DuplicateDetector:
    """
    Intelligent duplicate detection for bug bounty reports.
    
    Uses multiple signals:
    1. Exact title/description matching
    2. Fuzzy text similarity
    3. HTTP request fingerprinting
    4. Vulnerability type + component matching
    5. Payload similarity
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize duplicate detector.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.fingerprints: Dict[str, ReportFingerprint] = {}
        
        # Thresholds
        self.exact_match_threshold = self.config.get('exact_match_threshold', 0.95)
        self.fuzzy_match_threshold = self.config.get('fuzzy_match_threshold', 0.85)
        self.duplicate_threshold = self.config.get('duplicate_threshold', 0.75)
        
        logger.info(f"Initialized DuplicateDetector with {len(self.fingerprints)} fingerprints")
    
    def add_report(self, report, report_id: Optional[str] = None) -> ReportFingerprint:
        """
        Add a report to the duplicate detection database.
        
        Args:
            report: Bug bounty report
            report_id: Optional report ID (generated if not provided)
            
        Returns:
            ReportFingerprint
        """
        if report_id is None:
            report_id = self._generate_report_id(report)
        
        fingerprint = self._create_fingerprint(report, report_id)
        self.fingerprints[report_id] = fingerprint
        
        logger.debug(f"Added report fingerprint: {report_id}")
        return fingerprint
    
    def check_duplicate(self, report, report_id: Optional[str] = None) -> DuplicateMatch:
        """
        Check if a report is a duplicate of existing reports.
        
        Args:
            report: Bug bounty report to check
            report_id: Optional report ID
            
        Returns:
            DuplicateMatch with results
        """
        if not self.fingerprints:
            return DuplicateMatch(
                is_duplicate=False,
                confidence=0.0,
                reasoning=["No existing reports to compare against"]
            )
        
        # Create fingerprint for new report
        new_fingerprint = self._create_fingerprint(report, report_id or "new")
        
        # Find best match
        best_match = None
        best_score = 0.0
        best_scores = {}
        best_reasoning = []
        
        for existing_id, existing_fp in self.fingerprints.items():
            if existing_id == report_id:
                continue  # Skip self
            
            match_score, scores, reasoning = self._calculate_similarity(
                new_fingerprint, existing_fp
            )
            
            if match_score > best_score:
                best_score = match_score
                best_match = existing_id
                best_scores = scores
                best_reasoning = reasoning
        
        is_duplicate = best_score >= self.duplicate_threshold
        
        logger.info(f"Duplicate check: score={best_score:.3f}, is_duplicate={is_duplicate}")
        
        return DuplicateMatch(
            is_duplicate=is_duplicate,
            confidence=best_score,
            matched_report_id=best_match if is_duplicate else None,
            similarity_scores=best_scores,
            reasoning=best_reasoning
        )
    
    def _create_fingerprint(self, report, report_id: str) -> ReportFingerprint:
        """Create fingerprint from report."""
        # Get first affected component or None
        affected_component = None
        if hasattr(report, 'affected_components') and report.affected_components:
            affected_component = report.affected_components[0]

        fingerprint = ReportFingerprint(
            report_id=report_id,
            title=report.title or "",
            vulnerability_type=report.vulnerability_type,
            affected_component=affected_component,
            severity=report.severity.value if report.severity else None,
        )
        
        # Hash description
        if report.impact_description:
            fingerprint.description_hash = ReportFingerprint._hash_text(report.impact_description)
            fingerprint.normalized_description = ReportFingerprint._normalize_text(report.impact_description)
        
        # Fingerprint HTTP requests
        if hasattr(report, 'extracted_http_requests'):
            for req in report.extracted_http_requests:
                fp = self._fingerprint_http_request(req)
                if fp:
                    fingerprint.http_request_fingerprints.append(fp)
        
        # Extract and fingerprint payloads
        if report.proof_of_concept:
            payloads = self._extract_payloads(str(report.proof_of_concept))
            fingerprint.payload_fingerprints = [
                ReportFingerprint._hash_text(p) for p in payloads
            ]
        
        return fingerprint
    
    def _calculate_similarity(
        self, 
        fp1: ReportFingerprint, 
        fp2: ReportFingerprint
    ) -> Tuple[float, Dict[str, float], List[str]]:
        """
        Calculate similarity between two fingerprints.
        
        Returns:
            (overall_score, individual_scores, reasoning)
        """
        scores = {}
        reasoning = []
        
        # 1. Exact hash matching (highest weight)
        if fp1.title_hash == fp2.title_hash:
            scores['title_exact'] = 1.0
            reasoning.append("Exact title match")
        else:
            # Fuzzy title matching
            title_sim = self._fuzzy_similarity(fp1.normalized_title, fp2.normalized_title)
            scores['title_fuzzy'] = title_sim
            if title_sim > 0.8:
                reasoning.append(f"High title similarity ({title_sim:.2f})")
        
        # 2. Description similarity
        if fp1.description_hash == fp2.description_hash:
            scores['description_exact'] = 1.0
            reasoning.append("Exact description match")
        elif fp1.normalized_description and fp2.normalized_description:
            desc_sim = self._fuzzy_similarity(fp1.normalized_description, fp2.normalized_description)
            scores['description_fuzzy'] = desc_sim
            if desc_sim > 0.7:
                reasoning.append(f"Similar description ({desc_sim:.2f})")
        
        # 3. Vulnerability type matching
        if fp1.vulnerability_type and fp2.vulnerability_type:
            if fp1.vulnerability_type.lower() == fp2.vulnerability_type.lower():
                scores['vuln_type'] = 1.0
                reasoning.append("Same vulnerability type")
            else:
                scores['vuln_type'] = 0.0
        
        # 4. Affected component matching
        if fp1.affected_component and fp2.affected_component:
            comp_sim = self._fuzzy_similarity(
                fp1.affected_component.lower(),
                fp2.affected_component.lower()
            )
            scores['component'] = comp_sim
            if comp_sim > 0.8:
                reasoning.append(f"Same affected component ({comp_sim:.2f})")
        
        # 5. HTTP request fingerprint matching
        if fp1.http_request_fingerprints and fp2.http_request_fingerprints:
            http_sim = self._jaccard_similarity(
                set(fp1.http_request_fingerprints),
                set(fp2.http_request_fingerprints)
            )
            scores['http_requests'] = http_sim
            if http_sim > 0.5:
                reasoning.append(f"Similar HTTP requests ({http_sim:.2f})")
        
        # 6. Payload fingerprint matching
        if fp1.payload_fingerprints and fp2.payload_fingerprints:
            payload_sim = self._jaccard_similarity(
                set(fp1.payload_fingerprints),
                set(fp2.payload_fingerprints)
            )
            scores['payloads'] = payload_sim
            if payload_sim > 0.5:
                reasoning.append(f"Similar payloads ({payload_sim:.2f})")
        
        # Calculate weighted overall score
        weights = {
            'title_exact': 0.30,
            'title_fuzzy': 0.25,
            'description_exact': 0.20,
            'description_fuzzy': 0.15,
            'vuln_type': 0.10,
            'component': 0.10,
            'http_requests': 0.15,
            'payloads': 0.10,
        }
        
        overall_score = sum(
            scores.get(key, 0.0) * weight
            for key, weight in weights.items()
        )
        
        # Normalize by sum of applicable weights
        applicable_weight = sum(
            weight for key, weight in weights.items()
            if key in scores
        )
        if applicable_weight > 0:
            overall_score = overall_score / applicable_weight
        
        return overall_score, scores, reasoning

    @staticmethod
    def _fuzzy_similarity(text1: str, text2: str) -> float:
        """Calculate fuzzy similarity between two texts using SequenceMatcher."""
        if not text1 or not text2:
            return 0.0
        return SequenceMatcher(None, text1, text2).ratio()

    @staticmethod
    def _jaccard_similarity(set1: set, set2: set) -> float:
        """Calculate Jaccard similarity between two sets."""
        if not set1 or not set2:
            return 0.0
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0.0

    @staticmethod
    def _fingerprint_http_request(request) -> Optional[str]:
        """Generate fingerprint for HTTP request."""
        try:
            # Create fingerprint from method, path, and key parameters
            method = getattr(request, 'method', 'GET')
            url = getattr(request, 'url', '')

            # Extract path without query params
            from urllib.parse import urlparse
            parsed = urlparse(url)
            path = parsed.path

            # Sort query parameters for consistent fingerprinting
            query_params = getattr(request, 'query_params', {})
            sorted_params = sorted(query_params.keys()) if query_params else []

            # Create fingerprint string
            fp_string = f"{method}:{path}:{','.join(sorted_params)}"
            return hashlib.sha256(fp_string.encode('utf-8')).hexdigest()
        except Exception as e:
            logger.warning(f"Failed to fingerprint HTTP request: {e}")
            return None

    @staticmethod
    def _extract_payloads(text: str) -> List[str]:
        """Extract potential payloads from text."""
        payloads = []

        # Common payload patterns
        patterns = [
            r"<script[^>]*>.*?</script>",  # XSS
            r"'.*?OR.*?--",  # SQL injection
            r"\$\{.*?\}",  # Template injection
            r"{{.*?}}",  # SSTI
            r"file:///\S+",  # File inclusion
            r"http://\S+",  # SSRF
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE | re.DOTALL)
            payloads.extend(matches)

        return payloads

    @staticmethod
    def _generate_report_id(report) -> str:
        """Generate unique report ID."""
        timestamp = datetime.now().isoformat()
        title = report.title or "untitled"
        id_string = f"{timestamp}:{title}"
        return hashlib.sha256(id_string.encode('utf-8')).hexdigest()[:16]

    def get_statistics(self) -> Dict[str, Any]:
        """Get duplicate detection statistics."""
        return {
            "total_reports": len(self.fingerprints),
            "thresholds": {
                "exact_match": self.exact_match_threshold,
                "fuzzy_match": self.fuzzy_match_threshold,
                "duplicate": self.duplicate_threshold,
            },
        }

    def clear(self):
        """Clear all fingerprints."""
        self.fingerprints.clear()
        logger.info("Cleared all report fingerprints")

    def export_fingerprints(self) -> List[Dict[str, Any]]:
        """Export fingerprints for persistence."""
        return [
            {
                "report_id": fp.report_id,
                "title": fp.title,
                "title_hash": fp.title_hash,
                "description_hash": fp.description_hash,
                "vulnerability_type": fp.vulnerability_type,
                "affected_component": fp.affected_component,
                "severity": fp.severity,
                "created_at": fp.created_at.isoformat(),
                "http_request_fingerprints": fp.http_request_fingerprints,
                "payload_fingerprints": fp.payload_fingerprints,
            }
            for fp in self.fingerprints.values()
        ]

    def import_fingerprints(self, fingerprints_data: List[Dict[str, Any]]):
        """Import fingerprints from persistence."""
        for data in fingerprints_data:
            fp = ReportFingerprint(
                report_id=data["report_id"],
                title=data["title"],
                vulnerability_type=data.get("vulnerability_type"),
                affected_component=data.get("affected_component"),
                title_hash=data["title_hash"],
                description_hash=data.get("description_hash", ""),
                http_request_fingerprints=data.get("http_request_fingerprints", []),
                payload_fingerprints=data.get("payload_fingerprints", []),
                severity=data.get("severity"),
                created_at=datetime.fromisoformat(data["created_at"]),
            )
            self.fingerprints[fp.report_id] = fp

        logger.info(f"Imported {len(fingerprints_data)} fingerprints")

