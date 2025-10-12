import os
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional

from bountybot.models import CodeAnalysisResult

logger = logging.getLogger(__name__)


class CodeAnalyzer:
    """
    Static code analyzer that searches for vulnerability patterns in source code.
    Uses pattern matching to identify potential security issues.
    """
    
    # Vulnerability patterns for different types
    PATTERNS = {
        'sql injection': [
            r'execute\s*\(\s*["\'].*\+.*["\']',
            r'query\s*\(\s*["\'].*\+.*["\']',
            r'raw\s*\(\s*["\'].*\+.*["\']',
            r'\.format\s*\(.*\).*execute',
            r'f["\'].*\{.*\}.*["\'].*execute',
            r'["\'].*SELECT.*["\'].*\+',
            r'["\'].*INSERT.*["\'].*\+',
            r'["\'].*UPDATE.*["\'].*\+',
            r'["\'].*DELETE.*["\'].*\+',
            r'\+.*["\'].*WHERE',
            r'cursor\.execute\s*\(\s*["\'].*%.*["\'].*%',
            r'Statement\.executeQuery\s*\(\s*["\'].*\+',
            r'\$wpdb->query\s*\(\s*["\'].*\.',
        ],
        'xss': [
            r'innerHTML\s*=',
            r'document\.write\s*\(',
            r'eval\s*\(',
            r'dangerouslySetInnerHTML',
            r'v-html\s*=',
            r'outerHTML\s*=',
            r'insertAdjacentHTML',
            r'\.html\s*\(\s*[^)]*\+',
            r'echo\s+\$_GET',
            r'echo\s+\$_POST',
            r'print\s+request\.',
        ],
        'path traversal': [
            r'open\s*\(.*\+',
            r'readFile\s*\(.*\+',
            r'\.\./',
            r'path\.join\s*\(.*request',
            r'File\s*\(\s*.*\+',
            r'FileInputStream\s*\(\s*.*\+',
            r'include\s*\(\s*\$_GET',
            r'require\s*\(\s*\$_GET',
        ],
        'command injection': [
            r'exec\s*\(',
            r'system\s*\(',
            r'shell_exec\s*\(',
            r'subprocess\s*\.\s*call\s*\(',
            r'os\.system\s*\(',
            r'Runtime\.getRuntime\s*\(\s*\)\.exec',
            r'ProcessBuilder\s*\(',
            r'passthru\s*\(',
            r'popen\s*\(',
            r'child_process\.exec',
        ],
        'deserialization': [
            r'pickle\.loads',
            r'yaml\.load\s*\(',
            r'unserialize\s*\(',
            r'JSON\.parse.*eval',
            r'ObjectInputStream\.readObject',
            r'XMLDecoder\.readObject',
            r'Marshal\.load',
        ],
        'xxe': [
            r'DocumentBuilderFactory\.newInstance',
            r'SAXParserFactory\.newInstance',
            r'XMLInputFactory\.newInstance',
            r'xml\.etree\.ElementTree\.parse',
            r'lxml\.etree\.parse',
            r'simplexml_load_string',
            r'DOMDocument::loadXML',
        ],
        'ssrf': [
            r'requests\.get\s*\(.*request\.',
            r'urllib\.request\.urlopen\s*\(.*request\.',
            r'file_get_contents\s*\(\s*\$_GET',
            r'curl_exec\s*\(',
            r'HttpClient\.execute',
            r'fetch\s*\(.*req\.',
        ],
        'csrf': [
            r'@app\.route.*methods=\[.*POST.*\](?!.*csrf)',
            r'app\.post\s*\((?!.*csrf)',
            r'<form(?!.*csrf)',
        ],
        'idor': [
            r'get_object_or_404\s*\(.*request\.',
            r'findById\s*\(.*request\.',
            r'SELECT.*WHERE\s+id\s*=.*\$_GET',
        ],
        'authentication_bypass': [
            r'if\s+\$_GET\[.*admin.*\]',
            r'session\[.*\]\s*=\s*True',
            r'isAdmin\s*=\s*request\.',
        ],
    }
    
    # Security controls to look for
    SECURITY_CONTROLS = {
        'parameterized_queries': [
            r'prepare\s*\(',
            r'bind_param',
            r'placeholder',
            r'\?',  # SQL placeholders
        ],
        'input_validation': [
            r'validate',
            r'sanitize',
            r'escape',
            r'filter',
        ],
        'output_encoding': [
            r'htmlspecialchars',
            r'escape',
            r'encode',
            r'textContent',
        ],
    }
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize code analyzer.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config
        self.enabled_languages = config.get('languages', ['python', 'javascript'])
        self.exclude_patterns = config.get('exclude_patterns', [])
        self.max_file_size_mb = config.get('max_file_size_mb', 10)
    
    def analyze(self, codebase_path: str, 
                vulnerability_type: Optional[str] = None,
                affected_files: Optional[List[str]] = None) -> CodeAnalysisResult:
        """
        Analyze codebase for vulnerabilities.
        
        Args:
            codebase_path: Path to codebase root
            vulnerability_type: Type of vulnerability to look for
            affected_files: Specific files mentioned in report
            
        Returns:
            Code analysis result
        """
        logger.info(f"Analyzing codebase at: {codebase_path}")
        
        if not os.path.exists(codebase_path):
            logger.error(f"Codebase path does not exist: {codebase_path}")
            return CodeAnalysisResult(
                vulnerable_code_found=False,
                confidence=0,
                analysis_notes=["Codebase path does not exist"],
            )
        
        vulnerable_files = []
        vulnerable_patterns = []
        security_controls = {}
        
        # Get files to analyze
        files_to_analyze = self._get_files_to_analyze(codebase_path, affected_files)
        
        if not files_to_analyze:
            return CodeAnalysisResult(
                vulnerable_code_found=False,
                confidence=0,
                analysis_notes=["No files found to analyze"],
            )
        
        # Analyze each file
        for file_path in files_to_analyze:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Search for vulnerability patterns
                if vulnerability_type:
                    patterns = self._get_patterns_for_vuln_type(vulnerability_type)
                    matches = self._search_patterns(content, patterns)
                    
                    if matches:
                        vulnerable_files.append(str(file_path))
                        for match in matches:
                            vulnerable_patterns.append({
                                'file': str(file_path),
                                'pattern': match['pattern'],
                                'line': match['line'],
                                'code': match['code'],
                            })
                
                # Check for security controls
                controls = self._check_security_controls(content)
                for control, found in controls.items():
                    if control not in security_controls:
                        security_controls[control] = found
                    else:
                        security_controls[control] = security_controls[control] or found
            
            except Exception as e:
                logger.warning(f"Error analyzing file {file_path}: {e}")
        
        # Calculate confidence
        confidence = self._calculate_confidence(
            len(vulnerable_patterns),
            len(files_to_analyze),
            security_controls
        )
        
        vulnerable_code_found = len(vulnerable_patterns) > 0
        
        analysis_notes = []
        if vulnerable_code_found:
            analysis_notes.append(f"Found {len(vulnerable_patterns)} potential vulnerability patterns")
        else:
            analysis_notes.append("No obvious vulnerability patterns found")
        
        if security_controls:
            controls_found = [k for k, v in security_controls.items() if v]
            if controls_found:
                analysis_notes.append(f"Security controls found: {', '.join(controls_found)}")
        
        result = CodeAnalysisResult(
            vulnerable_code_found=vulnerable_code_found,
            vulnerable_files=vulnerable_files,
            vulnerable_patterns=vulnerable_patterns,
            security_controls=security_controls,
            confidence=confidence,
            analysis_notes=analysis_notes,
        )
        
        logger.info(f"Code analysis complete: {len(vulnerable_patterns)} patterns found")
        return result
    
    def _get_files_to_analyze(self, codebase_path: str, 
                             affected_files: Optional[List[str]]) -> List[Path]:
        """Get list of files to analyze."""
        files = []
        codebase = Path(codebase_path)
        
        # If specific files mentioned, try to find them
        if affected_files:
            for file_pattern in affected_files:
                # Try exact match
                file_path = codebase / file_pattern
                if file_path.exists() and file_path.is_file():
                    files.append(file_path)
                else:
                    # Try to find files matching pattern
                    for found_file in codebase.rglob(f"*{file_pattern}*"):
                        if found_file.is_file() and self._should_analyze_file(found_file):
                            files.append(found_file)
        
        # If no specific files or none found, analyze all relevant files
        if not files:
            for ext in ['.py', '.js', '.java', '.php', '.rb']:
                for file_path in codebase.rglob(f"*{ext}"):
                    if self._should_analyze_file(file_path):
                        files.append(file_path)
        
        return files[:100]  # Limit to 100 files for performance
    
    def _should_analyze_file(self, file_path: Path) -> bool:
        """Check if file should be analyzed."""
        # Check file size
        try:
            size_mb = file_path.stat().st_size / (1024 * 1024)
            if size_mb > self.max_file_size_mb:
                return False
        except Exception:
            return False
        
        # Check exclude patterns
        file_str = str(file_path)
        for pattern in self.exclude_patterns:
            pattern_regex = pattern.replace('*', '.*')
            if re.search(pattern_regex, file_str):
                return False
        
        return True
    
    def _get_patterns_for_vuln_type(self, vuln_type: str) -> List[str]:
        """Get regex patterns for vulnerability type."""
        vuln_type_lower = vuln_type.lower()
        for key, patterns in self.PATTERNS.items():
            if key in vuln_type_lower:
                return patterns
        return []
    
    def _search_patterns(self, content: str, patterns: List[str]) -> List[Dict[str, Any]]:
        """Search for patterns in content."""
        matches = []
        lines = content.split('\n')
        
        for pattern in patterns:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    matches.append({
                        'pattern': pattern,
                        'line': line_num,
                        'code': line.strip(),
                    })
        
        return matches
    
    def _check_security_controls(self, content: str) -> Dict[str, bool]:
        """Check for security controls in content."""
        controls = {}
        
        for control_name, patterns in self.SECURITY_CONTROLS.items():
            found = False
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    found = True
                    break
            controls[control_name] = found
        
        return controls
    
    def _calculate_confidence(self, num_patterns: int, 
                            num_files: int,
                            security_controls: Dict[str, bool]) -> int:
        """Calculate confidence score for analysis."""
        if num_patterns == 0:
            return 30  # Low confidence if nothing found
        
        # Base confidence on number of patterns found
        confidence = min(50 + (num_patterns * 10), 90)
        
        # Reduce confidence if security controls are present
        controls_present = sum(1 for v in security_controls.values() if v)
        confidence -= (controls_present * 10)
        
        return max(0, min(100, confidence))

