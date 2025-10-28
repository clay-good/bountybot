"""
Proof-of-Concept Executor for validating reported vulnerabilities.

This module provides safe execution of PoC exploits to verify if reported
vulnerabilities actually exist in the target system.
"""

import logging
import asyncio
import subprocess
import tempfile
import os
import re
import json
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime
from enum import Enum
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class ExecutionStatus(Enum):
    """Status of PoC execution."""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"
    BLOCKED = "BLOCKED"  # Blocked by security controls
    UNSAFE = "UNSAFE"  # PoC deemed unsafe to execute


@dataclass
class ExecutionResult:
    """Result of PoC execution."""
    status: ExecutionStatus
    vulnerability_confirmed: bool
    confidence: float  # 0.0 to 1.0
    
    # Execution details
    execution_time: float = 0.0
    http_status_code: Optional[int] = None
    response_body: Optional[str] = None
    response_headers: Optional[Dict[str, str]] = None
    
    # Evidence
    evidence: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    
    # Errors and warnings
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    # Safety checks
    safety_violations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'status': self.status.value,
            'vulnerability_confirmed': self.vulnerability_confirmed,
            'confidence': round(self.confidence, 3),
            'execution_time': round(self.execution_time, 3),
            'http_status_code': self.http_status_code,
            'response_body': self.response_body[:500] if self.response_body else None,  # Truncate
            'response_headers': self.response_headers,
            'evidence': self.evidence,
            'indicators': self.indicators,
            'errors': self.errors,
            'warnings': self.warnings,
            'safety_violations': self.safety_violations,
        }


class PoCExecutor:
    """
    Safe executor for proof-of-concept exploits.
    
    Features:
    - HTTP request replay with validation
    - Safety checks to prevent destructive operations
    - Response analysis for vulnerability indicators
    - Timeout and rate limiting
    - Evidence collection
    """
    
    # Dangerous patterns that should never be executed
    DANGEROUS_PATTERNS = [
        r'rm\s+-rf\s+/',
        r'DROP\s+DATABASE',
        r'format\s+c:',
        r'del\s+/f\s+/s\s+/q',
        r'mkfs\.',
        r'dd\s+if=.*of=/dev/',
        r':(){ :|:& };:',  # Fork bomb
        r'chmod\s+777',
        r'chown\s+root',
        r'sudo\s+',
    ]
    
    # Indicators of successful exploitation
    VULNERABILITY_INDICATORS = {
        'sql_injection': [
            r'SQL syntax.*error',
            r'mysql_fetch',
            r'ORA-\d+',
            r'PostgreSQL.*ERROR',
            r'SQLite.*error',
            r'SQLSTATE\[',
            r'Warning.*mysql_',
        ],
        'xss': [
            r'<script[^>]*>.*</script>',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
        ],
        'command_injection': [
            r'uid=\d+\(.*\)\s+gid=\d+',  # Output of 'id' command
            r'root:.*:0:0:',  # /etc/passwd
            r'total\s+\d+',  # ls -la output
            r'Directory of',  # Windows dir output
        ],
        'path_traversal': [
            r'root:.*:0:0:',  # /etc/passwd
            r'\[boot loader\]',  # Windows boot.ini
            r'<\?php',  # PHP source code
        ],
        'ssrf': [
            r'169\.254\.169\.254',  # AWS metadata
            r'metadata\.google\.internal',
            r'<title>.*Internal.*</title>',
        ],
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize PoC executor.
        
        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.timeout = self.config.get('timeout', 30)  # seconds
        self.max_response_size = self.config.get('max_response_size', 1024 * 1024)  # 1MB
        self.allow_destructive = self.config.get('allow_destructive', False)
        self.verify_ssl = self.config.get('verify_ssl', True)
        
        # Setup HTTP session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        logger.info(f"Initialized PoCExecutor (timeout={self.timeout}s, destructive={self.allow_destructive})")
    
    async def execute_poc(self, poc, target_url: str, 
                          vulnerability_type: Optional[str] = None) -> ExecutionResult:
        """
        Execute a proof-of-concept exploit against target.
        
        Args:
            poc: ProofOfConcept object
            target_url: Target URL to test against
            vulnerability_type: Type of vulnerability being tested
            
        Returns:
            ExecutionResult with validation results
        """
        logger.info(f"Executing PoC: {poc.title}")
        start_time = asyncio.get_event_loop().time()
        
        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            vulnerability_confirmed=False,
            confidence=0.0,
        )
        
        # Safety check: Verify PoC is safe to execute
        if not self._is_safe_to_execute(poc):
            result.status = ExecutionStatus.UNSAFE
            result.errors.append("PoC contains dangerous patterns and cannot be executed")
            return result
        
        try:
            # Execute based on available PoC format
            if poc.http_requests and len(poc.http_requests) > 0:
                # Execute HTTP request
                exec_result = await self._execute_http_request(
                    poc.http_requests[0], 
                    target_url,
                    vulnerability_type or poc.vulnerability_type
                )
                result = exec_result
            elif poc.curl_command:
                # Parse and execute curl command
                exec_result = await self._execute_curl_command(
                    poc.curl_command,
                    target_url,
                    vulnerability_type or poc.vulnerability_type
                )
                result = exec_result
            else:
                result.status = ExecutionStatus.ERROR
                result.errors.append("No executable PoC format available")
            
            result.execution_time = asyncio.get_event_loop().time() - start_time
            
        except asyncio.TimeoutError:
            result.status = ExecutionStatus.TIMEOUT
            result.errors.append(f"Execution timed out after {self.timeout}s")
            result.execution_time = self.timeout
        except Exception as e:
            result.status = ExecutionStatus.ERROR
            result.errors.append(f"Execution error: {str(e)}")
            result.execution_time = asyncio.get_event_loop().time() - start_time
            logger.error(f"PoC execution error: {e}", exc_info=True)
        
        logger.info(f"PoC execution complete: confirmed={result.vulnerability_confirmed}, confidence={result.confidence}")
        return result
    
    def _is_safe_to_execute(self, poc) -> bool:
        """
        Check if PoC is safe to execute.
        
        Args:
            poc: ProofOfConcept object
            
        Returns:
            True if safe, False otherwise
        """
        if self.allow_destructive:
            return True
        
        # Check all PoC content for dangerous patterns
        content_to_check = [
            poc.curl_command or '',
            poc.python_code or '',
            poc.javascript_code or '',
            poc.raw_http or '',
            poc.description or '',
        ]
        
        for content in content_to_check:
            for pattern in self.DANGEROUS_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    logger.warning(f"Dangerous pattern detected: {pattern}")
                    return False
        
        return True
    
    async def _execute_http_request(self, http_request, target_url: str,
                                    vulnerability_type: str) -> ExecutionResult:
        """Execute HTTP request and analyze response."""
        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            vulnerability_confirmed=False,
            confidence=0.0,
        )
        
        try:
            # Build request
            method = http_request.method.upper()
            url = target_url if target_url else http_request.url
            headers = http_request.headers or {}
            body = http_request.body
            
            # Execute request with timeout
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self.session.request,
                    method=method,
                    url=url,
                    headers=headers,
                    data=body,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                ),
                timeout=self.timeout
            )
            
            # Store response details
            result.http_status_code = response.status_code
            result.response_headers = dict(response.headers)
            result.response_body = response.text[:self.max_response_size]
            
            # Analyze response for vulnerability indicators
            confirmed, confidence, evidence = self._analyze_response(
                response,
                vulnerability_type
            )
            
            result.vulnerability_confirmed = confirmed
            result.confidence = confidence
            result.evidence = evidence
            
        except requests.exceptions.Timeout:
            result.status = ExecutionStatus.TIMEOUT
            result.errors.append("Request timed out")
        except requests.exceptions.ConnectionError as e:
            result.status = ExecutionStatus.FAILED
            result.errors.append(f"Connection error: {str(e)}")
        except Exception as e:
            result.status = ExecutionStatus.ERROR
            result.errors.append(f"Request error: {str(e)}")
        
        return result

    def _analyze_response(self, response: requests.Response,
                         vulnerability_type: str) -> Tuple[bool, float, List[str]]:
        """
        Analyze HTTP response for vulnerability indicators.

        Args:
            response: HTTP response object
            vulnerability_type: Type of vulnerability being tested

        Returns:
            Tuple of (confirmed, confidence, evidence)
        """
        confirmed = False
        confidence = 0.0
        evidence = []

        # Get indicators for this vulnerability type
        vuln_type_key = vulnerability_type.lower().replace(' ', '_').replace('-', '_')
        indicators = self.VULNERABILITY_INDICATORS.get(vuln_type_key, [])

        # Check response body for indicators
        response_text = response.text
        matches = 0

        for indicator_pattern in indicators:
            if re.search(indicator_pattern, response_text, re.IGNORECASE | re.MULTILINE):
                matches += 1
                evidence.append(f"Found indicator: {indicator_pattern}")

        # Calculate confidence based on matches
        if matches > 0:
            confirmed = True
            # More matches = higher confidence
            confidence = min(0.5 + (matches * 0.2), 1.0)

        # Additional checks based on status code
        if response.status_code == 500:
            evidence.append("Server returned 500 error (possible exploitation)")
            if not confirmed:
                confidence = 0.3
        elif response.status_code == 200 and matches > 0:
            # Successful response with indicators = high confidence
            confidence = min(confidence + 0.2, 1.0)

        # Check response headers for indicators
        if 'X-Error' in response.headers or 'X-Debug' in response.headers:
            evidence.append("Debug headers present in response")
            confidence = min(confidence + 0.1, 1.0)

        return confirmed, confidence, evidence

    async def _execute_curl_command(self, curl_command: str, target_url: str,
                                    vulnerability_type: str) -> ExecutionResult:
        """
        Parse and execute curl command.

        Args:
            curl_command: Curl command string
            target_url: Target URL to use (overrides URL in curl command)
            vulnerability_type: Type of vulnerability

        Returns:
            ExecutionResult
        """
        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            vulnerability_confirmed=False,
            confidence=0.0,
        )

        try:
            # Parse curl command to extract method, headers, body
            method, headers, body = self._parse_curl_command(curl_command)

            # Execute request
            response = await asyncio.wait_for(
                asyncio.to_thread(
                    self.session.request,
                    method=method,
                    url=target_url,
                    headers=headers,
                    data=body,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=False,
                ),
                timeout=self.timeout
            )

            # Store response
            result.http_status_code = response.status_code
            result.response_headers = dict(response.headers)
            result.response_body = response.text[:self.max_response_size]

            # Analyze response
            confirmed, confidence, evidence = self._analyze_response(
                response,
                vulnerability_type
            )

            result.vulnerability_confirmed = confirmed
            result.confidence = confidence
            result.evidence = evidence

        except Exception as e:
            result.status = ExecutionStatus.ERROR
            result.errors.append(f"Curl execution error: {str(e)}")

        return result

    def _parse_curl_command(self, curl_command: str) -> Tuple[str, Dict[str, str], Optional[str]]:
        """
        Parse curl command to extract method, headers, and body.

        Args:
            curl_command: Curl command string

        Returns:
            Tuple of (method, headers, body)
        """
        method = "GET"
        headers = {}
        body = None

        # Extract method
        if '-X POST' in curl_command or '--request POST' in curl_command:
            method = "POST"
        elif '-X PUT' in curl_command or '--request PUT' in curl_command:
            method = "PUT"
        elif '-X DELETE' in curl_command or '--request DELETE' in curl_command:
            method = "DELETE"
        elif '-X PATCH' in curl_command or '--request PATCH' in curl_command:
            method = "PATCH"

        # Extract headers
        header_pattern = r'-H\s+["\']([^:]+):\s*([^"\']+)["\']'
        for match in re.finditer(header_pattern, curl_command):
            header_name = match.group(1).strip()
            header_value = match.group(2).strip()
            headers[header_name] = header_value

        # Extract body
        data_pattern = r'(?:-d|--data)\s+["\']([^"\']+)["\']'
        data_match = re.search(data_pattern, curl_command)
        if data_match:
            body = data_match.group(1)

        return method, headers, body

    async def verify_poc_against_codebase(self, poc, codebase_path: str,
                                          vulnerability_type: str) -> ExecutionResult:
        """
        Verify if PoC vulnerability exists in codebase.

        This performs static analysis to check if the vulnerability
        pattern exists in the code without executing the PoC.

        Args:
            poc: ProofOfConcept object
            codebase_path: Path to codebase
            vulnerability_type: Type of vulnerability

        Returns:
            ExecutionResult with verification results
        """
        result = ExecutionResult(
            status=ExecutionStatus.SUCCESS,
            vulnerability_confirmed=False,
            confidence=0.0,
        )

        # This would integrate with the CodeAnalyzer to verify
        # if the vulnerability pattern exists in the codebase
        result.warnings.append("Codebase verification not yet implemented")

        return result

