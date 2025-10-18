import logging
import time
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


class ScanSeverity(Enum):
    """Severity levels for scan findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ScanFinding:
    """Represents a security finding from dynamic scanning."""
    vulnerability_type: str
    severity: ScanSeverity
    url: str
    method: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    description: str = ""
    remediation: str = ""
    confidence: int = 0  # 0-100
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'vulnerability_type': self.vulnerability_type,
            'severity': self.severity.value,
            'url': self.url,
            'method': self.method,
            'parameter': self.parameter,
            'payload': self.payload,
            'evidence': self.evidence,
            'description': self.description,
            'remediation': self.remediation,
            'confidence': self.confidence,
        }


@dataclass
class ScanResult:
    """Results from dynamic security scanning."""
    target_url: str
    scan_duration: float
    findings: List[ScanFinding] = field(default_factory=list)
    requests_sent: int = 0
    errors: List[str] = field(default_factory=list)
    scan_types: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'target_url': self.target_url,
            'scan_duration': self.scan_duration,
            'findings': [f.to_dict() for f in self.findings],
            'findings_count': len(self.findings),
            'requests_sent': self.requests_sent,
            'errors': self.errors,
            'scan_types': self.scan_types,
            'severity_breakdown': self._get_severity_breakdown(),
        }
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get count of findings by severity."""
        breakdown = {
            'CRITICAL': 0,
            'HIGH': 0,
            'MEDIUM': 0,
            'LOW': 0,
            'INFO': 0,
        }
        for finding in self.findings:
            breakdown[finding.severity.value] += 1
        return breakdown


class DynamicScanner:
    """
    Dynamic security scanner for safe, controlled vulnerability testing.
    
    Features:
    - SQL Injection detection
    - XSS detection
    - Command Injection detection
    - Path Traversal detection
    - SSRF detection
    - Open Redirect detection
    - XXE detection
    - Rate limiting and safety controls
    """
    
    # SQL Injection payloads (safe detection only)
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND '1'='1",
    ]
    
    # XSS payloads (safe detection only)
    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "javascript:alert('XSS')",
        "<svg onload=alert('XSS')>",
        "'\"><script>alert('XSS')</script>",
    ]
    
    # Command Injection payloads (safe detection only)
    CMD_PAYLOADS = [
        "; echo 'vulnerable'",
        "| echo 'vulnerable'",
        "& echo 'vulnerable'",
        "`echo 'vulnerable'`",
        "$(echo 'vulnerable')",
    ]
    
    # Path Traversal payloads
    PATH_PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    ]
    
    # SSRF payloads (safe internal IPs)
    SSRF_PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://169.254.169.254",  # AWS metadata
        "http://[::1]",
        "http://0.0.0.0",
    ]
    
    # SQL error patterns
    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_.*",
        r"valid MySQL result",
        r"MySqlClient\.",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_.*",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL.*Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"SqlException",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_.*",
        r"Warning.*ora_.*",
    ]
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize dynamic scanner.
        
        Args:
            config: Scanner configuration
        """
        self.config = config or {}
        self.timeout = self.config.get('timeout', 10)
        self.max_requests = self.config.get('max_requests', 100)
        self.delay_between_requests = self.config.get('delay', 0.5)
        self.verify_ssl = self.config.get('verify_ssl', True)
        self.user_agent = self.config.get('user_agent', 'BountyBot-Scanner/2.3.0')
        
        # Set up session with retries
        self.session = requests.Session()
        retry_strategy = Retry(
            total=2,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        self.session.headers.update({
            'User-Agent': self.user_agent,
        })
        
        logger.info(f"Dynamic scanner initialized (timeout={self.timeout}s, max_requests={self.max_requests})")
    
    def scan(self, target_url: str, scan_types: Optional[List[str]] = None) -> ScanResult:
        """
        Perform dynamic security scan on target URL.
        
        Args:
            target_url: Target URL to scan
            scan_types: List of scan types to perform (default: all)
                       Options: 'sqli', 'xss', 'cmdi', 'path_traversal', 'ssrf', 'open_redirect'
        
        Returns:
            ScanResult with findings
        """
        start_time = time.time()
        
        if scan_types is None:
            scan_types = ['sqli', 'xss', 'cmdi', 'path_traversal', 'ssrf', 'open_redirect']
        
        logger.info(f"Starting dynamic scan of {target_url} (types: {scan_types})")
        
        result = ScanResult(
            target_url=target_url,
            scan_duration=0,
            scan_types=scan_types,
        )
        
        try:
            # Verify target is accessible
            if not self._verify_target(target_url):
                result.errors.append(f"Target {target_url} is not accessible")
                result.scan_duration = time.time() - start_time
                return result
            
            # Run selected scans
            if 'sqli' in scan_types:
                self._scan_sql_injection(target_url, result)
            
            if 'xss' in scan_types:
                self._scan_xss(target_url, result)
            
            if 'cmdi' in scan_types:
                self._scan_command_injection(target_url, result)
            
            if 'path_traversal' in scan_types:
                self._scan_path_traversal(target_url, result)
            
            if 'ssrf' in scan_types:
                self._scan_ssrf(target_url, result)
            
            if 'open_redirect' in scan_types:
                self._scan_open_redirect(target_url, result)
            
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            result.errors.append(str(e))
        
        result.scan_duration = time.time() - start_time
        logger.info(f"Scan completed in {result.scan_duration:.2f}s, found {len(result.findings)} issues")

        return result

    def _verify_target(self, url: str) -> bool:
        """Verify target is accessible."""
        try:
            response = self.session.get(url, timeout=self.timeout, verify=self.verify_ssl)
            return response.status_code < 500
        except Exception as e:
            logger.error(f"Failed to access target: {e}")
            return False

    def _scan_sql_injection(self, target_url: str, result: ScanResult):
        """Scan for SQL injection vulnerabilities."""
        logger.info("Scanning for SQL injection...")

        # Parse URL to get parameters
        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            logger.info("No parameters found for SQL injection testing")
            return

        for param_name in params.keys():
            for payload in self.SQL_PAYLOADS:
                if result.requests_sent >= self.max_requests:
                    logger.warning("Max requests reached")
                    return

                # Test parameter with payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                try:
                    time.sleep(self.delay_between_requests)
                    response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                    result.requests_sent += 1

                    # Check for SQL errors in response
                    for pattern in self.SQL_ERROR_PATTERNS:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            finding = ScanFinding(
                                vulnerability_type="SQL Injection",
                                severity=ScanSeverity.CRITICAL,
                                url=target_url,
                                method="GET",
                                parameter=param_name,
                                payload=payload,
                                evidence=f"SQL error pattern detected: {pattern}",
                                description=f"SQL injection vulnerability detected in parameter '{param_name}'",
                                remediation="Use parameterized queries or prepared statements",
                                confidence=85,
                            )
                            result.findings.append(finding)
                            logger.warning(f"SQL injection found in parameter: {param_name}")
                            break

                except Exception as e:
                    logger.debug(f"Error testing SQL injection: {e}")

    def _scan_xss(self, target_url: str, result: ScanResult):
        """Scan for XSS vulnerabilities."""
        logger.info("Scanning for XSS...")

        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            logger.info("No parameters found for XSS testing")
            return

        for param_name in params.keys():
            for payload in self.XSS_PAYLOADS:
                if result.requests_sent >= self.max_requests:
                    return

                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                try:
                    time.sleep(self.delay_between_requests)
                    response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                    result.requests_sent += 1

                    # Check if payload is reflected in response
                    if payload in response.text:
                        finding = ScanFinding(
                            vulnerability_type="Cross-Site Scripting (XSS)",
                            severity=ScanSeverity.HIGH,
                            url=target_url,
                            method="GET",
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Payload reflected in response",
                            description=f"XSS vulnerability detected in parameter '{param_name}'",
                            remediation="Implement proper output encoding and Content Security Policy",
                            confidence=80,
                        )
                        result.findings.append(finding)
                        logger.warning(f"XSS found in parameter: {param_name}")
                        break

                except Exception as e:
                    logger.debug(f"Error testing XSS: {e}")

    def _scan_command_injection(self, target_url: str, result: ScanResult):
        """Scan for command injection vulnerabilities."""
        logger.info("Scanning for command injection...")

        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return

        for param_name in params.keys():
            for payload in self.CMD_PAYLOADS:
                if result.requests_sent >= self.max_requests:
                    return

                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                try:
                    time.sleep(self.delay_between_requests)
                    response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                    result.requests_sent += 1

                    # Check for command output in response
                    if 'vulnerable' in response.text.lower():
                        finding = ScanFinding(
                            vulnerability_type="Command Injection",
                            severity=ScanSeverity.CRITICAL,
                            url=target_url,
                            method="GET",
                            parameter=param_name,
                            payload=payload,
                            evidence="Command output detected in response",
                            description=f"Command injection vulnerability detected in parameter '{param_name}'",
                            remediation="Avoid executing system commands with user input. Use safe APIs instead",
                            confidence=90,
                        )
                        result.findings.append(finding)
                        logger.warning(f"Command injection found in parameter: {param_name}")
                        break

                except Exception as e:
                    logger.debug(f"Error testing command injection: {e}")

    def _scan_path_traversal(self, target_url: str, result: ScanResult):
        """Scan for path traversal vulnerabilities."""
        logger.info("Scanning for path traversal...")

        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return

        for param_name in params.keys():
            for payload in self.PATH_PAYLOADS:
                if result.requests_sent >= self.max_requests:
                    return

                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                try:
                    time.sleep(self.delay_between_requests)
                    response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                    result.requests_sent += 1

                    # Check for file content indicators
                    indicators = ['root:', '[boot loader]', '[extensions]', 'for 16-bit app support']
                    for indicator in indicators:
                        if indicator in response.text.lower():
                            finding = ScanFinding(
                                vulnerability_type="Path Traversal",
                                severity=ScanSeverity.HIGH,
                                url=target_url,
                                method="GET",
                                parameter=param_name,
                                payload=payload,
                                evidence=f"File content indicator detected: {indicator}",
                                description=f"Path traversal vulnerability detected in parameter '{param_name}'",
                                remediation="Validate and sanitize file paths. Use whitelisting",
                                confidence=85,
                            )
                            result.findings.append(finding)
                            logger.warning(f"Path traversal found in parameter: {param_name}")
                            break

                except Exception as e:
                    logger.debug(f"Error testing path traversal: {e}")

    def _scan_ssrf(self, target_url: str, result: ScanResult):
        """Scan for SSRF vulnerabilities."""
        logger.info("Scanning for SSRF...")

        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return

        for param_name in params.keys():
            for payload in self.SSRF_PAYLOADS:
                if result.requests_sent >= self.max_requests:
                    return

                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                try:
                    time.sleep(self.delay_between_requests)
                    start = time.time()
                    response = self.session.get(test_url, timeout=self.timeout, verify=self.verify_ssl)
                    duration = time.time() - start
                    result.requests_sent += 1

                    # Check for SSRF indicators (connection attempts, timeouts, etc.)
                    # Note: This is a basic check - real SSRF detection requires out-of-band testing
                    if duration > 5 or response.status_code in [500, 502, 503, 504]:
                        finding = ScanFinding(
                            vulnerability_type="Server-Side Request Forgery (SSRF)",
                            severity=ScanSeverity.HIGH,
                            url=target_url,
                            method="GET",
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Suspicious behavior detected (duration={duration:.2f}s, status={response.status_code})",
                            description=f"Potential SSRF vulnerability in parameter '{param_name}'",
                            remediation="Validate and whitelist allowed URLs. Disable redirects",
                            confidence=60,  # Lower confidence without out-of-band testing
                        )
                        result.findings.append(finding)
                        logger.warning(f"Potential SSRF found in parameter: {param_name}")
                        break

                except requests.exceptions.Timeout:
                    finding = ScanFinding(
                        vulnerability_type="Server-Side Request Forgery (SSRF)",
                        severity=ScanSeverity.HIGH,
                        url=target_url,
                        method="GET",
                        parameter=param_name,
                        payload=payload,
                        evidence="Request timeout - possible internal network access",
                        description=f"Potential SSRF vulnerability in parameter '{param_name}'",
                        remediation="Validate and whitelist allowed URLs. Disable redirects",
                        confidence=70,
                    )
                    result.findings.append(finding)
                    logger.warning(f"Potential SSRF (timeout) found in parameter: {param_name}")
                    break

                except Exception as e:
                    logger.debug(f"Error testing SSRF: {e}")

    def _scan_open_redirect(self, target_url: str, result: ScanResult):
        """Scan for open redirect vulnerabilities."""
        logger.info("Scanning for open redirects...")

        parsed = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed.query)

        if not params:
            return

        redirect_payloads = [
            "https://evil.com",
            "//evil.com",
            "https://google.com",
            "/\\evil.com",
        ]

        for param_name in params.keys():
            for payload in redirect_payloads:
                if result.requests_sent >= self.max_requests:
                    return

                test_params = params.copy()
                test_params[param_name] = [payload]
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params, doseq=True)}"

                try:
                    time.sleep(self.delay_between_requests)
                    response = self.session.get(
                        test_url,
                        timeout=self.timeout,
                        verify=self.verify_ssl,
                        allow_redirects=False
                    )
                    result.requests_sent += 1

                    # Check for redirect to external domain
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.com' in location or 'google.com' in location:
                            finding = ScanFinding(
                                vulnerability_type="Open Redirect",
                                severity=ScanSeverity.MEDIUM,
                                url=target_url,
                                method="GET",
                                parameter=param_name,
                                payload=payload,
                                evidence=f"Redirect to external domain: {location}",
                                description=f"Open redirect vulnerability in parameter '{param_name}'",
                                remediation="Validate redirect URLs against whitelist",
                                confidence=90,
                            )
                            result.findings.append(finding)
                            logger.warning(f"Open redirect found in parameter: {param_name}")
                            break

                except Exception as e:
                    logger.debug(f"Error testing open redirect: {e}")

    def close(self):
        """Close scanner session."""
        if self.session:
            self.session.close()
            logger.info("Scanner session closed")

