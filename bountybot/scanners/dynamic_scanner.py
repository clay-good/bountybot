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
    - SSTI (Server-Side Template Injection) detection
    - XXE (XML External Entity) detection
    - JWT vulnerability detection
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

            if 'ssti' in scan_types:
                self._scan_ssti(target_url, result)

            if 'xxe' in scan_types:
                self._scan_xxe(target_url, result)

            if 'jwt' in scan_types:
                self._scan_jwt(target_url, result)

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

    def _scan_ssti(self, target_url: str, result: ScanResult):
        """
        Test for Server-Side Template Injection vulnerabilities.

        Args:
            target_url: Target URL to test
            result: ScanResult object to append findings
        """
        logger.info("Testing for SSTI vulnerabilities")

        # SSTI detection payloads (safe mathematical expressions)
        ssti_payloads = [
            ('{{7*7}}', '49'),  # Jinja2, Twig
            ('${7*7}', '49'),   # Freemarker, Velocity
            ('<%= 7*7 %>', '49'),  # ERB
            ('${{7*7}}', '49'),  # Various
            ('#{7*7}', '49'),   # Various
            ('*{7*7}', '49'),   # Smarty
        ]

        parsed_url = urllib.parse.urlparse(target_url)
        params = urllib.parse.parse_qs(parsed_url.query)

        if not params:
            # Try common parameter names
            params = {'name': ['test'], 'input': ['test'], 'template': ['test']}

        for param_name in params.keys():
            for payload, expected_output in ssti_payloads:
                try:
                    test_params = params.copy()
                    test_params[param_name] = [payload]

                    test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    response = self.session.get(
                        test_url,
                        params=test_params,
                        timeout=self.timeout,
                        allow_redirects=False
                    )
                    result.requests_sent += 1

                    # Check if the mathematical expression was evaluated
                    if expected_output in response.text:
                        finding = ScanFinding(
                            vulnerability_type="SSTI",
                            severity=ScanSeverity.CRITICAL,
                            url=target_url,
                            method="GET",
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Template expression evaluated: {payload} = {expected_output}",
                            description=f"Server-Side Template Injection in parameter '{param_name}'",
                            remediation="Never embed user input directly in templates. Use template parameters instead.",
                            confidence=95,
                        )
                        result.findings.append(finding)
                        logger.warning(f"SSTI found in parameter: {param_name}")
                        break

                except Exception as e:
                    logger.debug(f"Error testing SSTI: {e}")

    def _scan_xxe(self, target_url: str, result: ScanResult):
        """
        Test for XML External Entity (XXE) vulnerabilities.

        Args:
            target_url: Target URL to test
            result: ScanResult object to append findings
        """
        logger.info("Testing for XXE vulnerabilities")

        # XXE detection payloads (safe, non-destructive)
        xxe_payloads = [
            # Basic XXE with file read attempt
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<root><data>&xxe;</data></root>''',

            # XXE with parameter entity
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/hostname">%xxe;]>
<root><data>test</data></root>''',

            # XXE with external DTD
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo SYSTEM "http://example.com/xxe.dtd">
<root><data>test</data></root>''',
        ]

        for payload in xxe_payloads:
            try:
                response = self.session.post(
                    target_url,
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=self.timeout,
                    allow_redirects=False
                )
                result.requests_sent += 1

                # Check for XXE indicators in response
                xxe_indicators = [
                    'hostname',  # /etc/hostname content
                    'localhost',  # Common hostname
                    '<!ENTITY',  # Entity declaration in error
                    'XML parsing error',  # Parser error
                    'External entity',  # Error message
                ]

                response_lower = response.text.lower()
                for indicator in xxe_indicators:
                    if indicator.lower() in response_lower:
                        finding = ScanFinding(
                            vulnerability_type="XXE",
                            severity=ScanSeverity.HIGH,
                            url=target_url,
                            method="POST",
                            payload=payload[:100] + "...",
                            evidence=f"XXE indicator found in response: {indicator}",
                            description="XML External Entity (XXE) vulnerability detected",
                            remediation="Disable external entity processing in XML parser. Use secure parser configuration.",
                            confidence=85,
                        )
                        result.findings.append(finding)
                        logger.warning("XXE vulnerability detected")
                        return  # Found one, no need to continue

            except Exception as e:
                logger.debug(f"Error testing XXE: {e}")

    def _scan_jwt(self, target_url: str, result: ScanResult):
        """
        Test for JWT (JSON Web Token) vulnerabilities.

        Args:
            target_url: Target URL to test
            result: ScanResult object to append findings
        """
        logger.info("Testing for JWT vulnerabilities")

        try:
            # First, try to get a JWT token from the response
            response = self.session.get(target_url, timeout=self.timeout)
            result.requests_sent += 1

            # Look for JWT in response headers or body
            jwt_token = None

            # Check Authorization header
            if 'Authorization' in response.headers:
                auth_header = response.headers['Authorization']
                if auth_header.startswith('Bearer '):
                    jwt_token = auth_header[7:]

            # Check cookies
            for cookie in self.session.cookies:
                if 'token' in cookie.name.lower() or 'jwt' in cookie.name.lower():
                    jwt_token = cookie.value
                    break

            # Check response body for JWT pattern
            if not jwt_token:
                import re
                jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
                match = re.search(jwt_pattern, response.text)
                if match:
                    jwt_token = match.group(0)

            if not jwt_token:
                logger.debug("No JWT token found in response")
                return

            # Analyze JWT structure
            jwt_parts = jwt_token.split('.')
            if len(jwt_parts) != 3:
                logger.debug("Invalid JWT format")
                return

            import base64
            import json

            # Decode header and payload
            try:
                # Add padding if needed
                header_b64 = jwt_parts[0] + '=' * (4 - len(jwt_parts[0]) % 4)
                payload_b64 = jwt_parts[1] + '=' * (4 - len(jwt_parts[1]) % 4)

                header = json.loads(base64.urlsafe_b64decode(header_b64))
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                # Check for vulnerabilities
                vulnerabilities_found = []

                # 1. Check for 'none' algorithm
                if header.get('alg', '').lower() == 'none':
                    vulnerabilities_found.append({
                        'type': 'Algorithm None',
                        'severity': ScanSeverity.CRITICAL,
                        'description': "JWT uses 'none' algorithm - signature verification bypassed",
                        'confidence': 100
                    })

                # 2. Check for weak algorithms
                weak_algs = ['HS256', 'HS384', 'HS512']
                if header.get('alg') in weak_algs:
                    vulnerabilities_found.append({
                        'type': 'Weak Algorithm',
                        'severity': ScanSeverity.MEDIUM,
                        'description': f"JWT uses weak HMAC algorithm: {header.get('alg')}. Vulnerable to brute force.",
                        'confidence': 70
                    })

                # 3. Check for missing expiration
                if 'exp' not in payload:
                    vulnerabilities_found.append({
                        'type': 'Missing Expiration',
                        'severity': ScanSeverity.MEDIUM,
                        'description': "JWT missing 'exp' claim - token never expires",
                        'confidence': 100
                    })

                # 4. Check for long expiration
                if 'exp' in payload and 'iat' in payload:
                    lifetime = payload['exp'] - payload['iat']
                    if lifetime > 3600:  # More than 1 hour
                        vulnerabilities_found.append({
                            'type': 'Long Token Lifetime',
                            'severity': ScanSeverity.LOW,
                            'description': f"JWT has long lifetime: {lifetime} seconds",
                            'confidence': 80
                        })

                # 5. Check for sensitive data in payload
                sensitive_keys = ['password', 'secret', 'api_key', 'private_key', 'ssn', 'credit_card']
                for key in payload.keys():
                    if any(sensitive in key.lower() for sensitive in sensitive_keys):
                        vulnerabilities_found.append({
                            'type': 'Sensitive Data Exposure',
                            'severity': ScanSeverity.HIGH,
                            'description': f"JWT payload contains sensitive field: {key}",
                            'confidence': 90
                        })

                # Add findings
                for vuln in vulnerabilities_found:
                    finding = ScanFinding(
                        vulnerability_type=f"JWT - {vuln['type']}",
                        severity=vuln['severity'],
                        url=target_url,
                        method="GET",
                        payload=jwt_token[:50] + "...",
                        evidence=f"Header: {json.dumps(header)}, Payload keys: {list(payload.keys())}",
                        description=vuln['description'],
                        remediation="Use strong algorithms (RS256/ES256), validate all claims, implement short token lifetimes",
                        confidence=vuln['confidence'],
                    )
                    result.findings.append(finding)
                    logger.warning(f"JWT vulnerability found: {vuln['type']}")

            except Exception as e:
                logger.debug(f"Error decoding JWT: {e}")

        except Exception as e:
            logger.debug(f"Error testing JWT: {e}")

    def close(self):
        """Close scanner session."""
        if self.session:
            self.session.close()
            logger.info("Scanner session closed")

